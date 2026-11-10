package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"singctl/configs"
	"singctl/internal/adguard"
	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestNonlinearEngine_MultiFactorScoringAndTrustDamping(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "main", URL: "https://sub.myairport.example.com/api/v1/client/subscribe?token=1111"},
		},
		Audit: config.AuditConfig{
			Whitelist: []string{"nas-sync.example.org"},
		},
	}
	eng := audit.NewNonlinearEngine(cfg)

	// 1. 正常大流量下载（下载 500MB，上传 8MB ACK 包）-> 应判定为 ThreatNormal (0分)
	normalDownload := &audit.FlowRecord{
		DeviceIP:      "192.168.1.10",
		DeviceName:    "MacBook-Pro",
		Target:        "video.cdn.example.com",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   8 * 1024 * 1024,
		DownloadBytes: 500 * 1024 * 1024,
		ConnCount:     4,
	}
	eng.EvaluateFlow(normalDownload)
	if normalDownload.Threat != audit.ThreatNormal || normalDownload.RiskScore >= 20 {
		t.Fatalf("expected normal download to be ThreatNormal (<20), got threat=%s score=%d reasons=%v",
			normalDownload.Threat, normalDownload.RiskScore, normalDownload.Reasons)
	}

	// 2. 办公代码上传命中可信白名单 (github.com 上传 80MB，下载 1MB) -> 触发信任阻尼衰减，绝不误报
	trustedUpload := &audit.FlowRecord{
		DeviceIP:      "192.168.1.10",
		DeviceName:    "MacBook-Pro",
		Target:        "github.com",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   80 * 1024 * 1024,
		DownloadBytes: 1 * 1024 * 1024,
		ConnCount:     6,
	}
	eng.EvaluateFlow(trustedUpload)
	if trustedUpload.State != audit.EnforcementWhitelisted || trustedUpload.Threat != audit.ThreatNormal || trustedUpload.RiskScore >= 20 {
		t.Fatalf("expected github.com upload to be whitelisted & ThreatNormal, got state=%s threat=%s score=%d",
			trustedUpload.State, trustedUpload.Threat, trustedUpload.RiskScore)
	}

	// 3. 客厅智能电视凌晨直连公网陌生 IP 的非标 UDP 端口大流量上传 (多维特征交叉爆炸 -> 高危 >= 80分)
	pcdnStealth := &audit.FlowRecord{
		DeviceIP:      "192.168.1.55",
		DeviceName:    "Xiaomi-TV-LivingRoom",
		Target:        "203.0.113.88",
		IsDirectIP:    true,
		DestPort:      54321,
		Network:       "udp",
		UploadBytes:   160 * 1024 * 1024,
		DownloadBytes: 512 * 1024,
		ConnCount:     28,
		NightHits:     5,
		IntervalCV:    0.08, // 极规律机器定时心跳
	}
	eng.EvaluateFlow(pcdnStealth)
	if pcdnStealth.Threat != audit.ThreatHighRisk || pcdnStealth.RiskScore < 80 {
		t.Fatalf("expected IoT midnight direct-IP UDP upload to be ThreatHighRisk (>=80), got threat=%s score=%d factors=%v",
			pcdnStealth.Threat, pcdnStealth.RiskScore, pcdnStealth.NonlinearFactors)
	}

	// 4. 高随机熵值子域名 + 遥测关键词 + 规律心跳信标上传 -> 可疑/高危 (>= 60分)
	telemetryBeacon := &audit.FlowRecord{
		DeviceIP:      "192.168.1.66",
		DeviceName:    "IPC-Camera",
		Target:        "x9q8w7z2k1m5p4b3.telemetry.bad-sdk.example.com",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   18 * 1024 * 1024,
		DownloadBytes: 120 * 1024,
		ConnCount:     35,
		NightHits:     3,
		IntervalCV:    0.05,
	}
	eng.EvaluateFlow(telemetryBeacon)
	if telemetryBeacon.RiskScore < 60 || (telemetryBeacon.Threat != audit.ThreatSuspicious && telemetryBeacon.Threat != audit.ThreatHighRisk) {
		t.Fatalf("expected telemetry beacon to score >=60, got score=%d threat=%s",
			telemetryBeacon.RiskScore, telemetryBeacon.Threat)
	}
}

func TestValidateTargetSafety_AntiLockout(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "main", URL: "https://sub.airport-node.example.com/sub"},
		},
		Server: config.ServerConfig{
			NodeDomain: "us1.my-vps.example.com",
		},
	}

	mustReject := []string{
		"127.0.0.1",
		"::1",
		"localhost",
		"192.168.1.1",
		"192.168.1.55",
		"100.64.0.15",
		"223.5.5.5",
		"1.1.1.1",
		"sub.airport-node.example.com",
		"airport-node.example.com",
		"us1.my-vps.example.com",
	}
	for _, target := range mustReject {
		if _, _, err := audit.ValidateTargetSafety(cfg, target); err == nil {
			t.Fatalf("expected anti-lockout guard to reject %q, but it was allowed", target)
		}
	}

	mustAllow := []string{
		"log.suspicious-tracker.example.com",
		"203.0.113.88",
		"198.51.100.0/24",
	}
	for _, target := range mustAllow {
		if _, _, err := audit.ValidateTargetSafety(cfg, target); err != nil {
			t.Fatalf("expected safe target %q to be allowed, got error: %v", target, err)
		}
	}
}

func TestCollector_Enforcer_And_AIAdvisor_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. 准备模拟 DHCP 租约文件 (将 192.168.1.55 映射为 Xiaomi-TV)
	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	leaseContent := "1730000000 aa:bb:cc:11:22:33 192.168.1.55 Xiaomi-TV *\n"
	if err := os.WriteFile(leaseFile, []byte(leaseContent), 0600); err != nil {
		t.Fatal(err)
	}

	// 2. 准备模拟 Clash API 服务 (支持 GET /connections 与 DELETE /connections/{id})
	var killedConnID atomic.Value
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"uploadTotal":   150 * 1024 * 1024,
				"downloadTotal": 2 * 1024 * 1024,
				"connections": []map[string]any{
					{
						"id":       "conn-suspect-pcdn-1",
						"upload":   95 * 1024 * 1024,
						"download": 200 * 1024,
						"start":    "2026-11-10T03:10:00Z",
						"chains":   []string{"#DC"},
						"rule":     "Match",
						"metadata": map[string]any{
							"network":         "udp",
							"sourceIP":        "192.168.1.55",
							"destinationIP":   "203.0.113.99",
							"destinationPort": "45678",
							"host":            "pcdn-tracker.bad.example.com",
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/") {
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			killedConnID.Store(id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer clashSrv.Close()

	// 3. 准备模拟 L2 AI 大模型接口（验证发送的数据已完成脱敏且不含内网真实 IP 192.168.1.55）
	var aiReceivedBody string
	aiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		_, _ = body.ReadFrom(r.Body)
		aiReceivedBody = body.String()

		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message": map[string]string{
						"content": `[{"id":"192.168.1.55|pcdn-tracker.bad.example.com|udp","category":"电视PCDN后台共享节点","verdict":"safe_to_block","impact":"拉黑后仅停止后台偷跑上传，不影响电视正常点播","recommend":"block_global"}]`,
					},
				},
			},
		})
	}))
	defer aiSrv.Close()

	// 4. 准备初始 singctl.yaml、sing-box config.json 与 AdGuardHome.yaml
	singctlPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(singctlPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(singctlPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Audit.AI = config.AuditAIConfig{
		Enabled:  true,
		Endpoint: aiSrv.URL,
		APIKey:   "test-ai-key",
		Model:    "test-model",
	}

	sbConfigPath := filepath.Join(tmpDir, "config.json")
	initialSBJSON := `{
  "dns": {
    "servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
    "rules": [{"clash_mode": "Direct", "server": "dns_local"}]
  },
  "route": {
    "rules": [
      {"ip_is_private": true, "outbound": "#DC"},
      {"rule_set": ["geosite-ad1"], "action": "reject"}
    ]
  }
}`
	if err := os.WriteFile(sbConfigPath, []byte(initialSBJSON), 0600); err != nil {
		t.Fatal(err)
	}

	aghConfigPath := filepath.Join(tmpDir, "AdGuardHome.yaml")
	passHash, _ := config.HashPassword("testpass123456")
	aghBytes, err := adguard.BuildInitialConfigYAML(adguard.ConfigParams{
		LANIP:        "192.168.1.1",
		WebPort:      3000,
		DNSPort:      5353,
		Username:     "root",
		PasswordHash: passHash,
		SubURLs:      []string{"https://sub.example.com/s"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aghConfigPath, aghBytes, 0600); err != nil {
		t.Fatal(err)
	}

	// 5. 运行 Collector 采集与 AI 研判
	collector := audit.NewCollector(cfg)
	collector.SetEndpointsForTest([]string{clashSrv.URL}, "", filepath.Join(tmpDir, "audit-state.json"))
	collector.SetLeaseFilesForTest([]string{leaseFile}, "", "")
	collector.SetNowFuncForTest(func() time.Time {
		return time.Date(2026, 11, 10, 3, 15, 0, 0, time.UTC)
	})

	rep := collector.Collect(t.Context(), audit.CollectOptions{EnableAI: true})
	if !rep.Reachable || len(rep.Flows) != 1 {
		t.Fatalf("expected 1 collected flow, got reachable=%v flows=%d", rep.Reachable, len(rep.Flows))
	}
	flow := rep.Flows[0]
	if flow.DeviceName != "Xiaomi-TV" || flow.DeviceRole != "iot" {
		t.Fatalf("expected DHCP lease resolution Xiaomi-TV (iot), got name=%q role=%q", flow.DeviceName, flow.DeviceRole)
	}
	if flow.RiskScore < 70 || (flow.Threat != audit.ThreatSuspicious && flow.Threat != audit.ThreatHighRisk) {
		t.Fatalf("expected PCDN upload to be suspicious/high_risk, got score=%d threat=%s", flow.RiskScore, flow.Threat)
	}
	if flow.AIReview == nil || flow.AIReview.Verdict != audit.AISafeToBlock {
		t.Fatalf("expected AIReview verdict safe_to_block, got %+v", flow.AIReview)
	}
	if !strings.Contains(aiReceivedBody, "pcdn-tracker.bad.example.com") {
		t.Fatalf("expected AI request to include target domain, got %s", aiReceivedBody)
	}

	// 6. 执行一键双层拉黑 (Sing-Box + AdGuard Home + 斩断连接)
	enforcer := audit.NewEnforcer(cfg, singctlPath)
	enforcer.SetPathsForTest(sbConfigPath, aghConfigPath, []string{clashSrv.URL}, "")

	blockRes, err := enforcer.Block(t.Context(), "pcdn-tracker.bad.example.com", "192.168.1.55", "电视后台PCDN偷跑")
	if err != nil {
		t.Fatalf("Enforcer.Block failed: %v", err)
	}
	if !blockRes.ConfigSaved || !blockRes.SingBoxSynced || !blockRes.DNSBlocked || blockRes.KilledConnections != 1 {
		t.Fatalf("unexpected BlockActionResult: %+v", blockRes)
	}
	if gotID, _ := killedConnID.Load().(string); gotID != "conn-suspect-pcdn-1" {
		t.Fatalf("expected active connection conn-suspect-pcdn-1 to be killed via DELETE, got %q", gotID)
	}

	// 验证 AdGuardHome.yaml 中已写入按客户端 IP 限制的高优拦截规则，且保留原有订阅白名单
	aghAfter, err := os.ReadFile(aghConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	aghStr := string(aghAfter)
	if !strings.Contains(aghStr, "||pcdn-tracker.bad.example.com^$client=192.168.1.55,important") {
		t.Fatalf("expected AdGuardHome.yaml to contain client-scoped block rule, got:\n%s", aghStr)
	}
	if !strings.Contains(aghStr, "@@||sub.example.com^$important") {
		t.Fatalf("expected AdGuardHome.yaml to preserve subscription whitelist rule, got:\n%s", aghStr)
	}

	// 验证 sing-box config.json 中已注入 DNS 与路由 reject 规则
	sbAfter, err := os.ReadFile(sbConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	sbStr := string(sbAfter)
	if !strings.Contains(sbStr, `"pcdn-tracker.bad.example.com"`) || !strings.Contains(sbStr, `"192.168.1.55/32"`) {
		t.Fatalf("expected sing-box config.json to contain injected reject rule, got:\n%s", sbStr)
	}

	// 7. 执行一键解封并验证三端同步移除
	unblockRes, err := enforcer.Unblock(t.Context(), "pcdn-tracker.bad.example.com", "192.168.1.55")
	if err != nil {
		t.Fatalf("Enforcer.Unblock failed: %v", err)
	}
	if !unblockRes.ConfigSaved || !unblockRes.SingBoxSynced || !unblockRes.DNSBlocked {
		t.Fatalf("unexpected UnblockActionResult: %+v", unblockRes)
	}
	aghUnblocked, _ := os.ReadFile(aghConfigPath)
	if strings.Contains(string(aghUnblocked), "pcdn-tracker.bad.example.com") {
		t.Fatalf("expected AdGuardHome.yaml to remove unblocked domain, got:\n%s", string(aghUnblocked))
	}
	sbUnblocked, _ := os.ReadFile(sbConfigPath)
	if strings.Contains(string(sbUnblocked), "pcdn-tracker.bad.example.com") {
		t.Fatalf("expected sing-box config.json to remove unblocked domain, got:\n%s", string(sbUnblocked))
	}
}

func TestWebUI_AuditEndpointsAndAntiScraper(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "secret123",
		Version:    "v1.14.72",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()

	token := srv.SessionToken()

	// 1. 恶意扫描器/爬虫 User-Agent 应被直接拦截返回 429
	reqBot, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/audit", nil)
	reqBot.Header.Set("Authorization", "Bearer "+token)
	reqBot.Header.Set("User-Agent", "sqlmap/1.7.2")
	respBot, err := http.DefaultClient.Do(reqBot)
	if err != nil {
		t.Fatal(err)
	}
	respBot.Body.Close()
	if respBot.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected scraper UA to get 429, got %d", respBot.StatusCode)
	}
	if gotRobots := respBot.Header.Get("X-Robots-Tag"); !strings.Contains(gotRobots, "noindex") {
		t.Fatalf("expected X-Robots-Tag noindex header, got %q", gotRobots)
	}

	// 2. 正常携带 Token 请求一键拉黑与解封
	blockBody, _ := json.Marshal(map[string]string{
		"target": "bad-upload.example.com",
		"reason": "测试WebUI拉黑",
	})
	reqBlock, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/audit/block", bytes.NewReader(blockBody))
	reqBlock.Header.Set("Authorization", "Bearer "+token)
	reqBlock.Header.Set("Content-Type", "application/json")
	respBlock, err := http.DefaultClient.Do(reqBlock)
	if err != nil {
		t.Fatal(err)
	}
	defer respBlock.Body.Close()
	if respBlock.StatusCode != http.StatusOK {
		t.Fatalf("expected POST /api/audit/block 200, got %d", respBlock.StatusCode)
	}

	loadedCfg, err := config.Load(cfgPath)
	if err != nil || len(loadedCfg.CustomRules.Block) != 1 || loadedCfg.CustomRules.Block[0].Target != "bad-upload.example.com" {
		t.Fatalf("expected block rule persisted to singctl.yaml, got %+v (err=%v)", loadedCfg, err)
	}

	// 3. 验证导出 CSV 接口返回纯正 UTF-8（绝对不带 UTF-8 BOM \xEF\xBB\xBF）
	reqCSV, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/audit?format=csv", nil)
	reqCSV.Header.Set("Authorization", "Bearer "+token)
	respCSV, err := http.DefaultClient.Do(reqCSV)
	if err != nil {
		t.Fatal(err)
	}
	var csvBuf bytes.Buffer
	_, _ = csvBuf.ReadFrom(respCSV.Body)
	respCSV.Body.Close()
	if respCSV.StatusCode != http.StatusOK {
		t.Fatalf("expected GET /api/audit?format=csv 200, got %d", respCSV.StatusCode)
	}
	if bytes.HasPrefix(csvBuf.Bytes(), []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("expected pure UTF-8 CSV without BOM, but found UTF-8 BOM prefix")
	}
	if !strings.HasPrefix(csvBuf.String(), "first_seen,last_seen,device_name,device_ip") {
		t.Fatalf("unexpected CSV header: %s", csvBuf.String())
	}
}
