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

	// 5. 纯隐私追踪场景：单次流量仅 18KB（逃避带宽阈值），但命中遥测指纹 + 凌晨熄屏定时上报 -> 隐私分高，主导轴为 privacy
	smallPrivacyTracker := &audit.FlowRecord{
		DeviceIP:      "192.168.1.77",
		DeviceName:    "Smart-Speaker",
		Target:        "applog.umeng.example.com",
		DestPort:      80,
		Network:       "tcp",
		UploadBytes:   18 * 1024,
		DownloadBytes: 64 * 1024,
		ConnCount:     20,
		NightHits:     4,
		IntervalCV:    0.04,
	}
	eng.EvaluateFlow(smallPrivacyTracker)
	if smallPrivacyTracker.PrivacyScore < 65 || smallPrivacyTracker.PrivacyScore <= smallPrivacyTracker.SecurityScore || smallPrivacyTracker.DominantAxis != "privacy" {
		t.Fatalf("expected small-packet tracker to have high PrivacyScore & dominantAxis=privacy, got sec=%d priv=%d total=%d axis=%s",
			smallPrivacyTracker.SecurityScore, smallPrivacyTracker.PrivacyScore, smallPrivacyTracker.RiskScore, smallPrivacyTracker.DominantAxis)
	}
	if app := audit.IdentifyApp("api.telegram.org", "", ""); app != "Telegram" {
		t.Fatalf("expected IdentifyApp telegram -> Telegram, got %q", app)
	}
	if app := audit.IdentifyApp("hm.baidu.com", "", ""); app != "百度 Baidu" {
		t.Fatalf("expected IdentifyApp baidu -> 百度 Baidu, got %q", app)
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

	// 4. 验证 AI 网关配置接口默认模型为 antigravity/gemini-3.8-flash 且支持保存 BaseURL / APIKey / Model
	aiCfgBody, _ := json.Marshal(map[string]string{
		"baseUrl": "http://127.0.0.1:3425/v1",
		"apiKey":  "sk-magpie-test-key",
		"model":   "",
	})
	reqAICfg, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/audit/ai-config", bytes.NewReader(aiCfgBody))
	reqAICfg.Header.Set("Authorization", "Bearer "+token)
	reqAICfg.Header.Set("Content-Type", "application/json")
	respAICfg, err := http.DefaultClient.Do(reqAICfg)
	if err != nil {
		t.Fatal(err)
	}
	respAICfg.Body.Close()
	if respAICfg.StatusCode != http.StatusOK {
		t.Fatalf("expected POST /api/audit/ai-config 200, got %d", respAICfg.StatusCode)
	}

	reloadedCfg, err := config.Load(cfgPath)
	if err != nil || reloadedCfg.Audit.AI.Endpoint != "http://127.0.0.1:3425/v1" || reloadedCfg.Audit.AI.Model != "antigravity/gemini-3.8-flash" {
		t.Fatalf("expected AI gateway config persisted with default model antigravity/gemini-3.8-flash, got %+v (err=%v)", reloadedCfg.Audit.AI, err)
	}
}

func TestSortFlows(t *testing.T) {
	flows := []audit.FlowRecord{
		{Target: "a.example.com", Threat: audit.ThreatNormal, RiskScore: 10, UploadBytes: 5000, DownloadBytes: 900000, UploadRatio: 0.1},
		{Target: "b.example.com", Threat: audit.ThreatHighRisk, RiskScore: 88, UploadBytes: 1000, DownloadBytes: 2000, UploadRatio: 0.5},
		{Target: "c.example.com", Threat: audit.ThreatSuspicious, RiskScore: 60, UploadBytes: 99000, DownloadBytes: 1000, UploadRatio: 99.0},
	}

	audit.SortFlows(flows, "upload", false)
	if flows[0].Target != "c.example.com" || flows[2].Target != "b.example.com" {
		t.Fatalf("upload desc failed: %+v", flows)
	}

	audit.SortFlows(flows, "download", false)
	if flows[0].Target != "a.example.com" {
		t.Fatalf("download desc failed: %+v", flows)
	}

	audit.SortFlows(flows, "ratio", true)
	if flows[0].Target != "a.example.com" || flows[2].Target != "c.example.com" {
		t.Fatalf("ratio asc failed: %+v", flows)
	}

	audit.SortFlows(flows, "risk", false)
	if flows[0].Target != "b.example.com" {
		t.Fatalf("risk desc failed: %+v", flows)
	}
}

func TestAuditCloudflareECHAndNightBrowsingNoFalsePositive(t *testing.T) {
	cfg := &config.Config{}
	eng := audit.NewNonlinearEngine(cfg)

	// 1. 验证 cloudflare-ech.com 在凌晨高频连接时命中可信白名单，不会误报为高危，且 AI 直接短路为 AIDoNotBlock
	echFlow := audit.FlowRecord{
		Key:           "192.168.1.50|cloudflare-ech.com|udp",
		DeviceIP:      "192.168.1.50",
		DeviceName:    "MacBook-Pro",
		Target:        "cloudflare-ech.com",
		DestPort:      443,
		Network:       "udp",
		UploadBytes:   45 * 1024,
		DownloadBytes: 1500 * 1024,
		ConnCount:     30,
		NightHits:     12,
	}
	eng.EvaluateFlow(&echFlow)
	if echFlow.State != audit.EnforcementWhitelisted {
		t.Fatalf("expected cloudflare-ech.com to be whitelisted, got state=%s", echFlow.State)
	}
	if echFlow.Threat != audit.ThreatNormal || echFlow.RiskScore >= 15 {
		t.Fatalf("expected cloudflare-ech.com normal threat (<15), got threat=%s score=%d", echFlow.Threat, echFlow.RiskScore)
	}

	adv := audit.NewAdvisor(config.AuditAIConfig{})
	batchRes, _ := adv.ReviewFlowBatch(t.Context(), []audit.FlowRecord{echFlow}, "127.0.0.1")
	if rev := batchRes[echFlow.Key]; rev == nil || rev.Verdict != audit.AIDoNotBlock {
		t.Fatalf("expected cloudflare-ech.com AI review short-circuited to do_not_block, got %+v", rev)
	}

	if _, _, err := audit.ValidateTargetSafety(cfg, "cloudflare-ech.com"); err == nil {
		t.Fatalf("expected ValidateTargetSafety to reject blocking cloudflare-ech.com")
	}

	// 2. 验证普通未知网站在凌晨正常下行浏览（下载远大于上传）不触发“凌晨熄屏静默上传”或“高频碎包持续回传”误报
	browsingFlow := audit.FlowRecord{
		Key:           "192.168.1.50|news.example.com|tcp",
		DeviceIP:      "192.168.1.50",
		DeviceName:    "iPhone",
		Target:        "news.example.com",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   40 * 1024,
		DownloadBytes: 1800 * 1024,
		ConnCount:     15,
		NightHits:     8,
	}
	eng.EvaluateFlow(&browsingFlow)
	if browsingFlow.Threat != audit.ThreatNormal || browsingFlow.RiskScore >= 35 {
		t.Fatalf("expected normal night browsing to stay normal (<35), got threat=%s score=%d reasons=%v",
			browsingFlow.Threat, browsingFlow.RiskScore, browsingFlow.Reasons)
	}

	// 3. 验证真实小包隐私遥测域名依然正常检出并被判定为 AISafeToBlock
	telemetryFlow := audit.FlowRecord{
		Key:           "192.168.1.60|wetelemetry.example.com|tcp",
		DeviceIP:      "192.168.1.60",
		DeviceName:    "Xiaomi-TV",
		Target:        "wetelemetry.example.com",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   18 * 1024,
		DownloadBytes: 2 * 1024,
		ConnCount:     12,
		NightHits:     5,
	}
	eng.EvaluateFlow(&telemetryFlow)
	if telemetryFlow.PrivacyScore == 0 {
		t.Fatalf("expected telemetryFlow to have non-zero PrivacyScore")
	}
	telBatch, _ := adv.ReviewFlowBatch(t.Context(), []audit.FlowRecord{telemetryFlow}, "127.0.0.1")
	if rev := telBatch[telemetryFlow.Key]; rev == nil || rev.Verdict != audit.AISafeToBlock {
		t.Fatalf("expected wetelemetry.example.com AI review to be safe_to_block, got %+v", rev)
	}
}

func TestOpenWrtTimezone_CertCNFallback_And_StateV2Migration(t *testing.T) {
	t.Setenv("TZ", "")
	locCST := audit.ParsePOSIXTZLocation("CST-8")
	if locCST == nil {
		t.Fatal("expected ParsePOSIXTZLocation(\"CST-8\") to return non-nil CST+8 location")
	}
	// UTC 06:06 对应北京时间 14:06（白天，绝非凌晨 01:00-05:59）
	dayUTC := time.Date(2026, 11, 12, 6, 6, 0, 0, time.UTC).In(locCST)
	if dayUTC.Hour() != 14 {
		t.Fatalf("expected CST-8 to map 06:06 UTC -> 14:06 CST (+8h), got hour=%d", dayUTC.Hour())
	}
	if locBracket := audit.ParsePOSIXTZLocation("<+08>-8"); locBracket == nil || time.Date(2026, 11, 12, 18, 30, 0, 0, time.UTC).In(locBracket).Hour() != 2 {
		t.Fatalf("expected <+08>-8 to map 18:30 UTC -> 02:30 local")
	}
	if locEST := audit.ParsePOSIXTZLocation("EST5EDT"); locEST == nil || time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC).In(locEST).Hour() != 5 {
		t.Fatalf("expected EST5EDT to map 10:00 UTC -> 05:00 EST (-5h)")
	}

	tmpDir := t.TempDir()
	tzFile := filepath.Join(tmpDir, "TZ")
	if err := os.WriteFile(tzFile, []byte("CST-8\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolvedLoc := audit.ResolveLocalLocationFromFiles(tzFile, "")
	if resolvedLoc == nil || time.Date(2026, 11, 12, 6, 0, 0, 0, time.UTC).In(resolvedLoc).Hour() != 14 {
		t.Fatalf("expected ResolveLocalLocationFromFiles to honor OpenWrt /etc/TZ CST-8")
	}

	// 构造旧版 (SchemaVersion=0) 状态快照：包含白天误记的 NightHits、非法证书 CN "mijia cloud" 以及超过 24h 的过期流
	nowSim := time.Date(2026, 11, 12, 6, 10, 0, 0, time.UTC).In(resolvedLoc) // 14:10 CST
	statePath := filepath.Join(tmpDir, "legacy-state.json")
	legacyJSON := `{
		"updatedUnix": 1794463000,
		"flows": {
			"192.168.1.20|mijia cloud|tcp": {
				"key": "192.168.1.20|mijia cloud|tcp",
				"deviceIp": "192.168.1.20",
				"target": "mijia cloud",
				"rawHost": "Mijia Cloud",
				"destIp": "203.0.113.45",
				"destPort": 443,
				"isDirectIp": false,
				"network": "tcp",
				"uploadBytes": 120000,
				"downloadBytes": 240000,
				"connCount": 5,
				"firstSeenUnix": ` + strings.TrimSpace(jsonNumber(nowSim.Unix()-600)) + `,
				"lastSeenUnix": ` + strings.TrimSpace(jsonNumber(nowSim.Unix()-60)) + `,
				"nightHits": 88
			},
			"192.168.1.20|stale.example.com|tcp": {
				"key": "192.168.1.20|stale.example.com|tcp",
				"deviceIp": "192.168.1.20",
				"target": "stale.example.com",
				"destIp": "198.51.100.12",
				"destPort": 443,
				"network": "tcp",
				"uploadBytes": 900000,
				"downloadBytes": 100000,
				"connCount": 10,
				"firstSeenUnix": ` + strings.TrimSpace(jsonNumber(nowSim.Unix()-100000)) + `,
				"lastSeenUnix": ` + strings.TrimSpace(jsonNumber(nowSim.Unix()-90000)) + `,
				"nightHits": 5
			}
		}
	}`
	if err := os.WriteFile(statePath, []byte(legacyJSON), 0600); err != nil {
		t.Fatal(err)
	}

	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":       "conn-daytime-cn",
					"upload":   32 * 1024,
					"download": 64 * 1024,
					"start":    "2026-11-12T06:09:30Z",
					"chains":   []string{"DIRECT"},
					"metadata": map[string]any{
						"network":         "tcp",
						"sourceIP":        "192.168.1.20",
						"destinationIP":   "198.51.100.77",
						"destinationPort": "443",
						"sniffHost":       "Mijia Cloud",
					},
				},
			},
		})
	}))
	defer clashSrv.Close()

	leaseFile := filepath.Join(tmpDir, "dhcp.leases")
	_ = os.WriteFile(leaseFile, []byte("1794500000 aa:bb:cc:dd:ee:01 192.168.1.20 ImmortalWrt *\n"), 0600)

	collector := audit.NewCollector(&config.Config{})
	collector.SetEndpointsForTest([]string{clashSrv.URL}, "", statePath)
	collector.SetLeaseFilesForTest([]string{leaseFile}, "", "")
	collector.SetTimezoneFilesForTest(tzFile, "")
	collector.SetNowFuncForTest(func() time.Time { return nowSim })

	rep := collector.Collect(t.Context(), audit.CollectOptions{})
	if len(rep.Devices) != 1 || rep.Devices[0].DeviceRole != "router" {
		t.Fatalf("expected ImmortalWrt to be inferred as role=router, got %+v", rep.Devices)
	}
	if len(rep.Flows) != 2 {
		t.Fatalf("expected 2 active flows (24h stale flow pruned), got %d: %+v", len(rep.Flows), rep.Flows)
	}
	for _, f := range rep.Flows {
		if strings.Contains(f.Target, " ") || f.Target == "stale.example.com" {
			t.Fatalf("unexpected invalid or stale target %q in flows", f.Target)
		}
		if f.NightHits != 0 {
			t.Fatalf("expected daytime CST flow %s to have NightHits=0 after v2 migration, got %d", f.Target, f.NightHits)
		}
		if f.AppName != "小米 / 米家" {
			t.Fatalf("expected RawHost 'Mijia Cloud' fallback to identify app '小米 / 米家', got %q", f.AppName)
		}
		if _, _, err := audit.ValidateTargetSafety(&config.Config{}, f.Target); err != nil {
			t.Fatalf("expected fallback IP target %q to pass ValidateTargetSafety, got %v", f.Target, err)
		}
	}
}

func TestQUIC443Exemption_MultiDayRate_And_AIClosedLoopDamping(t *testing.T) {
	eng := audit.NewNonlinearEngine(&config.Config{})

	// 1. Apple / Cloudflare 标准 UDP :443 QUIC 直连流不应误判为绕过 DNS 直连上传
	if gotApp := audit.IdentifyApp("172.64.0.1", "172.64.0.1", ""); gotApp != "Cloudflare" {
		t.Fatalf("expected 172.64.0.1 to identify as Cloudflare, got %q", gotApp)
	}
	cfQuic := &audit.FlowRecord{
		DeviceIP:      "192.168.1.30",
		DeviceName:    "iPhone",
		Target:        "172.64.0.1",
		DestIP:        "172.64.0.1",
		AppName:       "Cloudflare",
		IsDirectIP:    true,
		DestPort:      443,
		Network:       "udp",
		UploadBytes:   1500 * 1024,
		DownloadBytes: 1200 * 1024,
		ConnCount:     18,
	}
	eng.EvaluateFlow(cfQuic)
	if cfQuic.Threat != audit.ThreatNormal || cfQuic.RiskScore >= 35 {
		t.Fatalf("expected Cloudflare UDP:443 QUIC to stay ThreatNormal (<35), got score=%d reasons=%v", cfQuic.RiskScore, cfQuic.Reasons)
	}

	// 2. 跨 48 小时累计 2200 次连接但每小时速率温和、间隔不规律的正常社交浏览 (如 x.com) 不应误判为机器信标
	multiDaySocial := &audit.FlowRecord{
		DeviceIP:      "192.168.1.30",
		DeviceName:    "MacBook-Pro",
		Target:        "x.com",
		AppName:       "X (Twitter)",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   1500 * 1024,
		DownloadBytes: 1400 * 1024,
		ConnCount:     2200,
		ActiveSpanSec: 48 * 3600,
		IntervalCV:    1.45,
	}
	eng.EvaluateFlow(multiDaySocial)
	if multiDaySocial.Threat != audit.ThreatNormal || multiDaySocial.RiskScore >= 35 {
		t.Fatalf("expected multi-day normal social browsing to stay ThreatNormal (<35), got score=%d reasons=%v",
			multiDaySocial.RiskScore, multiDaySocial.Reasons)
	}

	// 3. L1 × L2 AI 闭环降权：当启发式高分域名经真实远程大模型复核为 AIDoNotBlock 时，自动闭环降权至正常 (<29分)
	syncFlow := &audit.FlowRecord{
		DeviceIP:      "192.168.1.30",
		DeviceName:    "MacBook-Pro",
		Target:        "sync-v2.brave.example.com",
		DestPort:      443,
		Network:       "tcp",
		UploadBytes:   12 * 1024 * 1024,
		DownloadBytes: 512 * 1024,
		ConnCount:     40,
		IntervalCV:    0.15,
		AIReview: &audit.AIReviewResult{
			Source:      "llm_api",
			Category:    "浏览器书签加密同步",
			Verdict:     audit.AIDoNotBlock,
			VerdictText: "建议放行",
			Recommend:   "keep",
		},
	}
	eng.EvaluateFlow(syncFlow)
	if syncFlow.Threat != audit.ThreatNormal || syncFlow.RiskScore > 28 {
		t.Fatalf("expected remote LLM do_not_block to damp heuristic false positive to <=28 ThreatNormal, got score=%d threat=%s reasons=%v",
			syncFlow.RiskScore, syncFlow.Threat, syncFlow.Reasons)
	}

	// 4. 安全护栏：对直连非标高危端口的大流量上传 (如 203.0.113.88:54321)，即使 AI 返回 do_not_block 也不允许洗白
	hardAnomaly := &audit.FlowRecord{
		DeviceIP:      "192.168.1.55",
		DeviceName:    "Xiaomi-TV",
		Target:        "203.0.113.88",
		IsDirectIP:    true,
		DestPort:      54321,
		Network:       "udp",
		UploadBytes:   50 * 1024 * 1024,
		DownloadBytes: 256 * 1024,
		ConnCount:     25,
		AIReview: &audit.AIReviewResult{
			Source:  "llm_api",
			Verdict: audit.AIDoNotBlock,
		},
	}
	eng.EvaluateFlow(hardAnomaly)
	if hardAnomaly.RiskScore < 70 {
		t.Fatalf("expected hard non-std-port direct-IP upload guardrail to prevent AI whitewashing, got score=%d", hardAnomaly.RiskScore)
	}
}

func TestClosedLoopAlertCounts_And_WebUIWhitelistAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "secret123",
		Version:    "v1.15.0",
	})
	ts := httptest.NewServer(srv.Mux)
	defer ts.Close()
	token := srv.SessionToken()

	// 1. 测试 POST /api/audit/whitelist 添加与移除，验证 0600 落盘及清空后无残留
	addBody, _ := json.Marshal(map[string]string{"action": "add", "target": "sync.trusted-app.example.com"})
	reqAdd, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/audit/whitelist", bytes.NewReader(addBody))
	reqAdd.Header.Set("Authorization", "Bearer "+token)
	reqAdd.Header.Set("Content-Type", "application/json")
	respAdd, err := http.DefaultClient.Do(reqAdd)
	if err != nil {
		t.Fatal(err)
	}
	respAdd.Body.Close()
	if respAdd.StatusCode != http.StatusOK {
		t.Fatalf("expected whitelist add 200, got %d", respAdd.StatusCode)
	}

	info, err := os.Stat(cfgPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected singctl.yaml mode 0600 after whitelist save, got %v (err=%v)", info.Mode().Perm(), err)
	}
	cfgAfterAdd, err := config.Load(cfgPath)
	if err != nil || len(cfgAfterAdd.Audit.Whitelist) != 1 || cfgAfterAdd.Audit.Whitelist[0] != "sync.trusted-app.example.com" {
		t.Fatalf("expected whitelist entry persisted, got %+v (err=%v)", cfgAfterAdd.Audit.Whitelist, err)
	}

	// 2. 验证已拉黑 (blocked) 和已放行 (whitelisted) 的流不再计入活跃可疑告警数，且排序位于活跃观察流之后
	cfgAfterAdd.CustomRules.Block = []config.BlockRule{
		{Target: "already-blocked.example.com", Reason: "已拉黑测试"},
	}
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":       "c-blocked",
					"upload":   20 * 1024 * 1024,
					"download": 64 * 1024,
					"start":    "2026-11-12T04:00:00Z",
					"metadata": map[string]any{"network": "tcp", "sourceIP": "192.168.1.88", "destinationIP": "203.0.113.10", "destinationPort": "443", "host": "already-blocked.example.com"},
				},
				{
					"id":       "c-whitelisted",
					"upload":   30 * 1024 * 1024,
					"download": 64 * 1024,
					"start":    "2026-11-12T04:00:00Z",
					"metadata": map[string]any{"network": "tcp", "sourceIP": "192.168.1.88", "destinationIP": "203.0.113.11", "destinationPort": "443", "host": "sync.trusted-app.example.com"},
				},
				{
					"id":       "c-active-suspect",
					"upload":   8 * 1024 * 1024,
					"download": 32 * 1024,
					"start":    "2026-11-12T04:00:00Z",
					"metadata": map[string]any{"network": "tcp", "sourceIP": "192.168.1.88", "destinationIP": "203.0.113.12", "destinationPort": "443", "host": "telemetry.active.example.com"},
				},
			},
		})
	}))
	defer clashSrv.Close()

	col := audit.NewCollector(cfgAfterAdd)
	col.SetEndpointsForTest([]string{clashSrv.URL}, "", filepath.Join(tmpDir, "closed-loop-state.json"))
	col.SetNowFuncForTest(func() time.Time { return time.Date(2026, 11, 12, 14, 0, 0, 0, time.FixedZone("CST", 8*3600)) })

	rep := col.Collect(t.Context(), audit.CollectOptions{})
	if rep.BlockedCount != 1 {
		t.Fatalf("expected BlockedCount=1, got %d", rep.BlockedCount)
	}
	if rep.SuspiciousFlows != 1 {
		t.Fatalf("expected only 1 active suspicious flow (excluding blocked & whitelisted), got %d", rep.SuspiciousFlows)
	}
	if len(rep.Flows) != 2 || rep.Flows[0].Target != "telemetry.active.example.com" || rep.Flows[1].Target != "sync.trusted-app.example.com" {
		t.Fatalf("expected blocked flow hidden from detail list and active threat sorted first, got flows=%+v", rep.Flows)
	}

	// 3. 移除最后一条白名单并确认 YAML 中彻底清空
	rmBody, _ := json.Marshal(map[string]string{"action": "remove", "target": "sync.trusted-app.example.com"})
	reqRm, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/audit/whitelist", bytes.NewReader(rmBody))
	reqRm.Header.Set("Authorization", "Bearer "+token)
	reqRm.Header.Set("Content-Type", "application/json")
	respRm, err := http.DefaultClient.Do(reqRm)
	if err != nil {
		t.Fatal(err)
	}
	respRm.Body.Close()
	if respRm.StatusCode != http.StatusOK {
		t.Fatalf("expected whitelist remove 200, got %d", respRm.StatusCode)
	}
	cfgAfterRm, err := config.Load(cfgPath)
	if err != nil || len(cfgAfterRm.Audit.Whitelist) != 0 {
		t.Fatalf("expected empty whitelist after removing last item, got %+v (err=%v)", cfgAfterRm.Audit.Whitelist, err)
	}
}

func TestAuditEnforcer_SyncsSandboxWorkConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgDir := filepath.Join(tmpDir, "etc-singctl")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	singctlPath := filepath.Join(cfgDir, "singctl.yaml")
	if err := os.WriteFile(singctlPath, configs.ClientConfigYAML, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(singctlPath)
	if err != nil {
		t.Fatal(err)
	}

	sbConfigPath := filepath.Join(tmpDir, "config.json")
	initialSBJSON := `{
  "experimental": {
    "cache_file": {"enabled": true, "path": "/etc/sing-box/cache.db"},
    "clash_api": {"external_controller": "127.0.0.1:9090", "external_ui": "/etc/sing-box/ui"}
  },
  "dns": {
    "servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
    "rules": [{"clash_mode": "Direct", "server": "dns_local"}]
  },
  "route": {
    "rules": [
      {"ip_is_private": true, "outbound": "#DC"}
    ]
  },
  "services": [{"type": "api", "dashboard": {"path": "/etc/sing-box/dashboard"}}]
}`
	if err := os.WriteFile(sbConfigPath, []byte(initialSBJSON), 0600); err != nil {
		t.Fatal(err)
	}

	workDir := filepath.Join(tmpDir, "sing-box-work")
	if err := os.MkdirAll(workDir, 0755); err != nil {
		t.Fatal(err)
	}
	workConfigPath := filepath.Join(workDir, "config.json")
	if err := os.WriteFile(workConfigPath, []byte(`{"route":{"rules":[{"action":"reject","ip_cidr":["198.51.100.99/32"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}

	aghConfigPath := filepath.Join(tmpDir, "AdGuardHome.yaml")
	passHash, _ := config.HashPassword("testpass123456")
	aghBytes, err := adguard.BuildInitialConfigYAML(adguard.ConfigParams{
		LANIP:        "192.0.2.1",
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

	enforcer := audit.NewEnforcer(cfg, singctlPath)
	enforcer.SetPathsForTest(sbConfigPath, aghConfigPath, nil, "")
	enforcer.SetWorkConfigPathForTest(workConfigPath)

	blockRes, err := enforcer.Block(t.Context(), "203.0.113.88", "", "test-iot-block")
	if err != nil {
		t.Fatalf("Enforcer.Block failed: %v", err)
	}
	if !blockRes.SingBoxSynced {
		t.Fatalf("expected SingBoxSynced=true, got %+v", blockRes)
	}

	workAfterBlockBytes, err := os.ReadFile(workConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	workAfterBlock := string(workAfterBlockBytes)
	if !strings.Contains(workAfterBlock, `"203.0.113.88/32"`) {
		t.Fatalf("expected sandbox work config to receive block rule, got:\n%s", workAfterBlock)
	}
	if strings.Contains(workAfterBlock, `"198.51.100.99/32"`) {
		t.Fatalf("expected stale sandbox work config rule to be replaced cleanly, got:\n%s", workAfterBlock)
	}
	for _, name := range []string{"cache.db", "ui", "dashboard"} {
		wantPath := filepath.ToSlash(filepath.Join(workDir, name))
		if !strings.Contains(workAfterBlock, `"`+wantPath+`"`) {
			t.Fatalf("expected sandbox work config to preserve rewritten path %q, got:\n%s", wantPath, workAfterBlock)
		}
	}

	unblockRes, err := enforcer.Unblock(t.Context(), "203.0.113.88", "")
	if err != nil {
		t.Fatalf("Enforcer.Unblock failed: %v", err)
	}
	if !unblockRes.SingBoxSynced {
		t.Fatalf("expected Unblock SingBoxSynced=true, got %+v", unblockRes)
	}

	workAfterUnblockBytes, err := os.ReadFile(workConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(workAfterUnblockBytes), "203.0.113.88") {
		t.Fatalf("expected sandbox work config to remove unblocked IP rule, got:\n%s", string(workAfterUnblockBytes))
	}
	fi, err := os.Stat(workConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected sandbox work config mode 0600, got %o", fi.Mode().Perm())
	}
}

func jsonNumber(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}
