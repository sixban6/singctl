package serverweb

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/subhub"
)

func TestIPLimiter_SourceAttributionAndLegacyMigration(t *testing.T) {
	tmpDir := t.TempDir()
	bansFile := filepath.Join(tmpDir, ".serverweb_bans.json")

	now := time.Now().UTC().Truncate(time.Second)
	// 模拟升级前旧版 .serverweb_bans.json（无 source 字段）
	legacyJSON := fmt.Sprintf(`{
  "198.51.100.11": {
    "fail_count": 3,
    "last_fail": %q,
    "banned_until": %q
  },
  "203.0.113.22": {
    "fail_count": 3,
    "last_fail": %q,
    "banned_until": %q
  }
}`,
		now.Add(-2*time.Hour).Format(time.RFC3339),
		now.Add(166*time.Hour).Format(time.RFC3339), // 7 天手动拉黑特征 (>1h)
		now.Add(-1*time.Minute).Format(time.RFC3339),
		now.Add(14*time.Minute).Format(time.RFC3339), // 15 分钟登录防爆破特征
	)
	if err := os.WriteFile(bansFile, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("write legacy bans file: %v", err)
	}

	limiter := NewIPLimiter(3, 10*time.Minute, 15*time.Minute, bansFile)
	defer limiter.Close()

	details := limiter.ListBanDetails()
	if len(details) != 2 {
		t.Fatalf("expected 2 migrated bans, got %d", len(details))
	}
	byIP := make(map[string]BanDetail, len(details))
	for _, item := range details {
		byIP[item.IP] = item
	}
	if d, ok := byIP["198.51.100.11"]; !ok || d.Source != BanSourceManualSniff || d.SourceLabel != "嗅探手动封禁" {
		t.Fatalf("expected 198.51.100.11 inferred as manual_sniff, got %+v", d)
	}
	if d, ok := byIP["203.0.113.22"]; !ok || d.Source != BanSourceLoginFail || d.SourceLabel != "密码试错拦截" {
		t.Fatalf("expected 203.0.113.22 inferred as login_fail, got %+v", d)
	}

	// 验证新增手动拉黑与人性化时长展示
	limiter.BanManual("192.0.2.99", 7*24*time.Hour, "订阅拉取异常 IP 手动封禁")
	var d99 BanDetail
	var found99 bool
	for _, item := range limiter.ListBanDetails() {
		if item.IP == "192.0.2.99" {
			d99, found99 = item, true
			break
		}
	}
	if !found99 || d99.Source != BanSourceManualSniff || d99.Reason != "订阅拉取异常 IP 手动封禁" {
		t.Fatalf("unexpected manual ban detail: %+v", d99)
	}

	if got := FormatDurationCN(6*24*time.Hour + 14*time.Hour); got != "6 天 14 小时" {
		t.Fatalf("expected '6 天 14 小时', got %q", got)
	}
	if got := FormatDurationCN(12 * time.Minute); got != "12 分钟" {
		t.Fatalf("expected '12 分钟', got %q", got)
	}
}

func TestServerWeb_FullChainUnbanAndSniffUnblock(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "config.json")
	subDir := filepath.Join(tmpDir, "sub-store")
	fleetFile := filepath.Join(tmpDir, "fleet.yaml")

	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_ = os.WriteFile(sbCfgPath, []byte(`{"inbounds":[]}`), 0600)

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     fleetFile,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	// 预先注入嗅探记录（模拟真实外网扫描，而非后台密码试探）
	srv.sniff.Observe("198.51.100.44", "TLS/443 伪装回落嗅探", "masqueraded", 4)
	srv.sniff.Observe("203.0.113.10", "HTTP/80 端口嗅探", "masqueraded", 3)
	srv.sniff.Observe("203.0.113.20", "HTTP/80 端口嗅探", "masqueraded", 2)

	doAuthReq := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.SetBasicAuth("opsadmin", "Password123")
		req.RemoteAddr = "127.0.0.1:54321"
		req.Header.Set("X-Real-IP", "192.0.2.1")
		if method != http.MethodGet {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. 手动拉黑单 IP 198.51.100.44 与整段 203.0.113.0/24
	if rec := doAuthReq(http.MethodPost, "/api/server/security/block", `{"target":"198.51.100.44","node":"local"}`); rec.Code != http.StatusOK {
		t.Fatalf("block IP failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(http.MethodPost, "/api/server/security/block", `{"target":"203.0.113.0/24","node":"local"}`); rec.Code != http.StatusOK {
		t.Fatalf("block CIDR failed: %d %s", rec.Code, rec.Body.String())
	}

	// 2. 验证 /api/server/bans 正确标记来源为 manual_sniff，且统计 manualSniffCount=1, loginFailCount=0
	recBans := doAuthReq(http.MethodGet, "/api/server/bans", "")
	if recBans.Code != http.StatusOK {
		t.Fatalf("list bans failed: %d %s", recBans.Code, recBans.Body.String())
	}
	var bansResp struct {
		LoginFailCount   int `json:"loginFailCount"`
		ManualSniffCount int `json:"manualSniffCount"`
		Bans             []struct {
			IP          string `json:"ip"`
			Source      string `json:"source"`
			SourceLabel string `json:"sourceLabel"`
		} `json:"bans"`
	}
	if err := json.Unmarshal(recBans.Body.Bytes(), &bansResp); err != nil {
		t.Fatalf("unmarshal bans: %v", err)
	}
	if len(bansResp.Bans) != 1 || bansResp.ManualSniffCount != 1 || bansResp.LoginFailCount != 0 {
		t.Fatalf("unexpected ban counts: %+v", bansResp)
	}
	if bansResp.Bans[0].Source != BanSourceManualSniff || bansResp.Bans[0].SourceLabel != "嗅探手动封禁" {
		t.Fatalf("unexpected ban source: %+v", bansResp.Bans[0])
	}

	// 3. 验证嗅探雷达中 198.51.100.44 的攻击类型未被污染为 "Web 管理端密码试探"
	snap := srv.sniff.SnapshotForNode(t.Context(), "local", false)
	for _, item := range snap.TopIPs {
		if item.IP == "198.51.100.44" && strings.Contains(item.Vector, "Web 管理端密码试探") {
			t.Fatalf("manual sniff block must not pollute vector with Web password probe, got %q", item.Vector)
		}
	}
	if snap.TotalBannedIPs != 3 {
		t.Fatalf("expected 3 banned IPs in SniffTracker (1 single + 2 in /24), got %d", snap.TotalBannedIPs)
	}

	// 4. 通过 /api/server/unban 解封单 IP，验证 IPLimiter 与 SniffTracker 同步解封！
	if rec := doAuthReq(http.MethodPost, "/api/server/unban", `{"ip":"198.51.100.44"}`); rec.Code != http.StatusOK {
		t.Fatalf("unban IP failed: %d %s", rec.Code, rec.Body.String())
	}
	if _, banned := srv.limiter.CheckBan("198.51.100.44"); banned {
		t.Fatalf("expected 198.51.100.44 cleared from IPLimiter")
	}
	snapAfterIPUnban := srv.sniff.SnapshotForNode(t.Context(), "local", false)
	for _, item := range snapAfterIPUnban.TopIPs {
		if item.IP == "198.51.100.44" && item.Status == "banned" {
			t.Fatalf("expected 198.51.100.44 unbanned in SniffTracker, still banned")
		}
	}

	// 5. 通过 /api/server/security/unblock 解封 /24 网段，验证整段恢复正常
	if rec := doAuthReq(http.MethodPost, "/api/server/security/unblock", `{"target":"203.0.113.0/24","node":"local"}`); rec.Code != http.StatusOK {
		t.Fatalf("unblock CIDR failed: %d %s", rec.Code, rec.Body.String())
	}
	snapAfterCIDRUnban := srv.sniff.SnapshotForNode(t.Context(), "local", false)
	if snapAfterCIDRUnban.TotalBannedIPs != 0 {
		t.Fatalf("expected 0 banned IPs after unblocking /24 subnet, got %d", snapAfterCIDRUnban.TotalBannedIPs)
	}
}

func TestServerWeb_BackupExportAndRestore(t *testing.T) {
	srcDir := t.TempDir()
	srcCfg := filepath.Join(srcDir, "singctl.yaml")
	srcSbCfg := filepath.Join(srcDir, "singbox.json")
	srcSubDir := filepath.Join(srcDir, "sub-store")
	srcFleet := filepath.Join(srcDir, "fleet.yaml")
	srcKeysDir := filepath.Join(srcDir, "fleet_keys")

	if err := os.MkdirAll(srcSubDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcKeysDir, 0700); err != nil {
		t.Fatal(err)
	}

	origSingctlYAML := `server:
  node_domain: "master.example.com"
  cf_dns_key: "cf-test-token"
  sni: "swdist.apple.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`
	origFleetYAML := `nodes:
  - id: jp1
    name: 日本东京
    host: 198.51.100.20
    port: 2222
    user: root
    auth_type: key_file
    key_path: ` + filepath.Join(srcKeysDir, "jp1.key") + `
    domain: jp1.example.com
    auto_sync: true
`
	dummyKeyContent := []byte("TEST-SSH-KEY-MATERIAL-JP1\n")

	_ = os.WriteFile(srcCfg, []byte(origSingctlYAML), 0600)
	_ = os.WriteFile(srcSbCfg, []byte(`{"inbounds":[]}`), 0600)
	_ = os.WriteFile(filepath.Join(srcSubDir, "sub-store.json"), []byte(`{"subs":[{"name":"auto_generated_hy2","content":"hysteria2://11111111-1111-1111-1111-111111111111@jp1.example.com:443/#JP1"}]}`), 0600)
	_ = os.WriteFile(filepath.Join(srcSubDir, "key"), []byte("subkey-example-123456"), 0600)
	_ = os.WriteFile(srcFleet, []byte(origFleetYAML), 0600)
	_ = os.WriteFile(filepath.Join(srcKeysDir, "jp1.key"), dummyKeyContent, 0600)

	srcSrv := New(Options{
		ConfigPath:        srcCfg,
		SingBoxConfigPath: srcSbCfg,
		SubStoreDir:       srcSubDir,
		FleetFilePath:     srcFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})

	doReq := func(s *Server, method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.SetBasicAuth("opsadmin", "Password123")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. 弱口令拦截
	if rec := doReq(srcSrv, http.MethodPost, "/api/server/backup/export", `{"passphrase":"short"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short passphrase, got %d", rec.Code)
	}

	// 2. 导出加密快照
	recExp := doReq(srcSrv, http.MethodPost, "/api/server/backup/export", `{"passphrase":"StrongPass#2026"}`)
	if recExp.Code != http.StatusOK {
		t.Fatalf("export backup failed: %d %s", recExp.Code, recExp.Body.String())
	}
	var expResp struct {
		Filename      string `json:"filename"`
		Data          string `json:"data"`
		HasSingctlCfg bool   `json:"hasSingctlCfg"`
		HasFleet      bool   `json:"hasFleet"`
		FleetKeyCount int    `json:"fleetKeyCount"`
		HasSubStore   bool   `json:"hasSubStore"`
	}
	if err := json.Unmarshal(recExp.Body.Bytes(), &expResp); err != nil {
		t.Fatalf("unmarshal export response: %v", err)
	}
	if expResp.Data == "" || !expResp.HasSingctlCfg || !expResp.HasFleet || expResp.FleetKeyCount != 1 || !expResp.HasSubStore {
		t.Fatalf("unexpected export payload: %+v", expResp)
	}

	rawEnvelope := []byte(expResp.Data)
	// 确保密文信封中不泄漏明文域名或 Token
	if strings.Contains(string(rawEnvelope), "master.example.com") || strings.Contains(string(rawEnvelope), "cf-test-token") {
		t.Fatalf("encrypted envelope leaked plaintext sensitive fields!")
	}

	// 3. 错误口令解密必须被 AES-GCM 认证拒绝
	if _, err := DecryptBackupBundle("WrongPass#2026", rawEnvelope); err == nil {
		t.Fatalf("expected error decrypting with wrong passphrase")
	}

	// 4. 在全新目标目录恢复灾备快照，验证 0600 权限与 fleet_keys 路径自动重写对齐
	dstDir := t.TempDir()
	dstCfg := filepath.Join(dstDir, "singctl.yaml")
	dstSbCfg := filepath.Join(dstDir, "singbox.json")
	dstSubDir := filepath.Join(dstDir, "sub-store")
	dstFleet := filepath.Join(dstDir, "fleet.yaml")

	_ = os.WriteFile(dstCfg, []byte("server:\n  node_domain: \"placeholder.example.com\"\n"), 0600)
	_ = os.WriteFile(dstSbCfg, []byte(`{"inbounds":[]}`), 0600)

	dstSrv := New(Options{
		ConfigPath:        dstCfg,
		SingBoxConfigPath: dstSbCfg,
		SubStoreDir:       dstSubDir,
		FleetFilePath:     dstFleet,
		Username:          "opsadmin",
		Password:          "Password123",
	})

	restoreReqBody, _ := json.Marshal(map[string]string{
		"passphrase": "StrongPass#2026",
		"data":       expResp.Data,
	})
	recRes := doReq(dstSrv, http.MethodPost, "/api/server/backup/restore", string(restoreReqBody))
	if recRes.Code != http.StatusOK {
		t.Fatalf("restore backup failed: %d %s", recRes.Code, recRes.Body.String())
	}

	restoredKeyPath := filepath.Join(dstDir, "fleet_keys", "jp1.key")
	gotKey, err := os.ReadFile(restoredKeyPath)
	if err != nil {
		t.Fatalf("expected restored fleet key at %s: %v", restoredKeyPath, err)
	}
	if string(gotKey) != string(dummyKeyContent) {
		t.Fatalf("restored key content mismatch: %q", string(gotKey))
	}

	for _, checkFile := range []string{
		dstCfg,
		dstFleet,
		restoredKeyPath,
		filepath.Join(dstSubDir, "sub-store.json"),
		filepath.Join(dstSubDir, "key"),
	} {
		st, err := os.Stat(checkFile)
		if err != nil {
			t.Fatalf("stat restored file %s: %v", checkFile, err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 perm on %s, got %o", checkFile, st.Mode().Perm())
		}
	}

	// 验证 fleet.yaml 中的 key_path 已自动从 srcDir 重写为 dstDir
	restoredFleetRaw, _ := os.ReadFile(dstFleet)
	if !strings.Contains(string(restoredFleetRaw), restoredKeyPath) {
		t.Fatalf("expected fleet.yaml key_path rewritten to %s, got:\n%s", restoredKeyPath, string(restoredFleetRaw))
	}

	// 5. 防目录穿越校验
	if _, err := sanitizeFleetKeyFilename("../../etc/passwd"); err == nil {
		t.Fatalf("expected path traversal rejection")
	}
	if got, err := sanitizeFleetKeyFilename("jp1.key"); err != nil || got != "jp1.key" {
		t.Fatalf("expected valid filename jp1.key, got %q err=%v", got, err)
	}
}

func TestSummarizeX509Cert_States(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	mkCert := func(notAfter time.Time) *x509.Certificate {
		return &x509.Certificate{
			Issuer:   pkix.Name{Organization: []string{"Let's Encrypt"}},
			NotAfter: notAfter,
		}
	}

	healthy := summarizeX509Cert("node.example.com", "代理节点域名", "caddy-disk", mkCert(now.Add(65*24*time.Hour)), now)
	if healthy.Status != "healthy" || healthy.DaysRemaining != 65 || healthy.Issuer != "Let's Encrypt" {
		t.Fatalf("unexpected healthy cert summary: %+v", healthy)
	}

	expiring := summarizeX509Cert("node.example.com", "代理节点域名", "caddy-disk", mkCert(now.Add(5*24*time.Hour)), now)
	if expiring.Status != "expiring" || expiring.DaysRemaining != 5 {
		t.Fatalf("unexpected expiring cert summary: %+v", expiring)
	}

	expired := summarizeX509Cert("node.example.com", "代理节点域名", "caddy-disk", mkCert(now.Add(-24*time.Hour)), now)
	if expired.Status != "expired" {
		t.Fatalf("unexpected expired cert summary: %+v", expired)
	}
}

func TestSubscriptionRiskEvaluationAndRealPorts(t *testing.T) {
	nowStr := time.Now().UTC().Format(time.RFC3339)

	// 1. 正常个人双设备拉取 -> safe
	safeRisk := evaluateSubscriptionAccessRisk([]subhub.AccessLogEntry{
		{Timestamp: nowStr, IP: "198.51.100.1", CountryCode: "SG", UserAgent: "Shadowrocket/2075", Status: "ok"},
		{Timestamp: nowStr, IP: "198.51.100.2", CountryCode: "SG", UserAgent: "ClashMetaForAndroid/2.10", Status: "ok"},
	})
	if safeRisk.Level != "safe" || safeRisk.UniqueIPs24h != 2 {
		t.Fatalf("expected safe risk, got %+v", safeRisk)
	}

	// 2. 11 个不同公网 IP + 4 个国家 + Python 爬虫 UA -> high
	var highLogs []subhub.AccessLogEntry
	countries := []string{"US", "NL", "DE", "RU"}
	for i := 1; i <= 11; i++ {
		highLogs = append(highLogs, subhub.AccessLogEntry{
			Timestamp:   nowStr,
			IP:          fmt.Sprintf("203.0.113.%d", i),
			CountryCode: countries[i%len(countries)],
			UserAgent:   "python-requests/2.31.0",
			Status:      "ok",
		})
	}
	highRisk := evaluateSubscriptionAccessRisk(highLogs)
	if highRisk.Level != "high" || highRisk.UniqueIPs24h != 11 || highRisk.UniqueCountries24h != 4 || len(highRisk.Reasons) < 2 {
		t.Fatalf("expected high risk summary, got %+v", highRisk)
	}

	// 3. 验证 /api/server/subscriptions 返回 sing-box 真实入站端口而非写死 443，以及审计分类
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "config.json")
	subDir := filepath.Join(tmpDir, "sub-store")

	_ = os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  hy2_port: 20853
  vless_port: 20443
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600)
	_ = os.WriteFile(sbCfgPath, []byte(`{
  "inbounds": [
    {"type": "hysteria2", "listen_port": 52021, "users": [{"password": "11111111-1111-1111-1111-111111111111"}]},
    {"type": "vless", "listen_port": 18443, "users": [{"uuid": "11111111-1111-1111-1111-111111111111"}], "tls": {"reality": {"private_key": "uLpIe_G30f3L8v5F0T3C8W7N2M1K4H6B9Z0X5V2P1E8", "short_id": ["abcd1234"]}}}
  ]
}`), 0600)

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     filepath.Join(tmpDir, "fleet.yaml"),
		Username:          "opsadmin",
		Password:          "Password123",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/server/subscriptions", nil)
	req.SetBasicAuth("opsadmin", "Password123")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("subscriptions endpoint failed: %d %s", rec.Code, rec.Body.String())
	}
	var subData struct {
		Nodes struct {
			Hy2   struct{ Port int } `json:"hy2"`
			Vless struct{ Port int } `json:"vless"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &subData); err != nil {
		t.Fatalf("unmarshal subData: %v", err)
	}
	if subData.Nodes.Hy2.Port != 20853 || subData.Nodes.Vless.Port != 20443 {
		t.Fatalf("expected configured external ports hy2=20853 vless=20443, got %+v", subData.Nodes)
	}

	// 4. 验证审计分类与上限 200
	if MaxAuditLogs != 200 {
		t.Fatalf("expected MaxAuditLogs == 200, got %d", MaxAuditLogs)
	}
	if got := ClassifyAuditCategory("管理员登录成功"); got != "login" {
		t.Fatalf("expected login category, got %q", got)
	}
	if got := ClassifyAuditCategory("导出加密灾备快照 (共 6 项敏感资产)"); got != "security" {
		t.Fatalf("expected security category, got %q", got)
	}
	if got := ClassifyAuditCategory("保存子节点 [jp1]"); got != "fleet" {
		t.Fatalf("expected fleet category, got %q", got)
	}
	if got := ClassifyAuditCategory("轮换客户端聚合订阅访问密钥"); got != "subscription" {
		t.Fatalf("expected subscription category, got %q", got)
	}
	if got := ClassifyAuditCategory("升级组件 [singctl] 至 v1.14.32"); got != "service" {
		t.Fatalf("expected service category, got %q", got)
	}
}
