// 文件职责：覆盖 IPLimiter 防爆破状态机、X-Real-IP 信任边界、全链路拉黑/解封协同、订阅防盗刷评估与审计分类单测。
package serverweb_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/serverweb"
	"singctl/internal/subhub"
)

func TestIPLimiter_RecordFailureNeverClearsActiveBanAfterWindow(t *testing.T) {
	dir := t.TempDir()
	persistPath := filepath.Join(dir, "bans.json")

	lim := serverweb.NewIPLimiter(2, 25*time.Millisecond, 5*time.Second, persistPath)
	defer lim.Close()

	ip := "198.51.100.99"
	banned, _, _ := lim.RecordFailure(ip)
	if banned {
		t.Fatal("first failure should not ban yet")
	}
	banned, _, _ = lim.RecordFailure(ip)
	if !banned {
		t.Fatal("second failure should trigger ban")
	}

	time.Sleep(40 * time.Millisecond)

	_, _, _ = lim.RecordFailure(ip)
	if rem, stillBanned := lim.CheckBan(ip); !stillBanned || rem <= 0 {
		t.Fatalf("active ban was prematurely wiped by RecordFailure after window elapsed! stillBanned=%v rem=%v", stillBanned, rem)
	}
}

func TestIPLimiter_ConcurrentAndXRealIPTrustBoundary(t *testing.T) {
	extReq := httptest.NewRequest("GET", "/login", nil)
	extReq.RemoteAddr = "203.0.113.50:41234"
	extReq.Header.Set("X-Real-IP", "127.0.0.1")
	extReq.Header.Set("X-Forwarded-For", "127.0.0.1")
	if got := serverweb.GetClientIP(extReq); got != "203.0.113.50" {
		t.Fatalf("GetClientIP trusted spoofed X-Real-IP from non-loopback peer: got %q", got)
	}

	localReq := httptest.NewRequest("GET", "/login", nil)
	localReq.RemoteAddr = "127.0.0.1:51234"
	localReq.Header.Set("X-Real-IP", "198.51.100.77")
	if got := serverweb.GetClientIP(localReq); got != "198.51.100.77" {
		t.Fatalf("GetClientIP failed to extract Caddy X-Real-IP: got %q", got)
	}

	dir := t.TempDir()
	persistPath := filepath.Join(dir, "bans_race.json")
	lim := serverweb.NewIPLimiter(3, time.Minute, 10*time.Minute, persistPath)

	var wg sync.WaitGroup
	for g := range 12 {
		id := g
		wg.Go(func() {
			ip := fmt.Sprintf("198.51.100.%d", 10+id)
			for range 5 {
				lim.RecordFailure(ip)
				_, _ = lim.CheckBan(ip)
				_ = lim.ListBans()
			}
			if id%3 == 0 {
				lim.RecordSuccess(ip)
			}
		})
	}
	wg.Wait()
	lim.Close()

	if st, err := os.Stat(persistPath); err == nil && st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on persisted bans.json, got %04o", st.Mode().Perm())
	}

	reloaded := serverweb.NewIPLimiter(3, time.Minute, 10*time.Minute, persistPath)
	defer reloaded.Close()
	if len(reloaded.ListBans()) == 0 {
		t.Fatal("expected active bans to survive persistence reload")
	}
	reloaded.Unban("all")
	if len(reloaded.ListBans()) != 0 {
		t.Fatal("expected Unban('all') to clear all bans")
	}
}

func TestIPLimiter_SourceAttributionAndLegacyMigration(t *testing.T) {
	tmpDir := t.TempDir()
	bansFile := filepath.Join(tmpDir, ".serverweb_bans.json")

	now := time.Now().UTC().Truncate(time.Second)
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
		now.Add(166*time.Hour).Format(time.RFC3339),
		now.Add(-1*time.Minute).Format(time.RFC3339),
		now.Add(14*time.Minute).Format(time.RFC3339),
	)
	if err := os.WriteFile(bansFile, []byte(legacyJSON), 0600); err != nil {
		t.Fatalf("write legacy bans file: %v", err)
	}

	limiter := serverweb.NewIPLimiter(3, 10*time.Minute, 15*time.Minute, bansFile)
	defer limiter.Close()

	details := limiter.ListBanDetails()
	if len(details) != 2 {
		t.Fatalf("expected 2 migrated bans, got %d", len(details))
	}
	byIP := make(map[string]serverweb.BanDetail, len(details))
	for _, item := range details {
		byIP[item.IP] = item
	}
	if d, ok := byIP["198.51.100.11"]; !ok || d.Source != serverweb.BanSourceManualSniff || d.SourceLabel != "嗅探手动封禁" {
		t.Fatalf("expected 198.51.100.11 inferred as manual_sniff, got %+v", d)
	}
	if d, ok := byIP["203.0.113.22"]; !ok || d.Source != serverweb.BanSourceLoginFail || d.SourceLabel != "密码试错拦截" {
		t.Fatalf("expected 203.0.113.22 inferred as login_fail, got %+v", d)
	}

	limiter.BanManual("192.0.2.99", 7*24*time.Hour, "订阅拉取异常 IP 手动封禁")
	var d99 serverweb.BanDetail
	var found99 bool
	for _, item := range limiter.ListBanDetails() {
		if item.IP == "192.0.2.99" {
			d99, found99 = item, true
			break
		}
	}
	if !found99 || d99.Source != serverweb.BanSourceManualSniff || d99.Reason != "订阅拉取异常 IP 手动封禁" {
		t.Fatalf("unexpected manual ban detail: %+v", d99)
	}

	if got := serverweb.FormatDurationCN(6*24*time.Hour + 14*time.Hour); got != "6 天 14 小时" {
		t.Fatalf("expected '6 天 14 小时', got %q", got)
	}
	if got := serverweb.FormatDurationCN(12 * time.Minute); got != "12 分钟" {
		t.Fatalf("expected '12 分钟', got %q", got)
	}
}

func TestServerWeb_FullChainUnbanAndSniffUnblock(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
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

	srv := serverweb.New(serverweb.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     fleetFile,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	srv.SniffTracker().Observe("198.51.100.44", "TLS/443 伪装回落嗅探", "masqueraded", 4)
	srv.SniffTracker().Observe("203.0.113.10", "HTTP/80 端口嗅探", "masqueraded", 3)
	srv.SniffTracker().Observe("203.0.113.20", "HTTP/80 端口嗅探", "masqueraded", 2)

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

	if rec := doAuthReq(http.MethodPost, "/api/server/security/block", `{"target":"198.51.100.44","node":"local"}`); rec.Code != http.StatusOK {
		t.Fatalf("block IP failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAuthReq(http.MethodPost, "/api/server/security/block", `{"target":"203.0.113.0/24","node":"local"}`); rec.Code != http.StatusOK {
		t.Fatalf("block CIDR failed: %d %s", rec.Code, rec.Body.String())
	}

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
	if bansResp.Bans[0].Source != serverweb.BanSourceManualSniff || bansResp.Bans[0].SourceLabel != "嗅探手动封禁" {
		t.Fatalf("unexpected ban source: %+v", bansResp.Bans[0])
	}

	snap := srv.SniffTracker().SnapshotForNode(t.Context(), "local", false)
	for _, item := range snap.TopIPs {
		if item.IP == "198.51.100.44" && strings.Contains(item.Vector, "Web 管理端密码试探") {
			t.Fatalf("manual sniff block must not pollute vector with Web password probe, got %q", item.Vector)
		}
	}
	if snap.TotalBannedIPs != 3 {
		t.Fatalf("expected 3 banned IPs in SniffTracker (1 single + 2 in /24), got %d", snap.TotalBannedIPs)
	}

	if rec := doAuthReq(http.MethodPost, "/api/server/unban", `{"ip":"198.51.100.44"}`); rec.Code != http.StatusOK {
		t.Fatalf("unban IP failed: %d %s", rec.Code, rec.Body.String())
	}
	if _, banned := srv.Limiter().CheckBan("198.51.100.44"); banned {
		t.Fatalf("expected 198.51.100.44 cleared from IPLimiter")
	}

	if rec := doAuthReq(http.MethodPost, "/api/server/security/unblock", `{"target":"203.0.113.0/24","node":"local"}`); rec.Code != http.StatusOK {
		t.Fatalf("unblock CIDR failed: %d %s", rec.Code, rec.Body.String())
	}
	snapAfterCIDRUnban := srv.SniffTracker().SnapshotForNode(t.Context(), "local", false)
	if snapAfterCIDRUnban.TotalBannedIPs != 0 {
		t.Fatalf("expected 0 banned IPs after unblocking /24 subnet, got %d", snapAfterCIDRUnban.TotalBannedIPs)
	}
}

func TestSubscriptionAuditEndpointAndAuditClassification(t *testing.T) {
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

	srv := serverweb.New(serverweb.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     filepath.Join(tmpDir, "fleet.yaml"),
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srv.Limiter().Close()

	nowStr := time.Now().UTC().Format(time.RFC3339)
	countries := []string{"US", "NL", "DE", "RU"}
	for i := 1; i <= 11; i++ {
		srv.SubStore().RecordAccess(subhub.AccessLogEntry{
			Timestamp:   nowStr,
			IP:          fmt.Sprintf("203.0.113.%d", i),
			CountryCode: countries[i%len(countries)],
			UserAgent:   "python-requests/2.31.0",
			Status:      "ok",
		})
	}

	auditReq := httptest.NewRequest(http.MethodGet, "/api/server/subscriptions/audit", nil)
	auditReq.SetBasicAuth("opsadmin", "Password123")
	auditRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(auditRec, auditReq)
	if auditRec.Code != http.StatusOK {
		t.Fatalf("subscriptions/audit endpoint failed: %d %s", auditRec.Code, auditRec.Body.String())
	}
	var auditResp struct {
		RiskSummary serverweb.SubscriptionRiskSummary `json:"riskSummary"`
	}
	if err := json.Unmarshal(auditRec.Body.Bytes(), &auditResp); err != nil {
		t.Fatal(err)
	}
	if auditResp.RiskSummary.Level != "high" || auditResp.RiskSummary.UniqueIPs24h != 11 {
		t.Fatalf("expected high risk summary from delegated subhub evaluator, got %+v", auditResp.RiskSummary)
	}

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

	if serverweb.MaxAuditLogs != 200 {
		t.Fatalf("expected MaxAuditLogs == 200, got %d", serverweb.MaxAuditLogs)
	}
	if got := serverweb.ClassifyAuditCategory("管理员登录成功"); got != "login" {
		t.Fatalf("expected login category, got %q", got)
	}
	if got := serverweb.ClassifyAuditCategory("导出加密灾备快照 (共 6 项敏感资产)"); got != "security" {
		t.Fatalf("expected security category, got %q", got)
	}
	if got := serverweb.ClassifyAuditCategory("保存子节点 [jp1]"); got != "fleet" {
		t.Fatalf("expected fleet category, got %q", got)
	}
	if got := serverweb.ClassifyAuditCategory("轮换客户端聚合订阅访问密钥"); got != "subscription" {
		t.Fatalf("expected subscription category, got %q", got)
	}
	if got := serverweb.ClassifyAuditCategory("升级组件 [singctl] 至 v1.14.32"); got != "service" {
		t.Fatalf("expected service category, got %q", got)
	}
}
