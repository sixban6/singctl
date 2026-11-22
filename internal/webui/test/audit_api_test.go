// 文件职责：验证客户端 WebUI 设备审计报告、滑动窗口防爬虫限流、连接掐断与白名单接口。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"singctl/internal/webui"
	"slices"
	"testing"

	"singctl/internal/config"
)

func TestAuditRateLimiterScopeIsolationAndBotBlock(t *testing.T) {
	limiter := webui.NewAuditRateLimiter()

	// Simulate hitting read and AI limits from the same client IP (different ephemeral ports).
	for i := range 200 {
		req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
		req.RemoteAddr = "192.0.2.10:40000"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		allowed := limiter.Allow(req, "read", 180)
		if i < 180 && !allowed {
			t.Fatalf("read request %d should be allowed", i)
		}
		if i >= 180 && allowed {
			t.Fatalf("read request %d should be rate-limited", i)
		}
	}

	for i := range 310 {
		req := httptest.NewRequest(http.MethodPost, "/api/audit/ai-review", nil)
		req.RemoteAddr = "192.0.2.10:40001"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		allowed := limiter.Allow(req, "ai", 300)
		if i < 300 && !allowed {
			t.Fatalf("ai request %d should be allowed", i)
		}
		if i >= 300 && allowed {
			t.Fatalf("ai request %d should be rate-limited", i)
		}
	}

	// Interactive write operations (whitelist/block/unblock) must retain full independent quota.
	for i := range 120 {
		req := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", nil)
		req.RemoteAddr = "192.0.2.10:40002"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		if !limiter.Allow(req, "write", 120) {
			t.Fatalf("write request %d should remain unaffected by read/ai bursts", i)
		}
	}

	botReq := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", nil)
	botReq.RemoteAddr = "192.0.2.99:50000"
	botReq.Header.Set("User-Agent", "sqlmap/1.7.2")
	if limiter.Allow(botReq, "write", 120) {
		t.Fatal("expected scraper user-agent to be blocked")
	}
}

func TestAuditWhitelistUnaffectedByAuditGetBurst(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: router\n"), 0600); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "test-pass-123",
		Version:    "v1.14.105",
	})
	token := srv.SessionToken()

	// Exhaust the read rate limit completely on the server's limiter.
	for i := range 180 {
		probeReq := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
		probeReq.RemoteAddr = "192.0.2.20:51000"
		probeReq.Header.Set("User-Agent", "Mozilla/5.0")
		if !srv.AuditLimiter().Allow(probeReq, "read", 180) {
			t.Fatalf("expected read probe %d to be allowed", i)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.RemoteAddr = "192.0.2.20:51000"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once read bucket is exhausted, got %d", rec.Code)
	}

	// Whitelist click from the same client IP must still succeed immediately.
	body, _ := json.Marshal(map[string]string{
		"target": "whitelist.example.com",
		"reason": "test whitelist",
	})
	wlReq := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", bytes.NewReader(body))
	wlReq.RemoteAddr = "192.0.2.20:51001"
	wlReq.Header.Set("Authorization", "Bearer "+token)
	wlReq.Header.Set("Content-Type", "application/json")
	wlReq.Header.Set("User-Agent", "Mozilla/5.0")
	wlRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(wlRec, wlReq)
	if wlRec.Code != http.StatusOK {
		t.Fatalf("expected POST /api/audit/whitelist 200 after read burst, got %d: %s", wlRec.Code, wlRec.Body.String())
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(loaded.Audit.Whitelist, "whitelist.example.com") {
		t.Fatalf("expected whitelist entry persisted in audit.whitelist, got %+v", loaded.Audit.Whitelist)
	}
}

func TestAuditSingletonCollector_ZeroStaleConfigAndLeaseFingerprint(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	leasePath := filepath.Join(dir, "dhcp.leases")
	statePath := filepath.Join(dir, "audit-state.json")

	if err := os.WriteFile(cfgPath, []byte("mode: router\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leasePath, []byte("1799999999 aa:bb:cc:dd:ee:01 192.168.1.50 iphone-old *\n"), 0600); err != nil {
		t.Fatal(err)
	}

	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":       "conn-1",
					"upload":   2048,
					"download": 4096,
					"chains":   []string{"DIRECT"},
					"metadata": map[string]any{
						"network":         "tcp",
						"sourceIP":        "192.168.1.50",
						"destinationIP":   "198.51.100.10",
						"destinationPort": "443",
						"host":            "telemetry.example.com",
					},
				},
			},
		})
	}))
	defer clashSrv.Close()

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "test-pass-123",
		Version:    "v1.14.131",
	})
	srv.AuditCollector().SetEndpointsForTest([]string{clashSrv.URL}, "", statePath)
	srv.AuditCollector().SetLeaseFilesForTest([]string{leasePath}, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))
	token := srv.SessionToken()

	fetchAudit := func() map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
		req.RemoteAddr = "192.0.2.30:41000"
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/audit failed: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1. Initial call warms singleton collector state + lease cache
	rep1 := fetchAudit()
	raw1, _ := json.Marshal(rep1)
	if !bytes.Contains(raw1, []byte("iphone-old")) {
		t.Fatalf("expected initial lease hostname iphone-old, got: %s", string(raw1))
	}

	// 2. Mutate dhcp.leases and whitelist via API -> next GET /api/audit must immediately reflect BOTH with 0 stale delay
	if err := os.WriteFile(leasePath, []byte("1799999999 aa:bb:cc:dd:ee:01 192.168.1.50 iphone-renamed *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	wlReq := httptest.NewRequest(http.MethodPost, "/api/audit/whitelist", bytes.NewReader([]byte(`{"action":"add","target":"telemetry.example.com"}`)))
	wlReq.RemoteAddr = "192.0.2.30:41001"
	wlReq.Header.Set("Authorization", "Bearer "+token)
	wlReq.Header.Set("Content-Type", "application/json")
	wlReq.Header.Set("User-Agent", "Mozilla/5.0")
	wlRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(wlRec, wlReq)
	if wlRec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/whitelist failed: %d", wlRec.Code)
	}

	rep2 := fetchAudit()
	raw2, _ := json.Marshal(rep2)
	if !bytes.Contains(raw2, []byte("iphone-renamed")) {
		t.Fatalf("expected updated lease hostname iphone-renamed immediately on next poll, got: %s", string(raw2))
	}
	if !bytes.Contains(raw2, []byte("telemetry.example.com")) || !bytes.Contains(raw2, []byte("whitelisted")) {
		t.Fatalf("expected newly whitelisted target reflected immediately, got: %s", string(raw2))
	}
}

func TestAuditChainsAndCloseConnections(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: router\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var deletedIDs []string
	deletedAll := false
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id":          "conn-gh-1",
						"upload":      1200,
						"download":    54000,
						"chains":      []string{"sec_san_hy2", "#VPS", "Proxy"},
						"rule":        "RuleSet",
						"rulePayload": "geosite-github",
						"metadata": map[string]any{
							"network":         "tcp",
							"sourceIP":        "192.168.1.88",
							"destinationIP":   "198.51.100.44",
							"destinationPort": "443",
							"host":            "github.com",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/connections/conn-gh-1":
			deletedIDs = append(deletedIDs, "conn-gh-1")
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/connections":
			deletedAll = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer clashSrv.Close()

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Listen:     "127.0.0.1:0",
		Password:   "test-pass-123",
	})
	srv.AuditCollector().SetEndpointsForTest([]string{clashSrv.URL}, "test-secret", filepath.Join(dir, "audit-state.json"))
	token := srv.SessionToken()

	// 1. GET /api/audit 应将 Clash chains 反转整理为入口->出口顺序并输出 activeConnIds
	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.RemoteAddr = "192.0.2.40:42000"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/audit failed: %d %s", rec.Code, rec.Body.String())
	}
	var auditResp struct {
		Flows []struct {
			Target        string   `json:"target"`
			Outbound      string   `json:"outbound"`
			Chains        []string `json:"chains"`
			ActiveConnIDs []string `json:"activeConnIds"`
		} `json:"flows"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &auditResp); err != nil {
		t.Fatal(err)
	}
	if len(auditResp.Flows) != 1 {
		t.Fatalf("expected 1 flow, got %+v", auditResp.Flows)
	}
	gotFlow := auditResp.Flows[0]
	if !slices.Equal(gotFlow.Chains, []string{"Proxy", "#VPS", "sec_san_hy2"}) {
		t.Fatalf("expected entry->exit chains [Proxy #VPS sec_san_hy2], got %v", gotFlow.Chains)
	}
	if !slices.Equal(gotFlow.ActiveConnIDs, []string{"conn-gh-1"}) {
		t.Fatalf("expected activeConnIds [conn-gh-1], got %v", gotFlow.ActiveConnIDs)
	}

	// 2. POST /api/audit/close-connections 单流精确断开
	postClose := func(payload string) *httptest.ResponseRecorder {
		cReq := httptest.NewRequest(http.MethodPost, "/api/audit/close-connections", bytes.NewReader([]byte(payload)))
		cReq.RemoteAddr = "192.0.2.40:42001"
		cReq.Header.Set("Authorization", "Bearer "+token)
		cReq.Header.Set("Content-Type", "application/json")
		cReq.Header.Set("User-Agent", "Mozilla/5.0")
		cRec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(cRec, cReq)
		return cRec
	}

	recOne := postClose(`{"connIds":["conn-gh-1"],"deviceIp":"192.168.1.88","target":"github.com","network":"tcp"}`)
	if recOne.Code != http.StatusOK {
		t.Fatalf("close single flow failed: %d %s", recOne.Code, recOne.Body.String())
	}
	var oneResp struct {
		OK     bool `json:"ok"`
		Closed int  `json:"closed"`
	}
	_ = json.Unmarshal(recOne.Body.Bytes(), &oneResp)
	if !oneResp.OK || oneResp.Closed != 1 || !slices.Equal(deletedIDs, []string{"conn-gh-1"}) {
		t.Fatalf("unexpected close single response: resp=%+v deletedIDs=%v", oneResp, deletedIDs)
	}

	// 3. POST /api/audit/close-connections all=true 一键清空所有活跃连接
	recAll := postClose(`{"all":true}`)
	if recAll.Code != http.StatusOK {
		t.Fatalf("close all flows failed: %d %s", recAll.Code, recAll.Body.String())
	}
	if !deletedAll {
		t.Fatal("expected DELETE /connections to be called for all=true")
	}
}
