// 文件职责：覆盖审计页一键切换连接出口规则 (/api/audit/route-rule) 持久化、DNS 联动、存量断开、防锁死校验与失败回滚契约。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
	"singctl/internal/webui"
)

func setupAuditRouteTestServer(t *testing.T, invalidSB bool) (*webui.Server, string, string, *[]string, *sync.Mutex) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "config.json")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(workDir, "config.json")

	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sbJSON := "{invalid-json"
	if !invalidSB {
		sbJSON = buildValidTestSingBoxJSON(t, dir)
	}
	if err := os.WriteFile(sbPath, []byte(sbJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workPath, []byte(sbJSON), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var deletedIDs []string
	clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id": "conn-sub",
						"metadata": map[string]string{
							"network":       "tcp",
							"sourceIP":      "192.168.1.50",
							"destinationIP": "203.0.113.50",
							"host":          "sub.api.example.com",
						},
					},
					{
						"id": "conn-other-dev",
						"metadata": map[string]string{
							"network":       "tcp",
							"sourceIP":      "192.168.1.99",
							"destinationIP": "203.0.113.50",
							"host":          "sub.api.example.com",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			mu.Lock()
			deletedIDs = append(deletedIDs, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(clashSrv.Close)

	srv := webui.New(webui.Options{
		ConfigPath:            cfgPath,
		SingBoxConfigPath:     sbPath,
		SingBoxWorkConfigPath: workPath,
		Listen:                "127.0.0.1:0",
		Password:              "test-pass-123",
	})
	srv.AuditCollector().SetEndpointsForTest([]string{clashSrv.URL}, "", filepath.Join(dir, "audit-state.json"))
	srv.AuditCollector().SetLeaseFilesForTest(nil, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))

	return srv, cfgPath, sbPath, &deletedIDs, &mu
}

func doAuthedJSON(srv *webui.Server, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.RemoteAddr = "192.0.2.40:42000"
	req.Header.Set("Authorization", "Bearer "+srv.SessionToken())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	return rec
}

func TestAuditRouteRuleAPI_UpsertUpdateDeleteAndCloseConnections(t *testing.T) {
	srv, cfgPath, sbPath, deletedIDs, mu := setupAuditRouteTestServer(t, false)

	// 1. POST /api/audit/route-rule creates custom route+dns rule and closes scoped matching connections.
	rec1 := doAuthedJSON(srv, http.MethodPost, "/api/audit/route-rule", map[string]any{
		"target":     "api.example.com",
		"matchType":  config.TrafficMatchDomainSuffix,
		"outbound":   "#VPS",
		"sourceIp":   "192.168.1.50",
		"connTarget": "sub.api.example.com",
	})
	if rec1.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/route-rule status=%d body=%s", rec1.Code, rec1.Body.String())
	}

	var resp1 struct {
		OK                bool                        `json:"ok"`
		ClosedConnections int                         `json:"closedConnections"`
		Rule              config.TrafficCustomRule    `json:"rule"`
		Rules             []config.TrafficCustomRule  `json:"rules"`
		Report            singbox.ClientRoutingReport `json:"report"`
	}
	if err := json.Unmarshal(rec1.Body.Bytes(), &resp1); err != nil {
		t.Fatalf("decode response1: %v", err)
	}
	if !resp1.OK || resp1.Rule.Target != "api.example.com" || resp1.Rule.Outbound != "#VPS" || len(resp1.Rules) != 1 {
		t.Fatalf("unexpected response1: %+v", resp1)
	}
	if resp1.ClosedConnections != 1 {
		t.Fatalf("expected closedConnections=1 (only scoped device 192.168.1.50), got %d", resp1.ClosedConnections)
	}
	mu.Lock()
	gotDeleted := slices.Clone(*deletedIDs)
	*deletedIDs = nil
	mu.Unlock()
	if !slices.Equal(gotDeleted, []string{"conn-sub"}) {
		t.Fatalf("expected only conn-sub closed, got %v", gotDeleted)
	}

	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("stat singctl.yaml: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("singctl.yaml perm = %o, want 0600", info.Mode().Perm())
	}
	loadedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loadedCfg.TrafficRouting.Rules) != 1 || loadedCfg.TrafficRouting.Rules[0].Outbound != "#VPS" {
		t.Fatalf("unexpected persisted Rules: %+v", loadedCfg.TrafficRouting.Rules)
	}

	sbBytes1, _ := os.ReadFile(sbPath)
	doc1, err := sboption.ParseDocument(sbBytes1)
	if err != nil {
		t.Fatalf("parse live config.json: %v", err)
	}
	hasRouteVPS := false
	for _, r := range doc1.Route.Rules {
		if slices.Contains(r.DomainSuffix.Slice(), "api.example.com") && r.Outbound == "#VPS" && slices.Contains(r.SourceIPCIDR.Slice(), "192.168.1.50/32") {
			hasRouteVPS = true
		}
	}
	if !hasRouteVPS {
		t.Fatalf("live config.json missing compiled route rule:\n%s", string(sbBytes1))
	}

	// 2. Second POST switches same rule to "direct" (#DC + dns_local), stripping previous #VPS rule.
	rec2 := doAuthedJSON(srv, http.MethodPost, "/api/audit/route-rule", map[string]any{
		"target":    "api.example.com",
		"matchType": config.TrafficMatchDomainSuffix,
		"outbound":  config.TrafficOutboundDirect,
		"sourceIp":  "192.168.1.50",
	})
	if rec2.Code != http.StatusOK {
		t.Fatalf("second POST /api/audit/route-rule status=%d body=%s", rec2.Code, rec2.Body.String())
	}
	loadedCfg2, _ := config.Load(cfgPath)
	if len(loadedCfg2.TrafficRouting.Rules) != 1 || loadedCfg2.TrafficRouting.Rules[0].Outbound != config.TrafficOutboundDirect {
		t.Fatalf("expected 1 rule updated in-place to direct, got %+v", loadedCfg2.TrafficRouting.Rules)
	}
	sbBytes2, _ := os.ReadFile(sbPath)
	doc2, _ := sboption.ParseDocument(sbBytes2)
	hasRouteDirect := false
	for _, r := range doc2.Route.Rules {
		if slices.Contains(r.DomainSuffix.Slice(), "api.example.com") {
			if r.Outbound == "#VPS" {
				t.Fatalf("stale #VPS route rule remained after switch to direct")
			}
			if r.Outbound == "#DC" {
				hasRouteDirect = true
			}
		}
	}
	hasDNSLocal := false
	for _, d := range doc2.DNS.Rules {
		if slices.Contains(d.DomainSuffix.Slice(), "api.example.com") {
			if d.Server == "dns_proxy" {
				t.Fatalf("stale dns_proxy DNS rule remained after switch to direct")
			}
			if d.Server == "dns_local" {
				hasDNSLocal = true
			}
		}
	}
	if !hasRouteDirect || !hasDNSLocal {
		t.Fatalf("expected #DC route (%v) and dns_local DNS (%v)", hasRouteDirect, hasDNSLocal)
	}

	// 3. GET /api/traffic-routing exposes customRules.
	recTR := doAuthedJSON(srv, http.MethodGet, "/api/traffic-routing", nil)
	if recTR.Code != http.StatusOK {
		t.Fatalf("GET /api/traffic-routing status=%d", recTR.Code)
	}
	var trRep singbox.ClientRoutingReport
	_ = json.Unmarshal(recTR.Body.Bytes(), &trRep)
	if len(trRep.CustomRules) != 1 || trRep.CustomRules[0].Target != "api.example.com" {
		t.Fatalf("expected customRules in /api/traffic-routing, got %+v", trRep.CustomRules)
	}

	// 4. DELETE /api/audit/route-rule removes persisted rule and strips compiled route+DNS rules.
	recDel := doAuthedJSON(srv, http.MethodDelete, "/api/audit/route-rule", map[string]any{
		"target":    "api.example.com",
		"matchType": config.TrafficMatchDomainSuffix,
		"sourceIp":  "192.168.1.50",
	})
	if recDel.Code != http.StatusOK {
		t.Fatalf("DELETE /api/audit/route-rule status=%d body=%s", recDel.Code, recDel.Body.String())
	}
	loadedCfg3, _ := config.Load(cfgPath)
	if len(loadedCfg3.TrafficRouting.Rules) != 0 {
		t.Fatalf("expected 0 rules after delete, got %+v", loadedCfg3.TrafficRouting.Rules)
	}
	sbBytes3, _ := os.ReadFile(sbPath)
	doc3, _ := sboption.ParseDocument(sbBytes3)
	for _, r := range doc3.Route.Rules {
		if slices.Contains(r.DomainSuffix.Slice(), "api.example.com") {
			t.Fatalf("deleted route rule still present: %+v", r)
		}
	}
	for _, d := range doc3.DNS.Rules {
		if slices.Contains(d.DomainSuffix.Slice(), "api.example.com") {
			t.Fatalf("deleted dns rule still present: %+v", d)
		}
	}
}

func TestAuditRouteRuleAPI_ValidationAndAntiLockout(t *testing.T) {
	srv, _, _, _, _ := setupAuditRouteTestServer(t, false)

	badCases := []struct {
		name string
		body map[string]any
	}{
		{"bootstrap domain cloudflare-ech", map[string]any{"target": "cloudflare-ech.com", "outbound": "direct"}},
		{"bootstrap domain dns.google", map[string]any{"target": "dns.google", "outbound": "direct"}},
		{"bootstrap ip 1.1.1.1", map[string]any{"target": "1.1.1.1", "outbound": "#VPS"}},
		{"loopback 127.0.0.1", map[string]any{"target": "127.0.0.1", "outbound": "#VPS"}},
		{"private LAN IP 192.168.1.1", map[string]any{"target": "192.168.1.1", "outbound": "#VPS"}},
		{"tailscale CGNAT IP", map[string]any{"target": "100.64.0.10", "outbound": "#VPS"}},
		{"nonexistent outbound group", map[string]any{"target": "safe.example.com", "outbound": "NoSuchGroup"}},
		{"injection payload", map[string]any{"target": "example.com;id", "outbound": "#VPS"}},
	}

	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doAuthedJSON(srv, http.MethodPost, "/api/audit/route-rule", tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for %s, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAuditRouteRuleAPI_RollbackOnInvalidSingBoxConfig(t *testing.T) {
	srv, cfgPath, _, _, _ := setupAuditRouteTestServer(t, true)
	rec := doAuthedJSON(srv, http.MethodPost, "/api/audit/route-rule", map[string]any{
		"target":   "safe.example.com",
		"outbound": "#VPS",
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("expected failure on invalid config.json, got 200")
	}
	loadedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loadedCfg.TrafficRouting.Rules) != 0 {
		t.Fatalf("expected rollback of singctl.yaml Rules, got %+v", loadedCfg.TrafficRouting.Rules)
	}
}
