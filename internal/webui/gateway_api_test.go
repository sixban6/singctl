package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/gateway"
	"singctl/internal/netdiag"
)

func TestGatewayAPI_GetPutAndSelfLoopReject(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	aghPath := filepath.Join(dir, "AdGuardHome.yaml")
	aghYAML, err := adguard.BuildInitialConfigYAML(adguard.ConfigParams{
		LANIP:             "192.168.100.2",
		WebPort:           3000,
		DNSPort:           5353,
		Username:          "root",
		PasswordHash:      "$2a$10$111111111111111111111u1111111111111111111111111111111",
		DisablePrivatePTR: false,
	})
	if err != nil {
		t.Fatalf("BuildInitialConfigYAML: %v", err)
	}
	if err := os.WriteFile(aghPath, aghYAML, 0600); err != nil {
		t.Fatalf("write AdGuardHome.yaml: %v", err)
	}

	srv := New(Options{
		ConfigPath:        cfgPath,
		AdGuardConfigPath: aghPath,
		Version:           "v1.14.122-test",
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{
				LANIP:                 "192.168.100.2",
				LANCIDR:               "192.168.100.0/24",
				LANIface:              "eth0",
				CurrentGatewayIP:      "192.168.100.1",
				SuggestedMainRouterIP: "192.168.100.1",
			}
		},
	})

	// 1. GET /api/gateway 默认返回 main 模式及探测到的拓扑信息
	req := httptest.NewRequest(http.MethodGet, "/api/gateway", nil)
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/gateway status=%d body=%s", rec.Code, rec.Body.String())
	}
	var getResp struct {
		Mode         string               `json:"mode"`
		MainRouterIP string               `json:"mainRouterIP"`
		Topology     gateway.TopologyInfo `json:"topology"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("decode GET /api/gateway: %v", err)
	}
	if getResp.Mode != "main" {
		t.Fatalf("expected default mode=main, got %q", getResp.Mode)
	}
	if getResp.Topology.SuggestedMainRouterIP != "192.168.100.1" || getResp.Topology.LANIP != "192.168.100.2" {
		t.Fatalf("unexpected topology: %+v", getResp.Topology)
	}

	// 2. PUT /api/gateway 填入等于本机 IP 的自环网关应返回 400 并保持原配置不变
	loopBody := `{"mode":"side","mainRouterIP":"192.168.100.2"}`
	reqLoop := httptest.NewRequest(http.MethodPut, "/api/gateway", bytes.NewBufferString(loopBody))
	reqLoop.Header.Set("Content-Type", "application/json")
	recLoop := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recLoop, reqLoop)
	if recLoop.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on self-loop mainRouterIP, got %d: %s", recLoop.Code, recLoop.Body.String())
	}

	// 3. PUT /api/gateway 切换为旁路由模式并保存合法主路由 IP
	validBody := `{"mode":"side","mainRouterIP":"192.168.100.1"}`
	reqPut := httptest.NewRequest(http.MethodPut, "/api/gateway", bytes.NewBufferString(validBody))
	reqPut.Header.Set("Content-Type", "application/json")
	recPut := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/gateway failed status=%d body=%s", recPut.Code, recPut.Body.String())
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload config: %v", err)
	}
	if loaded.Gateway.EffectiveMode() != "side" || loaded.Gateway.MainRouterIP != "192.168.100.1" {
		t.Fatalf("expected saved side gateway config, got %+v", loaded.Gateway)
	}
	aghSideRaw, err := os.ReadFile(aghPath)
	if err != nil {
		t.Fatalf("read synced AdGuardHome.yaml (side): %v", err)
	}
	if !strings.Contains(string(aghSideRaw), "use_private_ptr_resolvers: false") {
		t.Fatalf("expected PUT /api/gateway mode=side to sync use_private_ptr_resolvers: false, got:\n%s", string(aghSideRaw))
	}

	// 4. PUT /api/gateway 切回主路由模式
	backMain := `{"mode":"main"}`
	reqMain := httptest.NewRequest(http.MethodPut, "/api/gateway", bytes.NewBufferString(backMain))
	reqMain.Header.Set("Content-Type", "application/json")
	recMain := httptest.NewRecorder()
	srv.Mux.ServeHTTP(recMain, reqMain)
	if recMain.Code != http.StatusOK {
		t.Fatalf("PUT /api/gateway back to main failed status=%d body=%s", recMain.Code, recMain.Body.String())
	}
	loadedMain, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload main config: %v", err)
	}
	if loadedMain.Gateway.EffectiveMode() != "main" {
		t.Fatalf("expected EffectiveMode=main after switch back, got %q", loadedMain.Gateway.EffectiveMode())
	}
	aghMainRaw, err := os.ReadFile(aghPath)
	if err != nil {
		t.Fatalf("read synced AdGuardHome.yaml (main): %v", err)
	}
	if !strings.Contains(string(aghMainRaw), "use_private_ptr_resolvers: false") {
		t.Fatalf("expected PUT /api/gateway mode=main to keep use_private_ptr_resolvers: false (preventing PTR loop), got:\n%s", string(aghMainRaw))
	}
}

func TestGatewayIPv6ModeAndDNSLeakTestAPI(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	sbPath := filepath.Join(dir, "singbox.json")
	sampleSB := `{
  "dns": {
    "strategy": "ipv4_only",
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1"},
      {"tag": "dns_proxy", "type": "https", "server": "8.8.8.8", "detour": "proxy-out"}
    ],
    "rules": [
      {"rule_set": "geosite-cn", "server": "dns_local"},
      {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"}
    ],
    "final": "dns_proxy"
  },
  "outbounds": [
    {"tag": "proxy-out", "type": "direct"},
    {"tag": "direct", "type": "direct"}
  ],
  "route": {
    "final": "direct",
    "default_domain_resolver": "dns_local",
    "rule_set": [
      {"tag": "geosite-cn", "type": "inline", "rules": [{"domain_suffix": ["cn"]}]},
      {"tag": "geosite-private", "type": "inline", "rules": [{"domain_suffix": ["local"]}]},
      {"tag": "geosite-geolocation-!cn", "type": "inline", "rules": [{"domain_suffix": ["example.org"]}]}
    ]
  }
}`
	if err := os.WriteFile(sbPath, []byte(sampleSB), 0600); err != nil {
		t.Fatalf("write singbox.json: %v", err)
	}

	var capturedMode string
	var capturedRounds int
	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbPath,
		Version:           "v1.14.144-test",
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{LANIP: "192.168.100.2", LANCIDR: "192.168.100.0/24", LANIface: "eth0", SuggestedMainRouterIP: "192.168.100.1"}
		},
		DNSLeakRunnerForTest: func(_ context.Context, opts netdiag.DNSLeakTestOptions) *netdiag.DNSLeakReport {
			capturedMode = opts.IPv6Mode
			capturedRounds = opts.GatewayRounds
			return &netdiag.DNSLeakReport{
				Verdict:       "safe",
				IPv6Mode:      opts.IPv6Mode,
				GatewayRounds: opts.GatewayRounds,
				Checks: []netdiag.DNSLeakCheckItem{
					{ID: "overseas_egress", Title: "海外代理 DNS 出口溯源", Status: "pass", Summary: "OK"},
				},
			}
		},
	})

	// 1. PUT /api/gateway with side + cn_only must reject with 400
	badReq := httptest.NewRequest(http.MethodPut, "/api/gateway", bytes.NewBufferString(`{"mode":"side","mainRouterIP":"192.168.100.1","ipv6Mode":"cn_only"}`))
	badReq.Header.Set("Content-Type", "application/json")
	badRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when enabling ipv6Mode on side router, got %d: %s", badRec.Code, badRec.Body.String())
	}

	// 2. PUT /api/gateway with main + cn_only persists singctl.yaml & rewrites singbox config.json
	okReq := httptest.NewRequest(http.MethodPut, "/api/gateway", bytes.NewBufferString(`{"mode":"main","ipv6Mode":"cn_only"}`))
	okReq.Header.Set("Content-Type", "application/json")
	okRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("PUT /api/gateway main+cn_only failed status=%d body=%s", okRec.Code, okRec.Body.String())
	}
	loaded, err := config.Load(cfgPath)
	if err != nil || loaded.Gateway.EffectiveIPv6Mode() != "cn_only" {
		t.Fatalf("expected persisted ipv6_mode=cn_only, got %+v err=%v", loaded, err)
	}
	sbUpdated, _ := os.ReadFile(sbPath)
	if !strings.Contains(string(sbUpdated), `"prefer_ipv4"`) || !strings.Contains(string(sbUpdated), `"predefined"`) {
		t.Fatalf("expected singbox config updated with prefer_ipv4 and predefined AAAA rule, got:\n%s", string(sbUpdated))
	}

	// 3. POST /api/dns/leak-test passes effective ipv6Mode & default rounds (8), and respects mode=deep (16)
	leakReq := httptest.NewRequest(http.MethodPost, "/api/dns/leak-test", bytes.NewBufferString("{}"))
	leakReq.Header.Set("Content-Type", "application/json")
	leakRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(leakRec, leakReq)
	if leakRec.Code != http.StatusOK {
		t.Fatalf("POST /api/dns/leak-test failed status=%d body=%s", leakRec.Code, leakRec.Body.String())
	}
	if capturedMode != "cn_only" || capturedRounds != 8 {
		t.Fatalf("expected ipv6Mode=cn_only rounds=8, got mode=%q rounds=%d", capturedMode, capturedRounds)
	}

	deepReq := httptest.NewRequest(http.MethodPost, "/api/dns/leak-test", bytes.NewBufferString(`{"mode":"deep"}`))
	deepReq.Header.Set("Content-Type", "application/json")
	deepRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(deepRec, deepReq)
	if deepRec.Code != http.StatusOK || capturedRounds != 16 {
		t.Fatalf("expected POST /api/dns/leak-test deep status=200 rounds=16, got status=%d rounds=%d", deepRec.Code, capturedRounds)
	}
}
