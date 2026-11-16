package webui

import (
	"bytes"
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
	if !strings.Contains(string(aghMainRaw), "use_private_ptr_resolvers: true") {
		t.Fatalf("expected PUT /api/gateway mode=main to restore use_private_ptr_resolvers: true, got:\n%s", string(aghMainRaw))
	}
}
