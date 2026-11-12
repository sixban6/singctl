package serverweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/deploy"
)

func TestWarpRoutingHandlers_GuardAndQuickSwitch(t *testing.T) {
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
		t.Fatal(err)
	}

	tpl, err := deploy.TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbCfgPath, tpl, 0600); err != nil {
		t.Fatal(err)
	}

	// 模拟可控 Clash API 9099 测试服务器，验证 quick-switch 触发精准踢流
	evictedCount := 0
	clashMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id":       "missav-stream-1",
						"upload":   100,
						"download": 2048,
						"chains":   []string{"DC"},
						"rule":     "final",
						"metadata": map[string]any{
							"type":          "hysteria2",
							"host":          "missav.ws",
							"destinationIP": "198.51.100.30",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/connections/missav-stream-1":
			evictedCount++
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer clashMock.Close()

	// 注入 mock clash controller 地址
	updatedTpl := strings.ReplaceAll(string(tpl), "127.0.0.1:9099", strings.TrimPrefix(clashMock.URL, "http://"))
	_ = os.WriteFile(sbCfgPath, []byte(updatedTpl), 0600)

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     fleetFile,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	warpPortHealthy := false
	srv.warpDeps = &deploy.LiveWarpApplyDeps{
		CheckWarpPort:   func() bool { return warpPortHealthy },
		ValidateConfig:  func(string) error { return nil },
		IsServiceActive: func() bool { return false },
		ReloadService:   func(bool) error { return nil },
	}
	srv.warpDaemonProbe = func(bool) WarpDaemonStatus {
		return WarpDaemonStatus{
			Installed:     true,
			Running:       warpPortHealthy,
			TunnelHealthy: warpPortHealthy,
			SocksPort:     40000,
			WarpIP:        "198.51.100.88",
			WarpLoc:       "SJC",
		}
	}

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

	// 1. GET /api/server/warp/routing 返回 15 项预设且包含 missav
	rec := doAuthReq(http.MethodGet, "/api/server/warp/routing", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET warp/routing failed: %d %s", rec.Code, rec.Body.String())
	}
	var statusResp WarpRoutingStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	if len(statusResp.Presets) != 15 {
		t.Fatalf("expected 15 presets, got %d", len(statusResp.Presets))
	}

	// 2. 40000 未就绪时，切 WARP 必须返回 409 Conflict 防黑洞拦截
	rec = doAuthReq(http.MethodPost, "/api/server/warp/quick-switch", `{"target":"https://missav.ws/dm13/cn","outbound":"WARP"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when 40000 port is down, got %d %s", rec.Code, rec.Body.String())
	}

	// 3. 放行 40000 就绪后，一键切换 missav.ws -> 联动开启 missav 预设 + 编译 config.json + 精准踢断旧连接
	warpPortHealthy = true
	rec = doAuthReq(http.MethodPost, "/api/server/warp/quick-switch", `{"target":"https://missav.ws/dm13/cn","outbound":"WARP"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("quick-switch failed: %d %s", rec.Code, rec.Body.String())
	}
	if evictedCount != 1 {
		t.Fatalf("expected 1 evicted connection on quick-switch, got %d", evictedCount)
	}

	loadedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !loadedCfg.Server.WarpRouting.IsPresetEnabled("missav", false) {
		t.Fatal("expected missav preset to be enabled and persisted in singctl.yaml")
	}

	// 4. GET /api/server/warp/connections 可正常查询活跃连接
	rec = doAuthReq(http.MethodGet, "/api/server/warp/connections?q=missav", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "missav.ws") {
		t.Fatalf("GET warp/connections failed: %d %s", rec.Code, rec.Body.String())
	}
}
