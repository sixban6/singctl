// 文件职责：覆盖服务端单机 WARP 分流 HTTP 接口、40000 端口防黑洞拦截、三阶段看门狗熔断回切与手动换 IP 横幅清理单测。
package serverweb_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/serverweb"
	"singctl/internal/telemetry"
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

	updatedTpl := strings.ReplaceAll(string(tpl), telemetry.DefaultControllerAddr, strings.TrimPrefix(clashMock.URL, "http://"))
	_ = os.WriteFile(sbCfgPath, []byte(updatedTpl), 0600)

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

	warpPortHealthy := false
	srv.SetDeps(serverweb.Deps{
		WarpApplyDeps: &deploy.LiveWarpApplyDeps{
			CheckWarpPort:   func() bool { return warpPortHealthy },
			ValidateConfig:  func(string) error { return nil },
			IsServiceActive: func() bool { return false },
			ReloadService:   func(bool) error { return nil },
		},
		WarpDaemonProbe: func(bool) serverweb.WarpDaemonStatus {
			return serverweb.WarpDaemonStatus{
				Installed:     true,
				Running:       warpPortHealthy,
				TunnelHealthy: warpPortHealthy,
				SocksPort:     40000,
				WarpIP:        "198.51.100.88",
				WarpLoc:       "SJC",
			}
		},
	})

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

	rec := doAuthReq(http.MethodGet, "/api/server/warp/routing", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET warp/routing failed: %d %s", rec.Code, rec.Body.String())
	}
	var statusResp serverweb.WarpRoutingStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &statusResp); err != nil {
		t.Fatal(err)
	}
	if len(statusResp.Presets) != 15 {
		t.Fatalf("expected 15 presets, got %d", len(statusResp.Presets))
	}

	rec = doAuthReq(http.MethodPost, "/api/server/warp/quick-switch", `{"target":"https://missav.ws/dm13/cn","outbound":"WARP"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when 40000 port is down, got %d %s", rec.Code, rec.Body.String())
	}

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

	rec = doAuthReq(http.MethodGet, "/api/server/warp/connections?q=missav", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "missav.ws") {
		t.Fatalf("GET warp/connections failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWarpWatchdog_ThreeStageSelfHealAndAutoRecovery(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "config.json")
	subDir := filepath.Join(tmpDir, "sub-store")
	fleetFile := filepath.Join(tmpDir, "fleet.yaml")

	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
  warp_routing:
    mode: split
    presets:
      missav: true
      x: true
`), 0600); err != nil {
		t.Fatal(err)
	}

	tpl, err := deploy.TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatal(err)
	}

	evictedIDs := []string{}
	clashMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id":       "x-stream-1",
						"upload":   100,
						"download": 2048,
						"chains":   []string{"WARP"},
						"rule":     "rule-x",
						"metadata": map[string]any{
							"type":          "hysteria2",
							"host":          "x.com",
							"destinationIP": "198.51.100.40",
						},
					},
					{
						"id":       "dc-stream-1",
						"upload":   50,
						"download": 512,
						"chains":   []string{"DC"},
						"rule":     "final",
						"metadata": map[string]any{
							"type":          "vless",
							"host":          "example.com",
							"destinationIP": "203.0.113.50",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			evictedIDs = append(evictedIDs, strings.TrimPrefix(r.URL.Path, "/connections/"))
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer clashMock.Close()

	updatedTpl := strings.ReplaceAll(string(tpl), telemetry.DefaultControllerAddr, strings.TrimPrefix(clashMock.URL, "http://"))
	if err := os.WriteFile(sbCfgPath, []byte(updatedTpl), 0600); err != nil {
		t.Fatal(err)
	}

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

	probeHealthy := false
	switchCalls := 0
	rotateCalls := 0
	srv.SetDeps(serverweb.Deps{
		WarpApplyDeps: &deploy.LiveWarpApplyDeps{
			CheckWarpPort:   func() bool { return true },
			ValidateConfig:  func(string) error { return nil },
			IsServiceActive: func() bool { return false },
			ReloadService:   func(bool) error { return nil },
		},
		WarpWatchdogDeps: &serverweb.WarpWatchdogDeps{
			HasLegacyFscarmen: func() bool { return false },
			ProbeRealTargets: func(_ time.Duration) (string, string, error) {
				if probeHealthy {
					return "198.51.100.99", "LAX", nil
				}
				return "", "", os.ErrDeadlineExceeded
			},
			SwitchEndpoint: func() (string, string, string, error) {
				switchCalls++
				return "", "", "", os.ErrDeadlineExceeded
			},
			RotateIdentity: func() (string, string, error) {
				rotateCalls++
				return "", "", os.ErrDeadlineExceeded
			},
		},
	})

	ctx := t.Context()

	srv.RunWarpWatchdogTick(ctx)
	if switchCalls != 0 || rotateCalls != 0 || srv.ProbeWarpDaemon(false).DegradedFallback {
		t.Fatalf("expected tick 1 failure to debounce, got switch=%d rotate=%d degraded=%v", switchCalls, rotateCalls, srv.ProbeWarpDaemon(false).DegradedFallback)
	}
	rawSB, _ := os.ReadFile(sbCfgPath)
	if !strings.Contains(string(rawSB), `"8.8.8.8/32"`) || !strings.Contains(string(rawSB), `"sub.example.com"`) {
		t.Fatalf("expected boot sync to inject DNS and self-domain DC exemptions, got:\n%s", string(rawSB))
	}

	srv.RunWarpWatchdogTick(ctx)
	if switchCalls != 1 || rotateCalls != 1 {
		t.Fatalf("expected Stage 1 & Stage 2 attempts, got switch=%d rotate=%d", switchCalls, rotateCalls)
	}
	if !srv.ProbeWarpDaemon(false).DegradedFallback {
		t.Fatal("expected Stage 3 circuit breaker to enable DegradedFallback")
	}
	rawBypassed, _ := os.ReadFile(sbCfgPath)
	if strings.Contains(string(rawBypassed), `"outbound": "WARP"`) {
		t.Fatalf("expected live sing-box config to temporarily bypass all WARP rules during circuit break")
	}
	if len(evictedIDs) != 1 || evictedIDs[0] != "x-stream-1" {
		t.Fatalf("expected only WARP connection x-stream-1 evicted, got %v", evictedIDs)
	}

	probeHealthy = true
	srv.RunWarpWatchdogTick(ctx)
	if srv.ProbeWarpDaemon(false).DegradedFallback {
		t.Fatal("expected DegradedFallback to clear after WARP probe recovered")
	}
	rawRecovered, _ := os.ReadFile(sbCfgPath)
	if !strings.Contains(string(rawRecovered), `"rule-x"`) || !strings.Contains(string(rawRecovered), `"outbound": "WARP"`) {
		t.Fatalf("expected original WARP routing rules restored into config.json upon recovery, got:\n%s", string(rawRecovered))
	}
}

func TestHandleStatus_FastAndBoundedTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
	req.SetBasicAuth("opsadmin", "Password123")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK || elapsed > 3*time.Second {
		t.Fatalf("GET /api/server/status got %d in %v: %s", rec.Code, elapsed, rec.Body.String())
	}
}

func TestHandleWarpAction_RekeyClearsStaleHealBadge(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	srv.SeedWarpExitCache("2001:db8::1", "LAX", time.Now())

	// First trigger Stage 1 heal badge via watchdog tick so a real heal badge is present
	healedOnce := false
	srv.SetDeps(serverweb.Deps{
		WarpWatchdogDeps: &serverweb.WarpWatchdogDeps{
			HasLegacyFscarmen: func() bool { return false },
			ProbeRealTargets: func(time.Duration) (string, string, error) {
				if healedOnce {
					return "2001:db8::1", "LAX", nil
				}
				return "", "", os.ErrDeadlineExceeded
			},
			SwitchEndpoint: func() (string, string, string, error) {
				healedOnce = true
				return "162.159.192.1:2408", "2001:db8::1", "LAX", nil
			},
		},
	})
	srv.RunWarpWatchdogTick(t.Context())
	srv.RunWarpWatchdogTick(t.Context())

	gotPrevIP := ""
	srv.SetDeps(serverweb.Deps{
		WarpRotateIdentity: func(previousIP string) (string, string, error) {
			gotPrevIP = previousIP
			return "2001:db8::2", "SJC", nil
		},
		WarpPortChecker: func() bool { return true },
	})

	req := httptest.NewRequest(http.MethodPost, "/api/server/warp/action", strings.NewReader(`{"action":"rekey"}`))
	req.SetBasicAuth("opsadmin", "Password123")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/server/warp/action rekey failed: %d %s", rec.Code, rec.Body.String())
	}
	if gotPrevIP != "2001:db8::1" {
		t.Fatalf("expected previousIP 2001:db8::1 passed to rotate helper, got %q", gotPrevIP)
	}

	var payload struct {
		Message string                     `json:"message"`
		WarpIP  string                     `json:"warpIp"`
		WarpLoc string                     `json:"warpLoc"`
		Daemon  serverweb.WarpDaemonStatus `json:"daemon"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.WarpIP != "2001:db8::2" || payload.WarpLoc != "SJC" {
		t.Fatalf("unexpected payload IP/Loc: %+v", payload)
	}
	if !strings.Contains(payload.Message, "2001:db8::1 → 2001:db8::2") {
		t.Fatalf("expected before->after transition in message, got %q", payload.Message)
	}
	if payload.Daemon.AutoHealStatus != "" || payload.Daemon.LastHealedAt != "" {
		t.Fatalf("expected stale watchdog heal badge cleared after manual rekey, got %+v", payload.Daemon)
	}
}
