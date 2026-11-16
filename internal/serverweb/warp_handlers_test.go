package serverweb

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

	updatedTpl := strings.ReplaceAll(string(tpl), "127.0.0.1:9099", strings.TrimPrefix(clashMock.URL, "http://"))
	if err := os.WriteFile(sbCfgPath, []byte(updatedTpl), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     fleetFile,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	srv.sniff.EnableSystemProbe = false
	srv.warpDeps = &deploy.LiveWarpApplyDeps{
		CheckWarpPort:   func() bool { return true },
		ValidateConfig:  func(string) error { return nil },
		IsServiceActive: func() bool { return false },
		ReloadService:   func(bool) error { return nil },
	}

	probeHealthy := false
	switchCalls := 0
	rotateCalls := 0
	srv.warpWatchdogDeps = &WarpWatchdogDeps{
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
	}

	ctx := t.Context()

	// 1. 第 1 次失败：防抖观察，不应立即触发阶段1/2/3，但应完成首次硬豁免路由同步
	srv.RunWarpWatchdogTick(ctx)
	if switchCalls != 0 || rotateCalls != 0 || srv.probeWarpDaemon(false).DegradedFallback {
		t.Fatalf("expected tick 1 failure to debounce, got switch=%d rotate=%d degraded=%v", switchCalls, rotateCalls, srv.probeWarpDaemon(false).DegradedFallback)
	}
	rawSB, _ := os.ReadFile(sbCfgPath)
	if !strings.Contains(string(rawSB), `"8.8.8.8/32"`) || !strings.Contains(string(rawSB), `"sub.example.com"`) {
		t.Fatalf("expected boot sync to inject DNS and self-domain DC exemptions, got:\n%s", string(rawSB))
	}

	// 2. 第 2 次连续失败：触发 Stage 1 -> Stage 2 -> Stage 3 熔断降级至 DC，踢断 WARP 连接但保留 singctl.yaml 原配置
	srv.RunWarpWatchdogTick(ctx)
	if switchCalls != 1 || rotateCalls != 1 {
		t.Fatalf("expected Stage 1 & Stage 2 attempts, got switch=%d rotate=%d", switchCalls, rotateCalls)
	}
	daemonSt := srv.probeWarpDaemon(false)
	if !daemonSt.DegradedFallback {
		t.Fatal("expected Stage 3 circuit breaker to enable DegradedFallback")
	}
	rawBypassed, _ := os.ReadFile(sbCfgPath)
	if strings.Contains(string(rawBypassed), `"outbound": "WARP"`) {
		t.Fatalf("expected live sing-box config to temporarily bypass all WARP rules during circuit break")
	}
	if len(evictedIDs) != 1 || evictedIDs[0] != "x-stream-1" {
		t.Fatalf("expected only WARP connection x-stream-1 evicted, got %v", evictedIDs)
	}
	savedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if savedCfg.Server.WarpRouting.NormalizedMode() != config.WarpModeSplit || !savedCfg.Server.WarpRouting.IsPresetEnabled("x", false) {
		t.Fatalf("expected singctl.yaml original warp_routing to remain intact during circuit break, got %+v", savedCfg.Server.WarpRouting)
	}

	// 3. 当 WARP 后续恢复健康后，后台巡检自动回切至原分流策略并解除 DegradedFallback
	probeHealthy = true
	srv.RunWarpWatchdogTick(ctx)
	if srv.probeWarpDaemon(false).DegradedFallback {
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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	start := time.Now()
	req := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
	req.SetBasicAuth("opsadmin", "Password123")
	req.RemoteAddr = "127.0.0.1:54321"
	req.Header.Set("X-Real-IP", "192.0.2.1")
	rec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/server/status failed: %d %s", rec.Code, rec.Body.String())
	}
	if elapsed > 3*time.Second {
		t.Fatalf("expected /api/server/status within bounded timeout, took %v", elapsed)
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

	srv := New(Options{
		ConfigPath:    cfgPath,
		SubStoreDir:   filepath.Join(tmpDir, "sub-store"),
		FleetFilePath: filepath.Join(tmpDir, "fleet.yaml"),
		Username:      "opsadmin",
		Password:      "Password123",
	})
	srv.sniff.EnableSystemProbe = false

	srv.warpCacheMu.Lock()
	srv.warpCachedIP = "2001:db8::1"
	srv.warpCachedLoc = "LAX"
	srv.warpCachedAt = time.Now()
	srv.warpCacheMu.Unlock()

	srv.warpWatchdogMu.Lock()
	srv.warpDegraded = false
	srv.warpAutoHealStatus = "自动自愈成功：已更换 WARP IP 198.51.100.1 (LAX)"
	srv.warpLastHealedAt = "2026-11-16 15:00:00"
	srv.warpWatchdogMu.Unlock()

	gotPrevIP := ""
	srv.warpRotateIdentity = func(previousIP string) (string, string, error) {
		gotPrevIP = previousIP
		return "2001:db8::2", "SJC", nil
	}
	srv.warpDaemonProbe = func(bool) WarpDaemonStatus {
		srv.warpCacheMu.Lock()
		ip := srv.warpCachedIP
		loc := srv.warpCachedLoc
		srv.warpCacheMu.Unlock()
		return WarpDaemonStatus{
			Installed:     true,
			Running:       true,
			TunnelHealthy: true,
			SocksPort:     40000,
			WarpIP:        ip,
			WarpLoc:       loc,
		}
	}

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
		Message string           `json:"message"`
		WarpIP  string           `json:"warpIp"`
		WarpLoc string           `json:"warpLoc"`
		Daemon  WarpDaemonStatus `json:"daemon"`
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
