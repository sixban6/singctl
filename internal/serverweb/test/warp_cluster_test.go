// 文件职责：覆盖服务端多节点集群 WARP 单点隔离更新、全集群广播快切与 SWR 秒回契约单测。
package serverweb_test

import (
	"context"
	"encoding/base64"
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
	"singctl/internal/fleet"
	"singctl/internal/serverweb"
)

func TestWarpCluster_NodeIsolationAndClusterBroadcast(t *testing.T) {
	tmpDir := t.TempDir()
	tpl, err := deploy.TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatal(err)
	}

	masterCfgPath := filepath.Join(tmpDir, "master-singctl.yaml")
	masterSBPath := filepath.Join(tmpDir, "master-config.json")
	fleetPath := filepath.Join(tmpDir, "fleet.yaml")
	subDir := filepath.Join(tmpDir, "sub-store")

	if err := os.WriteFile(masterCfgPath, []byte(`
server:
  node_domain: "master.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(masterSBPath, tpl, 0600); err != nil {
		t.Fatal(err)
	}

	type fakeRemoteEnv struct {
		cfgPath     string
		sbPath      string
		warpHealthy bool
		warpIP      string
		warpLoc     string
	}
	makeRemoteEnv := func(id, dom string, healthy bool, ip, loc string) *fakeRemoteEnv {
		dir := filepath.Join(tmpDir, id)
		_ = os.MkdirAll(dir, 0700)
		cp := filepath.Join(dir, "singctl.yaml")
		sp := filepath.Join(dir, "config.json")
		_ = os.WriteFile(cp, []byte("server:\n  node_domain: \""+dom+"\"\n"), 0600)
		_ = os.WriteFile(sp, tpl, 0600)
		return &fakeRemoteEnv{cfgPath: cp, sbPath: sp, warpHealthy: healthy, warpIP: ip, warpLoc: loc}
	}
	sg1Env := makeRemoteEnv("sg1", "sg1.example.com", true, "198.51.100.81", "SIN")
	fr1Env := makeRemoteEnv("fr1", "fr1.example.com", false, "", "")
	remoteEnvs := map[string]*fakeRemoteEnv{
		"sg1": sg1Env,
		"fr1": fr1Env,
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:        masterCfgPath,
		SingBoxConfigPath: masterSBPath,
		SubStoreDir:       subDir,
		FleetFilePath:     fleetPath,
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	for _, n := range []fleet.UpsertInput{
		{ID: "sg1", Name: "新加坡主力", Host: "192.0.2.11", Port: 22, User: "root", AuthType: "ssh_alias", SSHAlias: "sg1", Enabled: new(true)},
		{ID: "fr1", Name: "法国节点", Host: "192.0.2.12", Port: 22, User: "root", AuthType: "ssh_alias", SSHAlias: "fr1", Enabled: new(true)},
	} {
		if _, err := srv.FleetManager().Store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}

	srv.SetDeps(serverweb.Deps{
		WarpApplyDeps: &deploy.LiveWarpApplyDeps{
			CheckWarpPort:   func() bool { return true },
			ValidateConfig:  func(string) error { return nil },
			IsServiceActive: func() bool { return false },
			ReloadService:   func(bool) error { return nil },
		},
		WarpDaemonProbe: func(bool) serverweb.WarpDaemonStatus {
			return serverweb.WarpDaemonStatus{
				Installed:     true,
				Running:       true,
				TunnelHealthy: true,
				SocksPort:     40000,
				WarpIP:        "198.51.100.10",
				WarpLoc:       "LAX",
			}
		},
	})

	srv.FleetManager().Runner = func(ctx context.Context, node fleet.Node, script string) (string, int, error) {
		env := remoteEnvs[node.ID]
		opts := deploy.LocalWarpCLIOptions{
			ConfigPath:        env.cfgPath,
			SingBoxConfigPath: env.sbPath,
			ApplyDeps: &deploy.LiveWarpApplyDeps{
				CheckWarpPort:   func() bool { return env.warpHealthy },
				ValidateConfig:  func(string) error { return nil },
				IsServiceActive: func() bool { return false },
				ReloadService:   func(bool) error { return nil },
			},
			DaemonProbe: func(bool) serverweb.WarpDaemonStatus {
				if !env.warpHealthy {
					return serverweb.WarpDaemonStatus{Installed: false, Running: false, TunnelHealthy: false, SocksPort: 40000, Error: "未安装 wireproxy"}
				}
				return serverweb.WarpDaemonStatus{Installed: true, Running: true, TunnelHealthy: true, SocksPort: 40000, WarpIP: env.warpIP, WarpLoc: env.warpLoc}
			},
			EnsureWarpFn: func(*config.Config) error {
				env.warpHealthy = true
				env.warpIP = "198.51.100.92"
				env.warpLoc = "CDG"
				return nil
			},
			RotateWarpFn: func(string) (string, string, error) {
				env.warpIP = "203.0.113.88"
				return env.warpIP, env.warpLoc, nil
			},
		}

		var payload []byte
		if idx := strings.Index(script, "WARPCTL_B64='"); idx >= 0 {
			rest := script[idx+len("WARPCTL_B64='"):]
			if end := strings.IndexByte(rest, '\''); end >= 0 {
				payload, _ = base64.StdEncoding.DecodeString(rest[:end])
			}
		}
		switch {
		case strings.Contains(script, "warp-ctl status"):
			out, err := deploy.ExecuteLocalWarpCLI(ctx, "status", payload, opts)
			return string(out), 15, err
		case strings.Contains(script, "warp-ctl apply"):
			out, err := deploy.ExecuteLocalWarpCLI(ctx, "apply", payload, opts)
			return string(out), 20, err
		case strings.Contains(script, "warp-ctl quick-switch"):
			out, err := deploy.ExecuteLocalWarpCLI(ctx, "quick-switch", payload, opts)
			return string(out), 20, err
		case strings.Contains(script, "warp-ctl connections"):
			out, err := deploy.ExecuteLocalWarpCLI(ctx, "connections", payload, opts)
			return string(out), 12, err
		case strings.Contains(script, "warp-ctl action"):
			out, err := deploy.ExecuteLocalWarpCLI(ctx, "action", payload, opts)
			return string(out), 25, err
		default:
			return "", 5, nil
		}
	}

	token := srv.CLIToken()
	doReq := func(method, path, body string) *httptest.ResponseRecorder {
		var r *http.Request
		if body != "" {
			r = httptest.NewRequest(method, path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.RemoteAddr = "127.0.0.1:54321"
		r.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, r)
		return rec
	}

	recAll := doReq(http.MethodGet, "/api/server/warp/routing?node=all&refresh=1", "")
	if recAll.Code != http.StatusOK {
		t.Fatalf("GET ?node=all failed: %d %s", recAll.Code, recAll.Body.String())
	}
	var statusAll serverweb.WarpRoutingStatusResponse
	if err := json.Unmarshal(recAll.Body.Bytes(), &statusAll); err != nil {
		t.Fatal(err)
	}
	if statusAll.SelectedNode != "all" || len(statusAll.Nodes) != 3 {
		t.Fatalf("expected selectedNode=all and 3 nodes, got selected=%q len=%d", statusAll.SelectedNode, len(statusAll.Nodes))
	}

	recSG1 := doReq(http.MethodPut, "/api/server/warp/routing", `{
		"node": "sg1",
		"mode": "global_warp",
		"warpDomains": [],
		"warpCidrs": [],
		"directDomains": ["netflix.com"],
		"directCidrs": []
	}`)
	if recSG1.Code != http.StatusOK {
		t.Fatalf("PUT sg1 routing failed: %d %s", recSG1.Code, recSG1.Body.String())
	}
	masterCfg, _ := config.Load(masterCfgPath)
	sg1Cfg, _ := config.Load(sg1Env.cfgPath)
	if masterCfg.Server.WarpRouting.NormalizedMode() != config.WarpModeSplit {
		t.Fatalf("master mode should stay split after sg1-only update, got %s", masterCfg.Server.WarpRouting.Mode)
	}
	if sg1Cfg.Server.WarpRouting.NormalizedMode() != config.WarpModeGlobalWarp {
		t.Fatalf("sg1 mode should be global_warp, got %s", sg1Cfg.Server.WarpRouting.Mode)
	}
	sg1SBBytes, _ := os.ReadFile(sg1Env.sbPath)
	if !strings.Contains(string(sg1SBBytes), "sg1.example.com") || strings.Contains(string(sg1SBBytes), "master.example.com") {
		t.Fatalf("expected sg1 config.json to protect sg1.example.com in isolation, got:\n%s", string(sg1SBBytes))
	}

	recQS := doReq(http.MethodPost, "/api/server/warp/quick-switch", `{
		"target": "https://missav.ws/en",
		"outbound": "WARP",
		"node": "local",
		"syncCluster": true
	}`)
	if recQS.Code != http.StatusOK {
		t.Fatalf("cluster quick-switch failed: %d %s", recQS.Code, recQS.Body.String())
	}

	recEnsure := doReq(http.MethodPost, "/api/server/warp/action", `{"action":"ensure","node":"fr1"}`)
	if recEnsure.Code != http.StatusOK {
		t.Fatalf("remote ensure on fr1 failed: %d %s", recEnsure.Code, recEnsure.Body.String())
	}
	recBroadcast := doReq(http.MethodPut, "/api/server/warp/routing", `{
		"node": "all",
		"mode": "split",
		"presets": {"openai": true, "reddit": true},
		"warpDomains": ["custom-ai.example.com"],
		"warpCidrs": [],
		"directDomains": [],
		"directCidrs": []
	}`)
	if recBroadcast.Code != http.StatusOK {
		t.Fatalf("cluster broadcast PUT failed: %d %s", recBroadcast.Code, recBroadcast.Body.String())
	}
	fr1Cfg, _ := config.Load(fr1Env.cfgPath)
	if len(fr1Cfg.Server.WarpRouting.WarpDomains) != 1 || fr1Cfg.Server.WarpRouting.WarpDomains[0] != "custom-ai.example.com" {
		t.Fatalf("expected fr1 to receive broadcasted warpDomains, got %+v", fr1Cfg.Server.WarpRouting)
	}

	start := time.Now()
	recWarm := doReq(http.MethodGet, "/api/server/warp/routing?node=all", "")
	if recWarm.Code != http.StatusOK || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("expected warm SWR GET ?node=all <50ms, got code=%d elapsed=%v", recWarm.Code, time.Since(start))
	}
}
