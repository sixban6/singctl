// 文件职责：覆盖 Fleet 集群 WARP 广播协调器、远端 warp-ctl Base64 脚本防注入、灾备密钥路径重写与 SSH 自举脚本模板测试。
package fleet_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/fleet"
	"singctl/internal/subhub"
)

func TestFleetBackupKeysAndRemoteWarpCtlScript_SecurityBoundaries(t *testing.T) {
	for _, bad := range []string{"", ".", "..", "../../etc/passwd", "a/b.key", `a\b.key`} {
		if _, err := fleet.SanitizeKeyFilename(bad); err == nil {
			t.Errorf("expected SanitizeKeyFilename(%q) to reject traversal/invalid name", bad)
		}
	}
	if got, err := fleet.SanitizeKeyFilename(" jp1.pem "); err != nil || got != "jp1.pem" {
		t.Fatalf("expected jp1.pem, got %q err=%v", got, err)
	}

	rawYAML := "nodes:\n  - id: jp1\n    key_path: /old/dir/fleet_keys/jp1.key\n"
	rewritten := fleet.RewriteRestoredKeyPaths(rawYAML, "/new/dir/fleet_keys", map[string][]byte{"jp1.key": []byte("k")})
	if !strings.Contains(rewritten, "/new/dir/fleet_keys/jp1.key") {
		t.Fatalf("expected key_path rewritten to /new/dir/fleet_keys/jp1.key, got:\n%s", rewritten)
	}

	// Subcommand injection must be rejected!
	for _, badSub := range []string{"", "status; rm -rf /", "$(id)", "unknown"} {
		if _, err := fleet.BuildRemoteWarpCtlScript(badSub, nil); err == nil {
			t.Errorf("expected BuildRemoteWarpCtlScript(%q) to reject invalid subcommand", badSub)
		}
	}
	script, err := fleet.BuildRemoteWarpCtlScript("status", deploy.WarpCLIStatusArgs{Refresh: true})
	if err != nil || !strings.Contains(script, "sr warp-ctl status") {
		t.Fatalf("unexpected remote warp-ctl script: %q err=%v", script, err)
	}
}

func TestWarpClusterCoordinator_BroadcastAndSkipUnreadyNode(t *testing.T) {
	tmpDir := t.TempDir()
	st := fleet.NewStore(filepath.Join(tmpDir, "fleet.yaml"))
	sub := subhub.NewStore(filepath.Join(tmpDir, "sub"), "")
	mgr := fleet.NewManager(st, sub)

	for _, n := range []fleet.UpsertInput{
		{ID: "sg1", Name: "新加坡", Host: "192.0.2.11", AuthType: fleet.AuthSSHAlias, SSHAlias: "sg1", Enabled: new(true)},
		{ID: "fr1", Name: "法国未装WARP", Host: "192.0.2.12", AuthType: fleet.AuthSSHAlias, SSHAlias: "fr1", Enabled: new(true)},
	} {
		if _, err := st.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}

	mgr.Runner = func(_ context.Context, node fleet.Node, script string) (string, int, error) {
		var b64Payload []byte
		if idx := strings.Index(script, "WARPCTL_B64='"); idx >= 0 {
			rest := script[idx+len("WARPCTL_B64='"):]
			if end := strings.IndexByte(rest, '\''); end >= 0 {
				b64Payload, _ = base64.StdEncoding.DecodeString(rest[:end])
			}
		}
		_ = b64Payload
		if node.ID == "fr1" && strings.Contains(script, "warp-ctl apply") {
			return "", 10, deploy.ErrWarpTunnelUnavailable
		}
		if strings.Contains(script, "warp-ctl status") {
			b, _ := json.Marshal(deploy.WarpRoutingStatusResponse{
				Daemon:  deploy.WarpDaemonStatus{Installed: node.ID == "sg1", Running: node.ID == "sg1", TunnelHealthy: node.ID == "sg1", SocksPort: 40000, WarpIP: "198.51.100.81"},
				Routing: config.WarpRoutingConfig{Mode: config.WarpModeSplit},
			})
			return "WARN banner\n" + string(b), 12, nil
		}
		b, _ := json.Marshal(deploy.WarpCLIApplyResult{
			Message:            "ok",
			EvictedConnections: 2,
			Status: deploy.WarpRoutingStatusResponse{
				Daemon:  deploy.WarpDaemonStatus{Installed: true, Running: true, TunnelHealthy: true, SocksPort: 40000},
				Routing: config.WarpRoutingConfig{Mode: config.WarpModeSplit},
			},
		})
		return string(b), 15, nil
	}

	coord := fleet.NewWarpClusterCoordinator(mgr)
	ctx := t.Context()

	evicted, items, msg, conflict, err := coord.BroadcastRouting(ctx, config.WarpRoutingConfig{Mode: config.WarpModeSplit}, func(context.Context) (int, error) {
		return 1, nil
	})
	if err != nil || conflict || evicted != 3 || len(items) != 3 {
		t.Fatalf("unexpected BroadcastRouting result: evicted=%d len=%d conflict=%v err=%v msg=%q", evicted, len(items), conflict, err, msg)
	}
	if !items[0].Success || !items[1].Success || !items[2].Skipped {
		t.Fatalf("expected local=ok, sg1=ok, fr1=skipped, got %+v", items)
	}

	allStatus, err := coord.BuildClusterStatus(ctx, deploy.WarpRoutingStatusResponse{
		Daemon:  deploy.WarpDaemonStatus{Installed: true, Running: true, TunnelHealthy: true, SocksPort: 40000},
		Routing: config.WarpRoutingConfig{Mode: config.WarpModeSplit},
	}, "all", true)
	if err != nil || len(allStatus.Nodes) != 3 {
		t.Fatalf("unexpected BuildClusterStatus(all): len=%d err=%v", len(allStatus.Nodes), err)
	}
}

func TestBootstrapScriptTemplates_RenderMultiLineDirectivesAndEnvPrefix(t *testing.T) {
	s1 := fleet.RenderSSHStage1Script("a2V5\n", 2222, "Port 22\nPort 2222")
	if !strings.Contains(s1, "Port 22\nPort 2222") || strings.Contains(s1, `Port 22\nPort 2222`) {
		t.Fatalf("expected literal multi-line Port 22\\nPort 2222 in stage1 script, got:\n%s", s1)
	}

	fin := fleet.RenderSSHFinalizeScript("Port 22\nPort 15500", 15500, 15500)
	if !strings.Contains(fin, "Port 22\nPort 15500\nPermitRootLogin prohibit-password") {
		t.Fatalf("expected literal DNAT Port 22\\nPort 15500 in finalize script, got:\n%s", fin)
	}

	rb := fleet.RenderSSHRollbackScript("Port 22\nPort 15500")
	if !strings.Contains(rb, "Port 22\nPort 15500") {
		t.Fatalf("expected literal rollback port directives, got:\n%s", rb)
	}

	inst := fleet.RenderBootstrapInstallScript("https://github.com/example/singctl", "c2VydmVyOg==", 15500, 11501, 11502)
	if !strings.Contains(inst, "printf '%s' 'c2VydmVyOg==' | base64 -d > /etc/singctl/singctl.yaml") {
		t.Fatalf("expected inline base64 decode line for singctl.yaml, got:\n%s", inst)
	}
	if !strings.Contains(inst, "SSH_PORT=15500 HY2_PORT=11501 VLESS_PORT=11502 singctl sr install") {
		t.Fatalf("expected exact env prefix before singctl sr install, got:\n%s", inst)
	}
}
