// 文件职责：覆盖单机 WARP 控制器（ExecuteLocalWarpCLI / ComputeQuickSwitchRouting / WarpProber）与三阶段看门狗表驱动单测。
package deploy_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
)

func TestWarpCtlAndWatchdog_TableDrivenAndThreeStageSelfHeal(t *testing.T) {
	t.Run("compute_quick_switch_routing_boundaries", func(t *testing.T) {
		if _, _, _, _, err := deploy.ComputeQuickSwitchRouting(config.WarpRoutingConfig{Mode: config.WarpModeBypass}, "openai.com", "WARP"); !errors.Is(err, deploy.ErrWarpQuickSwitchInBypass) {
			t.Fatalf("expected ErrWarpQuickSwitchInBypass, got %v", err)
		}
		if _, _, _, _, err := deploy.ComputeQuickSwitchRouting(config.WarpRoutingConfig{}, "", "WARP"); err == nil {
			t.Fatal("expected empty target error")
		}
		if _, _, _, _, err := deploy.ComputeQuickSwitchRouting(config.WarpRoutingConfig{}, "openai.com", "INVALID"); err == nil {
			t.Fatal("expected invalid outbound error")
		}

		nextWR, clean, out, preset, err := deploy.ComputeQuickSwitchRouting(config.WarpRoutingConfig{Mode: config.WarpModeSplit}, "https://missav.ws/en", "WARP")
		if err != nil || clean != "missav.ws" || out != "WARP" || preset == "" || !nextWR.IsPresetEnabled("missav", false) {
			t.Fatalf("unexpected quick-switch preset result: clean=%q out=%q preset=%q err=%v wr=%+v", clean, out, preset, err, nextWR)
		}
	})

	t.Run("execute_local_warp_cli_all_subcommands", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		sbPath := filepath.Join(tmpDir, "config.json")
		tpl, err := deploy.TemplateFiles.ReadFile("templates/server_config.json")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, []byte("server:\n  node_domain: \"node.example.com\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sbPath, tpl, 0600); err != nil {
			t.Fatal(err)
		}

		opts := deploy.LocalWarpCLIOptions{
			ConfigPath:        cfgPath,
			SingBoxConfigPath: sbPath,
			ApplyDeps: &deploy.LiveWarpApplyDeps{
				CheckWarpPort:   func() bool { return true },
				ValidateConfig:  func(string) error { return nil },
				IsServiceActive: func() bool { return false },
				ReloadService:   func(bool) error { return nil },
			},
			DaemonProbe: func(bool) deploy.WarpDaemonStatus {
				return deploy.WarpDaemonStatus{Installed: true, Running: true, TunnelHealthy: true, SocksPort: 40000, WarpIP: "198.51.100.10", WarpLoc: "LAX"}
			},
			RotateWarpFn: func(string) (string, string, error) {
				return "198.51.100.99", "SJC", nil
			},
			EnsureWarpFn: func(*config.Config) error { return nil },
		}

		stRaw, err := deploy.ExecuteLocalWarpCLI(t.Context(), "status", []byte(`{"refresh":true}`), opts)
		if err != nil {
			t.Fatalf("warp-ctl status failed: %v", err)
		}
		var stResp deploy.WarpRoutingStatusResponse
		if err := json.Unmarshal(stRaw, &stResp); err != nil || stResp.Daemon.WarpIP != "198.51.100.10" {
			t.Fatalf("unexpected status JSON: %s (err=%v)", string(stRaw), err)
		}

		qsRaw, err := deploy.ExecuteLocalWarpCLI(t.Context(), "quick-switch", []byte(`{"target":"missav.ws","outbound":"WARP"}`), opts)
		if err != nil {
			t.Fatalf("warp-ctl quick-switch failed: %v", err)
		}
		var qsResp deploy.WarpCLIApplyResult
		if err := json.Unmarshal(qsRaw, &qsResp); err != nil || qsResp.Target != "missav.ws" {
			t.Fatalf("unexpected quick-switch JSON: %s (err=%v)", string(qsRaw), err)
		}

		actRaw, err := deploy.ExecuteLocalWarpCLI(t.Context(), "action", []byte(`{"action":"rekey"}`), opts)
		if err != nil || !strings.Contains(string(actRaw), "198.51.100.99") {
			t.Fatalf("warp-ctl action rekey failed: %s (err=%v)", string(actRaw), err)
		}

		if _, err := deploy.ExecuteLocalWarpCLI(t.Context(), "unknown-cmd", nil, opts); err == nil {
			t.Fatal("expected error for unknown warp-ctl subcommand")
		}
	})

	t.Run("watchdog_three_stage_circuit_breaker_and_recovery", func(t *testing.T) {
		tmpDir := t.TempDir()
		sbPath := filepath.Join(tmpDir, "config.json")
		tpl, _ := deploy.TemplateFiles.ReadFile("templates/server_config.json")
		_ = os.WriteFile(sbPath, tpl, 0600)

		cfg := &config.Config{
			Server: config.ServerConfig{
				NodeDomain: "node.example.com",
				WarpRouting: config.WarpRoutingConfig{
					Mode:    config.WarpModeSplit,
					Presets: map[string]bool{"x": true},
				},
			},
		}

		var actionMu sync.Mutex
		var probeHealthy atomic.Bool
		var switchCalls, rotateCalls, evictCalls atomic.Int32

		wd := deploy.NewWarpWatchdog(deploy.WarpWatchdogRuntime{
			ActionMu:          &actionMu,
			SingBoxConfigPath: sbPath,
			LoadConfig:        func(time.Duration) (*config.Config, error) { return cfg.Clone(), nil },
			LiveDepsForConfig: func(*config.Config) *deploy.LiveWarpApplyDeps {
				return &deploy.LiveWarpApplyDeps{
					CheckWarpPort:   func() bool { return true },
					ValidateConfig:  func(string) error { return nil },
					IsServiceActive: func() bool { return false },
					ReloadService:   func(bool) error { return nil },
				}
			},
			EvictAllWarpConns: func(context.Context) int {
				evictCalls.Add(1)
				return 1
			},
		})
		wd.SetDeps(&deploy.WarpWatchdogDeps{
			HasLegacyFscarmen: func() bool { return false },
			ProbeRealTargets: func(time.Duration) (string, string, error) {
				if probeHealthy.Load() {
					return "198.51.100.55", "LAX", nil
				}
				return "", "", os.ErrDeadlineExceeded
			},
			SwitchEndpoint: func() (string, string, string, error) {
				switchCalls.Add(1)
				return "", "", "", os.ErrDeadlineExceeded
			},
			RotateIdentity: func() (string, string, error) {
				rotateCalls.Add(1)
				return "", "", os.ErrDeadlineExceeded
			},
		})

		ctx := t.Context()
		// Tick 1: debounce
		wd.RunTick(ctx)
		var st1 deploy.WarpDaemonStatus
		wd.DecorateDaemonStatus(&st1)
		if st1.DegradedFallback || switchCalls.Load() != 0 {
			t.Fatalf("tick 1 should debounce, got degraded=%v switch=%d", st1.DegradedFallback, switchCalls.Load())
		}

		// Tick 2: Stage 1 -> Stage 2 -> Stage 3 circuit break
		wd.RunTick(ctx)
		var st2 deploy.WarpDaemonStatus
		wd.DecorateDaemonStatus(&st2)
		if !st2.DegradedFallback || switchCalls.Load() != 1 || rotateCalls.Load() != 1 {
			t.Fatalf("tick 2 should trigger stage 3 fallback, got degraded=%v switch=%d rotate=%d", st2.DegradedFallback, switchCalls.Load(), rotateCalls.Load())
		}

		// Tick 3: probe healthy -> automatic recovery
		probeHealthy.Store(true)
		wd.RunTick(ctx)
		var st3 deploy.WarpDaemonStatus
		wd.DecorateDaemonStatus(&st3)
		if st3.DegradedFallback {
			t.Fatal("expected DegradedFallback cleared on healthy recovery tick")
		}
	})
}
