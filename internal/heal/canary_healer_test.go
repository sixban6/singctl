package heal

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
)

func TestCoreHealer_CanaryUpgradeAndRollback(t *testing.T) {
	ctx := t.Context()

	t.Run("success_upgrades_and_cleans_backup", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "sing-box")
		if err := os.WriteFile(binPath, []byte("old-singbox-v1"), 0755); err != nil {
			t.Fatal(err)
		}
		mockMgr := servicemgr.NewMock()
		_ = mockMgr.Start(ctx, "sing-box")

		h := &coreHealer{
			svcMgr:         mockMgr,
			locateBinaryFn: func([]string, string) string { return binPath },
			upgradeCompFn: func(id string, _ *config.Config) (bool, string, error) {
				if id != "singbox" {
					return false, "", errors.New("unexpected id")
				}
				// Verify backup exists during upgrade execution
				if _, err := os.Stat(binPath + ".heal.bak"); err != nil {
					return false, "", errors.New("expected backup file during upgrade")
				}
				return true, "1.14.9", os.WriteFile(binPath, []byte("new-singbox-v2"), 0755)
			},
			probeOverride: map[string]binaryHealthProbe{
				"singbox": func(context.Context, *coreHealer, string, bool) error { return nil },
			},
		}

		act := h.healComponent(ctx, &config.Config{}, "", ComponentCheck{
			Name:           "singbox",
			CurrentVersion: "1.14.8",
			LatestVersion:  "1.14.9",
			Installed:      true,
			HasUpdate:      true,
		}, false)
		if !act.Success || !act.Updated || act.RolledBack {
			t.Fatalf("expected successful upgrade without rollback, got %+v", act)
		}
		got, _ := os.ReadFile(binPath)
		if string(got) != "new-singbox-v2" {
			t.Fatalf("expected new binary content, got %q", string(got))
		}
		if _, err := os.Stat(binPath + ".heal.bak"); !os.IsNotExist(err) {
			t.Fatalf("expected backup to be cleaned up, stat err=%v", err)
		}
	})

	t.Run("upgrade_error_restores_binary_and_restarts_active_service", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			compName string
			unit     string
		}{
			{name: "singbox", compName: "singbox", unit: "sing-box"},
			{name: "caddy", compName: "caddy", unit: "caddy"},
			{name: "warp", compName: "warp", unit: "wireproxy"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				binPath := filepath.Join(dir, tc.unit)
				if err := os.WriteFile(binPath, []byte("stable-v1"), 0755); err != nil {
					t.Fatal(err)
				}
				mockMgr := servicemgr.NewMock()
				_ = mockMgr.Start(ctx, tc.unit)

				h := &coreHealer{
					svcMgr:         mockMgr,
					locateBinaryFn: func([]string, string) string { return binPath },
					upgradeCompFn: func(string, *config.Config) (bool, string, error) {
						_ = os.WriteFile(binPath, []byte("broken-partial"), 0755)
						return false, "", errors.New("checksum mismatch")
					},
				}

				act := h.healComponent(ctx, &config.Config{}, "", ComponentCheck{
					Name:           tc.compName,
					CurrentVersion: "1.0.0",
					LatestVersion:  "1.0.1",
				}, false)
				if act.Success || !act.RolledBack {
					t.Fatalf("expected RolledBack=true and Success=false, got %+v", act)
				}
				got, _ := os.ReadFile(binPath)
				if string(got) != "stable-v1" {
					t.Fatalf("expected restored binary stable-v1, got %q", string(got))
				}
				if !slices.Contains(mockMgr.Calls(), "restart "+tc.unit) {
					t.Fatalf("expected restart %s in mock calls %v", tc.unit, mockMgr.Calls())
				}
			})
		}
	})

	t.Run("probe_failure_restores_binary_and_restarts_service", func(t *testing.T) {
		dir := t.TempDir()
		binPath := filepath.Join(dir, "caddy")
		if err := os.WriteFile(binPath, []byte("caddy-v1"), 0755); err != nil {
			t.Fatal(err)
		}
		mockMgr := servicemgr.NewMock()
		_ = mockMgr.Start(ctx, "caddy")

		h := &coreHealer{
			svcMgr:         mockMgr,
			locateBinaryFn: func([]string, string) string { return binPath },
			upgradeCompFn: func(string, *config.Config) (bool, string, error) {
				return true, "2.9.0", os.WriteFile(binPath, []byte("caddy-v2-bad-cfg"), 0755)
			},
			probeOverride: map[string]binaryHealthProbe{
				"caddy": func(context.Context, *coreHealer, string, bool) error {
					return errors.New("Caddyfile validate failed")
				},
			},
		}

		act := h.healComponent(ctx, &config.Config{}, "", ComponentCheck{
			Name:           "caddy",
			CurrentVersion: "2.8.0",
			LatestVersion:  "2.9.0",
		}, false)
		if act.Success || !act.RolledBack {
			t.Fatalf("expected rollback on probe failure, got %+v", act)
		}
		got, _ := os.ReadFile(binPath)
		if string(got) != "caddy-v1" {
			t.Fatalf("expected binary restored to caddy-v1, got %q", string(got))
		}
		if !slices.Contains(mockMgr.Calls(), "restart caddy") {
			t.Fatalf("expected restart caddy call, got %v", mockMgr.Calls())
		}
	})

	t.Run("missing_binary_upgrade_failure_without_backup_does_not_panic", func(t *testing.T) {
		mockMgr := servicemgr.NewMock()
		h := &coreHealer{
			svcMgr:         mockMgr,
			locateBinaryFn: func([]string, string) string { return "" },
			upgradeCompFn: func(string, *config.Config) (bool, string, error) {
				return false, "", errors.New("network timeout")
			},
		}
		act := h.healComponent(ctx, &config.Config{}, "", ComponentCheck{
			Name:           "singbox",
			CurrentVersion: "1.14.0",
		}, false)
		if act.Success || act.RolledBack {
			t.Fatalf("expected Success=false RolledBack=false without backup, got %+v", act)
		}
	})

	t.Run("singctl_self_upgrade_success_and_rollback", func(t *testing.T) {
		dir := t.TempDir()
		exePath := filepath.Join(dir, "singctl")
		if err := os.WriteFile(exePath, []byte("singctl-v1"), 0755); err != nil {
			t.Fatal(err)
		}
		mockMgr := servicemgr.NewMock()
		_ = mockMgr.Start(ctx, "singctl-sub")

		var webRestarted, gotAsync bool
		h := &coreHealer{
			svcMgr:           mockMgr,
			resolveSelfExeFn: func() (string, error) { return exePath, nil },
			selfUpgradeFn: func(_, _, _ string) error {
				return os.WriteFile(exePath, []byte("singctl-v2"), 0755)
			},
			restartWebFn: func(async bool) {
				webRestarted = true
				gotAsync = async
			},
		}
		act := h.healComponent(ctx, &config.Config{}, filepath.Join(dir, "singctl.yaml"), ComponentCheck{
			Name:           "singctl",
			CurrentVersion: "1.14.157",
			LatestVersion:  "1.14.158",
		}, true)
		if !act.Success || !act.Updated || !webRestarted || !gotAsync {
			t.Fatalf("expected singctl upgrade + subhub + web restart, got act=%+v web=%v async=%v", act, webRestarted, gotAsync)
		}
		if !slices.Contains(mockMgr.Calls(), "restart singctl-sub") {
			t.Fatalf("expected restart singctl-sub, got %v", mockMgr.Calls())
		}

		// Failure case restores old binary
		h.selfUpgradeFn = func(_, _, _ string) error {
			_ = os.WriteFile(exePath, []byte("corrupt"), 0755)
			return errors.New("sha256 mismatch")
		}
		failAct := h.healComponent(ctx, &config.Config{}, "", ComponentCheck{
			Name:           "singctl",
			CurrentVersion: "1.14.158",
		}, false)
		if failAct.Success {
			t.Fatalf("expected singctl failure, got %+v", failAct)
		}
		restored, _ := os.ReadFile(exePath)
		if string(restored) != "singctl-v2" {
			t.Fatalf("expected singctl-v2 restored, got %q", string(restored))
		}
	})

	t.Run("unknown_component_idempotent_and_race_safe", func(t *testing.T) {
		h := &coreHealer{svcMgr: servicemgr.NewMock()}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				act := h.healComponent(ctx, nil, "", ComponentCheck{Name: "unknown-svc"}, false)
				if !act.Success || act.Updated || act.Message != "无需变更" {
					t.Errorf("unexpected unknown component result: %+v", act)
				}
			}()
		}
		wg.Wait()
	})
}
