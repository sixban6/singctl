// 文件职责：全覆盖验证声明式 healStep 自愈流水线（CheckOnly、APT/DNF/OpenWrt、证书/WARP、回滚摘要与并发互斥）。
package heal_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/heal"
	"singctl/internal/platform/servicemgr"
)

func TestRunWithDeps_DeclarativePipelineTableDriven(t *testing.T) {
	ctx := t.Context()

	t.Run("check_only_returns_scan_snapshot_without_mutations", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		scanCalls := 0
		res, err := heal.RunWithDeps(ctx, heal.RunOptions{
			ConfigPath:        cfgPath,
			CurrentSingctlVer: "1.14.0",
			CheckOnly:         true,
			Trigger:           "timer",
		}, heal.Deps{
			Scan: func(_ context.Context, gotPath, gotVer string) heal.StatusReport {
				scanCalls++
				if gotPath != cfgPath || gotVer != "1.14.0" {
					t.Errorf("unexpected scan args: %q, %q", gotPath, gotVer)
				}
				return heal.StatusReport{
					CheckedAt:    "2026-11-22T04:00:00Z",
					Posture:      heal.PostureRebootRequired,
					PostureLabel: "补丁已装·待重启生效",
					Kernel:       heal.KernelLayerStatus{RebootRequired: true},
				}
			},
		})
		if err != nil {
			t.Fatalf("CheckOnly failed: %v", err)
		}
		if scanCalls != 1 || !res.Execution.Success || !res.Execution.RebootRequired || res.Execution.Trigger != "timer" {
			t.Fatalf("unexpected CheckOnly result: %+v", res)
		}
	})

	t.Run("full_linux_apt_pipeline_with_stale_so_and_async_web_restart", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		binPath := filepath.Join(dir, "sing-box")
		_ = os.WriteFile(binPath, []byte("sb-v1"), 0755)

		mockMgr := servicemgr.NewMock()
		_ = mockMgr.Start(ctx, "sing-box")
		var webAsync bool
		var rebootCalled bool
		scanPass := 0

		coreHealer := heal.NewCoreHealer(heal.CoreHealerDeps{
			ServiceMgr:     mockMgr,
			LocateBinaryFn: func([]string, string) string { return binPath },
			UpgradeCompFn: func(id string, _ *config.Config) (bool, string, error) {
				return true, "1.14.10", os.WriteFile(binPath, []byte("sb-v2"), 0755)
			},
			ProbeOverride: map[string]heal.BinaryHealthProbe{
				"singbox": func(context.Context, *heal.CoreHealer, string, bool) error { return nil },
			},
		})

		res, err := heal.RunWithDeps(ctx, heal.RunOptions{
			ConfigPath:        cfgPath,
			CurrentSingctlVer: "1.14.9",
			AllowReboot:       true,
			AsyncWebRestart:   true,
			Trigger:           "manual",
		}, heal.Deps{
			GOOS:       "linux",
			IsOpenWrt:  func() bool { return false },
			ServiceMgr: mockMgr,
			CoreHealer: coreHealer,
			LoadConfig: func(string) (*config.Config, error) { return &config.Config{}, nil },
			Scan: func(_ context.Context, _, _ string) heal.StatusReport {
				scanPass++
				if scanPass == 1 {
					return heal.StatusReport{
						Core: heal.CoreLayerStatus{
							Components: []heal.ComponentCheck{
								{Name: "singbox", CurrentVersion: "1.14.9", LatestVersion: "1.14.10", Installed: true, HasUpdate: true},
								{Name: "caddy", CurrentVersion: "2.9.0", LatestVersion: "2.9.0", Installed: true, HasUpdate: false},
							},
						},
					}
				}
				return heal.StatusReport{
					Core: heal.CoreLayerStatus{Healthy: true},
					OS: heal.OSLayerStatus{
						SecurityCount: 0,
						StaleServices: []string{"singctl-ui"},
						Healthy:       false,
					},
					Kernel: heal.KernelLayerStatus{
						InstalledKernel: "6.1.0-27-amd64",
						RebootRequired:  true,
						Healthy:         false,
					},
				}
			},
			SyncHysteria2Cert: func(*config.Config) (bool, string, error) {
				return true, "Hysteria2 证书路径已同步", nil
			},
			SyncWarpConfig: func() (bool, string, error) {
				return true, "WARP IPv4 Endpoint 已修复", nil
			},
			HasBinary: func(name string) bool { return name == "apt-get" },
			RunCmd: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
				if name == "apt-get" && slices.Contains(args, "-s") {
					return []byte("Inst libssl3 [3.0.11] (3.0.13 Debian-Security:12/stable-security [amd64])\n"), nil
				}
				return []byte("ok"), nil
			},
			ScanStaleServices: func() []string { return []string{"sshd", "caddy", "singctl-ui", "cron"} },
			VerifySSHD:        func() bool { return true },
			RestartWebDaemon:  func(async bool) { webAsync = async },
			TriggerReboot:     func() { rebootCalled = true },
		})
		if err != nil {
			t.Fatalf("RunWithDeps failed: %v", err)
		}
		if !res.Execution.Success || !rebootCalled || !webAsync {
			t.Fatalf("expected all steps ok + reboot + async web restart, got res=%+v reboot=%v webAsync=%v", res.Execution, rebootCalled, webAsync)
		}
		if len(res.Status.OS.StaleServices) != 0 || !res.Status.OS.Healthy {
			t.Fatalf("expected singctl-ui cleared from post-scan StaleServices under AsyncWebRestart, got %+v", res.Status.OS)
		}
		if !strings.Contains(res.Execution.Summary, "平滑重启") {
			t.Fatalf("expected reboot summary, got %q", res.Execution.Summary)
		}
		var targets []string
		for _, a := range res.Execution.Actions {
			targets = append(targets, a.Target)
		}
		for _, want := range []string{"singbox", "hysteria2-cert", "warp-tunnel", "apt-security", "stale-libs", "kernel-reboot"} {
			if !slices.Contains(targets, want) {
				t.Fatalf("expected action target %q in %v", want, targets)
			}
		}
	})

	t.Run("dnf_error_and_openwrt_guard_and_rollback_summary", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")

		// 1. OpenWrt flash guard
		owRes, err := heal.RunWithDeps(ctx, heal.RunOptions{ConfigPath: cfgPath}, heal.Deps{
			GOOS:              "linux",
			IsOpenWrt:         func() bool { return true },
			Scan:              func(context.Context, string, string) heal.StatusReport { return heal.StatusReport{Core: heal.CoreLayerStatus{Healthy: true}, OS: heal.OSLayerStatus{Healthy: true}, Kernel: heal.KernelLayerStatus{Healthy: true}} },
			SyncHysteria2Cert: func(*config.Config) (bool, string, error) { return false, "", nil },
			SyncWarpConfig:    func() (bool, string, error) { return false, "", nil },
		})
		if err != nil || !owRes.Execution.Success || len(owRes.Execution.Actions) != 1 || owRes.Execution.Actions[0].Target != "openwrt-guard" {
			t.Fatalf("expected openwrt-guard action, got %+v (err=%v)", owRes.Execution, err)
		}

		// 2. DNF failure + Hysteria2 error + Canary rollback summary
		binPath := filepath.Join(dir, "caddy")
		_ = os.WriteFile(binPath, []byte("caddy-v1"), 0755)
		rollbackHealer := heal.NewCoreHealer(heal.CoreHealerDeps{
			ServiceMgr:     servicemgr.NewMock(),
			LocateBinaryFn: func([]string, string) string { return binPath },
			UpgradeCompFn:  func(string, *config.Config) (bool, string, error) { return false, "", errors.New("bad binary") },
		})
		rbRes, err := heal.RunWithDeps(ctx, heal.RunOptions{ConfigPath: cfgPath}, heal.Deps{
			GOOS:       "linux",
			IsOpenWrt:  func() bool { return false },
			CoreHealer: rollbackHealer,
			Scan: func(context.Context, string, string) heal.StatusReport {
				return heal.StatusReport{
					Core: heal.CoreLayerStatus{
						Components: []heal.ComponentCheck{{Name: "caddy", CurrentVersion: "2.8.0", LatestVersion: "2.9.0", Installed: true, HasUpdate: true}},
					},
				}
			},
			SyncHysteria2Cert: func(*config.Config) (bool, string, error) { return false, "", errors.New("cert read failed") },
			SyncWarpConfig:    func() (bool, string, error) { return false, "", errors.New("warp timeout") },
			HasBinary:         func(name string) bool { return name == "dnf" },
			RunCmd: func(_ context.Context, _ []string, name string, args ...string) ([]byte, error) {
				if name == "dnf" && slices.Contains(args, "check-update") {
					return []byte("openssl.x86_64 1:3.0.7 baseos\n"), nil
				}
				return []byte("mirror 502"), errors.New("exit 1")
			},
			ScanStaleServices: func() []string { return nil },
		})
		if err != nil {
			t.Fatalf("unexpected RunWithDeps err: %v", err)
		}
		if rbRes.Execution.Success || !strings.Contains(rbRes.Execution.Summary, "自动回滚") {
			t.Fatalf("expected rollback failure summary, got %+v", rbRes.Execution)
		}
	})

	t.Run("concurrent_heal_run_rejected_cleanly", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once

		slowDeps := heal.Deps{
			GOOS: "darwin",
			Scan: func(context.Context, string, string) heal.StatusReport {
				once.Do(func() { close(entered) })
				<-release
				return heal.StatusReport{}
			},
			SyncHysteria2Cert: func(*config.Config) (bool, string, error) { return false, "", nil },
			SyncWarpConfig:    func() (bool, string, error) { return false, "", nil },
		}

		done := make(chan error, 1)
		go func() {
			_, runErr := heal.RunWithDeps(ctx, heal.RunOptions{ConfigPath: cfgPath}, slowDeps)
			done <- runErr
		}()
		select {
		case <-entered:
		case earlyErr := <-done:
			t.Fatalf("first heal run exited before Scan: %v", earlyErr)
		}

		_, secondErr := heal.RunWithDeps(ctx, heal.RunOptions{ConfigPath: cfgPath}, heal.Deps{})
		if secondErr == nil || !strings.Contains(secondErr.Error(), "正在运行") {
			close(release)
			t.Fatalf("expected concurrent heal run rejection, got %v", secondErr)
		}
		close(release)
		if firstErr := <-done; firstErr != nil {
			t.Fatalf("expected first heal run to finish cleanly, got %v", firstErr)
		}
	})
}
