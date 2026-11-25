// 文件职责：验证路由器开机自启动与掉电恢复（singctl-autostart 单元模板防注入、状态探测、Procd/Systemd/Mock 对账及 boot-init 自愈幂等编排）。
package daemon_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/platform/servicemgr"
)

type stubCmdRunner struct {
	calls []string
}

func (s *stubCmdRunner) Run(_ context.Context, _ time.Duration, name string, args ...string) error {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	return nil
}

func (s *stubCmdRunner) CombinedOutput(_ context.Context, _ time.Duration, name string, args ...string) ([]byte, error) {
	s.calls = append(s.calls, name+" "+strings.Join(args, " "))
	return nil, nil
}

func TestBuildAutoStartUnitSpec(t *testing.T) {
	spec, err := daemon.BuildAutoStartUnitSpec("/usr/bin/singctl", "/etc/singctl/singctl.yaml")
	if err != nil {
		t.Fatalf("BuildAutoStartUnitSpec valid inputs failed: %v", err)
	}
	if spec.Name != daemon.AutoStartServiceName {
		t.Fatalf("Name = %q, want %q", spec.Name, daemon.AutoStartServiceName)
	}
	if !strings.Contains(spec.ProcdBody, "#!/bin/sh /etc/rc.common") ||
		!strings.Contains(spec.ProcdBody, "START=99") ||
		!strings.Contains(spec.ProcdBody, "USE_PROCD=1") ||
		!strings.Contains(spec.ProcdBody, `"/usr/bin/singctl" --config "/etc/singctl/singctl.yaml" dm boot-init`) {
		t.Fatalf("unexpected ProcdBody:\n%s", spec.ProcdBody)
	}
	if !strings.Contains(spec.SystemdBody, "[Unit]") ||
		!strings.Contains(spec.SystemdBody, "After=network-online.target") ||
		!strings.Contains(spec.SystemdBody, `ExecStart="/usr/bin/singctl" --config "/etc/singctl/singctl.yaml" dm boot-init --worker`) {
		t.Fatalf("unexpected SystemdBody:\n%s", spec.SystemdBody)
	}

	invalidCases := []struct {
		name string
		exe  string
		cfg  string
	}{
		{"empty_exe", "", "/etc/singctl/singctl.yaml"},
		{"empty_cfg", "/usr/bin/singctl", ""},
		{"relative_exe", "singctl", "/etc/singctl/singctl.yaml"},
		{"relative_cfg", "/usr/bin/singctl", "singctl.yaml"},
		{"newline_exe", "/usr/bin/singctl\nrm -rf /", "/etc/singctl/singctl.yaml"},
		{"semicolon_cfg", "/usr/bin/singctl", "/etc/singctl/singctl.yaml;id"},
		{"backtick_exe", "/usr/bin/`id`", "/etc/singctl/singctl.yaml"},
		{"dollar_cfg", "/usr/bin/singctl", "/etc/singctl/$(id).yaml"},
		{"quote_cfg", "/usr/bin/singctl", `/etc/singctl/"evil".yaml`},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := daemon.BuildAutoStartUnitSpec(tc.exe, tc.cfg); err == nil {
				t.Fatalf("expected injection/invalid error for exe=%q cfg=%q", tc.exe, tc.cfg)
			}
		})
	}
}

func TestInspectAndReconcileAutoStart(t *testing.T) {
	ctx := t.Context()

	t.Run("mock_enable_and_disable_idempotent", func(t *testing.T) {
		mock := servicemgr.NewMock()
		cfg := &config.Config{}
		deps := daemon.AutoStartDeps{
			GOOS:           "linux",
			ConfigPath:     filepath.Join(t.TempDir(), "singctl.yaml"),
			ExecutablePath: "/usr/bin/singctl",
			ServiceMgr:     mock,
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 256 * 1024 * 1024, AvailableBytes: 128 * 1024 * 1024}, nil
			},
		}

		st0 := daemon.InspectAutoStartStatus(ctx, cfg, deps)
		if !st0.Supported || !st0.ConfigEnabled || st0.ServiceEnabled || st0.Enabled {
			t.Fatalf("unexpected initial status: %+v", st0)
		}
		if st0.Mode != "unified_low_memory" || !st0.LowMemory {
			t.Fatalf("expected unified_low_memory mode on 256MiB device, got %+v", st0)
		}

		stOn, err := daemon.ReconcileAutoStart(ctx, cfg, true, deps)
		if err != nil {
			t.Fatalf("ReconcileAutoStart(true) failed: %v", err)
		}
		if !stOn.Enabled || !stOn.ConfigEnabled || !stOn.ServiceEnabled || !stOn.ServiceInstalled {
			t.Fatalf("expected all enabled flags true after enable, got %+v", stOn)
		}
		if stOn.ServiceName != daemon.AutoStartServiceName {
			t.Fatalf("ServiceName = %q, want %q", stOn.ServiceName, daemon.AutoStartServiceName)
		}

		// Repeat enable stays idempotent
		stOn2, err := daemon.ReconcileAutoStart(ctx, cfg, true, deps)
		if err != nil || !stOn2.Enabled {
			t.Fatalf("repeat ReconcileAutoStart(true) failed: st=%+v err=%v", stOn2, err)
		}

		stOff, err := daemon.ReconcileAutoStart(ctx, cfg, false, deps)
		if err != nil {
			t.Fatalf("ReconcileAutoStart(false) failed: %v", err)
		}
		if stOff.Enabled || stOff.ConfigEnabled || stOff.ServiceEnabled || stOff.ServiceInstalled {
			t.Fatalf("expected all flags false after disable, got %+v", stOff)
		}
		if cfg.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected cfg.Watchdog.IsAutoStartEnabled() == false after disable")
		}
	})

	t.Run("isolated_procd_tempdir_install_and_remove", func(t *testing.T) {
		root := t.TempDir()
		initDir := filepath.Join(root, "init.d")
		rcdDir := filepath.Join(root, "rc.d")
		rcCommon := filepath.Join(root, "rc.common")
		if err := os.MkdirAll(initDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(rcdDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rcCommon, []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}

		runner := &stubCmdRunner{}
		procdMgr := servicemgr.NewProcd(runner, initDir)
		cfg := &config.Config{}
		deps := daemon.AutoStartDeps{
			GOOS:           "linux",
			ConfigPath:     filepath.Join(root, "singctl.yaml"),
			ExecutablePath: "/usr/bin/singctl",
			ProcdInitDir:   initDir,
			RcCommonPath:   rcCommon,
			ServiceMgr:     procdMgr,
			ReadMemInfo: func() (sysinfo.MemInfo, error) {
				return sysinfo.MemInfo{TotalBytes: 2 * 1024 * 1024 * 1024, AvailableBytes: 1536 * 1024 * 1024}, nil
			},
		}

		stOn, err := daemon.ReconcileAutoStart(ctx, cfg, true, deps)
		if err != nil {
			t.Fatalf("procd ReconcileAutoStart(true) failed: %v", err)
		}
		initScript := filepath.Join(initDir, daemon.AutoStartServiceName)
		if _, err := os.Stat(initScript); err != nil {
			t.Fatalf("expected procd script created at %s: %v", initScript, err)
		}
		if stOn.InitSystem != "procd" || stOn.Mode != "standard" || !stOn.ServiceInstalled {
			t.Fatalf("unexpected procd status after install: %+v", stOn)
		}
		// Simulate procd enable creating S99 symlink
		if err := os.Symlink(initScript, filepath.Join(rcdDir, "S99"+daemon.AutoStartServiceName)); err != nil {
			t.Fatal(err)
		}
		stChecked := daemon.InspectAutoStartStatus(ctx, cfg, deps)
		if !stChecked.Enabled || !stChecked.ServiceEnabled {
			t.Fatalf("expected InspectAutoStartStatus enabled once S99 exists, got %+v", stChecked)
		}

		stOff, err := daemon.ReconcileAutoStart(ctx, cfg, false, deps)
		if err != nil {
			t.Fatalf("procd ReconcileAutoStart(false) failed: %v", err)
		}
		if stOff.Enabled || stOff.ServiceInstalled || stOff.ServiceEnabled {
			t.Fatalf("expected procd unit disabled/removed, got %+v", stOff)
		}
		if _, err := os.Stat(initScript); !os.IsNotExist(err) {
			t.Fatalf("expected procd init script removed, err=%v", err)
		}
	})
}

func TestRunBootInit(t *testing.T) {
	ctx := t.Context()

	t.Run("disabled_in_config_is_noop", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Watchdog.SetAutoStart(false)
		sbStarts, dmStarts, webStarts := 0, 0, 0
		err := daemon.RunBootInit(ctx, cfg, daemon.BootInitDeps{
			SingBoxConfigExists: func() bool { return true },
			StartSingBox:        func(context.Context) error { sbStarts++; return nil },
			StartDaemon:         func(context.Context) error { dmStarts++; return nil },
			StartWeb:            func(context.Context) error { webStarts++; return nil },
		})
		if err != nil || sbStarts != 0 || dmStarts != 0 || webStarts != 0 {
			t.Fatalf("expected complete noop when disabled, got err=%v sb=%d dm=%d web=%d", err, sbStarts, dmStarts, webStarts)
		}
	})

	t.Run("already_running_is_fast_noop", func(t *testing.T) {
		cfg := &config.Config{}
		netWaits, sbStarts := 0, 0
		err := daemon.RunBootInit(ctx, cfg, daemon.BootInitDeps{
			SingBoxConfigExists:    func() bool { return true },
			IsSingBoxRunning:       func() bool { return true },
			IsDaemonRunning:        func() bool { return true },
			IsStandaloneWebRunning: func() bool { return false },
			IsLowMemory:            func() bool { return true },
			WaitNetworkReady:       func(context.Context) error { netWaits++; return nil },
			StartSingBox:           func(context.Context) error { sbStarts++; return nil },
		})
		if err != nil || netWaits != 0 || sbStarts != 0 {
			t.Fatalf("expected fast noop when already running, got err=%v net=%d sb=%d", err, netWaits, sbStarts)
		}
	})

	t.Run("low_mem_cold_boot_with_singbox_config", func(t *testing.T) {
		cfg := &config.Config{}
		sbRunning, dmRunning := false, false
		sbStarts, dmStarts, webStarts := 0, 0, 0
		err := daemon.RunBootInit(ctx, cfg, daemon.BootInitDeps{
			SingBoxConfigExists: func() bool { return true },
			IsSingBoxRunning:    func() bool { return sbRunning },
			IsDaemonRunning:     func() bool { return dmRunning },
			IsLowMemory:         func() bool { return true },
			WaitNetworkReady:    func(context.Context) error { return nil },
			StartSingBox: func(context.Context) error {
				sbStarts++
				sbRunning = true
				dmRunning = true // singctl sb start also starts unified dm + embedded :8090
				return nil
			},
			StartDaemon: func(context.Context) error { dmStarts++; return nil },
			StartWeb:    func(context.Context) error { webStarts++; return nil },
		})
		if err != nil {
			t.Fatalf("RunBootInit low-mem failed: %v", err)
		}
		if sbStarts != 1 || dmStarts != 0 || webStarts != 0 {
			t.Fatalf("expected only StartSingBox=1 on low-mem unified boot, got sb=%d dm=%d web=%d", sbStarts, dmStarts, webStarts)
		}
	})

	t.Run("standard_mem_cold_boot_starts_sb_and_standalone_web", func(t *testing.T) {
		cfg := &config.Config{}
		sbRunning, dmRunning, webRunning := false, false, false
		sbStarts, webStarts := 0, 0
		err := daemon.RunBootInit(ctx, cfg, daemon.BootInitDeps{
			SingBoxConfigExists:    func() bool { return true },
			IsSingBoxRunning:       func() bool { return sbRunning },
			IsDaemonRunning:        func() bool { return dmRunning },
			IsStandaloneWebRunning: func() bool { return webRunning },
			IsLowMemory:            func() bool { return false },
			WaitNetworkReady:       func(context.Context) error { return nil },
			StartSingBox: func(context.Context) error {
				sbStarts++
				sbRunning = true
				dmRunning = true
				return nil
			},
			StartWeb: func(context.Context) error {
				webStarts++
				webRunning = true
				return nil
			},
		})
		if err != nil {
			t.Fatalf("RunBootInit standard failed: %v", err)
		}
		if sbStarts != 1 || webStarts != 1 {
			t.Fatalf("expected StartSingBox=1 and StartWeb=1 on standard boot, got sb=%d web=%d", sbStarts, webStarts)
		}
	})

	t.Run("no_singbox_config_still_brings_up_webui", func(t *testing.T) {
		dmStarts, webStarts := 0, 0
		if err := daemon.RunBootInit(ctx, &config.Config{}, daemon.BootInitDeps{
			SingBoxConfigExists: func() bool { return false },
			IsSingBoxRunning:    func() bool { return false },
			IsDaemonRunning:     func() bool { return false },
			IsLowMemory:         func() bool { return true },
			WaitNetworkReady:    func(context.Context) error { return nil },
			StartDaemon:         func(context.Context) error { dmStarts++; return nil },
			StartWeb:            func(context.Context) error { webStarts++; return nil },
		}); err != nil || dmStarts != 1 || webStarts != 0 {
			t.Fatalf("low-mem no-config boot: err=%v dm=%d web=%d", err, dmStarts, webStarts)
		}

		dmStarts, webStarts = 0, 0
		if err := daemon.RunBootInit(ctx, &config.Config{}, daemon.BootInitDeps{
			SingBoxConfigExists: func() bool { return false },
			IsSingBoxRunning:    func() bool { return false },
			IsDaemonRunning:     func() bool { return false },
			IsLowMemory:         func() bool { return false },
			WaitNetworkReady:    func(context.Context) error { return nil },
			StartDaemon:         func(context.Context) error { dmStarts++; return nil },
			StartWeb:            func(context.Context) error { webStarts++; return nil },
		}); err != nil || dmStarts != 0 || webStarts != 1 {
			t.Fatalf("standard no-config boot: err=%v dm=%d web=%d", err, dmStarts, webStarts)
		}
	})

	t.Run("retry_and_fallback_to_daemon_or_web_on_sb_failure", func(t *testing.T) {
		sbAttempts, dmStarts := 0, 0
		err := daemon.RunBootInit(ctx, &config.Config{}, daemon.BootInitDeps{
			SingBoxConfigExists: func() bool { return true },
			IsSingBoxRunning:    func() bool { return false },
			IsDaemonRunning:     func() bool { return false },
			IsLowMemory:         func() bool { return true },
			WaitNetworkReady:    func(context.Context) error { return nil },
			RetryAttempts:       2,
			RetryDelay:          time.Millisecond,
			StartSingBox: func(context.Context) error {
				sbAttempts++
				return errors.New("temporary interface not ready")
			},
			StartDaemon: func(context.Context) error {
				dmStarts++
				return nil
			},
		})
		if err == nil {
			t.Fatalf("expected error returned when sing-box failed all retries")
		}
		if sbAttempts != 2 || dmStarts != 1 {
			t.Fatalf("expected 2 sing-box attempts and 1 daemon fallback, got sb=%d dm=%d", sbAttempts, dmStarts)
		}
	})
}
