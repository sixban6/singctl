// 文件职责：覆盖 Tailscale 内核 TUN 驱动探测、纯用户态降级识别及一键安装 kmod-tun 切换内核模式的完整边界测试。
package tailscale_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/tailscale"
)

func TestInspectTunDiagnostics_Matrix(t *testing.T) {
	t.Run("kernel_tun_active_healthy", func(t *testing.T) {
		diag := tailscale.InspectTunDiagnostics(t.Context(), true, tailscale.TunProbeDeps{
			StatPath:     func(p string) bool { return p == "/dev/net/tun" },
			HasInterface: func(name string) bool { return name == "tailscale0" },
			ReadFile: func(p string) ([]byte, error) {
				return []byte("procd_append_param command --port=41641\n"), nil
			},
		})
		if !diag.TunAvailable || diag.UserspaceMode || !diag.TunInterfaceUp || diag.Reason != "" {
			t.Fatalf("unexpected healthy diag: %+v", diag)
		}
	})

	t.Run("tun_ready_but_script_stuck_in_userspace", func(t *testing.T) {
		diag := tailscale.InspectTunDiagnostics(t.Context(), true, tailscale.TunProbeDeps{
			StatPath:     func(p string) bool { return p == "/sys/class/misc/tun" },
			HasInterface: func(string) bool { return false },
			ReadFile: func(p string) ([]byte, error) {
				return []byte("procd_append_param command --tun=userspace-networking\n"), nil
			},
			Runner: func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
				return nil, errors.New("modprobe unavailable")
			},
		})
		if !diag.TunAvailable || !diag.UserspaceMode || diag.TunInterfaceUp || !diag.CanSwitchToKernel {
			t.Fatalf("expected TunAvailable=true UserspaceMode=true CanSwitchToKernel=true, got %+v", diag)
		}
		if diag.Reason == "" {
			t.Fatal("expected non-empty diagnostic reason")
		}
	})

	t.Run("missing_kmod_tun_and_no_dev_tun", func(t *testing.T) {
		diag := tailscale.InspectTunDiagnostics(t.Context(), true, tailscale.TunProbeDeps{
			StatPath:     func(string) bool { return false },
			HasInterface: func(string) bool { return false },
			ReadFile: func(string) ([]byte, error) {
				return []byte("procd_append_param command --tun=userspace-networking\n"), nil
			},
			Runner: func(_ context.Context, _ string, _ string, _ ...string) ([]byte, error) {
				return []byte("modprobe: not found"), errors.New("exit 1")
			},
		})
		if diag.TunAvailable || !diag.UserspaceMode || diag.TunInterfaceUp {
			t.Fatalf("expected TunAvailable=false UserspaceMode=true, got %+v", diag)
		}
		if !strings.Contains(diag.Reason, "kmod-tun") {
			t.Fatalf("expected reason to mention kmod-tun, got %q", diag.Reason)
		}
	})
}

func TestRepairTunMode_OpenWrtOpkgApkAndCustomFirmwareFallback(t *testing.T) {
	t.Run("opkg_installs_kmod_tun_and_switches_to_kernel_mode", func(t *testing.T) {
		dir := t.TempDir()
		initPath := filepath.Join(dir, "tailscale")
		if err := os.WriteFile(initPath, []byte("--tun=userspace-networking\n"), 0755); err != nil {
			t.Fatal(err)
		}

		kmodInstalled := false
		restarted := false
		fwConfigured := false
		shieldApplied := false
		var cmds []string

		diag, err := tailscale.RepairTunMode(t.Context(), tailscale.TunProbeDeps{
			InitScriptPath: initPath,
			IsOpenWrt:      func() bool { return true },
			TotalRAMBytes:  func() uint64 { return 512 * 1024 * 1024 },
			StatPath: func(p string) bool {
				return kmodInstalled && p == "/dev/net/tun"
			},
			HasInterface: func(name string) bool {
				return restarted && name == "tailscale0"
			},
			LookPath: func(bin string) (string, error) {
				if bin == "opkg" {
					return "/bin/opkg", nil
				}
				return "", errors.New("not found")
			},
			Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
				line := name + " " + strings.Join(args, " ")
				cmds = append(cmds, line)
				switch {
				case name == "modprobe" && !kmodInstalled:
					return []byte("failed to find module tun"), errors.New("exit 1")
				case name == "opkg" && len(args) >= 2 && args[0] == "install" && args[1] == "kmod-tun":
					kmodInstalled = true
					return []byte("Installing kmod-tun"), nil
				case name == initPath && len(args) == 1 && args[0] == "restart":
					restarted = true
					return []byte("restarted"), nil
				default:
					return []byte("ok"), nil
				}
			},
			ConfigureFW:      func() { fwConfigured = true },
			ApplyLanShieldFn: func(context.Context) error { shieldApplied = true; return nil },
			WaitPollAttempts: 2,
		})
		if err != nil {
			t.Fatalf("RepairTunMode(opkg) failed: %v (cmds=%v)", err, cmds)
		}
		if !diag.TunAvailable || diag.UserspaceMode || !diag.TunInterfaceUp {
			t.Fatalf("expected healthy kernel tun diag after repair, got %+v", diag)
		}
		if !fwConfigured || !shieldApplied || !restarted {
			t.Fatalf("expected fwConfigured=%v shieldApplied=%v restarted=%v", fwConfigured, shieldApplied, restarted)
		}
		rawScript, err := os.ReadFile(initPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(rawScript), "--tun=userspace-networking") {
			t.Fatalf("repaired init script must not contain --tun=userspace-networking:\n%s", string(rawScript))
		}
	})

	t.Run("apk_installs_kmod_tun_on_openwrt25", func(t *testing.T) {
		dir := t.TempDir()
		initPath := filepath.Join(dir, "tailscale")
		_ = os.WriteFile(initPath, []byte("--tun=userspace-networking\n"), 0755)

		installed := false
		restarted := false
		var cmds []string

		diag, err := tailscale.RepairTunMode(t.Context(), tailscale.TunProbeDeps{
			InitScriptPath: initPath,
			IsOpenWrt:      func() bool { return true },
			TotalRAMBytes:  func() uint64 { return 1024 * 1024 * 1024 },
			StatPath:       func(p string) bool { return installed && p == "/dev/net/tun" },
			HasInterface:   func(name string) bool { return restarted && name == "tailscale0" },
			LookPath: func(bin string) (string, error) {
				if bin == "apk" {
					return "/usr/bin/apk", nil
				}
				return "", errors.New("not found")
			},
			Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
				cmds = append(cmds, name+" "+strings.Join(args, " "))
				if name == "modprobe" && !installed {
					return nil, errors.New("no tun")
				}
				if name == "apk" && len(args) >= 2 && args[0] == "add" && args[1] == "kmod-tun" {
					installed = true
				}
				if name == initPath && len(args) == 1 && args[0] == "restart" {
					restarted = true
				}
				return []byte("ok"), nil
			},
			ConfigureFW:      func() {},
			ApplyLanShieldFn: func(context.Context) error { return nil },
			WaitPollAttempts: 2,
		})
		if err != nil {
			t.Fatalf("RepairTunMode(apk) failed: %v (cmds=%v)", err, cmds)
		}
		if !diag.TunInterfaceUp || diag.UserspaceMode {
			t.Fatalf("unexpected diag after apk repair: %+v", diag)
		}
	})

	t.Run("custom_firmware_missing_kmod_tun_aborts_safely_without_disrupting_service", func(t *testing.T) {
		dir := t.TempDir()
		initPath := filepath.Join(dir, "tailscale")
		origScript := "#!/bin/sh\n--tun=userspace-networking\n"
		if err := os.WriteFile(initPath, []byte(origScript), 0755); err != nil {
			t.Fatal(err)
		}

		restarted := false
		_, err := tailscale.RepairTunMode(t.Context(), tailscale.TunProbeDeps{
			InitScriptPath: initPath,
			IsOpenWrt:      func() bool { return true },
			StatPath:       func(string) bool { return false },
			HasInterface:   func(string) bool { return false },
			LookPath: func(bin string) (string, error) {
				if bin == "opkg" {
					return "/bin/opkg", nil
				}
				return "", errors.New("not found")
			},
			Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
				if name == initPath {
					restarted = true
				}
				if name == "opkg" && len(args) >= 2 && args[0] == "info" && args[1] == "kernel" {
					return []byte("Package: kernel\nVersion: 5.4.284-1-testvermagic\n"), nil
				}
				if name == "opkg" && len(args) >= 1 && args[0] == "install" {
					return []byte("Unknown package 'kmod-tun'."), errors.New("exit 255")
				}
				if name == "opkg" && len(args) >= 1 && args[0] == "update" {
					return []byte("Updated"), nil
				}
				return []byte("no tun"), errors.New("exit 1")
			},
		})
		if err == nil {
			t.Fatal("expected error when kmod-tun is absent from custom firmware feeds")
		}
		if !strings.Contains(err.Error(), "5.4.284-1-testvermagic") {
			t.Fatalf("expected actionable error with kernel vermagic, got: %v", err)
		}
		if restarted {
			t.Fatal("must NOT restart tailscaled when kmod-tun installation failed")
		}
		after, _ := os.ReadFile(initPath)
		if string(after) != origScript {
			t.Fatal("must NOT overwrite init script when kmod-tun installation failed")
		}
	})
}
