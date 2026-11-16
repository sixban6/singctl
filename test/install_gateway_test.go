package test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"singctl/configs"
	"singctl/internal/config"
)

func TestInstallScript_GatewayModeSelectionAndValidation(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	installSh := filepath.Join(repoRoot, "install.sh")

	runInstallGatewayFunc := func(t *testing.T, ttyInput string, extraArgs ...string) (*config.Config, string) {
		t.Helper()
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
			t.Fatalf("write base config: %v", err)
		}

		ttyFile := filepath.Join(dir, "mock_tty")
		if err := os.WriteFile(ttyFile, []byte(ttyInput), 0600); err != nil {
			t.Fatalf("write mock tty: %v", err)
		}

		// 以纯单元测试方式加载 install.sh 函数库（通过 SINGCTL_INSTALL_LIB_ONLY=1 跳过自动执行 main），
		// 注入模拟的本机 IP (192.168.100.2) 与探测默认网关 (192.168.100.1) 验证完整交互状态机。
		harness := filepath.Join(dir, "run.sh")
		script := `#!/bin/sh
set -e
export SINGCTL_INSTALL_LIB_ONLY=1
. "` + installSh + `"
CONFIG_FILE="` + cfgPath + `"
SINGCTL_TTY_PATH="` + ttyFile + `"
detect_lan_ip_and_iface() {
    DETECTED_LAN_IP="192.168.100.2"
    DETECTED_LAN_IFACE="eth0"
    DETECTED_MAIN_GW="192.168.100.1"
}
probe_gateway_reachable() {
    return 0
}
configure_gateway_mode "$@"
`
		if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
			t.Fatalf("write harness: %v", err)
		}

		cmd := exec.CommandContext(t.Context(), "sh", append([]string{harness}, extraArgs...)...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run configure_gateway_mode failed: %v\nOutput:\n%s", err, string(out))
		}

		st, err := os.Stat(cfgPath)
		if err != nil {
			t.Fatalf("stat config: %v", err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected config file mode 0600, got %04o", st.Mode().Perm())
		}

		loaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("Load config failed: %v\nRaw:\n%s", err, string(out))
		}
		return loaded, string(out)
	}

	t.Run("default_enter_keeps_main_router_mode", func(t *testing.T) {
		cfg, _ := runInstallGatewayFunc(t, "\n")
		if cfg.Gateway.EffectiveMode() != "main" {
			t.Fatalf("expected default mode=main, got %q", cfg.Gateway.EffectiveMode())
		}
	})

	t.Run("select_side_router_and_press_enter_accepts_detected_gateway", func(t *testing.T) {
		cfg, out := runInstallGatewayFunc(t, "2\n\n")
		if cfg.Gateway.EffectiveMode() != "side" {
			t.Fatalf("expected mode=side, got %q (out=%s)", cfg.Gateway.EffectiveMode(), out)
		}
		if cfg.Gateway.MainRouterIP != "192.168.100.1" {
			t.Fatalf("expected confirmed MainRouterIP=192.168.100.1, got %q", cfg.Gateway.MainRouterIP)
		}
	})

	t.Run("select_side_router_rejects_self_ip_then_accepts_modified_ip", func(t *testing.T) {
		// 先故意输入旁路由本机 IP 192.168.100.2 触发防自环拦截，再输入真实主路由 192.168.100.254
		cfg, out := runInstallGatewayFunc(t, "2\n192.168.100.2\n192.168.100.254\n")
		if !strings.Contains(out, "不能等于") && !strings.Contains(out, "死循环") {
			t.Fatalf("expected self-loop warning in output, got:\n%s", out)
		}
		if cfg.Gateway.EffectiveMode() != "side" || cfg.Gateway.MainRouterIP != "192.168.100.254" {
			t.Fatalf("expected mode=side & MainRouterIP=192.168.100.254, got %+v", cfg.Gateway)
		}
	})

	t.Run("cli_flags_non_interactive_side_router", func(t *testing.T) {
		cfg, _ := runInstallGatewayFunc(t, "", "--side-router", "--main-router-ip", "192.168.100.1")
		if cfg.Gateway.EffectiveMode() != "side" || cfg.Gateway.MainRouterIP != "192.168.100.1" {
			t.Fatalf("expected CLI flags to set side mode & 192.168.100.1, got %+v", cfg.Gateway)
		}
	})
}

func TestInstallScript_PurgeExistingSingbox(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	installSh := filepath.Join(repoRoot, "install.sh")

	setupMockEnv := func(t *testing.T, osName string) (dir, binDir, rootfs, logFile string) {
		t.Helper()
		dir = t.TempDir()
		binDir = filepath.Join(dir, "bin")
		rootfs = filepath.Join(dir, "rootfs")
		logFile = filepath.Join(dir, "calls.log")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatalf("mkdir bin: %v", err)
		}
		if err := os.MkdirAll(filepath.Join(rootfs, "etc", "sing-box"), 0755); err != nil {
			t.Fatalf("mkdir etc/sing-box: %v", err)
		}

		if err := os.WriteFile(filepath.Join(binDir, "sing-box"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatalf("write mock sing-box: %v", err)
		}
		for _, tool := range []string{"nft", "ip", "iptables", "killall", "systemctl"} {
			body := "#!/bin/sh\nprintf '%s %s\\n' \"" + tool + "\" \"$*\" >> \"" + logFile + "\"\nexit 0\n"
			if err := os.WriteFile(filepath.Join(binDir, tool), []byte(body), 0755); err != nil {
				t.Fatalf("write mock %s: %v", tool, err)
			}
		}

		harness := filepath.Join(dir, "purge_test.sh")
		script := `#!/bin/sh
set -e
export PATH="` + binDir + `:/bin:/usr/bin"
export SINGCTL_INSTALL_LIB_ONLY=1
export SINGCTL_ROOT_PREFIX="` + rootfs + `"
. "` + installSh + `"
OS="` + osName + `"
IS_FIRST_INSTALL="true"
purge_existing_singbox
`
		if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
			t.Fatalf("write harness: %v", err)
		}
		out, err := exec.CommandContext(t.Context(), "sh", harness).CombinedOutput()
		if err != nil {
			t.Fatalf("run purge_existing_singbox (%s) failed: %v\nOutput:\n%s", osName, err, string(out))
		}
		return dir, binDir, rootfs, logFile
	}

	t.Run("darwin_never_purges_existing_singbox", func(t *testing.T) {
		_, binDir, _, logFile := setupMockEnv(t, "darwin")
		if _, err := os.Stat(filepath.Join(binDir, "sing-box")); err != nil {
			t.Fatalf("expected mock sing-box on darwin to remain untouched, got stat err: %v", err)
		}
		if _, err := os.Stat(logFile); !os.IsNotExist(err) {
			t.Fatalf("expected zero firewall/process calls on darwin, got log file")
		}
	})

	t.Run("linux_first_install_purges_binary_and_cleans_orphan_tproxy", func(t *testing.T) {
		_, binDir, _, logFile := setupMockEnv(t, "linux")
		if _, err := os.Stat(filepath.Join(binDir, "sing-box")); !os.IsNotExist(err) {
			t.Fatalf("expected mock sing-box on linux to be removed, got err: %v", err)
		}
		rawLog, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatalf("read calls.log: %v", err)
		}
		logText := string(rawLog)
		for _, want := range []string{
			"nft delete table inet sing-box",
			"ip rule del fwmark 1 table 100",
			"ip route flush table 100",
		} {
			if !strings.Contains(logText, want) {
				t.Fatalf("expected calls.log to contain %q, got:\n%s", want, logText)
			}
		}
	})
}
