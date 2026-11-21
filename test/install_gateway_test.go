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
			"ip rule del fwmark 2 table 101",
			"ip route flush table 100",
			"ip route flush table 101",
		} {
			if !strings.Contains(logText, want) {
				t.Fatalf("expected calls.log to contain %q, got:\n%s", want, logText)
			}
		}
	})
}

func TestInstallScript_AutoRoleAndSmartTopologyDetection(t *testing.T) {
	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	installSh := filepath.Join(repoRoot, "install.sh")

	t.Run("detect_runtime_role_across_client_and_server_environments", func(t *testing.T) {
		type roleCase struct {
			name        string
			osName      string
			isOpenWrt   string
			mockIPs     string
			display     string
			setupRootfs func(t *testing.T, rootfs, cfgPath string)
			wantRole    string
		}

		cases := []roleCase{
			{
				name:   "openwrt_release_detected_as_client",
				osName: "linux",
				setupRootfs: func(t *testing.T, rootfs, _ string) {
					if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(rootfs, "etc", "openwrt_release"), []byte("DISTRIB_ID='OpenWrt'\n"), 0644); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "client",
			},
			{
				name:     "darwin_detected_as_client",
				osName:   "darwin",
				wantRole: "client",
			},
			{
				name:   "armbian_sbc_detected_as_client",
				osName: "linux",
				setupRootfs: func(t *testing.T, rootfs, _ string) {
					if err := os.MkdirAll(filepath.Join(rootfs, "etc"), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(rootfs, "etc", "armbian-release"), []byte("BOARD=orangepi\n"), 0644); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "client",
			},
			{
				name:     "linux_desktop_detected_as_client",
				osName:   "linux",
				display:  ":0",
				wantRole: "client",
			},
			{
				name:    "lan_private_home_gateway_qemu_detected_as_client",
				osName:  "linux",
				mockIPs: "192.168.100.2",
				setupRootfs: func(t *testing.T, rootfs, _ string) {
					dmiDir := filepath.Join(rootfs, "sys", "class", "dmi", "id")
					if err := os.MkdirAll(dmiDir, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dmiDir, "sys_vendor"), []byte("QEMU\n"), 0644); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "client",
			},
			{
				name:     "direct_public_ipv4_vps_detected_as_server",
				osName:   "linux",
				mockIPs:  "203.0.113.10",
				wantRole: "server",
			},
			{
				name:    "vpc_aws_cloud_vps_detected_as_server",
				osName:  "linux",
				mockIPs: "172.31.10.5",
				setupRootfs: func(t *testing.T, rootfs, _ string) {
					dmiDir := filepath.Join(rootfs, "sys", "class", "dmi", "id")
					if err := os.MkdirAll(dmiDir, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dmiDir, "sys_vendor"), []byte("Amazon EC2\n"), 0644); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "server",
			},
			{
				name:    "vpc_oracle_cloud_vps_detected_as_server",
				osName:  "linux",
				mockIPs: "10.0.0.15",
				setupRootfs: func(t *testing.T, rootfs, _ string) {
					dmiDir := filepath.Join(rootfs, "sys", "class", "dmi", "id")
					if err := os.MkdirAll(dmiDir, 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dmiDir, "sys_vendor"), []byte("OracleCloud.com\n"), 0644); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "server",
			},
			{
				name:    "openvz_vps_detected_as_server",
				osName:  "linux",
				mockIPs: "172.16.5.2",
				setupRootfs: func(t *testing.T, rootfs, _ string) {
					if err := os.MkdirAll(filepath.Join(rootfs, "proc", "vz"), 0755); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "server",
			},
			{
				name:    "pre_existing_server_config_overrides_private_ip",
				osName:  "linux",
				mockIPs: "192.168.100.2",
				setupRootfs: func(t *testing.T, _ string, cfgPath string) {
					seed := "server:\n  node_domain: \"us1.example.com\"\n  cf_dns_key: \"cf-test-token\"\n"
					if err := os.WriteFile(cfgPath, []byte(seed), 0600); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "server",
			},
			{
				name:    "pre_existing_client_config_overrides_public_ip",
				osName:  "linux",
				mockIPs: "203.0.113.10",
				setupRootfs: func(t *testing.T, _ string, cfgPath string) {
					seed := "subs:\n  - name: \"main\"\n    url: \"https://sub.example.com/1\"\n"
					if err := os.WriteFile(cfgPath, []byte(seed), 0600); err != nil {
						t.Fatal(err)
					}
				},
				wantRole: "client",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				dir := t.TempDir()
				rootfs := filepath.Join(dir, "rootfs")
				cfgPath := filepath.Join(dir, "singctl.yaml")
				if err := os.MkdirAll(rootfs, 0755); err != nil {
					t.Fatal(err)
				}
				if tc.setupRootfs != nil {
					tc.setupRootfs(t, rootfs, cfgPath)
				}
				isOW := tc.isOpenWrt
				if isOW == "" {
					isOW = "false"
				}

				harness := filepath.Join(dir, "role_test.sh")
				script := `#!/bin/sh
set -e
unset DISPLAY WAYLAND_DISPLAY
` + func() string {
					if tc.display != "" {
						return `export DISPLAY="` + tc.display + `"` + "\n"
					}
					return ""
				}() + `export SINGCTL_INSTALL_LIB_ONLY=1
export SINGCTL_ROOT_PREFIX="` + rootfs + `"
export SINGCTL_MOCK_IPV4_LIST="` + tc.mockIPs + `"
. "` + installSh + `"
OS="` + tc.osName + `"
IS_OPENWRT="` + isOW + `"
CONFIG_FILE="` + cfgPath + `"
PRE_EXISTING_ROLE=$(detect_existing_installed_role)
detect_runtime_role
printf "ROLE=%s REASON=%s\n" "$DETECTED_ROLE" "$DETECTED_ROLE_REASON"
`
				if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
				out, err := exec.CommandContext(t.Context(), "sh", harness).CombinedOutput()
				if err != nil {
					t.Fatalf("role detection failed: %v\nOutput:\n%s", err, string(out))
				}
				wantPrefix := "ROLE=" + tc.wantRole + " "
				if !strings.Contains(string(out), wantPrefix) {
					t.Fatalf("expected %q, got output:\n%s", wantPrefix, string(out))
				}
			})
		}
	})

	t.Run("resolve_install_mode_enter_only_escape_hatch_and_flags", func(t *testing.T) {
		runResolve := func(t *testing.T, mockIPs, ttyInput string, args ...string) string {
			t.Helper()
			dir := t.TempDir()
			rootfs := filepath.Join(dir, "rootfs")
			_ = os.MkdirAll(rootfs, 0755)
			ttyFile := filepath.Join(dir, "mock_tty")
			if err := os.WriteFile(ttyFile, []byte(ttyInput), 0600); err != nil {
				t.Fatal(err)
			}
			harness := filepath.Join(dir, "resolve_test.sh")
			script := `#!/bin/sh
set -e
unset DISPLAY WAYLAND_DISPLAY
export SINGCTL_INSTALL_LIB_ONLY=1
export SINGCTL_ROOT_PREFIX="` + rootfs + `"
export SINGCTL_MOCK_IPV4_LIST="` + mockIPs + `"
. "` + installSh + `"
OS="linux"
IS_OPENWRT="false"
CONFIG_FILE="` + filepath.Join(dir, "singctl.yaml") + `"
PRE_EXISTING_ROLE=""
SINGCTL_TTY_PATH="` + ttyFile + `"
resolve_install_mode "$@"
printf "SELECTED=%s YES=%s\n" "$SELECTED_INSTALL_MODE" "$AUTO_YES"
`
			if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			out, err := exec.CommandContext(t.Context(), "sh", append([]string{harness}, args...)...).CombinedOutput()
			if err != nil {
				t.Fatalf("resolve_install_mode failed: %v\nOutput:\n%s", err, string(out))
			}
			return string(out)
		}

		// Enter keeps auto-detected role
		if out := runResolve(t, "192.168.100.2", "\n"); !strings.Contains(out, "SELECTED=client ") {
			t.Fatalf("expected Enter on LAN IP to keep client, got:\n%s", out)
		}
		if out := runResolve(t, "203.0.113.10", "\n"); !strings.Contains(out, "SELECTED=server ") {
			t.Fatalf("expected Enter on public IP to keep server, got:\n%s", out)
		}
		// Single-key escape switches role cleanly
		if out := runResolve(t, "192.168.100.2", "s\n"); !strings.Contains(out, "SELECTED=server ") {
			t.Fatalf("expected 's' on client to switch to server, got:\n%s", out)
		}
		if out := runResolve(t, "203.0.113.10", "c\n"); !strings.Contains(out, "SELECTED=client ") {
			t.Fatalf("expected 'c' on server to switch to client, got:\n%s", out)
		}
		// Explicit flags & -y bypass TTY
		if out := runResolve(t, "192.168.100.2", "", "--server"); !strings.Contains(out, "SELECTED=server ") {
			t.Fatalf("expected --server flag override, got:\n%s", out)
		}
		if out := runResolve(t, "203.0.113.10", "", "--client"); !strings.Contains(out, "SELECTED=client ") {
			t.Fatalf("expected --client flag override, got:\n%s", out)
		}
		if out := runResolve(t, "203.0.113.10", "", "-y"); !strings.Contains(out, "SELECTED=server YES=true") {
			t.Fatalf("expected -y to accept server with AUTO_YES=true, got:\n%s", out)
		}
	})

	t.Run("smart_gateway_side_router_enter_only_and_yes_flag", func(t *testing.T) {
		runGW := func(t *testing.T, ttyInput string, args ...string) *config.Config {
			t.Helper()
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "singctl.yaml")
			if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
				t.Fatal(err)
			}
			ttyFile := filepath.Join(dir, "mock_tty")
			if err := os.WriteFile(ttyFile, []byte(ttyInput), 0600); err != nil {
				t.Fatal(err)
			}
			harness := filepath.Join(dir, "gw_auto_test.sh")
			script := `#!/bin/sh
set -e
export SINGCTL_INSTALL_LIB_ONLY=1
export SINGCTL_MOCK_GW_TOPOLOGY="side"
. "` + installSh + `"
OS="linux"
CONFIG_FILE="` + cfgPath + `"
SINGCTL_TTY_PATH="` + ttyFile + `"
detect_lan_ip_and_iface() {
    DETECTED_LAN_IP="192.168.100.2"
    DETECTED_LAN_IFACE="eth0"
    DETECTED_MAIN_GW="192.168.100.1"
}
probe_gateway_reachable() { return 0; }
configure_gateway_mode "$@"
`
			if err := os.WriteFile(harness, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			out, err := exec.CommandContext(t.Context(), "sh", append([]string{harness}, args...)...).CombinedOutput()
			if err != nil {
				t.Fatalf("configure_gateway_mode failed: %v\nOutput:\n%s", err, string(out))
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			return cfg
		}

		// Recommended side-router: user only presses Enter twice!
		cfgTTY := runGW(t, "\n\n")
		if cfgTTY.Gateway.EffectiveMode() != "side" || cfgTTY.Gateway.MainRouterIP != "192.168.100.1" {
			t.Fatalf("expected Enter-only recommended side mode with 192.168.100.1, got %+v", cfgTTY.Gateway)
		}

		// Non-interactive -y auto-applies recommended side mode & detected main gateway
		cfgYes := runGW(t, "", "-y")
		if cfgYes.Gateway.EffectiveMode() != "side" || cfgYes.Gateway.MainRouterIP != "192.168.100.1" {
			t.Fatalf("expected -y recommended side mode with 192.168.100.1, got %+v", cfgYes.Gateway)
		}
	})
}
