// 文件职责：针对 8 个内置深度体检算子（硬件资源、远程生命线、防火墙后端、策略路由、硬件卸载冲突、沙盒与配置、DNS 防劫持、双栈连通性）的全场景离线表驱动测试。
package doctor_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/doctor"
)

const mib = 1024 * 1024

func findCheck(t *testing.T, rep doctor.Report, id string) doctor.CheckResult {
	t.Helper()
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q not found in report %+v", id, rep.Checks)
	return doctor.CheckResult{}
}

func runSingleCheck(t *testing.T, id string, env *doctor.Env) doctor.CheckResult {
	t.Helper()
	for _, chk := range doctor.DefaultCheckers() {
		if chk.ID() == id {
			return doctor.NewRunner(chk).Run(t.Context(), env).Checks[0]
		}
	}
	t.Fatalf("builtin checker %q not registered", id)
	return doctor.CheckResult{}
}

func makeProcWithCmdline(t *testing.T, root, pid, comm, cmdline, oomAdj string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0644)
	if cmdline != "" {
		_ = os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0644)
	}
	if oomAdj != "" {
		_ = os.WriteFile(filepath.Join(dir, "oom_score_adj"), []byte(oomAdj), 0644)
	}
}

func TestChecker_HardwareResources(t *testing.T) {
	cases := []struct {
		name       string
		openwrt    bool
		overlay    sysinfo.DiskSpace
		tmp        sysinfo.DiskSpace
		mem        sysinfo.MemInfo
		statfsErr  error
		wantStatus doctor.Status
		wantDetail string
	}{
		{
			name:       "healthy_openwrt_standard_ram",
			openwrt:    true,
			overlay:    sysinfo.DiskSpace{TotalBytes: 256 * mib, AvailBytes: 120 * mib, UsedPercent: 53},
			tmp:        sysinfo.DiskSpace{TotalBytes: 512 * mib, AvailBytes: 400 * mib, UsedPercent: 22},
			mem:        sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 512 * mib},
			wantStatus: doctor.StatusPass,
			wantDetail: "/overlay",
		},
		{
			name:       "overlay_low_avail_warn_under_15MB",
			openwrt:    true,
			overlay:    sysinfo.DiskSpace{TotalBytes: 64 * mib, AvailBytes: 12 * mib, UsedPercent: 81},
			tmp:        sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 100 * mib, UsedPercent: 20},
			mem:        sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 180 * mib},
			wantStatus: doctor.StatusWarn,
			wantDetail: "低内存",
		},
		{
			name:       "overlay_critical_fail_under_8MB",
			openwrt:    true,
			overlay:    sysinfo.DiskSpace{TotalBytes: 32 * mib, AvailBytes: 5 * mib, UsedPercent: 84},
			tmp:        sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 100 * mib, UsedPercent: 20},
			mem:        sysinfo.MemInfo{TotalBytes: 512 * mib, AvailableBytes: 180 * mib},
			wantStatus: doctor.StatusFail,
			wantDetail: "/overlay",
		},
		{
			name:       "root_used_percent_92_fail",
			openwrt:    false,
			overlay:    sysinfo.DiskSpace{TotalBytes: 1000 * mib, AvailBytes: 80 * mib, UsedPercent: 92},
			tmp:        sysinfo.DiskSpace{TotalBytes: 500 * mib, AvailBytes: 400 * mib, UsedPercent: 20},
			mem:        sysinfo.MemInfo{TotalBytes: 2048 * mib, AvailableBytes: 1024 * mib},
			wantStatus: doctor.StatusFail,
			wantDetail: "/",
		},
		{
			name:       "mem_available_under_96MB_warn",
			openwrt:    true,
			overlay:    sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 80 * mib, UsedPercent: 38},
			tmp:        sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 90 * mib, UsedPercent: 30},
			mem:        sysinfo.MemInfo{TotalBytes: 256 * mib, AvailableBytes: 72 * mib},
			wantStatus: doctor.StatusWarn,
			wantDetail: "超低内存",
		},
		{
			name:       "mem_available_under_48MB_fail",
			openwrt:    true,
			overlay:    sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 80 * mib, UsedPercent: 38},
			tmp:        sysinfo.DiskSpace{TotalBytes: 128 * mib, AvailBytes: 90 * mib, UsedPercent: 30},
			mem:        sysinfo.MemInfo{TotalBytes: 256 * mib, AvailableBytes: 32 * mib},
			wantStatus: doctor.StatusFail,
			wantDetail: "MemAvailable",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &doctor.Env{
				Config:    &config.Config{},
				IsOpenWrt: func() bool { return tc.openwrt },
				Statfs: func(p string) (sysinfo.DiskSpace, error) {
					if tc.statfsErr != nil {
						return sysinfo.DiskSpace{}, tc.statfsErr
					}
					if p == "/tmp" {
						return tc.tmp, nil
					}
					return tc.overlay, nil
				},
				ReadMemInfo: func() (sysinfo.MemInfo, error) { return tc.mem, nil },
			}
			res := runSingleCheck(t, "hardware_resources", env)
			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (res=%+v)", res.Status, tc.wantStatus, res)
			}
			if tc.wantDetail != "" && !strings.Contains(res.Detail+res.Summary, tc.wantDetail) {
				t.Fatalf("expected %q in detail/summary, got res=%+v", tc.wantDetail, res)
			}
		})
	}
}

func TestChecker_RemoteLifeline(t *testing.T) {
	t.Run("protected_pass", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "200", "tailscaled", "tailscaled\x00", "-1000\n")
		res := runSingleCheck(t, "remote_lifeline", &doctor.Env{ProcRoot: procRoot})
		if res.Status != doctor.StatusPass || res.FixAction != "" {
			t.Fatalf("expected pass without fixAction, got %+v", res)
		}
	})

	t.Run("unprotected_warn_with_quick_fix", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "201", "tailscaled", "tailscaled\x00", "0\n")
		res := runSingleCheck(t, "remote_lifeline", &doctor.Env{ProcRoot: procRoot})
		if res.Status != doctor.StatusWarn || res.FixAction != "protect-tailscale-oom" || res.FixLabel != "一键加 OOM 免疫" {
			t.Fatalf("expected warn with protect-tailscale-oom fix, got %+v", res)
		}
	})

	t.Run("not_running_unconfigured_skip", func(t *testing.T) {
		res := runSingleCheck(t, "remote_lifeline", &doctor.Env{ProcRoot: t.TempDir(), Config: &config.Config{}})
		if res.Status != doctor.StatusSkip {
			t.Fatalf("expected skip when tailscaled unconfigured & absent, got %+v", res)
		}
	})

	t.Run("not_running_configured_warn", func(t *testing.T) {
		cfg := &config.Config{Tailscale: config.TailscaleConfig{Subnets: "192.168.1.0/24"}}
		res := runSingleCheck(t, "remote_lifeline", &doctor.Env{ProcRoot: t.TempDir(), Config: cfg})
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn when tailscale configured but stopped, got %+v", res)
		}
	})
}

func TestChecker_FirewallBackend(t *testing.T) {
	t.Run("nftables_healthy_with_p2p_and_throttle", func(t *testing.T) {
		env := &doctor.Env{
			LookPath: func(file string) (string, error) {
				if file == "nft" {
					return "/usr/sbin/nft", nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "nft list tables":
					return []byte("table inet fw4\ntable inet sing-box\ntable inet singctl_audit_throttle\n"), nil
				case "nft list table inet sing-box":
					return []byte("table inet sing-box {\n  chain prerouting {}\n  chain output {}\n}\n"), nil
				case "nft list chain inet fw4 singctl_ts_jit_guard":
					return []byte("chain singctl_ts_jit_guard {}\n"), nil
				default:
					return nil, errors.New("unexpected: " + cmd)
				}
			},
		}
		res := runSingleCheck(t, "firewall_backend", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass, got %+v", res)
		}
		if !strings.Contains(res.Detail, "Tailscale-P2P") || !strings.Contains(res.Detail, "Audit-Throttle") {
			t.Fatalf("expected P2P and Audit-Throttle status in Detail, got %+v", res)
		}
	})

	t.Run("iptables_ipset_healthy_dual_stack", func(t *testing.T) {
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly}},
			LookPath: func(file string) (string, error) {
				switch file {
				case "iptables", "ip6tables", "ipset":
					return "/usr/sbin/" + file, nil
				default:
					return "", errors.New("not found")
				}
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "iptables -t mangle -S":
					return []byte("-N SING_BOX\n-N SING_BOX_OUTPUT\n-A PREROUTING -j SING_BOX\n-A OUTPUT -j SING_BOX_OUTPUT\n"), nil
				case "ip6tables -t mangle -S":
					return []byte("-N SING_BOX\n-N SING_BOX_OUTPUT\n-A PREROUTING -j SING_BOX\n-A OUTPUT -j SING_BOX_OUTPUT\n"), nil
				case "iptables -S":
					return []byte("-N SINGCTL_TS_JIT\n-N SINGCTL_AUDIT_THROTTLE\n"), nil
				default:
					return nil, errors.New("not found")
				}
			},
		}
		res := runSingleCheck(t, "firewall_backend", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass for iptables+ipset dual stack, got %+v", res)
		}
	})

	t.Run("iptables_missing_ipv6_chain_when_ipv6_enabled_warns", func(t *testing.T) {
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly}},
			LookPath: func(file string) (string, error) {
				if file == "iptables" || file == "ip6tables" || file == "ipset" {
					return "/usr/sbin/" + file, nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "iptables" && len(args) >= 2 && args[1] == "mangle" {
					return []byte("-N SING_BOX\n-N SING_BOX_OUTPUT\n-A PREROUTING -j SING_BOX\n-A OUTPUT -j SING_BOX_OUTPUT\n"), nil
				}
				return []byte("-P PREROUTING ACCEPT\n"), nil
			},
		}
		res := runSingleCheck(t, "firewall_backend", env)
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn when IPv6 SING_BOX missing under cn_only, got %+v", res)
		}
	})

	t.Run("no_firewall_rules_mounted_fails", func(t *testing.T) {
		env := &doctor.Env{
			LookPath: func(file string) (string, error) {
				if file == "nft" {
					return "/usr/sbin/nft", nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return []byte("table inet fw4\n"), nil
			},
		}
		res := runSingleCheck(t, "firewall_backend", env)
		if res.Status != doctor.StatusFail {
			t.Fatalf("expected fail when inet sing-box missing, got %+v", res)
		}
	})
}

func TestChecker_PolicyRouting(t *testing.T) {
	fullTable100 := strings.Join([]string{
		"local default dev lo scope host",
		"throw 10.0.0.0/8",
		"throw 100.64.0.0/10",
		"throw 127.0.0.0/8",
		"throw 172.16.0.0/12",
		"throw 192.168.0.0/16",
	}, "\n")

	t.Run("healthy_tables_100_and_101", func(t *testing.T) {
		env := &doctor.Env{
			LookPath: func(string) (string, error) { return "/sbin/ip", nil },
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "ip rule show":
					return []byte("0: from all lookup local\n32764: from all fwmark 0x2 lookup 101\n32765: from all fwmark 0x1 lookup 100\n"), nil
				case "ip route show table 100":
					return []byte(fullTable100), nil
				case "ip route show table 101":
					return []byte("local default dev lo scope host\n"), nil
				default:
					return nil, errors.New("unexpected: " + cmd)
				}
			},
		}
		res := runSingleCheck(t, "policy_routing", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass, got %+v", res)
		}
	})

	t.Run("missing_throw_escape_routes_warns", func(t *testing.T) {
		env := &doctor.Env{
			LookPath: func(string) (string, error) { return "/sbin/ip", nil },
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				cmd := name + " " + strings.Join(args, " ")
				switch cmd {
				case "ip rule show":
					return []byte("32764: from all fwmark 0x2 lookup 101\n32765: from all fwmark 0x1 lookup 100\n"), nil
				case "ip route show table 100":
					return []byte("local default dev lo scope host\n"), nil
				case "ip route show table 101":
					return []byte("local default dev lo scope host\n"), nil
				default:
					return nil, errors.New("unexpected")
				}
			},
		}
		res := runSingleCheck(t, "policy_routing", env)
		if res.Status != doctor.StatusWarn || !strings.Contains(res.Detail, "192.168.0.0/16") {
			t.Fatalf("expected warn listing missing throw CIDRs, got %+v", res)
		}
	})

	t.Run("missing_table_100_rule_fails", func(t *testing.T) {
		env := &doctor.Env{
			LookPath: func(string) (string, error) { return "/sbin/ip", nil },
			RunCmd: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return []byte("0: from all lookup local\n32766: from all lookup main\n"), nil
			},
		}
		res := runSingleCheck(t, "policy_routing", env)
		if res.Status != doctor.StatusFail {
			t.Fatalf("expected fail when table 100 rule missing, got %+v", res)
		}
	})
}

func TestChecker_HWOffloadConflict(t *testing.T) {
	t.Run("singbox_running_with_uci_and_mtkhnat_warns", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "500", "sing-box", "sing-box\x00run\x00", "0\n")
		_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("mtkhnat 81920 1 - Live 0x0\nxt_FLOWOFFLOAD 16384 0 - Live 0x0\n"), 0644)

		env := &doctor.Env{
			ProcRoot:  procRoot,
			IsOpenWrt: func() bool { return true },
			LookPath:  func(file string) (string, error) { return "/sbin/" + file, nil },
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "uci" && len(args) == 3 && strings.Contains(args[2], "flow_offloading") {
					return []byte("1\n"), nil
				}
				return nil, errors.New("not found")
			},
		}
		res := runSingleCheck(t, "hw_offload_conflict", env)
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn on active offload conflict, got %+v", res)
		}
		if !strings.Contains(res.Detail, "mtkhnat") || !strings.Contains(res.Detail, "flow_offloading") || res.Advice == "" {
			t.Fatalf("expected mtkhnat, flow_offloading & disable advice, got %+v", res)
		}
		if res.FixAction != "disable-flow-offload" || res.FixLabel == "" {
			t.Fatalf("expected FixAction=disable-flow-offload when UCI offload active, got %+v", res)
		}
	})

	t.Run("uci_only_offload_omits_mtkhnat_advice_and_sets_fix_action", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "501", "sing-box", "/usr/bin/sing-box\x00run\x00", "0\n")
		_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("nf_tables 16384 1 - Live 0x0\n"), 0644)

		env := &doctor.Env{
			ProcRoot:  procRoot,
			IsOpenWrt: func() bool { return true },
			LookPath:  func(file string) (string, error) { return "/sbin/" + file, nil },
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "uci" && len(args) == 3 && strings.Contains(args[2], "flow_offloading") {
					return []byte("1\n"), nil
				}
				return nil, errors.New("not found")
			},
		}
		res := runSingleCheck(t, "hw_offload_conflict", env)
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn on UCI offload, got %+v", res)
		}
		if res.FixAction != "disable-flow-offload" || res.FixLabel != "一键关闭 UCI 流量卸载" {
			t.Fatalf("expected disable-flow-offload fix metadata, got %+v", res)
		}
		if strings.Contains(res.Advice, "mtkhnat") {
			t.Fatalf("x86 UCI-only offload advice must NOT mention mtkhnat: %q", res.Advice)
		}
		if !strings.Contains(res.Advice, "uci set firewall.@defaults[0].flow_offloading='0'") {
			t.Fatalf("UCI-only advice missing uci command: %q", res.Advice)
		}
	})

	t.Run("mtkhnat_only_omits_uci_advice_and_has_no_uci_fix", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "502", "sing-box", "/usr/bin/sing-box\x00run\x00", "0\n")
		_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("mtkhnat 81920 1 - Live 0x0\n"), 0644)

		env := &doctor.Env{
			ProcRoot:  procRoot,
			IsOpenWrt: func() bool { return true },
			LookPath:  func(file string) (string, error) { return "/sbin/" + file, nil },
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "uci" {
					return []byte("0\n"), nil
				}
				return nil, errors.New("not found")
			},
		}
		res := runSingleCheck(t, "hw_offload_conflict", env)
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn on mtkhnat module, got %+v", res)
		}
		if res.FixAction != "" {
			t.Fatalf("mtkhnat-only conflict should not attach UCI fix action, got %+v", res)
		}
		if !strings.Contains(res.Advice, "mtkhnat") || strings.Contains(res.Advice, "uci set") {
			t.Fatalf("mtkhnat-only advice should mention mtkhnat and omit uci set: %q", res.Advice)
		}
	})

	t.Run("singbox_stopped_with_offload_passes", func(t *testing.T) {
		procRoot := t.TempDir()
		_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("mtkhnat 81920 1 - Live 0x0\n"), 0644)
		env := &doctor.Env{
			ProcRoot:  procRoot,
			IsOpenWrt: func() bool { return true },
			LookPath:  func(string) (string, error) { return "", errors.New("no uci") },
		}
		res := runSingleCheck(t, "hw_offload_conflict", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass when sing-box is not running, got %+v", res)
		}
	})

	t.Run("turboacc_mtkhnat_enabled_warns_with_fix_and_disabled_hook_passes", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "510", "sing-box", "/usr/bin/sing-box\x00run\x00", "0\n")
		_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("mtkhnat 102400 1 mt_wifi, Live 0x0\nxt_FLOWOFFLOAD 16384 0 - Live 0x0\n"), 0644)
		_ = os.MkdirAll(filepath.Join(procRoot, "etc/config"), 0755)
		_ = os.WriteFile(filepath.Join(procRoot, "etc/config/turboacc"), []byte("config turboacc 'config'\n\toption fastpath 'mediatek_hnat'\n\toption fastpath_mh_eth_hnat '1'\n"), 0644)
		hookPath := filepath.Join(procRoot, "sys/kernel/debug/hnat/hook_toggle")
		_ = os.MkdirAll(filepath.Dir(hookPath), 0755)
		_ = os.WriteFile(hookPath, []byte("enabled\n"), 0644)

		env := &doctor.Env{
			ProcRoot:  procRoot,
			IsOpenWrt: func() bool { return true },
			LookPath:  func(file string) (string, error) { return "/sbin/" + file, nil },
			RunCmd: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return nil, errors.New("not set")
			},
		}
		resWarn := runSingleCheck(t, "hw_offload_conflict", env)
		if resWarn.Status != doctor.StatusWarn || resWarn.FixAction != "disable-flow-offload" {
			t.Fatalf("expected warn with fixAction=disable-flow-offload when HNAT hook enabled, got %+v", resWarn)
		}

		// Disabling TurboACC + HNAT hook must pass even though mtkhnat stays in /proc/modules.
		_ = os.WriteFile(filepath.Join(procRoot, "etc/config/turboacc"), []byte("config turboacc 'config'\n\toption fastpath 'none'\n\toption fastpath_mh_eth_hnat '0'\n"), 0644)
		_ = os.WriteFile(hookPath, []byte("disabled\n"), 0644)
		resPass := runSingleCheck(t, "hw_offload_conflict", env)
		if resPass.Status != doctor.StatusPass {
			t.Fatalf("expected pass when HNAT hook_toggle=disabled and mtkhnat pinned by wifi, got %+v", resPass)
		}
	})

	t.Run("delegated_main_router_with_active_offload_warns", func(t *testing.T) {
		procRoot := t.TempDir()
		_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("mtkhnat 102400 1 mt_wifi, Live 0x0\n"), 0644)
		_ = os.MkdirAll(filepath.Join(procRoot, "etc/config"), 0755)
		_ = os.WriteFile(filepath.Join(procRoot, "etc/config/turboacc"), []byte("config turboacc 'config'\n\toption fastpath 'mediatek_hnat'\n"), 0644)
		hookPath := filepath.Join(procRoot, "sys/kernel/debug/hnat/hook_toggle")
		_ = os.MkdirAll(filepath.Dir(hookPath), 0755)
		_ = os.WriteFile(hookPath, []byte("enabled\n"), 0644)

		env := &doctor.Env{
			ProcRoot:  procRoot,
			Config:    &config.Config{Gateway: config.GatewayConfig{Mode: "main", SideRouterIP: "192.0.2.88"}},
			IsOpenWrt: func() bool { return true },
			LookPath:  func(file string) (string, error) { return "/sbin/" + file, nil },
			RunCmd: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
				return nil, errors.New("not set")
			},
		}
		res := runSingleCheck(t, "hw_offload_conflict", env)
		if res.Status != doctor.StatusWarn || res.FixAction != "disable-flow-offload" {
			t.Fatalf("expected warn on delegated main router with active HNAT, got %+v", res)
		}
	})
}

func TestChecker_SandboxAndConfig(t *testing.T) {
	t.Run("openwrt_ujail_and_compliant_config_passes", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "600", "ujail", "/sbin/ujail\x00-n\x00sing-box\x00--\x00/usr/bin/sing-box\x00run\x00", "0\n")
		makeProcWithCmdline(t, procRoot, "601", "sing-box", "/usr/bin/sing-box\x00run\x00", "0\n")

		env := &doctor.Env{
			ProcRoot:          procRoot,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			IsOpenWrt:         func() bool { return true },
			ReadFile: func(p string) ([]byte, error) {
				if p == "/etc/sing-box/config.json" {
					return []byte(`{"dns":{"disable_cache":true,"optimistic":false,"servers":[]}}`), nil
				}
				return nil, os.ErrNotExist
			},
			LookPath: func(file string) (string, error) {
				if file == "sing-box" {
					return "/usr/bin/sing-box", nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "sing-box" && len(args) >= 1 && args[0] == "check" {
					return []byte("OK\n"), nil
				}
				return nil, errors.New("unexpected")
			},
		}
		res := runSingleCheck(t, "sandbox_and_config", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass, got %+v", res)
		}
	})

	t.Run("openwrt_ujail_prctl_renamed_comm_singbox_passes", func(t *testing.T) {
		procRoot := t.TempDir()
		// Real OpenWrt `ujail -n sing-box` sets /proc/<pid>/comm to "sing-box" via prctl(PR_SET_NAME).
		makeProcWithCmdline(t, procRoot, "12214", "sing-box", "ujail\x00-n\x00sing-box\x00-w\x00/tmp\x00-r\x00/etc/sing-box\x00--\x00/usr/bin/sing-box\x00run\x00", "0\n")
		makeProcWithCmdline(t, procRoot, "12216", "sing-box", "/usr/bin/sing-box\x00run\x00-c\x00/tmp/sing-box-work/config.json\x00", "0\n")

		env := &doctor.Env{
			ProcRoot:          procRoot,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			IsOpenWrt:         func() bool { return true },
			ReadFile: func(p string) ([]byte, error) {
				if p == "/etc/sing-box/config.json" {
					return []byte(`{"dns":{"disable_cache":true,"optimistic":false,"servers":[]}}`), nil
				}
				return nil, os.ErrNotExist
			},
			LookPath: func(file string) (string, error) {
				if file == "sing-box" {
					return "/usr/bin/sing-box", nil
				}
				return "", errors.New("not found")
			},
			RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name == "sing-box" && len(args) >= 1 && args[0] == "check" {
					return []byte("OK\n"), nil
				}
				return nil, errors.New("unexpected")
			},
		}
		res := runSingleCheck(t, "sandbox_and_config", env)
		if res.Status != doctor.StatusPass || !strings.Contains(res.Detail, "ujail 最小权限沙盒") {
			t.Fatalf("expected pass with ujail sandbox detected even when ujail comm is renamed to sing-box, got %+v", res)
		}
	})

	t.Run("openwrt_ujail_wrapper_only_without_child_reports_not_running", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "12214", "sing-box", "/sbin/ujail\x00-n\x00sing-box\x00-w\x00/tmp\x00", "0\n")

		env := &doctor.Env{
			ProcRoot:          procRoot,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			IsOpenWrt:         func() bool { return true },
			ReadFile: func(p string) ([]byte, error) {
				return []byte(`{"dns":{"disable_cache":true,"optimistic":false,"servers":[]}}`), nil
			},
			LookPath: func(string) (string, error) { return "", errors.New("not found") },
		}
		res := runSingleCheck(t, "sandbox_and_config", env)
		if !strings.Contains(res.Detail, "sing-box 当前未运行") {
			t.Fatalf("expected wrapper-only ujail without child sing-box to report not running, got %+v", res)
		}
	})

	t.Run("optimistic_true_or_no_ujail_warns", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "602", "sing-box", "/usr/bin/sing-box\x00run\x00", "0\n")
		env := &doctor.Env{
			ProcRoot:          procRoot,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			IsOpenWrt:         func() bool { return true },
			ReadFile: func(p string) ([]byte, error) {
				return []byte(`{"dns":{"disable_cache":false,"optimistic":true}}`), nil
			},
			LookPath: func(string) (string, error) { return "", errors.New("no binary") },
		}
		res := runSingleCheck(t, "sandbox_and_config", env)
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn for optimistic=true & no ujail, got %+v", res)
		}
		if !strings.Contains(res.Detail, "optimistic") || !strings.Contains(res.Detail, "ujail") {
			t.Fatalf("expected optimistic and ujail details, got %+v", res)
		}
	})

	t.Run("singbox_check_syntax_error_fails", func(t *testing.T) {
		env := &doctor.Env{
			ProcRoot:          t.TempDir(),
			SingBoxConfigPath: "/etc/sing-box/config.json",
			ReadFile: func(string) ([]byte, error) {
				return []byte(`{"dns":{"disable_cache":true,"optimistic":false}}`), nil
			},
			LookPath: func(string) (string, error) { return "/usr/bin/sing-box", nil },
			RunCmd: func(context.Context, string, ...string) ([]byte, error) {
				return []byte("FATAL: invalid outbound"), errors.New("exit status 1")
			},
		}
		res := runSingleCheck(t, "sandbox_and_config", env)
		if res.Status != doctor.StatusFail {
			t.Fatalf("expected fail when sing-box check fails, got %+v", res)
		}
	})
}

func TestChecker_DNSAntiHijack(t *testing.T) {
	t.Run("healthy_smartdns_and_loopback_dns_local_with_ipv6_off", func(t *testing.T) {
		cfg := &config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Off},
			DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: 5353},
		}
		env := &doctor.Env{
			Config:            cfg,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			SmartDNSConfPath:  "/etc/singctl/smartdns.conf",
			DialTCP:           func(context.Context, string) error { return nil },
			ReadFile: func(p string) ([]byte, error) {
				switch p {
				case "/etc/sing-box/config.json":
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), nil
				case "/etc/singctl/smartdns.conf":
					return []byte("bind 127.0.0.1:5353\nforce-AAAA-SOA yes\n"), nil
				default:
					return nil, os.ErrNotExist
				}
			},
		}
		res := runSingleCheck(t, "dns_anti_hijack", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass, got %+v", res)
		}
	})

	t.Run("default_probe_detects_udp_only_smartdns_listener", func(t *testing.T) {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		defer pc.Close()

		udpAddr := pc.LocalAddr().(*net.UDPAddr)
		go func() {
			buf := make([]byte, 512)
			for {
				n, raddr, rerr := pc.ReadFrom(buf)
				if rerr != nil {
					return
				}
				if n < 12 {
					continue
				}
				resp := make([]byte, 12)
				resp[0], resp[1] = buf[0], buf[1]
				resp[2] = 0x81 // QR=1, RD=1
				resp[3] = 0x80 // RA=1, NOERROR
				_, _ = pc.WriteTo(resp, raddr)
			}
		}()

		cfg := &config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly},
			DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: udpAddr.Port},
		}
		sbJSON := fmt.Sprintf(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":%d}]}}`, udpAddr.Port)
		sdConf := fmt.Sprintf("bind 127.0.0.1:%d\n", udpAddr.Port)
		env := &doctor.Env{
			Config:            cfg,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			SmartDNSConfPath:  "/etc/singctl/smartdns.conf",
			// DialTCP intentionally nil to exercise default production local DNS probe (TCP + UDP fallback).
			ReadFile: func(p string) ([]byte, error) {
				switch p {
				case "/etc/sing-box/config.json":
					return []byte(sbJSON), nil
				case "/etc/singctl/smartdns.conf":
					return []byte(sdConf), nil
				default:
					return nil, os.ErrNotExist
				}
			},
		}
		res := runSingleCheck(t, "dns_anti_hijack", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected UDP-only SmartDNS to pass default doctor probe, got %+v", res)
		}
	})

	t.Run("ipv6_cn_only_with_stale_force_aaaa_soa_warns_with_fix", func(t *testing.T) {
		cfg := &config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly},
			DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: 5353},
		}
		env := &doctor.Env{
			Config:            cfg,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			SmartDNSConfPath:  "/etc/singctl/smartdns.conf",
			DialTCP:           func(context.Context, string) error { return nil },
			ReadFile: func(p string) ([]byte, error) {
				switch p {
				case "/etc/sing-box/config.json":
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), nil
				case "/etc/singctl/smartdns.conf":
					return []byte("bind 127.0.0.1:5353\nforce-AAAA-SOA yes\n"), nil
				default:
					return nil, os.ErrNotExist
				}
			},
		}
		res := runSingleCheck(t, "dns_anti_hijack", env)
		if res.Status != doctor.StatusWarn || res.FixAction != "sync-smartdns-ipv6" {
			t.Fatalf("expected warn with FixAction=sync-smartdns-ipv6, got %+v", res)
		}
	})

	t.Run("unsafe_private_or_loop_udp53_fails_while_public_wan_udp53_passes_when_disabled", func(t *testing.T) {
		for _, unsafeJSON := range []string{
			`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"192.168.1.1","server_port":53}]}}`,
			`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":53}]}}`,
			`{"dns":{"servers":[{"tag":"dns_local","type":"local"}]}}`,
		} {
			env := &doctor.Env{
				Config:            &config.Config{},
				SingBoxConfigPath: "/etc/sing-box/config.json",
				DialTCP:           func(context.Context, string) error { return errors.New("refused") },
				ReadFile: func(p string) ([]byte, error) {
					if p == "/etc/sing-box/config.json" {
						return []byte(unsafeJSON), nil
					}
					return nil, os.ErrNotExist
				},
			}
			res := runSingleCheck(t, "dns_anti_hijack", env)
			if res.Status != doctor.StatusFail || res.FixAction != "sync-dns-local" {
				t.Fatalf("expected fail with FixAction=sync-dns-local for unsafe %s, got %+v", unsafeJSON, res)
			}
		}

		// Public ISP / fallback UDP 53 passes when external local DNS is disabled/stopped
		for _, safeJSON := range []string{
			`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"114.114.114.114","server_port":53}]}}`,
			`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"192.0.2.53","server_port":53}]}}`,
		} {
			env := &doctor.Env{
				Config:            &config.Config{},
				SingBoxConfigPath: "/etc/sing-box/config.json",
				DialTCP:           func(context.Context, string) error { return errors.New("not listening") },
				ReadFile: func(p string) ([]byte, error) {
					if p == "/etc/sing-box/config.json" {
						return []byte(safeJSON), nil
					}
					return nil, os.ErrNotExist
				},
			}
			res := runSingleCheck(t, "dns_anti_hijack", env)
			if res.Status != doctor.StatusPass {
				t.Fatalf("expected pass for safe public UDP 53 fallback %s, got %+v", safeJSON, res)
			}
		}

		// When external local DNS IS listening, public UDP 53 fallback warns to take over local engine
		envTakeover := &doctor.Env{
			Config:            &config.Config{DNS: config.ClientDNSConfig{DNSPort: 5353}},
			SingBoxConfigPath: "/etc/sing-box/config.json",
			DialTCP:           func(context.Context, string) error { return nil },
			ReadFile: func(p string) ([]byte, error) {
				if p == "/etc/sing-box/config.json" {
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"114.114.114.114","server_port":53}]}}`), nil
				}
				return nil, os.ErrNotExist
			},
		}
		resTakeover := runSingleCheck(t, "dns_anti_hijack", envTakeover)
		if resTakeover.Status != doctor.StatusWarn || resTakeover.FixAction != "sync-dns-local" {
			t.Fatalf("expected warn with FixAction=sync-dns-local when local engine ready under fallback UDP 53, got %+v", resTakeover)
		}
	})

	t.Run("fallback_encrypted_doh_without_external_dns_passes", func(t *testing.T) {
		env := &doctor.Env{
			Config:            &config.Config{},
			SingBoxConfigPath: "/etc/sing-box/config.json",
			DialTCP:           func(context.Context, string) error { return errors.New("not listening") },
			ReadFile: func(p string) ([]byte, error) {
				if p == "/etc/sing-box/config.json" {
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"https","server":"223.5.5.5","server_port":443,"path":"/dns-query"}]}}`), nil
				}
				return nil, os.ErrNotExist
			},
		}
		res := runSingleCheck(t, "dns_anti_hijack", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass for encrypted DoH fallback, got %+v", res)
		}
	})

	t.Run("loopback_dns_local_with_dead_port_fails_and_legacy_private_udp53_fails", func(t *testing.T) {
		envDead := &doctor.Env{
			Config:            &config.Config{DNS: config.ClientDNSConfig{DNSPort: 5353}},
			SingBoxConfigPath: "/etc/sing-box/config.json",
			DialTCP:           func(context.Context, string) error { return errors.New("connection refused") },
			ReadFile: func(p string) ([]byte, error) {
				if p == "/etc/sing-box/config.json" {
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), nil
				}
				return nil, os.ErrNotExist
			},
		}
		resDead := runSingleCheck(t, "dns_anti_hijack", envDead)
		if resDead.Status != doctor.StatusFail || resDead.FixAction != "sync-dns-local" {
			t.Fatalf("expected fail with sync-dns-local when loopback DNS port is dead, got %+v", resDead)
		}

		envLegacy := &doctor.Env{
			Config:            &config.Config{},
			SingBoxConfigPath: "/etc/sing-box/config.json",
			DialTCP:           func(context.Context, string) error { return errors.New("refused") },
			ReadFile: func(p string) ([]byte, error) {
				if p == "/etc/sing-box/config.json" {
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","address":"udp://192.168.1.1:53"}]}}`), nil
				}
				return nil, os.ErrNotExist
			},
		}
		resLegacy := runSingleCheck(t, "dns_anti_hijack", envLegacy)
		if resLegacy.Status != doctor.StatusFail || resLegacy.FixAction != "sync-dns-local" {
			t.Fatalf("expected fail for legacy private udp://192.168.1.1:53, got %+v", resLegacy)
		}
	})

	t.Run("ipv6_off_missing_force_aaaa_soa_warns", func(t *testing.T) {
		cfg := &config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Off},
			DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: 5353},
		}
		env := &doctor.Env{
			Config:            cfg,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			SmartDNSConfPath:  "/etc/singctl/smartdns.conf",
			DialTCP:           func(context.Context, string) error { return nil },
			ReadFile: func(p string) ([]byte, error) {
				switch p {
				case "/etc/sing-box/config.json":
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), nil
				case "/etc/singctl/smartdns.conf":
					return []byte("bind 127.0.0.1:5353\n"), nil
				default:
					return nil, os.ErrNotExist
				}
			},
		}
		res := runSingleCheck(t, "dns_anti_hijack", env)
		if res.Status != doctor.StatusWarn || res.FixAction != "sync-smartdns-ipv6" {
			t.Fatalf("expected warn with sync-smartdns-ipv6, got %+v", res)
		}
	})

	t.Run("auto_engine_with_adguardhome_running_skips_stale_smartdns_conf", func(t *testing.T) {
		procRoot := t.TempDir()
		makeProcWithCmdline(t, procRoot, "777", "AdGuardHome", "/usr/bin/AdGuardHome\x00-c\x00/etc/AdGuardHome/AdGuardHome.yaml\x00", "0\n")

		cfg := &config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly},
			DNS:     config.ClientDNSConfig{Engine: "auto", DNSPort: 5353},
		}
		env := &doctor.Env{
			Config:            cfg,
			ProcRoot:          procRoot,
			SingBoxConfigPath: "/etc/sing-box/config.json",
			SmartDNSConfPath:  "/etc/singctl/smartdns.conf",
			DialTCP:           func(context.Context, string) error { return nil },
			ReadFile: func(p string) ([]byte, error) {
				switch p {
				case "/etc/sing-box/config.json":
					return []byte(`{"dns":{"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), nil
				case "/etc/singctl/smartdns.conf":
					// Historical leftover smartdns.conf with conflicting force-AAAA-SOA yes
					return []byte("bind 127.0.0.1:5353\nforce-AAAA-SOA yes\n"), nil
				default:
					return nil, os.ErrNotExist
				}
			},
		}
		res := runSingleCheck(t, "dns_anti_hijack", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass when AdGuardHome is active under auto engine despite stale smartdns.conf, got %+v", res)
		}
		if !strings.Contains(res.Detail, "AdGuardHome") {
			t.Fatalf("expected detail to note active engine AdGuardHome, got %+v", res)
		}
	})
}

func TestChecker_DualStackConnectivity(t *testing.T) {
	t.Run("ipv6_probe_url_constants_target_geosite_cn_and_gstatic", func(t *testing.T) {
		if doctor.ProbeURLDomesticIPv6 != "https://ipv6.baidu.com" {
			t.Fatalf("ProbeURLDomesticIPv6 = %q, want %q", doctor.ProbeURLDomesticIPv6, "https://ipv6.baidu.com")
		}
		if doctor.ProbeURLOverseasIPv6 != "https://www.gstatic.com/generate_204" {
			t.Fatalf("ProbeURLOverseasIPv6 = %q, want %q", doctor.ProbeURLOverseasIPv6, "https://www.gstatic.com/generate_204")
		}
	})

	t.Run("http_probe_ipv6_override_is_used_for_v6_probes_only", func(t *testing.T) {
		var v4Calls, v6Calls atomic.Int32
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Full}},
			HTTPProbe: func(_ context.Context, _ string) (int, int64, error) {
				v4Calls.Add(1)
				return 200, 12, nil
			},
			HTTPProbeIPv6: func(_ context.Context, _ string) (int, int64, error) {
				v6Calls.Add(1)
				return 204, 25, nil
			},
		}
		res := runSingleCheck(t, "dual_stack_connectivity", env)
		if res.Status != doctor.StatusPass || v4Calls.Load() != 2 || v6Calls.Load() != 2 {
			t.Fatalf("expected 2 v4 calls and 2 v6 calls with pass, got res=%+v v4=%d v6=%d", res, v4Calls.Load(), v6Calls.Load())
		}
	})

	t.Run("default_http_probe_ipv6_enforces_tcp6_and_rejects_ipv4_only_listener", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen tcp4: %v", err)
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		srv.Listener = ln
		srv.Start()
		defer srv.Close()

		if code, _, probeErr := doctor.DefaultHTTPProbeIPv6(t.Context(), srv.URL); probeErr == nil {
			t.Fatalf("expected DefaultHTTPProbeIPv6 to fail on IPv4-only listener %s, but succeeded with HTTP %d", srv.URL, code)
		}
	})
	t.Run("ipv6_off_probes_domestic_and_overseas_only", func(t *testing.T) {
		var ipv6Called atomic.Int32
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Off}},
			HTTPProbe: func(_ context.Context, url string) (int, int64, error) {
				switch url {
				case doctor.ProbeURLDomestic:
					return 200, 15, nil
				case doctor.ProbeURLOverseas:
					return 204, 68, nil
				default:
					ipv6Called.Add(1)
					return 200, 10, nil
				}
			},
		}
		res := runSingleCheck(t, "dual_stack_connectivity", env)
		if res.Status != doctor.StatusPass || ipv6Called.Load() != 0 {
			t.Fatalf("expected pass without IPv6 probes when off, got res=%+v ipv6Called=%d", res, ipv6Called.Load())
		}
	})

	t.Run("ipv6_cn_only_domestic_v6_unreachable_warns", func(t *testing.T) {
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly}},
			HTTPProbe: func(_ context.Context, url string) (int, int64, error) {
				switch url {
				case doctor.ProbeURLDomestic:
					return 200, 18, nil
				case doctor.ProbeURLOverseas:
					return 204, 75, nil
				case doctor.ProbeURLDomesticIPv6:
					return 0, 0, errors.New("no route to host")
				default:
					return 200, 10, nil
				}
			},
		}
		res := runSingleCheck(t, "dual_stack_connectivity", env)
		if res.Status != doctor.StatusWarn {
			t.Fatalf("expected warn when domestic IPv6 fails under cn_only, got %+v", res)
		}
	})

	t.Run("ipv6_full_all_probes_pass", func(t *testing.T) {
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Full}},
			HTTPProbe: func(_ context.Context, _ string) (int, int64, error) {
				return 204, 30, nil
			},
		}
		res := runSingleCheck(t, "dual_stack_connectivity", env)
		if res.Status != doctor.StatusPass {
			t.Fatalf("expected pass when all dual-stack probes succeed, got %+v", res)
		}
	})

	t.Run("overseas_proxy_unreachable_fails", func(t *testing.T) {
		env := &doctor.Env{
			Config: &config.Config{Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Off}},
			HTTPProbe: func(_ context.Context, url string) (int, int64, error) {
				if url == doctor.ProbeURLDomestic {
					return 200, 12, nil
				}
				return 0, 0, errors.New("proxy timeout")
			},
		}
		res := runSingleCheck(t, "dual_stack_connectivity", env)
		if res.Status != doctor.StatusFail {
			t.Fatalf("expected fail when overseas proxy unreachable, got %+v", res)
		}
	})
}

func TestDefaultRunner_EndToEndOfflineHealthy(t *testing.T) {
	procRoot := t.TempDir()
	makeProcWithCmdline(t, procRoot, "101", "tailscaled", "tailscaled\x00", "-1000\n")
	makeProcWithCmdline(t, procRoot, "102", "ujail", "/sbin/ujail\x00-n\x00sing-box\x00--\x00/usr/bin/sing-box\x00run\x00", "0\n")
	makeProcWithCmdline(t, procRoot, "103", "sing-box", "/usr/bin/sing-box\x00run\x00", "0\n")
	_ = os.WriteFile(filepath.Join(procRoot, "modules"), []byte("nf_tables 12345 2 - Live 0x0\n"), 0644)

	env := &doctor.Env{
		Config: &config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6Off},
			DNS:     config.ClientDNSConfig{Engine: "smartdns", DNSPort: 5353},
		},
		SingBoxConfigPath: "/etc/sing-box/config.json",
		SmartDNSConfPath:  "/etc/singctl/smartdns.conf",
		ProcRoot:          procRoot,
		IsOpenWrt:         func() bool { return true },
		Statfs: func(string) (sysinfo.DiskSpace, error) {
			return sysinfo.DiskSpace{TotalBytes: 256 * mib, AvailBytes: 180 * mib, UsedPercent: 30}, nil
		},
		ReadMemInfo: func() (sysinfo.MemInfo, error) {
			return sysinfo.MemInfo{TotalBytes: 1024 * mib, AvailableBytes: 600 * mib}, nil
		},
		LookPath: func(file string) (string, error) {
			switch file {
			case "nft", "ip", "uci", "sing-box":
				return "/usr/bin/" + file, nil
			default:
				return "", errors.New("not found")
			}
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmd := name + " " + strings.Join(args, " ")
			switch cmd {
			case "nft list tables":
				return []byte("table inet fw4\ntable inet sing-box\n"), nil
			case "nft list table inet sing-box":
				return []byte("table inet sing-box {\n chain prerouting {}\n chain output {}\n}\n"), nil
			case "nft list chain inet fw4 singctl_ts_jit_guard":
				return nil, errors.New("not configured")
			case "ip rule show":
				return []byte("32764: from all fwmark 0x2 lookup 101\n32765: from all fwmark 0x1 lookup 100\n"), nil
			case "ip route show table 100":
				return []byte("local default dev lo\nthrow 10.0.0.0/8\nthrow 100.64.0.0/10\nthrow 127.0.0.0/8\nthrow 172.16.0.0/12\nthrow 192.168.0.0/16\n"), nil
			case "ip route show table 101":
				return []byte("local default dev lo\n"), nil
			case "uci -q get firewall.@defaults[0].flow_offloading", "uci -q get firewall.@defaults[0].flow_offloading_hw":
				return []byte("0\n"), nil
			case "sing-box check -c /etc/sing-box/config.json":
				return []byte("OK\n"), nil
			default:
				return nil, errors.New("unexpected: " + cmd)
			}
		},
		ReadFile: func(p string) ([]byte, error) {
			switch p {
			case "/etc/sing-box/config.json":
				return []byte(`{"dns":{"disable_cache":true,"optimistic":false,"servers":[{"tag":"dns_local","type":"udp","server":"127.0.0.1","server_port":5353}]}}`), nil
			case "/etc/singctl/smartdns.conf":
				return []byte("bind 127.0.0.1:5353\nforce-AAAA-SOA yes\n"), nil
			default:
				return os.ReadFile(p)
			}
		},
		DialTCP:   func(context.Context, string) error { return nil },
		HTTPProbe: func(context.Context, string) (int, int64, error) { return 204, 22, nil },
	}

	rep := doctor.NewDefaultRunner().Run(t.Context(), env)
	if rep.Score != 100 || rep.Overall != doctor.StatusPass || rep.Passed != 8 {
		t.Fatalf("expected 100/pass/8 passed, got score=%d overall=%q passed=%d checks=%+v",
			rep.Score, rep.Overall, rep.Passed, rep.Checks)
	}
	_ = findCheck(t, rep, "hardware_resources")
	_ = findCheck(t, rep, "dual_stack_connectivity")
	if txt := doctor.FormatText(rep); !strings.Contains(txt, "100") {
		t.Fatalf("FormatText missing score 100: %s", txt)
	}
}
