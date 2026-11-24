// 文件职责：以 TDD 验证 OpenWrt 透明代理脚本 OCP 拆分、nftables/iptables 严格隔离、规则 1:1 对齐、procd-ujail 自动安装及 POSIX /bin/sh 语法与运行行为。
package singbox_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/singbox/scripts"
)

func runShSyntaxCheck(t *testing.T, name, script string) {
	t.Helper()
	scriptPath := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-n", scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("/bin/sh -n failed for %s: %v\noutput:\n%s", name, err, string(out))
	}
}

// stripMainInvocation 去掉脚本末尾对 main 的自动调用，便于单元测试在 /bin/sh 中安全 source 内部函数并单点验证。
func stripMainInvocation(script string) string {
	lines := strings.Split(script, "\n")
	var kept []string
	for _, line := range lines {
		if strings.TrimSpace(line) == "main" {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n") + "\n"
}

func TestOpenWrtFirewallBackendDetection(t *testing.T) {
	cases := []struct {
		name           string
		osRelease      string
		openwrtRelease string
		hasNFT         bool
		want           scripts.OpenWrtFirewallBackend
	}{
		{
			name:      "openwrt_23_with_nft",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"23.05.3\"\nID=\"openwrt\"\n",
			hasNFT:    true,
			want:      scripts.BackendNFTables,
		},
		{
			name:      "openwrt_24_with_nft",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"24.10.0\"\nID=\"openwrt\"\n",
			hasNFT:    true,
			want:      scripts.BackendNFTables,
		},
		{
			name:      "openwrt_snapshot_with_nft",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"SNAPSHOT\"\nID=\"openwrt\"\n",
			hasNFT:    true,
			want:      scripts.BackendNFTables,
		},
		{
			name:      "openwrt_23_without_nft_falls_back_iptables",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"23.05.3\"\nID=\"openwrt\"\n",
			hasNFT:    false,
			want:      scripts.BackendIPTables,
		},
		{
			name:      "immortalwrt_21_02_without_nft_n60pro",
			osRelease: "NAME=\"ImmortalWrt\"\nVERSION=\"21.02-SNAPSHOT\"\nID=\"immortalwrt\"\n",
			hasNFT:    false,
			want:      scripts.BackendIPTables,
		},
		{
			name:      "openwrt_21_02_even_with_nft_uses_iptables",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"21.02.7\"\nID=\"openwrt\"\n",
			hasNFT:    true,
			want:      scripts.BackendIPTables,
		},
		{
			name:      "openwrt_22_03_with_nft_uses_iptables",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"22.03.5\"\nID=\"openwrt\"\n",
			hasNFT:    true,
			want:      scripts.BackendIPTables,
		},
		{
			name:      "openwrt_22_03_without_nft_uses_iptables",
			osRelease: "NAME=\"OpenWrt\"\nVERSION=\"22.03.5\"\nID=\"openwrt\"\n",
			hasNFT:    false,
			want:      scripts.BackendIPTables,
		},
		{
			name:           "fallback_to_openwrt_release_21_02",
			osRelease:      "NAME=\"OpenWrt\"\nVERSION=\"SNAPSHOT\"\n",
			openwrtRelease: "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='21.02.7'\n",
			hasNFT:         true,
			want:           scripts.BackendIPTables,
		},
		{
			name:           "fallback_to_openwrt_release_23_05",
			osRelease:      "",
			openwrtRelease: "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='23.05.4'\n",
			hasNFT:         true,
			want:           scripts.BackendNFTables,
		},
		{
			name:      "version_id_only_21_02",
			osRelease: "ID=openwrt\nVERSION_ID=\"21.02.3\"\n",
			hasNFT:    true,
			want:      scripts.BackendIPTables,
		},
		{
			name:      "empty_inputs_with_nft",
			osRelease: "",
			hasNFT:    true,
			want:      scripts.BackendNFTables,
		},
		{
			name:      "empty_inputs_without_nft",
			osRelease: "",
			hasNFT:    false,
			want:      scripts.BackendIPTables,
		},
		{
			name:      "malformed_version_injection_with_nft",
			osRelease: "VERSION=\"$(rm -rf /)\"\nVERSION_ID=\"not-a-number\"\n",
			hasNFT:    true,
			want:      scripts.BackendNFTables,
		},
		{
			name:      "malformed_version_injection_without_nft",
			osRelease: "VERSION=\";echo bad\"\n",
			hasNFT:    false,
			want:      scripts.BackendIPTables,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scripts.ResolveOpenWrtFirewallBackend(tc.osRelease, tc.openwrtRelease, tc.hasNFT)
			if got != tc.want {
				t.Fatalf("ResolveOpenWrtFirewallBackend() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("detect_host_backend_returns_known_constant", func(t *testing.T) {
		got := scripts.DetectOpenWrtFirewallBackend()
		if got != scripts.BackendNFTables && got != scripts.BackendIPTables {
			t.Fatalf("DetectOpenWrtFirewallBackend() returned unknown backend %q", got)
		}
	})
}

func TestOpenWrtScripts_SyntaxIsolationAndOCPLayout(t *testing.T) {
	nftStart := scripts.GetOpenWrtStartScript(scripts.BackendNFTables)
	nftStop := scripts.GetOpenWrtStopScript(scripts.BackendNFTables)
	iptStart := scripts.GetOpenWrtStartScript(scripts.BackendIPTables)
	iptStop := scripts.GetOpenWrtStopScript(scripts.BackendIPTables)

	allScripts := []struct {
		name    string
		content string
		isStart bool
	}{
		{"openwrt_nft_start.sh", nftStart, true},
		{"openwrt_nft_stop.sh", nftStop, false},
		{"openwrt_ipt_start.sh", iptStart, true},
		{"openwrt_ipt_stop.sh", iptStop, false},
	}

	gnuOnlyPatterns := []string{
		"#!/bin/bash",
		"sort -h",
		"grep -P",
		"[[ ",
		"<<<",
	}

	for _, item := range allScripts {
		t.Run("syntax_and_posix_"+item.name, func(t *testing.T) {
			if strings.TrimSpace(item.content) == "" {
				t.Fatalf("%s is empty", item.name)
			}
			if !strings.HasPrefix(item.content, "#!/bin/sh\n") {
				t.Fatalf("%s must start with #!/bin/sh", item.name)
			}
			if strings.Count(item.content, "#!/bin/sh") != 1 {
				t.Fatalf("%s must contain exactly one #!/bin/sh shebang, got %d", item.name, strings.Count(item.content, "#!/bin/sh"))
			}
			if item.isStart && !strings.Contains(item.content, "OpenWrt sing-box TProxy模式") {
				t.Fatalf("%s missing OpenWrt TProxy description header", item.name)
			}
			for _, bad := range gnuOnlyPatterns {
				if strings.Contains(item.content, bad) {
					t.Fatalf("%s contains non-POSIX/GNU-only construct %q", item.name, bad)
				}
			}
			runShSyntaxCheck(t, item.name, item.content)
		})
	}

	t.Run("strict_backend_isolation", func(t *testing.T) {
		for _, pair := range []struct {
			name string
			body string
		}{
			{"nft_start", nftStart},
			{"nft_stop", nftStop},
		} {
			lower := strings.ToLower(pair.body)
			if !strings.Contains(lower, "nft") {
				t.Fatalf("%s expected nft commands", pair.name)
			}
			if strings.Contains(lower, "iptables") || strings.Contains(lower, "ip6tables") {
				t.Fatalf("%s must NOT contain any iptables/ip6tables code or comments", pair.name)
			}
		}

		for _, pair := range []struct {
			name string
			body string
		}{
			{"ipt_start", iptStart},
			{"ipt_stop", iptStop},
		} {
			lower := strings.ToLower(pair.body)
			if !strings.Contains(lower, "iptables") {
				t.Fatalf("%s expected iptables commands", pair.name)
			}
			if strings.Contains(lower, "nft") {
				t.Fatalf("%s must NOT contain any nft/nftables code or comments", pair.name)
			}
		}
	})

	t.Run("unknown_or_empty_backend_falls_back_safely", func(t *testing.T) {
		for _, bad := range []scripts.OpenWrtFirewallBackend{"", "unknown", "foo;rm -rf /"} {
			sStart := scripts.GetOpenWrtStartScript(bad)
			sStop := scripts.GetOpenWrtStopScript(bad)
			if sStart != nftStart {
				t.Fatalf("GetOpenWrtStartScript(%q) did not fall back to nftables backend", bad)
			}
			if sStop != nftStop {
				t.Fatalf("GetOpenWrtStopScript(%q) did not fall back to nftables backend", bad)
			}
		}
	})

	t.Run("legacy_monolithic_openwrt_scripts_removed", func(t *testing.T) {
		scriptsDir := filepath.Join("..", "scripts")
		for _, legacy := range []string{"start_singbox.sh", "stop_singbox.sh"} {
			if _, err := os.Stat(filepath.Join(scriptsDir, legacy)); !os.IsNotExist(err) {
				t.Fatalf("legacy monolithic %s should be removed after OCP split", legacy)
			}
		}
		for _, modular := range []string{
			"openwrt_common.sh",
			"openwrt_fw_nftables.sh",
			"openwrt_fw_iptables.sh",
			"openwrt_start_main.sh",
			"openwrt_stop_main.sh",
		} {
			if _, err := os.Stat(filepath.Join(scriptsDir, modular)); err != nil {
				t.Fatalf("expected modular script %s to exist: %v", modular, err)
			}
		}
	})
}

func TestOpenWrtIPTablesBackend_SafetyAndNFTablesParity(t *testing.T) {
	iptStart := scripts.GetOpenWrtStartScript(scripts.BackendIPTables)
	iptStop := scripts.GetOpenWrtStopScript(scripts.BackendIPTables)

	t.Run("never_flushes_host_prerouting_or_output", func(t *testing.T) {
		for _, pair := range []struct {
			name string
			body string
		}{
			{"ipt_start", iptStart},
			{"ipt_stop", iptStop},
		} {
			for _, forbidden := range []string{"-F PREROUTING", "-F OUTPUT"} {
				if strings.Contains(pair.body, forbidden) {
					t.Fatalf("%s must never destructively execute %q", pair.name, forbidden)
				}
			}
		}
	})

	t.Run("no_tailscale_inbound_return_for_exitnode_parity", func(t *testing.T) {
		if strings.Contains(iptStart, "-i tailscale+ -j RETURN") {
			t.Fatalf("iptables SING_BOX PREROUTING must not bypass -i tailscale+ so ExitNode traffic uses TProxy")
		}
	})

	t.Run("ipv4_and_ipv6_parity_markers_and_order", func(t *testing.T) {
		required := []string{
			"fw_check_deps",
			"fw_cleanup_pre",
			"fw_apply",
			"fw_stop_cleanup",
			"SING_BOX_OUTPUT",
			"-D PREROUTING -j SING_BOX",
			"-D OUTPUT -j SING_BOX_OUTPUT",
			"-m addrtype --dst-type LOCAL",
			"ip -4 addr show",
			"-m conntrack --ctstate DNAT -j RETURN",
			"-p udp --dport 67:68 -j RETURN",
			"100.64.0.0/10",
			"0x80000",
			"41641",
			"-o tailscale+ -j RETURN",
			"BYPASS_DNS_V4_IPS",
			"BYPASS_DNS_V6_IPS",
			"LAN_IPV6_PFXS",
			"ip6tables",
			"fd7a:115c:a1e0::/48",
			"icmpv6",
			"fc00::/7",
			"fe80::/10",
			"ff00::/8",
			"ensure_openwrt_ujail",
			"procd-ujail",
			"collect_bypass_dns_ips",
			"collect_lan_ipv6_prefixes",
			"stop_singbox_proc",
			"cleanup_sandbox_work",
			"sync_dnsmasq_ipv4_only",
		}
		for _, token := range required {
			if !strings.Contains(iptStart, token) {
				t.Fatalf("iptables start script missing required token %q", token)
			}
		}

		// 验证 DNS 53 劫持规则位于 192.168.0.0/16 放行规则之前，堵死光猫明文 DNS 漏网。
		dnsIdx := strings.Index(iptStart, "--dport 53 -j TPROXY")
		lanIdx := strings.Index(iptStart, "-d 192.168.0.0/16 -j RETURN")
		if dnsIdx < 0 || lanIdx < 0 || dnsIdx >= lanIdx {
			t.Fatalf("expected DNS 53 TPROXY rule (idx=%d) before 192.168.0.0/16 RETURN (idx=%d)", dnsIdx, lanIdx)
		}
	})
}

func TestOpenWrtNFTablesBackend_ParityAndSmartDNSBypass(t *testing.T) {
	nftStart := scripts.GetOpenWrtStartScript(scripts.BackendNFTables)
	nftStop := scripts.GetOpenWrtStopScript(scripts.BackendNFTables)

	requiredStart := []string{
		"fw_check_deps",
		"fw_cleanup_pre",
		"fw_apply",
		"fw_stop_cleanup",
		"collect_bypass_dns_ips",
		"collect_lan_ipv6_prefixes",
		"table inet sing-box",
		"LOCAL_IPV4_SET",
		"LOCAL_IPV6_SET",
		"fib daddr type local",
		"ct status dnat accept",
		"BYPASS_DNS_V4_IPS",
		"BYPASS_DNS_V6_IPS",
		"/etc/singctl/smartdns.conf",
		"/etc/AdGuardHome/AdGuardHome.yaml",
		"ensure_openwrt_ujail",
		"procd-ujail",
		"sync_dnsmasq_ipv4_only",
	}
	for _, token := range requiredStart {
		if !strings.Contains(nftStart, token) {
			t.Fatalf("nftables start script missing required token %q", token)
		}
	}
	if !strings.Contains(nftStop, "fw_stop_cleanup") || !strings.Contains(nftStop, "nft delete table inet sing-box") {
		t.Fatalf("nftables stop script missing cleanup contract")
	}
}

func TestOpenWrtCommon_CollectBypassDNSIPs_RuntimeSh(t *testing.T) {
	dir := t.TempDir()
	libPath := filepath.Join(dir, "openwrt_lib.sh")
	if err := os.WriteFile(libPath, []byte(stripMainInvocation(scripts.GetOpenWrtStartScript(scripts.BackendIPTables))), 0700); err != nil {
		t.Fatal(err)
	}

	aghPath := filepath.Join(dir, "AdGuardHome.yaml")
	aghContent := `dns:
  upstream_dns:
    - https://223.5.5.5/dns-query
    - https://198.51.100.11/dns-query
    - tls://203.0.113.22:853
    - quic://192.0.2.33:853
    - https://[2001:db8::11]/dns-query
    - tls://[2001:db8::22]:853
    - https://dns.example.com/dns-query
    - https://198.51.100.44.example.com/dns-query
    - https://127.0.0.1/dns-query
    - https://999.999.999.999/dns-query
    # - https://198.51.100.99/dns-query
    # - tls://[2001:db8::99]:853
`
	if err := os.WriteFile(aghPath, []byte(aghContent), 0600); err != nil {
		t.Fatal(err)
	}

	sdnsPath := filepath.Join(dir, "smartdns.conf")
	sdnsContent := `# SmartDNS config fixture
bind 127.0.0.1:5353
server-https https://198.51.100.11/dns-query
server-https https://198.51.100.55:443/dns-query
server-https https://[2001:db8::55]/dns-query
server-tls 203.0.113.66:853
server-tls [2001:db8::66]:853
server-quic 192.0.2.77:853
server-quic [2001:db8::77]:853
server-https https://dns.example.com/dns-query
# server-tls 198.51.100.88:853
# server-tls [2001:db8::88]:853
`
	if err := os.WriteFile(sdnsPath, []byte(sdnsContent), 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("extracts_both_adguard_and_smartdns_v4_and_v6_deduped", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `
. "$1"
collect_bypass_dns_ips
printf 'V4=%s\nV6=%s\n' "$BYPASS_DNS_V4_IPS" "$BYPASS_DNS_V6_IPS"
`, "_", libPath)
		cmd.Env = append(os.Environ(),
			"ADGUARD_CONFIG_FILE="+aghPath,
			"SMARTDNS_CONFIG_FILE="+sdnsPath,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("collect_bypass_dns_ips failed: %v\n%s", err, string(out))
		}
		text := string(out)
		var v4Line, v6Line string
		for line := range strings.SplitSeq(text, "\n") {
			if rest, ok := strings.CutPrefix(line, "V4="); ok {
				v4Line = rest
			} else if rest, ok := strings.CutPrefix(line, "V6="); ok {
				v6Line = rest
			}
		}

		for _, wantV4 := range []string{
			"223.5.5.5", "223.6.6.6", "1.12.12.12", "120.53.53.53",
			"198.51.100.11", "203.0.113.22", "192.0.2.33",
			"198.51.100.55", "203.0.113.66", "192.0.2.77",
		} {
			if !strings.Contains(" "+v4Line+" ", " "+wantV4+" ") {
				t.Fatalf("missing expected IPv4 %q in %q", wantV4, v4Line)
			}
		}
		for _, badV4 := range []string{"198.51.100.99", "198.51.100.88", "198.51.100.44", "127.0.0.1", "999.999.999.999"} {
			if strings.Contains(" "+v4Line+" ", " "+badV4+" ") {
				t.Fatalf("unexpected/invalid IPv4 %q leaked into %q", badV4, v4Line)
			}
		}
		if strings.Count(" "+v4Line+" ", " 198.51.100.11 ") != 1 {
			t.Fatalf("expected 198.51.100.11 deduplicated, got %q", v4Line)
		}

		for _, wantV6 := range []string{
			"2400:3200::1", "2400:3200:baba::1",
			"2001:db8::11", "2001:db8::22", "2001:db8::55", "2001:db8::66", "2001:db8::77",
		} {
			if !strings.Contains(" "+v6Line+" ", " "+wantV6+" ") {
				t.Fatalf("missing expected IPv6 %q in %q", wantV6, v6Line)
			}
		}
		for _, badV6 := range []string{"2001:db8::99", "2001:db8::88", "::1"} {
			if strings.Contains(" "+v6Line+" ", " "+badV6+" ") {
				t.Fatalf("unexpected/commented IPv6 %q leaked into %q", badV6, v6Line)
			}
		}
	})

	t.Run("missing_config_files_returns_defaults_only", func(t *testing.T) {
		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `
. "$1"
collect_bypass_dns_ips
printf 'V4=%s\nV6=%s\n' "$BYPASS_DNS_V4_IPS" "$BYPASS_DNS_V6_IPS"
`, "_", libPath)
		cmd.Env = append(os.Environ(),
			"ADGUARD_CONFIG_FILE="+filepath.Join(dir, "missing_agh.yaml"),
			"SMARTDNS_CONFIG_FILE="+filepath.Join(dir, "missing_smartdns.conf"),
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("collect_bypass_dns_ips(missing files) failed: %v\n%s", err, string(out))
		}
		text := string(out)
		if !strings.Contains(text, "V4=223.5.5.5 223.6.6.6 1.12.12.12 120.53.53.53") ||
			!strings.Contains(text, "V6=2400:3200::1 2400:3200:baba::1") {
			t.Fatalf("unexpected default bypass sets:\n%s", text)
		}
	})

	t.Run("collect_vlan_proxy_bypass_cidrs_filters_invalid_and_dedups", func(t *testing.T) {
		bypassFile := filepath.Join(dir, "vlan-proxy-bypass.list")
		raw := strings.Join([]string{
			"# comment",
			"192.168.20.0/24",
			"192.168.20.0/24",
			"10.10.20.0/24",
			"192.168.30.0/24;rm -rf /",
			"not-a-cidr",
			"127.0.0.0/8",
		}, "\n") + "\n"
		if err := os.WriteFile(bypassFile, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `
. "$1"
collect_vlan_proxy_bypass_cidrs
printf 'CIDRS=%s\n' "$BYPASS_VLAN_V4_CIDRS"
`, "_", libPath)
		cmd.Env = append(os.Environ(), "VLAN_PROXY_BYPASS_FILE="+bypassFile)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("collect_vlan_proxy_bypass_cidrs failed: %v\n%s", err, string(out))
		}
		text := strings.TrimSpace(string(out))
		if text != "CIDRS=192.168.20.0/24 10.10.20.0/24" {
			t.Fatalf("unexpected BYPASS_VLAN_V4_CIDRS: %q", text)
		}
	})
}

func TestOpenWrtCommon_EnsureUjailAndLogCap_RuntimeSh(t *testing.T) {
	dir := t.TempDir()
	libPath := filepath.Join(dir, "openwrt_lib.sh")
	if err := os.WriteFile(libPath, []byte(stripMainInvocation(scripts.GetOpenWrtStartScript(scripts.BackendIPTables))), 0700); err != nil {
		t.Fatal(err)
	}

	writeMockExec := func(binDir, name, body string) {
		t.Helper()
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatalf("write mock %s: %v", name, err)
		}
	}

	t.Run("skips_when_overlay_space_below_512kb", func(t *testing.T) {
		binDir := filepath.Join(dir, "bin_low_space")
		overlayDir := filepath.Join(dir, "overlay_low")
		relFile := filepath.Join(dir, "openwrt_release_low")
		logFile := filepath.Join(dir, "opkg_low.log")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(overlayDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(relFile, []byte("DISTRIB_ID='ImmortalWrt'\n"), 0600); err != nil {
			t.Fatal(err)
		}
		writeMockExec(binDir, "df", `echo "Filesystem 1024-blocks Used Available Capacity Mounted on"; echo "overlayfs:/overlay 8192 7900 292 96% /overlay"`)
		writeMockExec(binDir, "opkg", `echo "$@" >> "`+logFile+`"; exit 0`)

		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; ensure_openwrt_ujail`, "_", libPath)
		cmd.Env = []string{
			"PATH=" + binDir + ":/usr/bin:/bin",
			"OPENWRT_RELEASE_FILE=" + relFile,
			"OVERLAY_DIR=" + overlayDir,
		}
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected non-zero return when overlay < 512KB, output:\n%s", string(out))
		}
		if !strings.Contains(string(out), "512 KB") {
			t.Fatalf("expected low-space warning mentioning 512 KB, got:\n%s", string(out))
		}
		if _, statErr := os.Stat(logFile); !os.IsNotExist(statErr) {
			t.Fatalf("opkg must not be invoked when overlay space < 512KB")
		}
	})

	t.Run("installs_from_cached_opkg_list_without_update", func(t *testing.T) {
		binDir := filepath.Join(dir, "bin_cached")
		overlayDir := filepath.Join(dir, "overlay_cached")
		relFile := filepath.Join(dir, "openwrt_release_cached")
		logFile := filepath.Join(dir, "opkg_cached.log")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(overlayDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(relFile, []byte("DISTRIB_ID='ImmortalWrt'\n"), 0600); err != nil {
			t.Fatal(err)
		}
		writeMockExec(binDir, "df", `echo "Filesystem 1024-blocks Used Available Capacity Mounted on"; echo "overlayfs:/overlay 16384 4096 12288 25% /overlay"`)
		writeMockExec(binDir, "opkg", `echo "$@" >> "`+logFile+`"
if [ "$1" = "list" ]; then
    echo "procd-ujail - 2021-03-08-test - OpenWrt jail"
    exit 0
fi
if [ "$1" = "install" ] && [ "$2" = "procd-ujail" ]; then
    printf '#!/bin/sh\necho ok\n' > "`+filepath.Join(binDir, "ujail")+`"
    chmod 0755 "`+filepath.Join(binDir, "ujail")+`"
    exit 0
fi
exit 1`)

		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; ensure_openwrt_ujail`, "_", libPath)
		cmd.Env = []string{
			"PATH=" + binDir + ":/usr/bin:/bin",
			"OPENWRT_RELEASE_FILE=" + relFile,
			"OVERLAY_DIR=" + overlayDir,
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("expected ensure_openwrt_ujail to succeed from cache: %v\n%s", err, string(out))
		}
		logged, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatal(err)
		}
		logText := string(logged)
		if strings.Contains(logText, "update") {
			t.Fatalf("should not run opkg update when cached install succeeds, log:\n%s", logText)
		}
		if !strings.Contains(logText, "install procd-ujail") {
			t.Fatalf("expected opkg install procd-ujail, log:\n%s", logText)
		}
	})

	t.Run("runs_bounded_opkg_update_on_cache_miss_and_survives_timeout", func(t *testing.T) {
		binDir := filepath.Join(dir, "bin_timeout")
		overlayDir := filepath.Join(dir, "overlay_timeout")
		relFile := filepath.Join(dir, "openwrt_release_timeout")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(overlayDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(relFile, []byte("DISTRIB_ID='ImmortalWrt'\n"), 0600); err != nil {
			t.Fatal(err)
		}
		writeMockExec(binDir, "df", `echo "Filesystem 1024-blocks Used Available Capacity Mounted on"; echo "overlayfs:/overlay 16384 4096 12288 25% /overlay"`)
		writeMockExec(binDir, "opkg", `if [ "$1" = "list" ]; then exit 0; fi; if [ "$1" = "update" ]; then sleep 10; exit 0; fi; exit 1`)

		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; ensure_openwrt_ujail || echo "GRACEFUL_FALLBACK"`, "_", libPath)
		cmd.Env = []string{
			"PATH=" + binDir + ":/usr/bin:/bin",
			"OPENWRT_RELEASE_FILE=" + relFile,
			"OVERLAY_DIR=" + overlayDir,
			"UJAIL_OPKG_TIMEOUT=1",
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("shell aborted unexpectedly on opkg timeout: %v\n%s", err, string(out))
		}
		if !strings.Contains(string(out), "GRACEFUL_FALLBACK") || !strings.Contains(string(out), "超时") {
			t.Fatalf("expected timeout warning and graceful fallback on opkg timeout, got:\n%s", string(out))
		}
	})

	t.Run("skips_silently_on_non_openwrt_host", func(t *testing.T) {
		binDir := filepath.Join(dir, "bin_non_openwrt")
		logFile := filepath.Join(dir, "opkg_non_openwrt.log")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		writeMockExec(binDir, "opkg", `echo "$@" >> "`+logFile+`"; exit 0`)
		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; ensure_openwrt_ujail || echo "NON_OPENWRT"`, "_", libPath)
		cmd.Env = []string{
			"PATH=" + binDir + ":/usr/bin:/bin",
			"OPENWRT_RELEASE_FILE=" + filepath.Join(dir, "missing_openwrt_release"),
		}
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "NON_OPENWRT") {
			t.Fatalf("expected non-OpenWrt skip, err=%v out=%s", err, string(out))
		}
		if _, statErr := os.Stat(logFile); !os.IsNotExist(statErr) {
			t.Fatalf("opkg must not be called when /etc/openwrt_release is absent")
		}
	})

	t.Run("old_openwrt_21_02_ujail_downgrades_env_and_proc_flags", func(t *testing.T) {
		script := scripts.GetOpenWrtStartScript(scripts.BackendIPTables)
		for _, want := range []string{
			`ujail -n test-basic -w /tmp -- /bin/echo "test"`,
			`ujail -n test-env -w /tmp -e PATH -- /bin/echo "ok"`,
			`ujail -n test-proc -w /tmp -r /proc -- /bin/echo "ok"`,
			`ujail -n test-proc -w /tmp -p -- /bin/echo "ok"`,
			`/tmp/sing-box-work/config.json`,
		} {
			if !strings.Contains(script, want) {
				t.Fatalf("OpenWrt start script missing 21.02 ujail compatibility probe %q", want)
			}
		}
	})

	t.Run("cap_singbox_log_256k_truncates_in_place", func(t *testing.T) {
		logFile := filepath.Join(dir, "sing-box-basic.log")
		payload := append(bytes.Repeat([]byte("A123456789012345678901234567890\n"), 10000), []byte("TAIL_MARKER\n")...)
		if err := os.WriteFile(logFile, payload, 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; SINGCTL_LOW_MEMORY=1; cap_singbox_log_256k "$2"`, "_", libPath, logFile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("cap_singbox_log_256k failed: %v\n%s", err, string(out))
		}
		st, err := os.Stat(logFile)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 262144 {
			t.Fatalf("expected truncated size <= 262144, got %d", st.Size())
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("expected mode 0600, got %04o", st.Mode().Perm())
		}
		data, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(string(data), "TAIL_MARKER\n") {
			t.Fatalf("expected TAIL_MARKER preserved")
		}
	})
}

func TestOpenWrtIPTablesBackend_MockExecution(t *testing.T) {
	dir := t.TempDir()
	libPath := filepath.Join(dir, "openwrt_ipt_lib.sh")
	if err := os.WriteFile(libPath, []byte(stripMainInvocation(scripts.GetOpenWrtStartScript(scripts.BackendIPTables))), 0700); err != nil {
		t.Fatal(err)
	}

	writeMockExec := func(binDir, name, body string) {
		t.Helper()
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0755); err != nil {
			t.Fatalf("write mock %s: %v", name, err)
		}
	}

	t.Run("fallback_without_addrtype_and_without_ip6tables_tproxy", func(t *testing.T) {
		binDir := filepath.Join(dir, "bin_no_addrtype")
		logFile := filepath.Join(dir, "ipt_no_addrtype.log")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		writeMockExec(binDir, "iptables", `echo "iptables $*" >> "`+logFile+`"
case "$*" in
    *"-m addrtype"*) exit 1 ;;
    *"-j REJECT"*) exit 1 ;;
    *"-D PREROUTING"*|*"-D OUTPUT"*) exit 1 ;;
esac
exit 0`)
		writeMockExec(binDir, "ip6tables", `echo "ip6tables $*" >> "`+logFile+`"
case "$*" in
    *"-j TPROXY"*) exit 1 ;;
    *"-D PREROUTING"*|*"-D OUTPUT"*) exit 1 ;;
esac
exit 0`)
		writeMockExec(binDir, "ip", `if [ "$1" = "-4" ] && [ "$2" = "addr" ]; then
    echo "    inet 127.0.0.1/8 scope host lo"
    echo "    inet 192.168.1.1/24 brd 192.168.1.255 scope global br-lan"
    exit 0
fi
exit 0`)

		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; fw_apply && fw_stop_cleanup && fw_stop_cleanup`, "_", libPath)
		cmd.Env = []string{
			"PATH=" + binDir + ":/usr/bin:/bin",
			"ADGUARD_CONFIG_FILE=" + filepath.Join(dir, "none.yaml"),
			"SMARTDNS_CONFIG_FILE=" + filepath.Join(dir, "none.conf"),
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("iptables fallback execution failed: %v\n%s", err, string(out))
		}
		logBytes, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatal(err)
		}
		logText := string(logBytes)
		if strings.Contains(logText, "-F PREROUTING") || strings.Contains(logText, "-F OUTPUT") {
			t.Fatalf("mock execution flushed host PREROUTING/OUTPUT:\n%s", logText)
		}
		for _, want := range []string{
			"iptables -t mangle -A SING_BOX -d 192.168.1.1 -p tcp --dport 7895 -j DROP",
			"iptables -t mangle -A SING_BOX -d 192.168.1.1 -j RETURN",
			"iptables -t mangle -A SING_BOX -p udp --dport 53 -j TPROXY --on-port 7895 --tproxy-mark 1",
			"iptables -t mangle -A PREROUTING -j SING_BOX",
			"iptables -t mangle -A OUTPUT -j SING_BOX_OUTPUT",
			"iptables -t mangle -X SING_BOX_OUTPUT",
		} {
			if !strings.Contains(logText, want) {
				t.Fatalf("expected mock iptables invocation %q, got:\n%s", want, logText)
			}
		}
		if strings.Contains(logText, "ip6tables -t mangle -A PREROUTING -j SING_BOX") {
			t.Fatalf("ip6tables should skip PREROUTING attach when TPROXY probe fails:\n%s", logText)
		}
	})

	t.Run("full_dual_stack_with_addrtype_and_ip6tables_tproxy", func(t *testing.T) {
		binDir := filepath.Join(dir, "bin_dual_stack")
		logFile := filepath.Join(dir, "ipt_dual_stack.log")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatal(err)
		}
		writeMockExec(binDir, "iptables", `echo "iptables $*" >> "`+logFile+`"
case "$*" in
    *"-D PREROUTING"*|*"-D OUTPUT"*) exit 1 ;;
esac
exit 0`)
		writeMockExec(binDir, "ip6tables", `echo "ip6tables $*" >> "`+logFile+`"
case "$*" in
    *"-D PREROUTING"*|*"-D OUTPUT"*) exit 1 ;;
esac
exit 0`)
		writeMockExec(binDir, "ip", `if [ "$1" = "link" ] && [ "$2" = "show" ] && [ "$3" = "br-lan" ]; then
    exit 0
fi
if [ "$1" = "-6" ] && [ "$2" = "route" ]; then
    echo "2001:db8:1234::/64 proto kernel metric 256 pref medium"
    exit 0
fi
exit 1`)

		cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", `. "$1"; fw_apply && fw_stop_cleanup`, "_", libPath)
		cmd.Env = []string{
			"PATH=" + binDir + ":/usr/bin:/bin",
			"ADGUARD_CONFIG_FILE=" + filepath.Join(dir, "none.yaml"),
			"SMARTDNS_CONFIG_FILE=" + filepath.Join(dir, "none.conf"),
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("dual-stack iptables execution failed: %v\n%s", err, string(out))
		}
		logBytes, err := os.ReadFile(logFile)
		if err != nil {
			t.Fatal(err)
		}
		logText := string(logBytes)
		for _, want := range []string{
			"iptables -t mangle -A SING_BOX -m addrtype --dst-type LOCAL -p tcp --dport 7895 -j REJECT",
			"iptables -t mangle -A SING_BOX -m addrtype --dst-type LOCAL -j RETURN",
			"ip6tables -t mangle -A SING_BOX -m addrtype --dst-type LOCAL -j RETURN",
			"ip6tables -t mangle -A SING_BOX -d 2001:db8:1234::/64 -j RETURN",
			"ip6tables -t mangle -A SING_BOX_OUTPUT -p icmpv6 -j RETURN",
			"ip6tables -t mangle -A SING_BOX_OUTPUT -d 2400:3200::1 -p tcp --dport 443 -j RETURN",
			"ip6tables -t mangle -A PREROUTING -j SING_BOX",
			"ip6tables -t mangle -A OUTPUT -j SING_BOX_OUTPUT",
		} {
			if !strings.Contains(logText, want) {
				t.Fatalf("expected dual-stack invocation %q, got:\n%s", want, logText)
			}
		}
	})
}

func TestOpenWrtScripts_BackwardCompatAndConcurrentRace(t *testing.T) {
	if got := scripts.GetStartScriptForTarget("darwin", false); !strings.Contains(got, "macOS") {
		t.Fatalf("darwin target script broken")
	}
	if got := scripts.GetStartScriptForTarget("windows", false); !strings.Contains(strings.ToLower(got), "sing-box") {
		t.Fatalf("windows target script broken")
	}
	if got := scripts.GetStartScriptForTarget("linux", true); !strings.Contains(got, "Debian sing-box TProxy模式") {
		t.Fatalf("debian target script broken")
	}
	if got := scripts.GetStartScriptForTarget("linux", false); !strings.Contains(got, "OpenWrt sing-box TProxy模式") {
		t.Fatalf("openwrt target script broken")
	}

	dir := t.TempDir()
	startPath := filepath.Join(dir, "start.sh")
	stopPath := filepath.Join(dir, "stop.sh")
	if err := scripts.WriteStartScript(startPath); err != nil {
		t.Fatalf("WriteStartScript: %v", err)
	}
	if err := scripts.WriteStopScript(stopPath); err != nil {
		t.Fatalf("WriteStopScript: %v", err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_ = scripts.GetOpenWrtStartScript(scripts.BackendNFTables)
			_ = scripts.GetOpenWrtStopScript(scripts.BackendNFTables)
			_ = scripts.GetOpenWrtStartScript(scripts.BackendIPTables)
			_ = scripts.GetOpenWrtStopScript(scripts.BackendIPTables)
			_ = scripts.DetectOpenWrtFirewallBackend()
			_ = scripts.ResolveOpenWrtFirewallBackend("VERSION=\"21.02.7\"", "", false)
		})
	}
	wg.Wait()
}
