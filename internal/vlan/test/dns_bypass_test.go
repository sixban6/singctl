// 文件职责：测试 VLAN 自定义 DNS 与旁路由托管 53 端口免劫持持久化脚本（fw3/fw4）、运行时规则同步、防注入校验及并发幂等性。
package vlan_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"singctl/internal/vlan"
)

func TestVLAN_SyncFW4AndFW3DNSBypassInclude(t *testing.T) {
	// 1. Missing fw4Root degrades gracefully to nil without creating directories.
	missingRoot := filepath.Join(t.TempDir(), "nonexistent-nftables.d")
	rules := []vlan.VLANDNSBypassRule{
		{CIDR: "192.168.89.0/24", DNSIPs: []string{"192.168.55.88"}},
		{CIDR: "192.168.34.0/24", DNSIPs: []string{"223.5.5.5", "192.168.55.88"}},
	}
	if err := vlan.SyncFW4DNSBypassInclude(missingRoot, rules); err != nil {
		t.Fatalf("missing fw4Root must return nil gracefully, got: %v", err)
	}
	if _, err := os.Stat(missingRoot); !os.IsNotExist(err) {
		t.Fatalf("missing fw4Root should not be created, err=%v", err)
	}

	// 2. Existing fw4Root writes 0600 nft include under chain-pre/dstnat/singctl-vlan-dns.nft.
	fw4Root := t.TempDir()
	if err := vlan.SyncFW4DNSBypassInclude(fw4Root, rules); err != nil {
		t.Fatalf("SyncFW4DNSBypassInclude failed: %v", err)
	}
	nftFile := filepath.Join(fw4Root, "chain-pre", "dstnat", "singctl-vlan-dns.nft")
	stNFT, err := os.Stat(nftFile)
	if err != nil || stNFT.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on %s, err=%v mode=%v", nftFile, err, stNFT.Mode().Perm())
	}
	nftRaw, err := os.ReadFile(nftFile)
	if err != nil {
		t.Fatalf("read fw4 dns bypass file: %v", err)
	}
	nftText := string(nftRaw)
	for _, want := range []string{
		`ip saddr 192.168.89.0/24 ip daddr 192.168.55.88 meta l4proto { tcp, udp } th dport 53 accept comment "singctl-vlan-dns"`,
		`ip saddr 192.168.34.0/24 ip daddr 223.5.5.5 meta l4proto { tcp, udp } th dport 53 accept comment "singctl-vlan-dns"`,
		`ip saddr 192.168.34.0/24 ip daddr 192.168.55.88 meta l4proto { tcp, udp } th dport 53 accept comment "singctl-vlan-dns"`,
	} {
		if !strings.Contains(nftText, want) {
			t.Fatalf("fw4 dns bypass missing %q:\n%s", want, nftText)
		}
	}

	// 3. fw3 script writes 0600 + registers UCI firewall.singctl_vlan_dns=include.
	scriptPath := filepath.Join(t.TempDir(), "etc", "singctl", "vlan-dns-bypass.fw3.sh")
	var cmds []string
	uciPresent := false
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		switch line {
		case "uci -q get firewall.singctl_vlan_dns":
			if !uciPresent {
				return nil, os.ErrNotExist
			}
		case "uci set firewall.singctl_vlan_dns=include":
			uciPresent = true
		case "uci delete firewall.singctl_vlan_dns":
			uciPresent = false
		}
		return nil, nil
	}
	if err := vlan.SyncFW3DNSBypassInclude(scriptPath, rules, runner); err != nil {
		t.Fatalf("SyncFW3DNSBypassInclude failed: %v", err)
	}
	stFW3, err := os.Stat(scriptPath)
	if err != nil || stFW3.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on %s, err=%v mode=%v", scriptPath, err, stFW3.Mode().Perm())
	}
	fw3Raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read fw3 dns bypass script: %v", err)
	}
	fw3Text := string(fw3Raw)
	for _, want := range []string{
		"iptables -w 2 -t nat -S PREROUTING",
		"iptables -w 2 -t mangle -L SING_BOX -n",
		"iptables -w 2 -t nat -I PREROUTING 1 -s 192.168.89.0/24 -d 192.168.55.88 -p udp --dport 53 -m comment --comment singctl-vlan-dns -j ACCEPT",
		"iptables -w 2 -t nat -I PREROUTING 1 -s 192.168.89.0/24 -d 192.168.55.88 -p tcp --dport 53 -m comment --comment singctl-vlan-dns -j ACCEPT",
		"iptables -w 2 -t mangle -I SING_BOX 1 -s 192.168.89.0/24 -d 192.168.55.88 -p udp --dport 53 -m comment --comment singctl-vlan-dns -j RETURN",
	} {
		if !strings.Contains(fw3Text, want) {
			t.Fatalf("fw3 dns bypass script missing %q:\n%s", want, fw3Text)
		}
	}
	joined := strings.Join(cmds, "\n")
	for _, wantCmd := range []string{
		"uci set firewall.singctl_vlan_dns=include",
		"uci set firewall.singctl_vlan_dns.type=script",
		"uci set firewall.singctl_vlan_dns.path=" + scriptPath,
		"uci set firewall.singctl_vlan_dns.reload=1",
		"uci commit firewall",
	} {
		if !strings.Contains(joined, wantCmd) {
			t.Fatalf("missing UCI command %q in:\n%s", wantCmd, joined)
		}
	}

	// 4. Reject malformed/loopback/injection inputs while preserving existing valid 0600 files.
	badInputs := [][]vlan.VLANDNSBypassRule{
		{{CIDR: "192.168.89.0/24; id", DNSIPs: []string{"192.168.55.88"}}},
		{{CIDR: "192.168.89.0/24", DNSIPs: []string{"127.0.0.1"}}},
		{{CIDR: "192.168.89.0/24", DNSIPs: []string{"192.168.55.88$(id)"}}},
	}
	for _, bad := range badInputs {
		if err := vlan.SyncFW4DNSBypassInclude(fw4Root, bad); err == nil {
			t.Fatalf("expected SyncFW4DNSBypassInclude to reject invalid rules %+v", bad)
		}
		if err := vlan.SyncFW3DNSBypassInclude(scriptPath, bad, runner); err == nil {
			t.Fatalf("expected SyncFW3DNSBypassInclude to reject invalid rules %+v", bad)
		}
	}
	if _, err := os.Stat(nftFile); err != nil {
		t.Fatalf("valid nft file must survive validation error: %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("valid fw3 script must survive validation error: %v", err)
	}

	// 5. Empty rules remove both nft include and fw3 script + UCI section idempotently.
	if err := vlan.SyncFW4DNSBypassInclude(fw4Root, nil); err != nil {
		t.Fatalf("SyncFW4DNSBypassInclude(nil) failed: %v", err)
	}
	if _, err := os.Stat(nftFile); !os.IsNotExist(err) {
		t.Fatalf("expected nft file deleted on empty rules, err=%v", err)
	}
	cmds = nil
	if err := vlan.SyncFW3DNSBypassInclude(scriptPath, nil, runner); err != nil {
		t.Fatalf("SyncFW3DNSBypassInclude(nil) failed: %v", err)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Fatalf("expected fw3 script deleted on empty rules, err=%v", err)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "uci delete firewall.singctl_vlan_dns") {
		t.Fatalf("expected uci delete firewall.singctl_vlan_dns, got:\n%s", strings.Join(cmds, "\n"))
	}
}

func TestVLAN_SyncFW4AndFW3SideDNSBypassInclude(t *testing.T) {
	// 1. With sideRouterIP and multiple VLAN CIDRs.
	fw4Root := t.TempDir()
	cidrs := []string{"192.168.89.0/24", "192.168.34.0/24"}
	if err := vlan.SyncFW4SideDNSBypassInclude(fw4Root, "192.168.55.88", cidrs); err != nil {
		t.Fatalf("SyncFW4SideDNSBypassInclude failed: %v", err)
	}
	nftFile := filepath.Join(fw4Root, "chain-pre", "dstnat", "singctl-side-dns.nft")
	stNFT, err := os.Stat(nftFile)
	if err != nil || stNFT.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on %s, err=%v mode=%v", nftFile, err, stNFT.Mode().Perm())
	}
	nftRaw, err := os.ReadFile(nftFile)
	if err != nil {
		t.Fatalf("read fw4 side dns nft: %v", err)
	}
	nftText := string(nftRaw)
	for _, want := range []string{
		`ip saddr 192.168.55.88 meta l4proto { tcp, udp } th dport 53 accept comment "singctl-side-dns"`,
		`ip daddr 192.168.55.88 meta l4proto { tcp, udp } th dport 53 accept comment "singctl-side-dns"`,
		`ip saddr { 192.168.34.0/24, 192.168.89.0/24 } meta l4proto { tcp, udp } th dport 53 accept comment "singctl-side-dns"`,
	} {
		if !strings.Contains(nftText, want) {
			t.Fatalf("fw4 side dns nft missing %q:\n%s", want, nftText)
		}
	}

	scriptPath := filepath.Join(t.TempDir(), "etc", "singctl", "vlan-side-dns.fw3.sh")
	var cmds []string
	uciPresent := false
	runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
		line := name + " " + strings.Join(args, " ")
		cmds = append(cmds, line)
		switch line {
		case "uci -q get firewall.singctl_vlan_side_dns":
			if !uciPresent {
				return nil, os.ErrNotExist
			}
		case "uci set firewall.singctl_vlan_side_dns=include":
			uciPresent = true
		case "uci delete firewall.singctl_vlan_side_dns":
			uciPresent = false
		}
		return nil, nil
	}
	if err := vlan.SyncFW3SideDNSBypassInclude(scriptPath, "192.168.55.88", cidrs, runner); err != nil {
		t.Fatalf("SyncFW3SideDNSBypassInclude failed: %v", err)
	}
	stFW3, err := os.Stat(scriptPath)
	if err != nil || stFW3.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 perm on %s, err=%v mode=%v", scriptPath, err, stFW3.Mode().Perm())
	}
	fw3Raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read fw3 side dns script: %v", err)
	}
	fw3Text := string(fw3Raw)
	for _, want := range []string{
		"iptables -w 2 -t nat -I PREROUTING 1 -s 192.168.55.88/32 -p udp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
		"iptables -w 2 -t nat -I PREROUTING 1 -s 192.168.55.88/32 -p tcp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
		"iptables -w 2 -t nat -I PREROUTING 1 -d 192.168.55.88/32 -p udp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
		"iptables -w 2 -t nat -I PREROUTING 1 -d 192.168.55.88/32 -p tcp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
		"iptables -w 2 -t nat -I PREROUTING 1 -s 192.168.34.0/24 -p udp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
		"iptables -w 2 -t nat -I PREROUTING 1 -s 192.168.89.0/24 -p tcp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
	} {
		if !strings.Contains(fw3Text, want) {
			t.Fatalf("fw3 side dns script missing %q:\n%s", want, fw3Text)
		}
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "uci set firewall.singctl_vlan_side_dns=include") {
		t.Fatalf("expected UCI firewall.singctl_vlan_side_dns=include, got:\n%s", strings.Join(cmds, "\n"))
	}

	// 2. Pure delegated single-LAN mode (sideRouterIP set, cidrs nil): still keeps saddr/daddr sideRouterIP rules.
	if err := vlan.SyncFW4SideDNSBypassInclude(fw4Root, "192.168.55.88", nil); err != nil {
		t.Fatalf("SyncFW4SideDNSBypassInclude(nil cidrs) failed: %v", err)
	}
	nftSingleRaw, _ := os.ReadFile(nftFile)
	nftSingle := string(nftSingleRaw)
	if !strings.Contains(nftSingle, "ip saddr 192.168.55.88") || !strings.Contains(nftSingle, "ip daddr 192.168.55.88") || strings.Contains(nftSingle, "192.168.89.0/24") {
		t.Fatalf("expected only sideRouterIP rules in pure delegated mode, got:\n%s", nftSingle)
	}
	if err := vlan.SyncFW3SideDNSBypassInclude(scriptPath, "192.168.55.88", nil, runner); err != nil {
		t.Fatalf("SyncFW3SideDNSBypassInclude(nil cidrs) failed: %v", err)
	}
	fw3SingleRaw, _ := os.ReadFile(scriptPath)
	fw3Single := string(fw3SingleRaw)
	if !strings.Contains(fw3Single, "-s 192.168.55.88/32") || !strings.Contains(fw3Single, "-d 192.168.55.88/32") || strings.Contains(fw3Single, "192.168.89.0/24") {
		t.Fatalf("expected only sideRouterIP rules in fw3 pure delegated mode, got:\n%s", fw3Single)
	}

	// 3. Rejects invalid/injection/loopback sideRouterIP or CIDRs without corrupting existing files.
	for _, tc := range []struct {
		ip    string
		cidrs []string
	}{
		{ip: "192.168.55.88;rm", cidrs: cidrs},
		{ip: "127.0.0.1", cidrs: cidrs},
		{ip: "192.168.55.88", cidrs: []string{"192.168.89.0/24;id"}},
	} {
		if err := vlan.SyncFW4SideDNSBypassInclude(fw4Root, tc.ip, tc.cidrs); err == nil {
			t.Fatalf("expected SyncFW4SideDNSBypassInclude to reject (%q, %v)", tc.ip, tc.cidrs)
		}
		if err := vlan.SyncFW3SideDNSBypassInclude(scriptPath, tc.ip, tc.cidrs, runner); err == nil {
			t.Fatalf("expected SyncFW3SideDNSBypassInclude to reject (%q, %v)", tc.ip, tc.cidrs)
		}
	}
	if _, err := os.Stat(nftFile); err != nil {
		t.Fatalf("existing nft file should survive validation failure: %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("existing fw3 script should survive validation failure: %v", err)
	}

	// 4. Empty sideRouterIP removes both files and UCI section idempotently.
	if err := vlan.SyncFW4SideDNSBypassInclude(fw4Root, "", nil); err != nil {
		t.Fatalf("SyncFW4SideDNSBypassInclude(empty) failed: %v", err)
	}
	if _, err := os.Stat(nftFile); !os.IsNotExist(err) {
		t.Fatalf("expected nft file removed on empty sideRouterIP, err=%v", err)
	}
	cmds = nil
	if err := vlan.SyncFW3SideDNSBypassInclude(scriptPath, "", nil, runner); err != nil {
		t.Fatalf("SyncFW3SideDNSBypassInclude(empty) failed: %v", err)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Fatalf("expected fw3 script removed on empty sideRouterIP, err=%v", err)
	}
	if !strings.Contains(strings.Join(cmds, "\n"), "uci delete firewall.singctl_vlan_side_dns") {
		t.Fatalf("expected uci delete firewall.singctl_vlan_side_dns, got:\n%s", strings.Join(cmds, "\n"))
	}
}

func TestVLAN_ApplyRuntimeDNSAndSideDNSBypass(t *testing.T) {
	t.Run("openwrt24_nft_dnsmasq_fw4_singbox", func(t *testing.T) {
		var cmds []string
		runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			switch line {
			case "nft -a list chain inet dnsmasq prerouting":
				return []byte("table inet dnsmasq {\n\tchain prerouting {\n\t\tip saddr 192.168.99.0/24 meta l4proto { tcp, udp } th dport 53 accept comment \"singctl-side-dns\" # handle 11\n\t\tip saddr 192.168.77.0/24 ip daddr 1.1.1.1 meta l4proto { tcp, udp } th dport 53 accept comment \"singctl-vlan-dns\" # handle 12\n\t\tmeta nfproto { ipv4, ipv6 } udp dport 53 counter redirect to :53 comment \"DNSMASQ HIJACK\" # handle 99\n\t}\n}\n"), nil
			case "nft -a list chain inet fw4 dstnat":
				return []byte("table inet fw4 {\n\tchain dstnat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n\t\tip saddr 192.168.99.0/24 meta l4proto { tcp, udp } th dport 53 accept comment \"singctl-side-dns\" # handle 21\n\t}\n}\n"), nil
			case "nft -a list chain inet sing-box prerouting":
				return []byte("table inet sing-box {\n\tchain prerouting {\n\t\tmeta l4proto { tcp, udp } th dport 53 tproxy to :7895 # handle 55\n\t}\n}\n"), nil
			default:
				return nil, context.DeadlineExceeded
			}
		}

		if err := vlan.ApplyRuntimeSideDNSBypass(t.Context(), "192.168.55.88", []string{"192.168.89.0/24"}, runner); err != nil {
			t.Fatalf("ApplyRuntimeSideDNSBypass failed: %v", err)
		}
		if err := vlan.ApplyRuntimeDNSBypass(t.Context(), []vlan.VLANDNSBypassRule{{CIDR: "192.168.34.0/24", DNSIPs: []string{"223.5.5.5"}}}, runner); err != nil {
			t.Fatalf("ApplyRuntimeDNSBypass failed: %v", err)
		}

		joined := strings.Join(cmds, "\n")
		for _, want := range []string{
			"nft delete rule inet dnsmasq prerouting handle 11",
			"nft delete rule inet fw4 dstnat handle 21",
			"nft delete rule inet dnsmasq prerouting handle 12",
			"nft insert rule inet dnsmasq prerouting ip saddr 192.168.89.0/24 meta l4proto { tcp, udp } th dport 53 accept comment singctl-side-dns",
			"nft insert rule inet dnsmasq prerouting ip saddr 192.168.55.88 meta l4proto { tcp, udp } th dport 53 accept comment singctl-side-dns",
			"nft insert rule inet dnsmasq prerouting ip daddr 192.168.55.88 meta l4proto { tcp, udp } th dport 53 accept comment singctl-side-dns",
			"nft insert rule inet fw4 dstnat ip saddr 192.168.89.0/24 meta l4proto { tcp, udp } th dport 53 accept comment singctl-side-dns",
			"nft insert rule inet sing-box prerouting ip saddr 192.168.89.0/24 meta l4proto { tcp, udp } th dport 53 accept comment singctl-side-dns",
			"nft insert rule inet dnsmasq prerouting ip saddr 192.168.34.0/24 ip daddr 223.5.5.5 meta l4proto { tcp, udp } th dport 53 accept comment singctl-vlan-dns",
			"nft insert rule inet fw4 dstnat ip saddr 192.168.34.0/24 ip daddr 223.5.5.5 meta l4proto { tcp, udp } th dport 53 accept comment singctl-vlan-dns",
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("missing nft command %q in:\n%s", want, joined)
			}
		}
		for _, forbid := range []string{"handle 99", "handle 55"} {
			if strings.Contains(joined, forbid) {
				t.Fatalf("must not delete non-singctl handle %q:\n%s", forbid, joined)
			}
		}
	})

	t.Run("openwrt21_iptables_nat_prerouting_and_mangle_sing_box", func(t *testing.T) {
		var cmds []string
		runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			line := name + " " + strings.Join(args, " ")
			cmds = append(cmds, line)
			switch line {
			case "iptables -t nat -S PREROUTING":
				return []byte("-P PREROUTING ACCEPT\n-A PREROUTING -s 192.168.99.0/24 -p udp -m udp --dport 53 -m comment --comment \"singctl-side-dns\" -j ACCEPT\n-A PREROUTING -p udp -m comment --comment \"DNSMASQ\" -m udp --dport 53 -j REDIRECT --to-ports 53\n"), nil
			case "iptables -t mangle -S SING_BOX":
				return []byte("-N SING_BOX\n-A SING_BOX -s 192.168.77.0/24 -d 1.1.1.1/32 -p udp -m udp --dport 53 -m comment --comment \"singctl-vlan-dns\" -j RETURN\n"), nil
			default:
				return nil, context.DeadlineExceeded
			}
		}

		if err := vlan.ApplyRuntimeSideDNSBypass(t.Context(), "192.168.55.88", []string{"192.168.89.0/24"}, runner); err != nil {
			t.Fatalf("ApplyRuntimeSideDNSBypass failed: %v", err)
		}
		if err := vlan.ApplyRuntimeDNSBypass(t.Context(), []vlan.VLANDNSBypassRule{{CIDR: "192.168.34.0/24", DNSIPs: []string{"192.168.55.88"}}}, runner); err != nil {
			t.Fatalf("ApplyRuntimeDNSBypass failed: %v", err)
		}

		joined := strings.Join(cmds, "\n")
		for _, want := range []string{
			"iptables -t nat -D PREROUTING -s 192.168.99.0/24 -p udp -m udp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
			"iptables -t nat -I PREROUTING 1 -s 192.168.89.0/24 -p udp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
			"iptables -t nat -I PREROUTING 1 -s 192.168.89.0/24 -p tcp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
			"iptables -t nat -I PREROUTING 1 -s 192.168.55.88/32 -p udp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
			"iptables -t nat -I PREROUTING 1 -d 192.168.55.88/32 -p tcp --dport 53 -m comment --comment singctl-side-dns -j ACCEPT",
			"iptables -t mangle -D SING_BOX -s 192.168.77.0/24 -d 1.1.1.1/32 -p udp -m udp --dport 53 -m comment --comment singctl-vlan-dns -j RETURN",
			"iptables -t nat -I PREROUTING 1 -s 192.168.34.0/24 -d 192.168.55.88 -p udp --dport 53 -m comment --comment singctl-vlan-dns -j ACCEPT",
			"iptables -t mangle -I SING_BOX 1 -s 192.168.34.0/24 -d 192.168.55.88 -p tcp --dport 53 -m comment --comment singctl-vlan-dns -j RETURN",
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("missing iptables command %q in:\n%s", want, joined)
			}
		}
		if strings.Contains(joined, "-D PREROUTING -p udp -m comment --comment DNSMASQ") {
			t.Fatalf("must NEVER delete DNSMASQ rule:\n%s", joined)
		}
	})

	t.Run("side_route_integration_apply_single_lan_suspend_and_concurrent_race", func(t *testing.T) {
		var mu sync.Mutex
		var natRules []string
		var active atomic.Int32
		var overlapped atomic.Bool

		runner := func(_ context.Context, name string, args ...string) ([]byte, error) {
			if active.Add(1) > 1 {
				overlapped.Store(true)
			}
			defer active.Add(-1)
			line := name + " " + strings.Join(args, " ")
			switch {
			case line == "ip -4 rule show":
				return []byte("18810:\tfrom 192.168.89.0/24 lookup 188\n"), nil
			case strings.HasPrefix(line, "ip -4 "):
				return nil, nil
			case line == "iptables -t nat -S PREROUTING":
				mu.Lock()
				defer mu.Unlock()
				lines := append([]string{"-P PREROUTING ACCEPT"}, natRules...)
				return []byte(strings.Join(lines, "\n") + "\n"), nil
			case strings.HasPrefix(line, "iptables -t nat -D PREROUTING "):
				spec := strings.TrimPrefix(line, "iptables -t nat -D PREROUTING ")
				spec = strings.Replace(spec, "singctl-side-dns", `"singctl-side-dns"`, 1)
				rule := "-A PREROUTING " + spec
				mu.Lock()
				if idx := slices.Index(natRules, rule); idx >= 0 {
					natRules = append(natRules[:idx], natRules[idx+1:]...)
				}
				mu.Unlock()
				return nil, nil
			case strings.HasPrefix(line, "iptables -t nat -I PREROUTING 1 "):
				spec := strings.TrimPrefix(line, "iptables -t nat -I PREROUTING 1 ")
				spec = strings.Replace(spec, "singctl-side-dns", `"singctl-side-dns"`, 1)
				rule := "-A PREROUTING " + spec
				mu.Lock()
				natRules = append([]string{rule}, natRules...)
				mu.Unlock()
				return nil, nil
			default:
				return nil, context.DeadlineExceeded
			}
		}

		// Apply with VLANs -> creates rules for sideRouterIP + 192.168.89.0/24.
		if err := vlan.ApplyRuntimeSideRoutes(t.Context(), vlan.VLANSideRouteSpec{
			SideRouterIP: "192.168.55.88",
			CIDRs:        []string{"192.168.89.0/24"},
		}, runner); err != nil {
			t.Fatalf("ApplyRuntimeSideRoutes(with VLAN) failed: %v", err)
		}
		mu.Lock()
		joinedWithVLAN := strings.Join(natRules, "\n")
		mu.Unlock()
		if !strings.Contains(joinedWithVLAN, "192.168.89.0/24") || !strings.Contains(joinedWithVLAN, "192.168.55.88/32") {
			t.Fatalf("expected both 192.168.89.0/24 and 192.168.55.88/32 in PREROUTING:\n%s", joinedWithVLAN)
		}

		// Apply with sideRouterIP only (cidrs=nil) -> drops 192.168.89.0/24, keeps 192.168.55.88/32!
		if err := vlan.ApplyRuntimeSideRoutes(t.Context(), vlan.VLANSideRouteSpec{
			SideRouterIP: "192.168.55.88",
		}, runner); err != nil {
			t.Fatalf("ApplyRuntimeSideRoutes(single-LAN delegated) failed: %v", err)
		}
		mu.Lock()
		joinedSingle := strings.Join(natRules, "\n")
		mu.Unlock()
		if strings.Contains(joinedSingle, "192.168.89.0/24") || !strings.Contains(joinedSingle, "192.168.55.88/32") {
			t.Fatalf("expected only 192.168.55.88/32 kept in single-LAN delegated mode:\n%s", joinedSingle)
		}

		// Suspend -> clears singctl-side-dns completely so failover to main router dnsmasq works.
		if err := vlan.SuspendRuntimeSideRoutes(t.Context(), runner); err != nil {
			t.Fatalf("SuspendRuntimeSideRoutes failed: %v", err)
		}
		mu.Lock()
		remainingAfterSuspend := len(natRules)
		mu.Unlock()
		if remainingAfterSuspend != 0 {
			t.Fatalf("expected 0 singctl-side-dns rules after SuspendRuntimeSideRoutes, got %v", natRules)
		}

		// Concurrent -race safety across ApplyRuntimeSideRoutes, SuspendRuntimeSideRoutes, and ApplyRuntimeDNSBypass.
		var wg sync.WaitGroup
		for i := range 6 {
			wg.Go(func() {
				switch i % 3 {
				case 0:
					_ = vlan.ApplyRuntimeSideRoutes(t.Context(), vlan.VLANSideRouteSpec{
						SideRouterIP: "192.168.55.88",
						CIDRs:        []string{"192.168.89.0/24"},
					}, runner)
				case 1:
					_ = vlan.SuspendRuntimeSideRoutes(t.Context(), runner)
				default:
					_ = vlan.ApplyRuntimeDNSBypass(t.Context(), []vlan.VLANDNSBypassRule{{CIDR: "192.168.34.0/24", DNSIPs: []string{"223.5.5.5"}}}, runner)
				}
			})
		}
		wg.Wait()
		if overlapped.Load() {
			t.Fatal("expected concurrent firewall mutations to serialize via mutex")
		}
	})
}
