// 文件职责：覆盖主机安全防火墙加固 iptables+ip6tables+ipset 独立后端探测、多端口分批诱捕、xt_SET 降级、统计解析、实时增删与 OpenWrt fw3 持久化测试。
package firewall_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/firewall"
)

func TestDetectBackendWith_Precedence(t *testing.T) {
	has := func(bins ...string) func(string) (string, error) {
		return func(file string) (string, error) {
			if slices.Contains(bins, file) {
				return "/usr/sbin/" + file, nil
			}
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		}
	}

	if got := firewall.DetectBackendWith("darwin", has("nft", "iptables", "ipset")); got != firewall.BackendNone {
		t.Fatalf("expected none on non-linux, got %q", got)
	}
	if got := firewall.DetectBackendWith("linux", has("nft", "iptables", "ipset")); got != firewall.BackendNFTables {
		t.Fatalf("expected nftables when nft present, got %q", got)
	}
	if got := firewall.DetectBackendWith("linux", has("iptables", "ipset")); got != firewall.BackendIPTables {
		t.Fatalf("expected iptables when nft missing and iptables+ipset present, got %q", got)
	}
	if got := firewall.DetectBackendWith("linux", has("iptables")); got != firewall.BackendNone {
		t.Fatalf("expected none when ipset missing, got %q", got)
	}
}

func TestIPTablesBackend_RenderScript_MultiportChunkingAndPrefixLimits(t *testing.T) {
	// 18 protected ports -> must chunk into <=15 ports per multiport rule (15 + 3).
	ports := []int{20, 21, 23, 25, 110, 143, 465, 587, 993, 995, 1080, 1433, 1434, 1521, 3306, 3389, 5432, 6379}
	opts := firewall.BuildOptions{
		SSHConnection:        "192.0.2.55 51234 192.0.2.1 2222",
		CallerIP:             "198.51.100.77",
		ActiveSSHPorts:       []int{2222},
		Mode:                 "standard",
		BanTimeoutDays:       14,
		PingLimitPerSec:      20,
		CustomWhitelist:      []string{"203.0.113.10", "2001:db8:cafe::/48"},
		ExtraForeverBan:      []string{"198.51.100.0/24"},
		CustomProtectedPorts: ports,
	}

	b := &firewall.IPTablesBackend{}
	script := b.RenderScript(opts)

	for _, must := range []string{
		"#!/bin/sh",
		"ipset create blocklist_ip4_forever hash:net",
		"ipset create blocklist_ip4 hash:ip family inet timeout 1209600 -exist",
		"ipset create blocklist_ip6 hash:ip family inet6 timeout 1209600 -exist",
		"ipset create whitelist_ip hash:net family inet -exist",
		"ipset create whitelist_ip6 hash:net family inet6 -exist",
		"SINGCTL_SECURITY",
		"iptables -w 5 -N SINGCTL_SECURITY",
		"ip6tables -w 5 -N SINGCTL_SECURITY",
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-i lo -j ACCEPT",
		"-i tailscale0 -j ACCEPT",
		"-i wg+ -j ACCEPT",
		"-i tun+ -j ACCEPT",
		"-i docker0 -j ACCEPT",
		"--limit 20/sec",
		"-m set --match-set whitelist_ip src -j ACCEPT",
		"-m set --match-set blocklist_ip4_forever src",
		"-m set --match-set blocklist_ip4 src",
		"-m multiport --dports 20,21,23,25,110,143,465,587,993,995,1080,1433,1434,1521,3306",
		"-m multiport --dports 3389,5432,6379",
		"-j SET --add-set blocklist_ip4 src",
		"|| true",
		"192.0.2.55",
		"198.51.100.77",
		"203.0.113.10",
		"2001:db8:cafe::/48",
		"198.51.100.0/24",
	} {
		if !strings.Contains(script, must) {
			t.Fatalf("rendered iptables security script missing %q:\n%s", must, script)
		}
	}

	// Verify every --log-prefix is strictly <= 29 bytes (Linux xt_LOG hard limit).
	for line := range strings.SplitSeq(script, "\n") {
		if _, after, ok := strings.Cut(line, `--log-prefix "`); ok {
			if pfx, _, closed := strings.Cut(after, `"`); closed {
				if len(pfx) > 29 {
					t.Fatalf("xt_LOG prefix exceeds 29-byte kernel limit (%d bytes): %q", len(pfx), pfx)
				}
			}
		}
	}

	// Script must pass POSIX sh -n check.
	if shBin, err := exec.LookPath("sh"); err == nil {
		p := filepath.Join(t.TempDir(), "security-iptables.sh")
		if err := os.WriteFile(p, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.CommandContext(t.Context(), shBin, "-n", p).CombinedOutput(); err != nil {
			t.Fatalf("security-iptables.sh failed sh -n: %v (%s)", err, string(out))
		}
	}

	// Minimal mode must omit multiport honeypot rules.
	minScript := b.RenderScript(firewall.BuildOptions{Mode: "minimal"})
	if strings.Contains(minScript, "--dports") || strings.Contains(minScript, "honeypot_") {
		t.Fatalf("minimal mode must not emit honeypot multiport rules:\n%s", minScript)
	}
}

func TestIPTablesBackend_EnableXtSetFallbackPersistenceLiveOpsAndDisable(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "security-iptables.sh")
	fwUserPath := filepath.Join(tmpDir, "firewall.user")
	if err := os.WriteFile(fwUserPath, []byte("# existing user rule\n"), 0600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var cmds []string
	sets := map[string]map[string]int64{}
	chainActive := false

	b := &firewall.IPTablesBackend{
		ScriptPath:       scriptPath,
		FirewallUserPath: fwUserPath,
		IsOpenWrt:        func() bool { return true },
		LookPath: func(file string) (string, error) {
			if file == "iptables" || file == "ip6tables" || file == "ipset" {
				return "/usr/sbin/" + file, nil
			}
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		},
		Runner: func(_ context.Context, _ string, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			full := name + " " + strings.Join(args, " ")
			cmds = append(cmds, full)

			// Simulate kernel lacking xt_SET target -> must gracefully degrade to LOG + DROP!
			if (name == "iptables" || name == "ip6tables") && slices.Contains(args, "SET") {
				return []byte("iptables: No chain/target/match by that name."), errors.New("exit 1")
			}

			if name == "ipset" && len(args) >= 2 {
				switch args[0] {
				case "create":
					if _, ok := sets[args[1]]; !ok {
						sets[args[1]] = map[string]int64{}
					}
				case "add":
					if _, ok := sets[args[1]]; !ok {
						sets[args[1]] = map[string]int64{}
					}
					if len(args) >= 3 {
						sets[args[1]][args[2]] = 604800
					}
				case "del":
					if len(args) >= 3 {
						delete(sets[args[1]], args[2])
					}
				case "flush":
					sets[args[1]] = map[string]int64{}
				case "destroy":
					delete(sets, args[1])
				case "list":
					m, ok := sets[args[1]]
					if !ok {
						return []byte("ipset v7: The set with the given name does not exist"), errors.New("exit 1")
					}
					var sb strings.Builder
					sb.WriteString("Name: " + args[1] + "\nType: hash:ip\nHeader: family inet timeout 604800\nMembers:\n")
					for k, exp := range m {
						if strings.Contains(args[1], "blocklist_ip4") && !strings.Contains(args[1], "forever") || args[1] == "blocklist_ip6" {
							sb.WriteString(k + " timeout 518400\n")
							_ = exp
						} else {
							sb.WriteString(k + "\n")
						}
					}
					return []byte(sb.String()), nil
				}
				return nil, nil
			}

			if (name == "iptables" || name == "ip6tables") && len(args) >= 2 {
				switch args[0] {
				case "-N":
					if args[1] == firewall.IPTablesSecurityChain {
						chainActive = true
					}
				case "-L":
					if !chainActive {
						return []byte("iptables: No chain/target/match by that name."), errors.New("exit 1")
					}
					return []byte("Chain SINGCTL_SECURITY (1 references)\n pkts bytes target prot opt in out source destination\n"), nil
				case "-C":
					return nil, errors.New("exit 1")
				case "-X":
					if args[1] == firewall.IPTablesSecurityChain {
						chainActive = false
					}
				}
			}
			return nil, nil
		},
	}

	opts := firewall.BuildOptions{
		SSHConnection:  "192.0.2.55 51234 192.0.2.1 22",
		ActiveSSHPorts: []int{22},
		Mode:           "standard",
		BanTimeoutDays: 7,
	}
	if err := b.EnableWithOptions(opts, true); err != nil {
		t.Fatalf("EnableWithOptions should gracefully tolerate missing xt_SET, got error: %v", err)
	}

	// Verify script file written with 0700 and /etc/firewall.user contains managed block.
	info, err := os.Stat(scriptPath)
	if err != nil {
		t.Fatalf("expected script at %s: %v", scriptPath, err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 mode on security-iptables.sh, got %04o", info.Mode().Perm())
	}
	fwUserRaw, _ := os.ReadFile(fwUserPath)
	if !strings.Contains(string(fwUserRaw), firewall.SecurityFirewallUserBegin) ||
		!strings.Contains(string(fwUserRaw), scriptPath) ||
		!strings.Contains(string(fwUserRaw), "# existing user rule") {
		t.Fatalf("unexpected firewall.user after Enable:\n%s", string(fwUserRaw))
	}
	if !b.IsSecurityTableActive() {
		t.Fatal("expected IsSecurityTableActive() == true after Enable")
	}
	if stats, err := b.InspectSecurityStats(); err != nil || stats.ForeverCount == 0 || stats.WhitelistCount == 0 {
		t.Fatalf("unexpected InspectSecurityStats: stats=%+v err=%v", stats, err)
	}
	// Verify package-level status/stats helpers compile and return safe non-panicking results on any OS.
	_ = firewall.IsSecurityTableActive()
	_, _ = firewall.InspectSecurityStats()

	// Live ban / unban / flush / whitelist mutations
	cfg := &config.Config{Server: config.ServerConfig{ServerIP: "198.51.100.200"}}
	norm, isV6, err := b.AddLiveBan("203.0.113.42", "dynamic", 7, "198.51.100.1", cfg)
	if err != nil || isV6 || norm != "203.0.113.42" {
		t.Fatalf("AddLiveBan v4 failed: norm=%q isV6=%v err=%v", norm, isV6, err)
	}
	if _, _, err := b.AddLiveBan("192.168.1.50", "dynamic", 7, "198.51.100.1", cfg); err == nil {
		t.Fatal("AddLiveBan must reject private LAN IP")
	}
	if _, _, err := b.AddLiveBan("2001:db8::42", "dynamic", 7, "198.51.100.1", cfg); err != nil {
		t.Fatalf("AddLiveBan v6 failed: %v", err)
	}
	if _, _, err := b.AddLiveBan("203.0.113.0/24", "forever", 0, "198.51.100.1", cfg); err != nil {
		t.Fatalf("AddLiveBan forever CIDR failed: %v", err)
	}

	if err := b.RemoveLiveBan("203.0.113.42", "dynamic_v4"); err != nil {
		t.Fatalf("RemoveLiveBan failed: %v", err)
	}
	if err := b.FlushDynamicBans("all"); err != nil {
		t.Fatalf("FlushDynamicBans failed: %v", err)
	}
	if _, _, err := b.AddWhitelist("203.0.113.99"); err != nil {
		t.Fatalf("AddWhitelist failed: %v", err)
	}
	if _, _, err := b.RemoveWhitelist("203.0.113.99"); err != nil {
		t.Fatalf("RemoveWhitelist failed: %v", err)
	}
	if _, _, err := b.RemoveWhitelist("10.0.0.0/8"); err == nil {
		t.Fatal("RemoveWhitelist must reject builtin anti-lockout whitelist")
	}

	// Clean Disable removes script, strips firewall.user block, deletes chain & ipsets.
	if err := b.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}
	if _, err := os.Stat(scriptPath); !os.IsNotExist(err) {
		t.Fatalf("expected scriptPath removed after Disable, stat err=%v", err)
	}
	fwAfter, _ := os.ReadFile(fwUserPath)
	if strings.Contains(string(fwAfter), firewall.SecurityFirewallUserBegin) || !strings.Contains(string(fwAfter), "# existing user rule") {
		t.Fatalf("Disable corrupted firewall.user:\n%s", string(fwAfter))
	}
	if b.IsSecurityTableActive() {
		t.Fatal("expected IsSecurityTableActive() == false after Disable")
	}
}

func TestParseIPTablesSecuritySnapshot_FullParityWithNFTStats(t *testing.T) {
	v4Out := `Chain SINGCTL_SECURITY (1 references)
    pkts      bytes target     prot opt in     out     source               destination
    1500   120000 ACCEPT     all  --  *      *       0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
      12      840 ACCEPT     icmp --  *      *       0.0.0.0/0            0.0.0.0/0            icmptype 8 limit: avg 15/sec burst 30
       9      540 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blocklist_ip4_forever src LOG flags 0 level 4 prefix "[NFT] Ban Forever IPv4: "
     120     7200 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blocklist_ip4_forever src /* singctl-fw:forever_v4 */
      80     4800 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set blocklist_ip4 src /* singctl-fw:dynamic_v4 */
      35     2100 DROP       tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 23,3389 /* singctl-fw:honeypot_tcp_v4 */
      10      600 DROP       udp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 23,3389 /* singctl-fw:honeypot_udp_v4 */
`
	v6Out := `Chain SINGCTL_SECURITY (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      15      900 DROP       all      *      *       ::/0                 ::/0                 match-set blocklist_ip6 src /* singctl-fw:dynamic_v6 */
       5      300 DROP       tcp      *      *       ::/0                 ::/0                 multiport dports 23,3389 /* singctl-fw:honeypot_tcp_v6 */
       2      120 DROP       udp      *      *       ::/0                 ::/0                 multiport dports 23,3389 /* singctl-fw:honeypot_udp_v6 */
`
	ipsets := map[string]string{
		"blocklist_ip4_forever": "Name: blocklist_ip4_forever\nType: hash:net\nMembers:\n167.94.138.0/24\n198.51.100.0/24\n",
		"blocklist_ip4":         "Name: blocklist_ip4\nType: hash:ip\nHeader: family inet hashsize 1024 maxelem 65535 timeout 604800\nMembers:\n203.0.113.99 timeout 518400\n",
		"blocklist_ip6":         "Name: blocklist_ip6\nType: hash:ip\nHeader: family inet6 hashsize 1024 maxelem 65535 timeout 604800\nMembers:\n2001:db8::99 timeout 3600\n",
		"whitelist_ip":          "Name: whitelist_ip\nType: hash:net\nMembers:\n10.0.0.0/8\n203.0.113.10\n",
		"whitelist_ip6":         "Name: whitelist_ip6\nType: hash:net\nMembers:\n2001:db8:cafe::/48\n",
	}

	snap := firewall.ParseIPTablesSecuritySnapshot(v4Out, v6Out, ipsets)
	if !snap.Active || snap.Mode != "standard" {
		t.Fatalf("expected active standard snapshot, got active=%v mode=%s", snap.Active, snap.Mode)
	}
	if snap.BanTimeoutDays != 7 || snap.PingLimitPerSec != 15 {
		t.Fatalf("unexpected params: timeout=%d ping=%d", snap.BanTimeoutDays, snap.PingLimitPerSec)
	}
	if snap.Stats.ForeverCount != 2 || snap.Stats.DynamicV4Count != 1 || snap.Stats.DynamicV6Count != 1 || snap.Stats.WhitelistCount != 3 {
		t.Fatalf("unexpected counts: %+v", snap.Stats)
	}
	if !slices.Equal(snap.ProtectedPorts, []int{23, 3389}) {
		t.Fatalf("unexpected protected ports: %v", snap.ProtectedPorts)
	}
	if snap.Stats.ForeverBlocked.Packets != 120 || snap.Stats.DynamicV4Blocked.Packets != 80 ||
		snap.Stats.DynamicV6Blocked.Packets != 15 || snap.Stats.HoneypotTCPV4.Packets != 35 ||
		snap.Stats.HoneypotUDPv4.Packets != 10 || snap.Stats.HoneypotTCPV6.Packets != 5 ||
		snap.Stats.HoneypotUDPv6.Packets != 2 {
		t.Fatalf("unexpected per-category counters: %+v", snap.Stats)
	}
	wantTotalPkts := int64(120 + 80 + 15 + 35 + 10 + 5 + 2)
	wantTotalBytes := int64(7200 + 4800 + 900 + 2100 + 600 + 300 + 120)
	if snap.Stats.TotalBlockedPackets != wantTotalPkts || snap.Stats.TotalBlockedBytes != wantTotalBytes {
		t.Fatalf("unexpected totals: got (%d, %d) want (%d, %d)",
			snap.Stats.TotalBlockedPackets, snap.Stats.TotalBlockedBytes, wantTotalPkts, wantTotalBytes)
	}
	if len(snap.DynamicV4) != 1 || snap.DynamicV4[0].ExpiresSec != 518400 {
		t.Fatalf("unexpected DynamicV4 entry: %+v", snap.DynamicV4)
	}
}
