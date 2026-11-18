package test

import (
	"singctl/internal/firewall"
	"strings"
	"testing"
)

func TestBuildSecurityNFT_SanitizedAndExcludesActiveSSH(t *testing.T) {
	// Default SSH on port 22 with public client IP 198.51.100.42
	nftDefaultSSH := firewall.BuildSecurityNFT("198.51.100.42 54321 203.0.113.10 22", []int{22})

	if !strings.Contains(nftDefaultSSH, "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 198.51.100.42") {
		t.Fatalf("expected RFC1918 + CGNAT + active SSH client IP in whitelist_ip, got:\n%s", nftDefaultSSH)
	}

	// Ensure port 22 is excluded when SSH runs on 22, while Telnet (23) and FTP (21) remain protected
	if strings.Contains(nftDefaultSSH, "\n            22,\n") {
		t.Fatalf("port 22 must be excluded from protected_ports when sshd listens on 22:\n%s", nftDefaultSSH)
	}
	if !strings.Contains(nftDefaultSSH, "21,") || !strings.Contains(nftDefaultSSH, "23,") {
		t.Fatalf("expected FTP (21) and Telnet (23) to remain protected:\n%s", nftDefaultSSH)
	}

	// When SSH has been hardened to port 22222, port 22 SHOULD be protected
	nftCustomSSH := firewall.BuildSecurityNFT("2001:db8::99 54321 2001:db8::1 22222", []int{22222})
	if !strings.Contains(nftCustomSSH, "\n            22,\n") {
		t.Fatalf("expected port 22 to be protected when sshd moved to 22222:\n%s", nftCustomSSH)
	}
	if !strings.Contains(nftCustomSSH, "set whitelist_ip6") || !strings.Contains(nftCustomSSH, "2001:db8::99") {
		t.Fatalf("expected IPv6 SSH client to be added to whitelist_ip6:\n%s", nftCustomSSH)
	}
}

func TestBuildFirewallSystemdUnit_PreloadsModuleAndRetriesBootNetlink(t *testing.T) {
	unit := firewall.BuildFirewallSystemdUnit("/etc/sing-box/sec_block.nft")
	if !strings.Contains(unit, "modprobe nf_tables") {
		t.Fatalf("expected systemd unit to preload nf_tables module, got:\n%s", unit)
	}
	if !strings.Contains(unit, "while [") || !strings.Contains(unit, "/etc/sing-box/sec_block.nft") {
		t.Fatalf("expected systemd unit ExecStart to retry nft -f on early boot Netlink race, got:\n%s", unit)
	}
}

func TestBuildMinimalBlocklistNFT_ZeroPortTouchAndWhitelistsPrivate(t *testing.T) {
	rules := firewall.BuildMinimalBlocklistNFT()
	for _, required := range []string{
		"table inet security",
		"set blocklist_ip4_forever",
		"set blocklist_ip4",
		"set blocklist_ip6",
		"set whitelist_ip",
		"ct state established,related counter accept",
		"100.64.0.0/10",
	} {
		if !strings.Contains(rules, required) {
			t.Fatalf("minimal blocklist NFT missing %q:\n%s", required, rules)
		}
	}
	if strings.Contains(rules, "protected_ports") {
		t.Fatalf("minimal fallback blocklist NFT must not touch any ports:\n%s", rules)
	}
}
