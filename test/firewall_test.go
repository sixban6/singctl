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
