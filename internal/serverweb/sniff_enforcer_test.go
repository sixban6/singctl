package serverweb

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestSniffEnforcer_TableDrivenBoundaries(t *testing.T) {
	protected := map[string]struct{}{
		"198.51.100.10": {},
		"203.0.113.25":  {},
	}

	t.Run("rejects_malformed_injection_private_and_protected_targets", func(t *testing.T) {
		badTargets := []string{
			"",
			"   ",
			"198.51.100.1;rm -rf /",
			"$(whoami)",
			"198.51.100.999",
			"127.0.0.1",
			"192.168.1.5",
			"100.64.0.5",
			"198.51.100.10",    // exact protected operator IP
			"203.0.113.0/24",   // subnet containing protected client IP
			"198.51.0.0/8",     // overly broad IPv4 mask
			"2001:db8::/16",    // overly broad IPv6 mask
			"192.168.1.0/24",   // private CIDR
		}
		for _, raw := range badTargets {
			if _, err := validateSniffBlockTarget(raw, protected, true); err == nil {
				t.Errorf("expected validateSniffBlockTarget(%q) to fail, got nil", raw)
			}
		}
	})

	t.Run("normalizes_valid_ipv4_ipv6_and_cidr_targets", func(t *testing.T) {
		spec4, err := validateSniffBlockTarget(" 198.51.100.55 ", protected, true)
		if err != nil || spec4.isCIDR || !spec4.isIPv4 || spec4.canonical != "198.51.100.55" {
			t.Fatalf("unexpected IPv4 spec: %+v err=%v", spec4, err)
		}

		spec6, err := validateSniffBlockTarget("[2001:db8::1]", protected, true)
		if err != nil || spec6.isCIDR || spec6.isIPv4 || spec6.canonical != "2001:db8::1" {
			t.Fatalf("unexpected IPv6 spec: %+v err=%v", spec6, err)
		}

		specCIDR, err := validateSniffBlockTarget("203.0.114.99/24", protected, true)
		if err != nil || !specCIDR.isCIDR || !specCIDR.isIPv4 || specCIDR.canonical != "203.0.114.0/24" || specCIDR.parsedNet == nil {
			t.Fatalf("unexpected CIDR spec: %+v err=%v", specCIDR, err)
		}
	})

	t.Run("unblock_mode_allows_private_cleanup_and_rejects_injection", func(t *testing.T) {
		if _, err := validateSniffBlockTarget("192.168.1.5;id", protected, false); err == nil {
			t.Fatal("expected unblock validation to still reject shell injection")
		}
		spec, err := validateSniffBlockTarget("198.51.100.10", protected, false)
		if err != nil || spec.canonical != "198.51.100.10" {
			t.Fatalf("expected unblock mode to allow canonical target parsing, got %+v err=%v", spec, err)
		}
	})

	t.Run("enforcer_block_unblock_lifecycle_and_race_safety", func(t *testing.T) {
		// Isolate from host firewall binaries so test runs deterministically without touching host PATH nft
		t.Setenv("PATH", t.TempDir())
		dir := t.TempDir()
		sniffPath := filepath.Join(dir, "sniff.json")
		lim := NewIPLimiter(5, time.Minute, time.Hour, filepath.Join(dir, "bans.json"))
		defer lim.Close()

		tr := NewSniffTracker(nil, lim, sniffPath)
		tr.EnableSystemProbe = false
		ctx := t.Context()

		canon, nodes, err := tr.BlockTargetForNode(ctx, "203.0.114.88", "local", "198.51.100.10")
		if err != nil || canon != "203.0.114.88" || nodes == 0 {
			t.Fatalf("BlockTargetForNode failed: canon=%q nodes=%d err=%v", canon, nodes, err)
		}
		fi, err := os.Stat(sniffPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 sniff.json after block, got %v (err=%v)", fi, err)
		}

		unCanon, uNodes, err := tr.UnblockTargetForNode(ctx, "203.0.114.88", "local")
		if err != nil || unCanon != "203.0.114.88" || uNodes == 0 {
			t.Fatalf("UnblockTargetForNode failed: canon=%q nodes=%d err=%v", unCanon, uNodes, err)
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = validateSniffBlockTarget("203.0.114.88", protected, true)
			}()
		}
		wg.Wait()
		_ = net.IPv4len
	})
}
