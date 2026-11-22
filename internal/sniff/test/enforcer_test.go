// 文件职责：覆盖 sniff 封禁执行器的防自锁边界、CIDR 掩码校验、命令注入拦截、本机 nft 自举与集群远端回调执行单测。
package sniff_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/sniff"
)

type fakeBanLimiter struct {
	mu       sync.Mutex
	rev      atomic.Uint64
	attempts map[string]sniff.LimiterAttempt
}

func newFakeBanLimiter() *fakeBanLimiter {
	return &fakeBanLimiter{attempts: make(map[string]sniff.LimiterAttempt)}
}

func (f *fakeBanLimiter) Revision() uint64 { return f.rev.Load() }

func (f *fakeBanLimiter) ListAllAttempts() []sniff.LimiterAttempt {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]sniff.LimiterAttempt, 0, len(f.attempts))
	for _, v := range f.attempts {
		out = append(out, v)
	}
	return out
}

func (f *fakeBanLimiter) BanManual(ip string, _ time.Duration, _ ...string) {
	f.mu.Lock()
	f.attempts[ip] = sniff.LimiterAttempt{IP: ip, FailCount: 3, LastFail: time.Now(), Banned: true, Source: sniff.BanSourceManualSniff}
	f.rev.Add(1)
	f.mu.Unlock()
}

func (f *fakeBanLimiter) Unban(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ip == "all" {
		clear(f.attempts)
	} else {
		delete(f.attempts, ip)
	}
	f.rev.Add(1)
	return true
}

func (f *fakeBanLimiter) recordLoginFail(ip string) {
	f.mu.Lock()
	f.attempts[ip] = sniff.LimiterAttempt{IP: ip, FailCount: 2, LastFail: time.Now(), Banned: false, Source: "login_fail"}
	f.rev.Add(1)
	f.mu.Unlock()
}

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
			"198.51.100.10",
			"203.0.113.0/24",
			"198.51.0.0/8",
			"2001:db8::/16",
			"192.168.1.0/24",
		}
		for _, raw := range badTargets {
			if _, err := sniff.ValidateBlockTarget(raw, protected, true); err == nil {
				t.Errorf("expected ValidateBlockTarget(%q) to fail, got nil", raw)
			}
		}
	})

	t.Run("normalizes_valid_ipv4_ipv6_and_cidr_targets", func(t *testing.T) {
		spec4, err := sniff.ValidateBlockTarget(" 198.51.100.55 ", protected, true)
		if err != nil || spec4.IsCIDR || !spec4.IsIPv4 || spec4.Canonical != "198.51.100.55" {
			t.Fatalf("unexpected IPv4 spec: %+v err=%v", spec4, err)
		}

		spec6, err := sniff.ValidateBlockTarget("[2001:db8::1]", protected, true)
		if err != nil || spec6.IsCIDR || spec6.IsIPv4 || spec6.Canonical != "2001:db8::1" {
			t.Fatalf("unexpected IPv6 spec: %+v err=%v", spec6, err)
		}

		specCIDR, err := sniff.ValidateBlockTarget("203.0.114.99/24", protected, true)
		if err != nil || !specCIDR.IsCIDR || !specCIDR.IsIPv4 || specCIDR.Canonical != "203.0.114.0/24" || specCIDR.ParsedNet == nil {
			t.Fatalf("unexpected CIDR spec: %+v err=%v", specCIDR, err)
		}
	})

	t.Run("unblock_mode_allows_private_cleanup_and_rejects_injection", func(t *testing.T) {
		if _, err := sniff.ValidateBlockTarget("192.168.1.5;id", protected, false); err == nil {
			t.Fatal("expected unblock validation to still reject shell injection")
		}
		spec, err := sniff.ValidateBlockTarget("198.51.100.10", protected, false)
		if err != nil || spec.Canonical != "198.51.100.10" {
			t.Fatalf("expected unblock mode to allow canonical target parsing, got %+v err=%v", spec, err)
		}
	})

	t.Run("enforcer_block_unblock_remote_callback_and_0600_persistence", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		dir := t.TempDir()
		sniffPath := filepath.Join(dir, "sniff.json")
		lim := newFakeBanLimiter()

		tr := sniff.NewTracker(nil, lim, sniffPath)
		tr.EnableSystemProbe = false

		var remoteCalls atomic.Int32
		tr.SetRemoteProvider(&sniff.RemoteProvider{
			ListTargets: func() ([]sniff.RemoteTarget, error) {
				return []sniff.RemoteTarget{
					{ID: "sg1", Name: "SG Edge", Host: "192.0.2.50", Enabled: true, Online: true},
				}, nil
			},
			Revision: func() uint64 { return 1 },
			Exec: func(_ context.Context, _ sniff.RemoteTarget, script string) (string, int, error) {
				if strings.Contains(script, "203.0.114.88") {
					remoteCalls.Add(1)
				}
				return "", 5, nil
			},
		})

		ctx := t.Context()
		// Must refuse locking out remote cluster node host IP 192.0.2.50!
		if _, _, err := tr.BlockTargetForNode(ctx, "192.0.2.50", "all", "198.51.100.10"); err == nil {
			t.Fatal("expected anti-lockout guard to protect cluster node host IP 192.0.2.50")
		}

		canon, nodes, err := tr.BlockTargetForNode(ctx, "203.0.114.88", "all", "198.51.100.10")
		if err != nil || canon != "203.0.114.88" || nodes != 2 || remoteCalls.Load() != 1 {
			t.Fatalf("BlockTargetForNode failed: canon=%q nodes=%d remoteCalls=%d err=%v", canon, nodes, remoteCalls.Load(), err)
		}
		fi, err := os.Stat(sniffPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 sniff.json after block, got %v (err=%v)", fi, err)
		}

		unCanon, uNodes, err := tr.UnblockTargetForNode(ctx, "203.0.114.88", "all")
		if err != nil || unCanon != "203.0.114.88" || uNodes != 2 {
			t.Fatalf("UnblockTargetForNode failed: canon=%q nodes=%d err=%v", unCanon, uNodes, err)
		}
	})
}

func TestSniffEnforcer_NFTTableAutoBootstrapOnMissingSecurityTable(t *testing.T) {
	remoteIPScript := sniff.BuildRemoteNFTBlockScript("203.0.113.88", false, true)
	for _, want := range []string{
		"nft list table inet security",
		"modprobe nf_tables",
		"table inet security",
		"blocklist_ip4",
		"203.0.113.88",
	} {
		if !strings.Contains(remoteIPScript, want) {
			t.Fatalf("remote block script missing %q:\n%s", want, remoteIPScript)
		}
	}
	if s := sniff.BuildRemoteNFTUnblockScript("203.0.113.0/24", true, true); !strings.Contains(s, "203.0.113.0/24") {
		t.Fatalf("unexpected remote NFT unblock script: %s", s)
	}
	if s := sniff.BuildRemoteNFTFlushScript(); s == "" {
		t.Fatal("expected non-empty remote NFT flush script")
	}

	binDir := t.TempDir()
	stateFile := filepath.Join(binDir, "table_loaded")
	logFile := filepath.Join(binDir, "nft_calls.log")
	fakeNFT := filepath.Join(binDir, "nft")
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %q
if [ "$1" = "list" ] && [ "$2" = "table" ] && [ "$3" = "inet" ] && [ "$4" = "security" ]; then
  [ -f %q ] && exit 0 || exit 1
fi
if [ "$1" = "-f" ]; then
  touch %q
  exit 0
fi
if [ "$1" = "add" ] && [ "$2" = "element" ]; then
  [ -f %q ] && exit 0 || exit 1
fi
exit 0
`, logFile, stateFile, stateFile, stateFile)
	if err := os.WriteFile(fakeNFT, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+":"+os.Getenv("PATH"))

	if err := sniff.ApplyNFTBlockIP("203.0.113.77", true); err != nil {
		t.Fatalf("expected ApplyNFTBlockIP to auto-bootstrap missing security table and succeed, got: %v", err)
	}
	callsBytes, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(callsBytes)
	if !strings.Contains(calls, "list table inet security") || !strings.Contains(calls, "-f") || !strings.Contains(calls, "add element inet security blocklist_ip4") {
		t.Fatalf("expected list -> -f bootstrap -> add element sequence, got:\n%s", calls)
	}
}
