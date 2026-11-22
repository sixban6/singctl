// 文件职责：覆盖行为审计“限速不拉黑”双后端（nftables / iptables xt_limit）、速率换算、DNS 双栈分离解析及 30 分钟韧性缓存测试。
package audit_test

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestCalcThrottlePPS_Boundaries(t *testing.T) {
	cases := []struct {
		rateKBps  int
		wantPPS   int
		wantBurst int
	}{
		{rateKBps: 1, wantPPS: 1, wantBurst: 5},
		{rateKBps: 5, wantPPS: 3, wantBurst: 5},
		{rateKBps: 10, wantPPS: 7, wantBurst: 7},
		{rateKBps: 100, wantPPS: 73, wantBurst: 73},
		{rateKBps: 102400, wantPPS: 10000, wantBurst: 10000},
	}
	for _, tc := range cases {
		pps, burst := audit.CalcThrottlePPS(tc.rateKBps)
		if pps != tc.wantPPS || burst != tc.wantBurst {
			t.Fatalf("CalcThrottlePPS(%d) = (%d, %d), want (%d, %d)", tc.rateKBps, pps, burst, tc.wantPPS, tc.wantBurst)
		}
	}
}

func TestThrottler_IPTablesBackend_ApplyTeardownDualStackAndRace(t *testing.T) {
	ctx := t.Context()
	cfg := &config.Config{
		Server: config.ServerConfig{ServerIP: "198.51.100.250"},
		Audit: config.AuditConfig{
			Throttles: []config.AuditThrottleRule{
				{Target: "iot-cloud.example.com", Port: 443, RateKBps: 10},
				{Target: "203.0.113.80", Port: 0, RateKBps: 1},
				{Target: "2001:db8::80", Port: 8443, RateKBps: 100},
			},
		},
	}

	var mu sync.Mutex
	var cmds []string
	attached := map[string]bool{}

	th := audit.NewThrottlerWithDeps(audit.ThrottlerDeps{
		GOOS: "linux",
		LookPath: func(file string) (string, error) {
			if file == "iptables" || file == "ip6tables" {
				return "/usr/sbin/" + file, nil
			}
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		},
		LookupIPs: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("192.168.1.10"),   // private -> ignored
				netip.MustParseAddr("198.51.100.250"), // server IP -> ignored
				netip.MustParseAddr("203.0.113.69"),   // public IPv4 -> kept
			}, nil
		},
		RunCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			cmds = append(cmds, name+" "+strings.Join(args, " "))
			if len(args) >= 4 && args[0] == "-C" && args[3] == audit.ThrottleIPTablesChain {
				if attached[name+":"+args[1]] {
					return nil, nil
				}
				return nil, errors.New("exit 1")
			}
			if len(args) >= 5 && args[0] == "-I" && args[4] == audit.ThrottleIPTablesChain {
				attached[name+":"+args[1]] = true
			}
			if len(args) >= 4 && args[0] == "-D" && args[3] == audit.ThrottleIPTablesChain {
				delete(attached, name+":"+args[1])
			}
			return nil, nil
		},
	})

	res := th.Apply(ctx, cfg)
	if !res.Applied || res.ActiveRules != 3 || res.ActiveIPs != 3 {
		t.Fatalf("expected iptables Apply to succeed with 3 rules / 3 IPs, got %+v", res)
	}
	if strings.Contains(res.Message, "未检测到 nft") {
		t.Fatalf("iptables backend must not emit missing nft warning: %q", res.Message)
	}

	joined := strings.Join(cmds, "\n")
	for _, want := range []string{
		"iptables -N SINGCTL_AUDIT_THROTTLE",
		"iptables -F SINGCTL_AUDIT_THROTTLE",
		"iptables -A SINGCTL_AUDIT_THROTTLE -o lo -j RETURN",
		"iptables -A SINGCTL_AUDIT_THROTTLE -d 203.0.113.69 -p tcp --dport 443 -m limit --limit 7/sec --limit-burst 7 -j ACCEPT",
		"iptables -A SINGCTL_AUDIT_THROTTLE -d 203.0.113.69 -p tcp --dport 443 -j DROP",
		"iptables -A SINGCTL_AUDIT_THROTTLE -d 203.0.113.69 -p udp --dport 443 -m limit --limit 7/sec --limit-burst 7 -j ACCEPT",
		"iptables -A SINGCTL_AUDIT_THROTTLE -d 203.0.113.80 -p tcp -m limit --limit 1/sec --limit-burst 5 -j ACCEPT",
		"iptables -I FORWARD 1 -j SINGCTL_AUDIT_THROTTLE",
		"iptables -I OUTPUT 1 -j SINGCTL_AUDIT_THROTTLE",
		"ip6tables -A SINGCTL_AUDIT_THROTTLE -d 2001:db8::80 -p tcp --dport 8443 -m limit --limit 73/sec --limit-burst 73 -j ACCEPT",
		"ip6tables -I FORWARD 1 -j SINGCTL_AUDIT_THROTTLE",
		"ip6tables -I OUTPUT 1 -j SINGCTL_AUDIT_THROTTLE",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("iptables execution missing %q:\n%s", want, joined)
		}
	}
	for _, forbidden := range []string{"192.168.1.10", "198.51.100.250"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("iptables rules leaked protected IP %s:\n%s", forbidden, joined)
		}
	}

	// Teardown on empty rules cleans up FORWARD/OUTPUT jumps and deletes SINGCTL_AUDIT_THROTTLE.
	cfg.Audit.Throttles = nil
	resClean := th.Apply(ctx, cfg)
	if !resClean.Applied || resClean.ActiveRules != 0 {
		t.Fatalf("expected clean teardown on iptables backend, got %+v", resClean)
	}
	joinedAfter := strings.Join(cmds, "\n")
	for _, want := range []string{
		"iptables -D FORWARD -j SINGCTL_AUDIT_THROTTLE",
		"iptables -D OUTPUT -j SINGCTL_AUDIT_THROTTLE",
		"iptables -X SINGCTL_AUDIT_THROTTLE",
		"ip6tables -X SINGCTL_AUDIT_THROTTLE",
	} {
		if !strings.Contains(joinedAfter, want) {
			t.Fatalf("teardown missing %q:\n%s", want, joinedAfter)
		}
	}
}

func TestThrottler_AutoDetectBackendPrecedenceAndMissingBoth(t *testing.T) {
	ctx := t.Context()
	cfg := &config.Config{
		Audit: config.AuditConfig{
			Throttles: []config.AuditThrottleRule{{Target: "203.0.113.5", RateKBps: 5}},
		},
	}

	// 1. Both nft and iptables exist -> prefers nft.
	var nftUsed, iptUsed atomic.Bool
	thPreferNFT := audit.NewThrottlerWithDeps(audit.ThrottlerDeps{
		GOOS: "linux",
		LookPath: func(file string) (string, error) {
			return "/usr/sbin/" + file, nil
		},
		RunNFT: func(_ context.Context, _ string) error {
			nftUsed.Store(true)
			return nil
		},
		RunCmd: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			iptUsed.Store(true)
			return nil, nil
		},
	})
	if res := thPreferNFT.Apply(ctx, cfg); !res.Applied || !nftUsed.Load() || iptUsed.Load() {
		t.Fatalf("expected nft preferred over iptables: res=%+v nft=%v ipt=%v", res, nftUsed.Load(), iptUsed.Load())
	}
	if script, rules, ips := thPreferNFT.BuildNFTScript(ctx, cfg); rules != 1 || ips != 1 || !strings.Contains(script, "203.0.113.5") {
		t.Fatalf("unexpected BuildNFTScript output: rules=%d ips=%d script=%s", rules, ips, script)
	}

	// 2. Neither nft nor iptables exists -> returns clear error.
	thNone := audit.NewThrottlerWithDeps(audit.ThrottlerDeps{
		GOOS: "linux",
		LookPath: func(file string) (string, error) {
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		},
	})
	resNone := thNone.Apply(ctx, cfg)
	if resNone.Applied || resNone.Message == "" {
		t.Fatalf("expected failure when neither nft nor iptables exists, got %+v", resNone)
	}
}

func TestThrottler_SplitIPv4IPv6LookupRetryAnd30MinCacheResilience(t *testing.T) {
	ctx := t.Context()
	cfg := &config.Config{
		Audit: config.AuditConfig{
			Throttles: []config.AuditThrottleRule{
				{Target: "telemetry.example.com", Port: 443, RateKBps: 5},
			},
		},
	}

	var clockMu sync.Mutex
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	// Case A: First ip4 attempt fails, retry succeeds; ip6 hangs/fails (AAAA SERVFAIL) -> ip4 still succeeds!
	var ip4Attempts atomic.Int32
	var forceFail atomic.Bool
	var lastScript string
	var scriptMu sync.Mutex

	th := audit.NewThrottlerWithDeps(audit.ThrottlerDeps{
		GOOS: "linux",
		Now:  nowFn,
		LookPath: func(file string) (string, error) {
			if file == "nft" {
				return "/usr/sbin/nft", nil
			}
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		},
		LookupNetIP: func(lCtx context.Context, network, host string) ([]netip.Addr, error) {
			if forceFail.Load() {
				return nil, errors.New("temporary dns SERVFAIL")
			}
			if network == "ip6" {
				return nil, errors.New("AAAA SERVFAIL")
			}
			if ip4Attempts.Add(1) == 1 {
				return nil, errors.New("transient ip4 timeout")
			}
			return []netip.Addr{netip.MustParseAddr("203.0.113.77")}, nil
		},
		RunNFT: func(_ context.Context, script string) error {
			scriptMu.Lock()
			lastScript = script
			scriptMu.Unlock()
			return nil
		},
	})

	res1 := th.Apply(ctx, cfg)
	if !res1.Applied || res1.ActiveRules != 1 || res1.ActiveIPs != 1 {
		t.Fatalf("expected ip4 retry to succeed despite AAAA SERVFAIL, got %+v", res1)
	}
	if ip4Attempts.Load() != 2 {
		t.Fatalf("expected 2 ip4 attempts (1 failure + 1 retry), got %d", ip4Attempts.Load())
	}

	// Case B: Transient DNS outage 10 minutes later -> reuses 30m cache, stays Applied=true with zero WARN!
	forceFail.Store(true)
	advance(10 * time.Minute)
	resCached := th.Apply(ctx, cfg)
	if !resCached.Applied || resCached.ActiveIPs != 1 {
		t.Fatalf("expected cached public IP reused during transient DNS blip, got %+v", resCached)
	}
	scriptMu.Lock()
	gotCachedScript := lastScript
	scriptMu.Unlock()
	if !strings.Contains(gotCachedScript, "203.0.113.77") {
		t.Fatalf("expected cached IP 203.0.113.77 in nft script:\n%s", gotCachedScript)
	}

	// Concurrent Apply calls under -race with active cache.
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			r := th.Apply(ctx, cfg)
			if !r.Applied {
				t.Errorf("concurrent cached Apply failed: %+v", r)
			}
		})
	}
	wg.Wait()

	// Case C: Outage persists past 30-minute cache TTL -> cache expires, reports Applied=false!
	advance(25 * time.Minute)
	resExpired := th.Apply(ctx, cfg)
	if resExpired.Applied || resExpired.ActiveIPs != 0 {
		t.Fatalf("expected cache expiry after 30m to report unresolved, got %+v", resExpired)
	}

	// Case D: First-time resolution failure with empty cache -> immediately returns Applied=false.
	thFresh := audit.NewThrottlerWithDeps(audit.ThrottlerDeps{
		GOOS: "linux",
		Now:  nowFn,
		LookPath: func(file string) (string, error) {
			if file == "nft" {
				return "/usr/sbin/nft", nil
			}
			return "", &exec.Error{Name: file, Err: exec.ErrNotFound}
		},
		LookupNetIP: func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return nil, errors.New("dns down")
		},
		RunNFT: func(_ context.Context, _ string) error { return nil },
	})
	if resFirstFail := thFresh.Apply(ctx, cfg); resFirstFail.Applied {
		t.Fatalf("expected first-time DNS failure with empty cache to return Applied=false, got %+v", resFirstFail)
	}
}
