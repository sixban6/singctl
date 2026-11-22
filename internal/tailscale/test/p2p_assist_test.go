// 文件职责：覆盖 P2PAssistController 核心 JIT 打洞状态机、冷却退避、定时双向过期收敛与并发安全测试。
package tailscale_test

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/tailscale"
)

type fakeLocalAPI struct {
	mu          sync.Mutex
	statusFn    func(call int) (*tailscale.StatusSnapshot, error)
	pingFn      func(ctx context.Context, peerTSIP string) (*tailscale.PingResult, error)
	netMap      *tailscale.NetMapSnapshot
	pingCalls   []string
	statusCalls int
}

func (f *fakeLocalAPI) Status(ctx context.Context) (*tailscale.StatusSnapshot, error) {
	f.mu.Lock()
	f.statusCalls++
	call := f.statusCalls
	fn := f.statusFn
	f.mu.Unlock()
	return fn(call)
}

func (f *fakeLocalAPI) NetMap(ctx context.Context) (*tailscale.NetMapSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.netMap == nil {
		return &tailscale.NetMapSnapshot{PeerEndpoints: map[string][]string{}}, nil
	}
	return f.netMap, nil
}

func (f *fakeLocalAPI) PingDisco(ctx context.Context, peerTSIP string) (*tailscale.PingResult, error) {
	f.mu.Lock()
	f.pingCalls = append(f.pingCalls, peerTSIP)
	fn := f.pingFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, peerTSIP)
	}
	return &tailscale.PingResult{IP: peerTSIP, DERPRegionCode: "sfo", LatencySeconds: 0.03}, nil
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.Advance(d)
	return ctx.Err()
}

type recordedNFT struct {
	mu          sync.Mutex
	fw4Applies  int
	fw4Removes  int
	openV4      [][]string
	closeV4     [][]string
	liveOpenSet map[string]bool
	failFW4     bool
}

func newRecordedFW4(t *testing.T) (*tailscale.FW4Manager, *recordedNFT) {
	t.Helper()
	rec := &recordedNFT{liveOpenSet: make(map[string]bool)}
	mgr := &tailscale.FW4Manager{
		BaseDir: t.TempDir(),
		Runner: func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
			rec.mu.Lock()
			defer rec.mu.Unlock()
			if name == "nft" && len(args) >= 2 && args[0] == "-c" {
				return nil, nil
			}
			if name == "nft" && len(args) >= 3 && args[0] == "list" && args[1] == "chain" {
				if rec.fw4Applies > 0 {
					return []byte("chain singctl_ts_jit_guard {}"), nil
				}
				return nil, context.DeadlineExceeded
			}
			if name == "fw4" && len(args) == 1 && args[0] == "check" {
				if rec.failFW4 {
					return nil, context.DeadlineExceeded
				}
				return nil, nil
			}
			if name == "fw4" && len(args) == 1 && args[0] == "reload" {
				rec.fw4Applies++
				return nil, nil
			}
			if name == "nft" && len(args) >= 5 && args[0] == "add" && args[1] == "element" && args[4] == tailscale.SetTSJITAllow4Name {
				rec.openV4 = append(rec.openV4, append([]string{}, args...))
				if f := strings.Fields(strings.Trim(args[5], "{} ")); len(f) > 0 {
					rec.liveOpenSet[f[0]] = true
				}
				return nil, nil
			}
			if name == "nft" && len(args) >= 5 && args[0] == "delete" && args[1] == "element" && args[4] == tailscale.SetTSJITAllow4Name {
				rec.closeV4 = append(rec.closeV4, append([]string{}, args...))
				if f := strings.Fields(strings.Trim(args[5], "{} ")); len(f) > 0 {
					delete(rec.liveOpenSet, f[0])
				}
				return nil, nil
			}
			if name == "nft" && len(args) >= 4 && args[0] == "-j" && args[1] == "list" && args[2] == "set" {
				return []byte(`{"nftables":[]}`), nil
			}
			return nil, nil
		},
	}
	return mgr, rec
}

func TestP2PAssistController_IdleAlreadyDirectAndUnauthorizedNeverOpen(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)

	api := &fakeLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", ShortName: "n4120"},
				Peers: []tailscale.PeerStatus{
					{ID: "pIdle", ShortName: "remote-idle", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: false, Relay: "sfo"},
					{ID: "pDirect", ShortName: "remote-direct", TailscaleIPs: []string{"100.64.200.3"}, Online: true, Active: true, CurAddr: "198.51.100.20:41641"},
					{ID: "pUnauth", ShortName: "remote-unauth", TailscaleIPs: []string{"100.64.200.4"}, Online: true, Active: true, Relay: "sfo"},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			PeerEndpoints: map[string][]string{
				"pIdle":   {"198.51.100.10:41641"},
				"pDirect": {"198.51.100.20:41641"},
				"pUnauth": {"198.51.100.30:41641"},
			},
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:       api,
		FW4:            fw4,
		Now:            clk.Now,
		Sleep:          clk.Sleep,
		DefaultLANCIDR: func() string { return "192.168.180.0/24" },
		HostSelfIPs:    func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}

	cfg := config.TailscaleP2PAssistConfig{
		Enabled: true,
		Peers: []config.TailscaleP2PPeerConfig{
			{ID: "pIdle", Name: "remote-idle", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
			{ID: "pDirect", Name: "remote-direct", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
			{ID: "pUnauth", Name: "remote-unauth", JITEnabled: false, AccessMode: config.TailscaleAccessOutboundOnly},
		},
	}

	snap, err := ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if !snap.Enabled || snap.ApplyMode != tailscale.ApplyModeFW4Reload {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.openV4) != 0 {
		t.Fatalf("expected 0 pinholes for idle/direct/unauthorized peers, got %v", rec.openV4)
	}
}

func TestP2PAssistController_ActiveDERPUpgradesAndClosesImmediately(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)

	var events []string
	var mu sync.Mutex

	api := &fakeLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			curAddr := ""
			relay := "sfo"
			if call >= 4 {
				curAddr = "198.51.100.10:41641"
				relay = ""
			}
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", Addrs: []string{"203.0.113.1:41641"}},
				Peers: []tailscale.PeerStatus{
					{ID: "p1", ShortName: "router-remote", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: curAddr, Relay: relay},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{
				"p1": {"192.168.55.1:41641", "198.51.100.10:41641", "203.0.113.1:41641"},
			},
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:        api,
		FW4:             fw4,
		Now:             clk.Now,
		Sleep:           clk.Sleep,
		MinAutoJITBytes: -1,
		DefaultLANCIDR:  func() string { return "192.168.180.0/24" },
		HostSelfIPs:     func() []netip.Addr { return nil },
		OnEvent: func(action string, healthy bool, summary string) {
			mu.Lock()
			events = append(events, action+":"+summary)
			mu.Unlock()
		},
	}

	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 8,
		Peers: []config.TailscaleP2PPeerConfig{
			{ID: "p1", Name: "router-remote", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
		},
	}

	if _, err := ctrl.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	ctrl.WaitBackground()

	rec.mu.Lock()
	openCount := len(rec.openV4)
	closeCount := len(rec.closeV4)
	rec.mu.Unlock()
	if openCount != 1 || closeCount != 1 {
		t.Fatalf("expected 1 open and 1 immediate close, got open=%d close=%d", openCount, closeCount)
	}

	st := ctrl.PeerStates()["p1"]
	if st.LastUpgradeAt == "" || st.InFlight || st.PinholeOpen || st.ConsecutiveFails != 0 {
		t.Fatalf("unexpected peer state after upgrade: %+v", st)
	}
	if elapsed := clk.Now().Sub(time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)); elapsed >= 5*time.Second {
		t.Fatalf("expected early pinhole closure before 5s, elapsed=%v", elapsed)
	}
}

func TestP2PAssistController_FailureCooldownTimedExpiryAndDisable(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)

	api := &fakeLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf"},
				Peers: []tailscale.PeerStatus{
					{ID: "p1", ShortName: "router-remote", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, Relay: "sfo"},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{
			PeerEndpoints: map[string][]string{
				"p1": {"198.51.100.10:41641"},
			},
		},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:        api,
		FW4:             fw4,
		Now:             clk.Now,
		Sleep:           clk.Sleep,
		MinAutoJITBytes: -1,
		DefaultLANCIDR:  func() string { return "192.168.180.0/24" },
		HostSelfIPs:     func() []netip.Addr { return nil },
	}

	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 3,
		CooldownSec:  120,
		Peers: []config.TailscaleP2PPeerConfig{
			{
				ID:                 "p1",
				Name:               "router-remote",
				JITEnabled:         true,
				AccessMode:         config.TailscaleAccessBidirectionalTimed,
				BidirectionalUntil: clk.Now().Add(60 * time.Second).Format(time.RFC3339),
				AllowedLANTargets:  []string{"192.168.180.10:8445"},
			},
		},
	}

	_, _ = ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()
	_, _ = ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()

	st := ctrl.PeerStates()["p1"]
	if st.ConsecutiveFails != 2 || st.CooldownRemainingSec <= 0 {
		t.Fatalf("expected cooldown after 2 failed attempts, got %+v", st)
	}

	_, _ = ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()
	rec.mu.Lock()
	opensDuringCooldown := len(rec.openV4)
	appliesBeforeExpiry := rec.fw4Applies
	rec.mu.Unlock()
	if opensDuringCooldown != 2 {
		t.Fatalf("expected cooldown to block 3rd open, got %d opens", opensDuringCooldown)
	}

	clk.Advance(125 * time.Second)
	_, err := ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()
	if err != nil {
		t.Fatalf("Reconcile after expiry failed: %v", err)
	}
	rec.mu.Lock()
	opensAfterCooldown := len(rec.openV4)
	appliesAfterExpiry := rec.fw4Applies
	rec.mu.Unlock()
	if opensAfterCooldown != 3 {
		t.Fatalf("expected retry after cooldown expiry, got %d opens", opensAfterCooldown)
	}
	if appliesAfterExpiry <= appliesBeforeExpiry {
		t.Fatalf("expected expired bidirectional_timed to trigger FW4 re-apply (before=%d after=%d)", appliesBeforeExpiry, appliesAfterExpiry)
	}
	stAfterCooldown := ctrl.PeerStates()["p1"]
	if stAfterCooldown.ConsecutiveFails != 1 || stAfterCooldown.CooldownRemainingSec != 0 {
		t.Fatalf("expected 1 fresh failure without immediate re-cooldown, got %+v", stAfterCooldown)
	}

	pokeRes, err := ctrl.PokePeer(ctx, cfg, "p1")
	if err != nil || pokeRes == nil || pokeRes.CandidateCount != 1 {
		t.Fatalf("unexpected PokePeer result: %+v err=%v", pokeRes, err)
	}
	if _, err := ctrl.PokePeer(ctx, cfg, "unknown-peer"); err == nil {
		t.Fatal("expected error when poking unknown peer")
	}

	cfg.Enabled = false
	snapOff, err := ctrl.Reconcile(ctx, cfg)
	if err != nil || snapOff.Enabled {
		t.Fatalf("expected clean disable, got %+v err=%v", snapOff, err)
	}
}

func TestP2PAssistController_RaceSafety(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, _ := newRecordedFW4(t)
	var toggle atomic.Bool

	api := &fakeLocalAPI{
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			cur := ""
			relay := "sfo"
			if toggle.Load() {
				cur = "198.51.100.10:41641"
				relay = ""
			}
			toggle.Store(!toggle.Load())
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf"},
				Peers: []tailscale.PeerStatus{
					{ID: "p1", ShortName: "r1", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: cur, Relay: relay},
				},
			}, nil
		},
		netMap: &tailscale.NetMapSnapshot{PeerEndpoints: map[string][]string{"p1": {"198.51.100.10:41641"}}},
	}

	ctrl := &tailscale.P2PAssistController{
		LocalAPI:        api,
		FW4:             fw4,
		Now:             clk.Now,
		Sleep:           clk.Sleep,
		MinAutoJITBytes: -1,
		DefaultLANCIDR:  func() string { return "192.168.180.0/24" },
		HostSelfIPs:     func() []netip.Addr { return nil },
	}
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 3,
		CooldownSec:  30,
		Peers:        []config.TailscaleP2PPeerConfig{{ID: "p1", Name: "r1", JITEnabled: true}},
	}

	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			_, _ = ctrl.Reconcile(ctx, cfg)
		})
	}
	wg.Go(func() {
		_, _ = ctrl.PokePeer(ctx, cfg, "p1")
	})
	wg.Wait()
	ctrl.WaitBackground()
}
