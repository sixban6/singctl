package tailscale

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
)

type fakeLocalAPI struct {
	mu          sync.Mutex
	statusFn    func(call int) (*StatusSnapshot, error)
	pingFn      func(ctx context.Context, peerTSIP string) (*PingResult, error)
	netMap      *NetMapSnapshot
	pingCalls   []string
	statusCalls int
}

func (f *fakeLocalAPI) Status(ctx context.Context) (*StatusSnapshot, error) {
	f.mu.Lock()
	f.statusCalls++
	call := f.statusCalls
	fn := f.statusFn
	f.mu.Unlock()
	return fn(call)
}

func (f *fakeLocalAPI) NetMap(ctx context.Context) (*NetMapSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.netMap == nil {
		return &NetMapSnapshot{PeerEndpoints: map[string][]string{}}, nil
	}
	return f.netMap, nil
}

func (f *fakeLocalAPI) PingDisco(ctx context.Context, peerTSIP string) (*PingResult, error) {
	f.mu.Lock()
	f.pingCalls = append(f.pingCalls, peerTSIP)
	fn := f.pingFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, peerTSIP)
	}
	return &PingResult{IP: peerTSIP, DERPRegionCode: "sfo", LatencySeconds: 0.03}, nil
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

func newRecordedFW4(t *testing.T) (*FW4Manager, *recordedNFT) {
	t.Helper()
	rec := &recordedNFT{liveOpenSet: make(map[string]bool)}
	mgr := &FW4Manager{
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
			if name == "nft" && len(args) >= 5 && args[0] == "add" && args[1] == "element" && args[4] == setTSJITAllow4 {
				// args[5] = "{ 198.51.100.10 timeout 5s }"
				rec.openV4 = append(rec.openV4, append([]string{}, args...))
				if f := strings.Fields(strings.Trim(args[5], "{} ")); len(f) > 0 {
					rec.liveOpenSet[f[0]] = true
				}
				return nil, nil
			}
			if name == "nft" && len(args) >= 5 && args[0] == "delete" && args[1] == "element" && args[4] == setTSJITAllow4 {
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

func waitControllerBackground(c *P2PAssistController) {
	c.wg.Wait()
}

func TestP2PAssistController_IdleAlreadyDirectAndUnauthorizedNeverOpen(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)

	api := &fakeLocalAPI{
		statusFn: func(call int) (*StatusSnapshot, error) {
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf", ShortName: "n4120"},
				Peers: []PeerStatus{
					{ID: "pIdle", ShortName: "remote-idle", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: false, Relay: "sfo"},
					{ID: "pDirect", ShortName: "remote-direct", TailscaleIPs: []string{"100.64.200.3"}, Online: true, Active: true, CurAddr: "198.51.100.20:41641"},
					{ID: "pUnauth", ShortName: "remote-unauth", TailscaleIPs: []string{"100.64.200.4"}, Online: true, Active: true, Relay: "sfo"},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{
			PeerEndpoints: map[string][]string{
				"pIdle":   {"198.51.100.10:41641"},
				"pDirect": {"198.51.100.20:41641"},
				"pUnauth": {"198.51.100.30:41641"},
			},
		},
	}

	ctrl := &P2PAssistController{
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
	waitControllerBackground(ctrl)
	if err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	if !snap.Enabled || snap.ApplyMode != ApplyModeFW4Reload {
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
		statusFn: func(call int) (*StatusSnapshot, error) {
			curAddr := ""
			relay := "sfo"
			// Call 1 = Reconcile status, Call 2 = worker pre-check, Call 3..4 = 300ms polls; upgrade on poll #2 (call >= 4)
			if call >= 4 {
				curAddr = "198.51.100.10:41641"
				relay = ""
			}
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf", Addrs: []string{"203.0.113.1:41641"}},
				Peers: []PeerStatus{
					{ID: "p1", ShortName: "router-remote", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: curAddr, Relay: relay},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{
				"p1": {"192.168.55.1:41641", "198.51.100.10:41641", "203.0.113.1:41641"},
			},
		},
	}

	ctrl := &P2PAssistController{
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
	waitControllerBackground(ctrl)

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
	// Must have finished early (not consuming the full 8s window)
	if elapsed := clk.Now().Sub(time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)); elapsed >= 5*time.Second {
		t.Fatalf("expected early pinhole closure before 5s, elapsed=%v", elapsed)
	}
}

func TestP2PAssistController_FailureCooldownTimedExpiryAndDisable(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)

	// Always remain DERP (symmetric NAT simulation)
	api := &fakeLocalAPI{
		statusFn: func(call int) (*StatusSnapshot, error) {
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf"},
				Peers: []PeerStatus{
					{ID: "p1", ShortName: "router-remote", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, Relay: "sfo"},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{
			PeerEndpoints: map[string][]string{
				"p1": {"198.51.100.10:41641"},
			},
		},
	}

	ctrl := &P2PAssistController{
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

	// Attempt 1 fails -> consecutiveFails=1, not yet in cooldown
	_, _ = ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)
	// Attempt 2 fails -> consecutiveFails=2 -> enters 120s cooldown
	_, _ = ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)

	st := ctrl.PeerStates()["p1"]
	if st.ConsecutiveFails != 2 || st.CooldownRemainingSec <= 0 {
		t.Fatalf("expected cooldown after 2 failed attempts, got %+v", st)
	}

	// Attempt 3 within cooldown must NOT open pinhole
	_, _ = ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)
	rec.mu.Lock()
	opensDuringCooldown := len(rec.openV4)
	appliesBeforeExpiry := rec.fw4Applies
	rec.mu.Unlock()
	if opensDuringCooldown != 2 {
		t.Fatalf("expected cooldown to block 3rd open, got %d opens", opensDuringCooldown)
	}

	// Advance clock past bidirectional_until (60s) AND past cooldown (120s)
	clk.Advance(125 * time.Second)
	_, err := ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)
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
	// After cooldown expiry, consecutiveFails resets so the 1st new failure is 1 (not >=2 re-cooldown)
	stAfterCooldown := ctrl.PeerStates()["p1"]
	if stAfterCooldown.ConsecutiveFails != 1 || stAfterCooldown.CooldownRemainingSec != 0 {
		t.Fatalf("expected 1 fresh failure without immediate re-cooldown, got %+v", stAfterCooldown)
	}

	// Manual PokePeer works on authorized peer, rejects unauthorized peer
	pokeRes, err := ctrl.PokePeer(ctx, cfg, "p1")
	if err != nil || pokeRes == nil || pokeRes.CandidateCount != 1 {
		t.Fatalf("unexpected PokePeer result: %+v err=%v", pokeRes, err)
	}
	if _, err := ctrl.PokePeer(ctx, cfg, "unknown-peer"); err == nil {
		t.Fatal("expected error when poking unknown peer")
	}

	// Disabling removes drop-ins cleanly
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
		statusFn: func(call int) (*StatusSnapshot, error) {
			cur := ""
			relay := "sfo"
			if toggle.Load() {
				cur = "198.51.100.10:41641"
				relay = ""
			}
			toggle.Store(!toggle.Load())
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf"},
				Peers: []PeerStatus{
					{ID: "p1", ShortName: "r1", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: cur, Relay: relay},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{PeerEndpoints: map[string][]string{"p1": {"198.51.100.10:41641"}}},
	}

	ctrl := &P2PAssistController{
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
	waitControllerBackground(ctrl)
}

func TestP2PAssistController_AsyncJITSurvivesCallerReconcileCancel(t *testing.T) {
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)
	daemonCtx := t.Context()

	api := &fakeLocalAPI{
		statusFn: func(call int) (*StatusSnapshot, error) {
			curAddr := ""
			relay := "sfo"
			// poll #2 upgrades after caller recCtx is canceled
			if call >= 4 {
				curAddr = "198.51.100.10:41641"
				relay = ""
			}
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf", Addrs: []string{"203.0.113.1:41641"}},
				Peers: []PeerStatus{
					{ID: "p1", ShortName: "router-remote", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: curAddr, Relay: relay},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{"p1": {"198.51.100.10:41641"}},
		},
	}

	startedSleep := make(chan struct{}, 1)
	releaseSleep := make(chan struct{})
	ctrl := &P2PAssistController{
		BaseCtx:         daemonCtx,
		LocalAPI:        api,
		FW4:             fw4,
		Now:             clk.Now,
		MinAutoJITBytes: -1,
		Sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case startedSleep <- struct{}{}:
			default:
			}
			select {
			case <-releaseSleep:
			case <-ctx.Done():
				return ctx.Err()
			}
			clk.Advance(d)
			return nil
		},
		DefaultLANCIDR: func() string { return "192.168.180.0/24" },
		HostSelfIPs:    func() []netip.Addr { return nil },
	}
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 5,
		Peers:        []config.TailscaleP2PPeerConfig{{ID: "p1", Name: "router-remote", JITEnabled: true}},
	}

	recCtx, cancelRec := context.WithCancel(daemonCtx)
	if _, err := ctrl.Reconcile(recCtx, cfg); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
	// Cancel caller context immediately just like daemon maybeReconcileTailscaleP2PAsync defer cancel()
	cancelRec()
	<-startedSleep
	close(releaseSleep)
	waitControllerBackground(ctrl)

	rec.mu.Lock()
	opens := len(rec.openV4)
	closes := len(rec.closeV4)
	rec.mu.Unlock()
	if opens != 1 || closes != 1 {
		t.Fatalf("expected open=1 close=1 despite canceled caller context, got open=%d close=%d", opens, closes)
	}
	st := ctrl.PeerStates()["p1"]
	if st.LastResult != "direct" || st.LastUpgradeAt == "" {
		t.Fatalf("expected direct upgrade state after caller cancel, got %+v", st)
	}
}

func TestP2PAssistController_DirectPeerClearsStaleCooldown(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, _ := newRecordedFW4(t)
	var directNow atomic.Bool

	api := &fakeLocalAPI{
		statusFn: func(call int) (*StatusSnapshot, error) {
			cur := ""
			relay := "sfo"
			if directNow.Load() {
				cur = "198.51.100.10:41641"
				relay = ""
			}
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf"},
				Peers: []PeerStatus{
					{ID: "p1", ShortName: "r1", TailscaleIPs: []string{"100.64.200.2"}, Online: true, Active: true, CurAddr: cur, Relay: relay},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{PeerEndpoints: map[string][]string{"p1": {"198.51.100.10:41641"}}},
	}
	ctrl := &P2PAssistController{
		BaseCtx:         ctx,
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
		CooldownSec:  300,
		Peers:        []config.TailscaleP2PPeerConfig{{ID: "p1", Name: "r1", JITEnabled: true}},
	}
	_, _ = ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)
	_, _ = ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)
	if st := ctrl.PeerStates()["p1"]; st.ConsecutiveFails != 2 || st.CooldownRemainingSec == 0 {
		t.Fatalf("expected seeded cooldown, got %+v", st)
	}

	directNow.Store(true)
	_, _ = ctrl.Reconcile(ctx, cfg)
	if st := ctrl.PeerStates()["p1"]; st.ConsecutiveFails != 0 || st.CooldownRemainingSec != 0 || st.LastResult != "direct" {
		t.Fatalf("expected direct peer in Reconcile to clear stale cooldown/fails, got %+v", st)
	}
}

func TestP2PAssistController_AutoJITTrafficThreshold(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)

	var (
		mu      sync.Mutex
		active  bool
		curAddr string
		relay   = "sfo"
		rxBytes int64
		txBytes int64
	)

	// Cold start: peer is already Active+DERP with historical byte counters (41272 total)
	active = true
	rxBytes = 24824
	txBytes = 16448

	api := &fakeLocalAPI{
		statusFn: func(int) (*StatusSnapshot, error) {
			rec.mu.Lock()
			isOpenNow := len(rec.openV4) > len(rec.closeV4)
			rec.mu.Unlock()
			mu.Lock()
			defer mu.Unlock()
			if curAddr == "" && active && isOpenNow {
				// Simulate quick upgrade only while a WAN pinhole is actively open
				curAddr = "198.51.100.10:41641"
				relay = ""
			}
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf", Addrs: []string{"203.0.113.1:41641"}},
				Peers: []PeerStatus{
					{
						ID:           "p1",
						ShortName:    "router-remote",
						TailscaleIPs: []string{"100.64.200.2"},
						Online:       true,
						Active:       active,
						CurAddr:      curAddr,
						Relay:        relay,
						RxBytes:      rxBytes,
						TxBytes:      txBytes,
					},
				},
			}, nil
		},
		netMap: &NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{
				"p1": {"198.51.100.10:41641"},
			},
		},
	}

	ctrl := &P2PAssistController{
		LocalAPI:       api,
		FW4:            fw4,
		Now:            clk.Now,
		Sleep:          clk.Sleep,
		DefaultLANCIDR: func() string { return "192.168.180.0/24" },
		HostSelfIPs:    func() []netip.Addr { return nil },
	}
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 5,
		Peers:        []config.TailscaleP2PPeerConfig{{ID: "p1", Name: "router-remote", JITEnabled: true}},
	}

	// 1. Cold-start Active+DERP records baseline without opening a pinhole
	if _, err := ctrl.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("cold-start Reconcile: %v", err)
	}
	waitControllerBackground(ctrl)

	// 2. Repeated idle -> Active+DERP with small WireGuard handshake/keepalive (+400 bytes)
	// stays suppressed across multiple active ticks, and returning idle resets the baseline so
	// 15 cycles (6000 cumulative bytes) never trigger a pinhole.
	for range 15 {
		mu.Lock()
		active = false
		mu.Unlock()
		_, _ = ctrl.Reconcile(ctx, cfg)
		waitControllerBackground(ctrl)

		mu.Lock()
		active = true
		rxBytes += 200
		txBytes += 200
		mu.Unlock()
		_, _ = ctrl.Reconcile(ctx, cfg)
		waitControllerBackground(ctrl)
		_, _ = ctrl.Reconcile(ctx, cfg)
		waitControllerBackground(ctrl)
	}

	rec.mu.Lock()
	opensBeforeRealTraffic := len(rec.openV4)
	rec.mu.Unlock()
	if opensBeforeRealTraffic != 0 {
		t.Fatalf("expected 0 automatic pinholes during tiny handshake bursts, got %d", opensBeforeRealTraffic)
	}

	// 3. Real business traffic (+6000 bytes >= 4096) triggers automatic JIT pinhole & direct upgrade
	mu.Lock()
	active = true
	rxBytes += 4000
	txBytes += 2000
	mu.Unlock()
	if _, err := ctrl.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("traffic Reconcile: %v", err)
	}
	waitControllerBackground(ctrl)

	rec.mu.Lock()
	opensAfterRealTraffic := len(rec.openV4)
	closesAfterRealTraffic := len(rec.closeV4)
	rec.mu.Unlock()
	if opensAfterRealTraffic != 1 || closesAfterRealTraffic != 1 {
		t.Fatalf("expected 1 open and 1 close on real traffic, got open=%d close=%d", opensAfterRealTraffic, closesAfterRealTraffic)
	}

	// 4. Manual PokePeer still works even when CurAddr returns to DERP with zero new traffic
	mu.Lock()
	curAddr = ""
	relay = "sfo"
	mu.Unlock()
	_, _ = ctrl.Reconcile(ctx, cfg)
	waitControllerBackground(ctrl)

	res, err := ctrl.PokePeer(ctx, cfg, "p1")
	if err != nil || res == nil || res.CandidateCount != 1 {
		t.Fatalf("expected manual PokePeer to succeed regardless of traffic threshold, got res=%+v err=%v", res, err)
	}
}

func TestP2PAssist_AsyncDiscoAndPostCloseGraceDetectsDirect(t *testing.T) {
	ctx := t.Context()
	clk := newFakeClock()
	startTime := clk.Now()
	fw4, rec := newRecordedFW4(t)

	var pingStarted atomic.Int32
	var pingExited atomic.Int32

	api := &fakeLocalAPI{
		statusFn: func(_ int) (*StatusSnapshot, error) {
			rec.mu.Lock()
			closedCount := len(rec.closeV4)
			stillOpen := len(rec.liveOpenSet)
			rec.mu.Unlock()

			// While JIT pinhole is open (0..3000ms), peer stays on DERP;
			// only AFTER ClosePinhole has run cleanly and at least 600ms of
			// post-close grace has elapsed does conntrack report CurAddr.
			elapsed := clk.Now().Sub(startTime)
			curAddr := ""
			relay := "sfo"
			if closedCount == 1 && stillOpen == 0 && elapsed >= 3600*time.Millisecond {
				curAddr = "198.51.100.55:41641"
				relay = ""
			}
			return &StatusSnapshot{
				BackendState: "Running",
				Self:         PeerStatus{ID: "nSelf", ShortName: "n4120"},
				Peers: []PeerStatus{
					{
						ID:           "pLate",
						ShortName:    "ax3000t",
						TailscaleIPs: []string{"100.64.200.8"},
						Online:       true,
						Active:       true,
						CurAddr:      curAddr,
						Relay:        relay,
					},
				},
			}, nil
		},
		pingFn: func(pCtx context.Context, _ string) (*PingResult, error) {
			pingStarted.Add(1)
			defer pingExited.Add(1)
			<-pCtx.Done()
			return nil, pCtx.Err()
		},
		netMap: &NetMapSnapshot{
			PeerEndpoints: map[string][]string{"pLate": {"198.51.100.55:41641"}},
		},
	}

	ctrl := &P2PAssistController{
		LocalAPI:       api,
		FW4:            fw4,
		Now:            clk.Now,
		Sleep:          clk.Sleep,
		DefaultLANCIDR: func() string { return "192.168.180.0/24" },
		HostSelfIPs:    func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("203.0.113.1")} },
	}
	cfg := config.TailscaleP2PAssistConfig{
		Enabled:      true,
		JITWindowSec: 3,
		Peers: []config.TailscaleP2PPeerConfig{
			{ID: "pLate", Name: "ax3000t", JITEnabled: true, AccessMode: config.TailscaleAccessOutboundOnly},
		},
	}

	wallStart := time.Now()
	res, err := ctrl.PokePeer(ctx, cfg, "pLate")
	wallElapsed := time.Since(wallStart)
	if err != nil {
		t.Fatalf("PokePeer returned error: %v", err)
	}
	if wallElapsed > time.Second {
		t.Fatalf("blocking PingDisco delayed PokePeer wall time (%v)", wallElapsed)
	}
	if res == nil || !res.Direct || res.CurAddr != "198.51.100.55:41641" {
		t.Fatalf("expected post-close grace to detect Direct upgrade, got %+v", res)
	}
	if res.PinholeMs != 3000 {
		t.Fatalf("expected strict 3000ms pinhole open duration (async DISCO must not extend pinhole), got %dms", res.PinholeMs)
	}
	if !strings.Contains(res.Message, "conntrack") {
		t.Fatalf("expected conntrack grace message, got %q", res.Message)
	}
	if pingStarted.Load() != 3 || pingExited.Load() != 3 {
		t.Fatalf("expected all 3 async DISCO goroutines started & cleanly cancelled, started=%d exited=%d", pingStarted.Load(), pingExited.Load())
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.openV4) != 1 || len(rec.closeV4) != 1 || len(rec.liveOpenSet) != 0 {
		t.Fatalf("expected strict 1 open / 1 close / 0 live pinholes, got open=%d close=%d live=%d", len(rec.openV4), len(rec.closeV4), len(rec.liveOpenSet))
	}
}
