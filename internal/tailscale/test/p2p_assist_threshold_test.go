// 文件职责：覆盖 P2PAssistController 异步上下文生命周期、流量噪音抑制阈值与关孔后 conntrack 宽限期检测测试。
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

func TestP2PAssistController_AsyncJITSurvivesCallerReconcileCancel(t *testing.T) {
	clk := newFakeClock()
	fw4, rec := newRecordedFW4(t)
	daemonCtx := t.Context()

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
			PeerEndpoints: map[string][]string{"p1": {"198.51.100.10:41641"}},
		},
	}

	startedSleep := make(chan struct{}, 1)
	releaseSleep := make(chan struct{})
	ctrl := &tailscale.P2PAssistController{
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
	cancelRec()
	<-startedSleep
	close(releaseSleep)
	ctrl.WaitBackground()

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
		statusFn: func(call int) (*tailscale.StatusSnapshot, error) {
			cur := ""
			relay := "sfo"
			if directNow.Load() {
				cur = "198.51.100.10:41641"
				relay = ""
			}
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
	ctrl.WaitBackground()
	_, _ = ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()
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
		active  = true
		curAddr string
		relay   = "sfo"
		rxBytes = int64(24824)
		txBytes = int64(16448)
	)

	api := &fakeLocalAPI{
		statusFn: func(int) (*tailscale.StatusSnapshot, error) {
			rec.mu.Lock()
			isOpenNow := len(rec.openV4) > len(rec.closeV4)
			rec.mu.Unlock()
			mu.Lock()
			defer mu.Unlock()
			if curAddr == "" && active && isOpenNow {
				curAddr = "198.51.100.10:41641"
				relay = ""
			}
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", Addrs: []string{"203.0.113.1:41641"}},
				Peers: []tailscale.PeerStatus{
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
		netMap: &tailscale.NetMapSnapshot{
			SelfEndpoints: []string{"203.0.113.1:41641"},
			PeerEndpoints: map[string][]string{
				"p1": {"198.51.100.10:41641"},
			},
		},
	}

	ctrl := &tailscale.P2PAssistController{
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

	if _, err := ctrl.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("cold-start Reconcile: %v", err)
	}
	ctrl.WaitBackground()

	for range 15 {
		mu.Lock()
		active = false
		mu.Unlock()
		_, _ = ctrl.Reconcile(ctx, cfg)
		ctrl.WaitBackground()

		mu.Lock()
		active = true
		rxBytes += 200
		txBytes += 200
		mu.Unlock()
		_, _ = ctrl.Reconcile(ctx, cfg)
		ctrl.WaitBackground()
		_, _ = ctrl.Reconcile(ctx, cfg)
		ctrl.WaitBackground()
	}

	rec.mu.Lock()
	opensBeforeRealTraffic := len(rec.openV4)
	rec.mu.Unlock()
	if opensBeforeRealTraffic != 0 {
		t.Fatalf("expected 0 automatic pinholes during tiny handshake bursts, got %d", opensBeforeRealTraffic)
	}

	mu.Lock()
	active = true
	rxBytes += 4000
	txBytes += 2000
	mu.Unlock()
	if _, err := ctrl.Reconcile(ctx, cfg); err != nil {
		t.Fatalf("traffic Reconcile: %v", err)
	}
	ctrl.WaitBackground()

	rec.mu.Lock()
	opensAfterRealTraffic := len(rec.openV4)
	closesAfterRealTraffic := len(rec.closeV4)
	rec.mu.Unlock()
	if opensAfterRealTraffic != 1 || closesAfterRealTraffic != 1 {
		t.Fatalf("expected 1 open and 1 close on real traffic, got open=%d close=%d", opensAfterRealTraffic, closesAfterRealTraffic)
	}

	mu.Lock()
	curAddr = ""
	relay = "sfo"
	mu.Unlock()
	_, _ = ctrl.Reconcile(ctx, cfg)
	ctrl.WaitBackground()

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
		statusFn: func(_ int) (*tailscale.StatusSnapshot, error) {
			rec.mu.Lock()
			closedCount := len(rec.closeV4)
			stillOpen := len(rec.liveOpenSet)
			rec.mu.Unlock()

			elapsed := clk.Now().Sub(startTime)
			curAddr := ""
			relay := "sfo"
			if closedCount == 1 && stillOpen == 0 && elapsed >= 3600*time.Millisecond {
				curAddr = "198.51.100.55:41641"
				relay = ""
			}
			return &tailscale.StatusSnapshot{
				BackendState: "Running",
				Self:         tailscale.PeerStatus{ID: "nSelf", ShortName: "n4120"},
				Peers: []tailscale.PeerStatus{
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
		pingFn: func(pCtx context.Context, _ string) (*tailscale.PingResult, error) {
			pingStarted.Add(1)
			defer pingExited.Add(1)
			<-pCtx.Done()
			return nil, pCtx.Err()
		},
		netMap: &tailscale.NetMapSnapshot{
			PeerEndpoints: map[string][]string{"pLate": {"198.51.100.55:41641"}},
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
		t.Fatalf("expected strict 3000ms pinhole open duration, got %dms", res.PinholeMs)
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
