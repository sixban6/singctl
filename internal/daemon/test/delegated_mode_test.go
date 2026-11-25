// 文件职责：测试主路由旁路由托管模式（delegated）的健康检查免误报、开机免拉起 sing-box 及旁路由离线自动回退救生艇状态机。
package daemon_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/vlan"
)

func TestMonitor_CheckHealth_DelegatedMode(t *testing.T) {
	cfgDelegated := &config.Config{
		Gateway: config.GatewayConfig{
			Mode:         "main",
			WorkMode:     config.WorkModeDelegated,
			SideRouterIP: "192.168.55.88",
		},
	}
	res := daemon.NewMonitor(cfgDelegated).CheckHealth()
	if !res.Healthy || !res.DNSOK {
		t.Fatalf("delegated mode must report Healthy=true even when local sing-box is stopped, got %+v", res)
	}
	if !strings.Contains(res.Details, "旁路由托管") {
		t.Fatalf("expected delegated details summary, got %q", res.Details)
	}

	// Regression guard: audit mode must still detect stopped sing-box as unhealthy.
	cfgAudit := &config.Config{
		Gateway: config.GatewayConfig{
			Mode:     "main",
			WorkMode: config.WorkModeAudit,
		},
	}
	resAudit := daemon.NewMonitor(cfgAudit).CheckHealth()
	if resAudit.Healthy {
		t.Fatalf("audit mode without running sing-box must report Healthy=false, got %+v", resAudit)
	}
}

func TestBootInit_DelegatedModeSkipsSingBox(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{{Name: "main", URL: "https://example.com/sub"}},
		Gateway: config.GatewayConfig{
			Mode:         "main",
			WorkMode:     config.WorkModeDelegated,
			SideRouterIP: "192.168.55.88",
		},
	}

	dmRunning := false
	sbStarts, dmStarts, webStarts := 0, 0, 0
	deps := daemon.BootInitDeps{
		SingBoxConfigExists: func() bool { return true }, // stale config.json still present on disk
		IsSingBoxRunning:    func() bool { return false },
		IsDaemonRunning:     func() bool { return dmRunning },
		IsLowMemory:         func() bool { return true },
		WaitNetworkReady:    func(context.Context) error { return nil },
		StartSingBox:        func(context.Context) error { sbStarts++; return nil },
		StartDaemon:         func(context.Context) error { dmStarts++; dmRunning = true; return nil },
		StartWeb:            func(context.Context) error { webStarts++; return nil },
	}

	if daemon.IsBootInitSatisfied(cfg, deps) {
		t.Fatal("expected IsBootInitSatisfied=false while daemon is stopped in low-mem delegated mode")
	}
	if err := daemon.RunBootInit(t.Context(), cfg, deps); err != nil {
		t.Fatalf("RunBootInit in delegated mode failed: %v", err)
	}
	if sbStarts != 0 || dmStarts != 1 || webStarts != 0 {
		t.Fatalf("expected delegated low-mem boot to skip sing-box and start daemon only: sb=%d dm=%d web=%d", sbStarts, dmStarts, webStarts)
	}
	if !daemon.IsBootInitSatisfied(cfg, deps) {
		t.Fatal("expected IsBootInitSatisfied=true after daemon started in delegated mode without sing-box")
	}
}

func TestSideRouterFailoverGuard(t *testing.T) {
	sideFile := filepath.Join(t.TempDir(), "vlan-side-routes.list")
	spec := vlan.VLANSideRouteSpec{
		SideRouterIP: "192.168.55.88",
		CIDRs:        []string{"192.168.89.0/24"},
	}
	if err := vlan.WriteSideRouteSpec(sideFile, spec); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	probeOnline := true
	suspendCalls := 0
	applyCalls := 0
	var events []string

	guard := daemon.NewSideRouterFailoverGuard(daemon.SideRouterGuardDeps{
		SideRoutesFile: sideFile,
		FailThreshold:  2,
		ProbeOnline: func(_ context.Context, ip string) bool {
			mu.Lock()
			defer mu.Unlock()
			return probeOnline && ip == "192.168.55.88"
		},
		SuspendRoutes: func(context.Context) error {
			mu.Lock()
			suspendCalls++
			mu.Unlock()
			return nil
		},
		ApplyRoutes: func(context.Context, vlan.VLANSideRouteSpec) error {
			mu.Lock()
			applyCalls++
			mu.Unlock()
			return nil
		},
		OnEvent: func(action string, _ bool, summary string) {
			mu.Lock()
			events = append(events, action+":"+summary)
			mu.Unlock()
		},
	})

	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			Mode:         "main",
			WorkMode:     config.WorkModeDelegated,
			SideRouterIP: "192.168.55.88",
		},
	}

	// 1. Healthy baseline: no failover action
	guard.EvaluateOnce(t.Context(), cfg)
	if suspendCalls != 0 || applyCalls != 0 || guard.IsSuspended() {
		t.Fatalf("unexpected action while online: suspend=%d apply=%d suspended=%v", suspendCalls, applyCalls, guard.IsSuspended())
	}

	// 2. Single transient failure: must NOT trip on first failure
	mu.Lock()
	probeOnline = false
	mu.Unlock()
	guard.EvaluateOnce(t.Context(), cfg)
	if suspendCalls != 0 || guard.IsSuspended() {
		t.Fatalf("single failure must not trigger failover yet: suspend=%d suspended=%v", suspendCalls, guard.IsSuspended())
	}

	// 3. Consecutive failure #2: suspends PBR rules and emits failover event once
	guard.EvaluateOnce(t.Context(), cfg)
	if suspendCalls != 1 || !guard.IsSuspended() {
		t.Fatalf("second consecutive failure must trigger failover suspend: suspend=%d suspended=%v", suspendCalls, guard.IsSuspended())
	}

	// 4. Repeated failure #3 while suspended: must be idempotent (no spam)
	guard.EvaluateOnce(t.Context(), cfg)
	if suspendCalls != 1 || len(events) != 1 {
		t.Fatalf("expected idempotent failover while offline, suspend=%d events=%v", suspendCalls, events)
	}

	// 5. Side router recovers: re-applies PBR rules and emits recovered event
	mu.Lock()
	probeOnline = true
	mu.Unlock()
	guard.EvaluateOnce(t.Context(), cfg)
	if applyCalls != 1 || guard.IsSuspended() || len(events) != 2 {
		t.Fatalf("expected recovery re-apply and event, apply=%d suspended=%v events=%v", applyCalls, guard.IsSuspended(), events)
	}
	if !strings.HasPrefix(events[0], "SIDE_ROUTER_FAILOVER:") || !strings.HasPrefix(events[1], "SIDE_ROUTER_RECOVERED:") {
		t.Fatalf("unexpected failover/recovery event sequence: %v", events)
	}

	// 6. Error in SuspendRoutes resets/retries gracefully without marking suspended
	failGuard := daemon.NewSideRouterFailoverGuard(daemon.SideRouterGuardDeps{
		SideRoutesFile: sideFile,
		FailThreshold:  1,
		ProbeOnline:    func(context.Context, string) bool { return false },
		SuspendRoutes:  func(context.Context) error { return errors.New("ip failed") },
	})
	failGuard.EvaluateOnce(t.Context(), cfg)
	if failGuard.IsSuspended() {
		t.Fatal("failed SuspendRoutes must not mark state as suspended")
	}

	// 7. Concurrent -race check
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			guard.EvaluateOnce(t.Context(), cfg)
		})
	}
	wg.Wait()
}
