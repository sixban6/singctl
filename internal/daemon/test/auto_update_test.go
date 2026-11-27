// 文件职责：测试守护进程核心组件自动更新编排器（全关零执行、单开按序、周期/失败退避、取消与并发安全）。
package daemon_test

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
)

type stubAutoUpdateTarget struct {
	id          string
	displayName string
	enabledFn   func(*config.Config) bool
	runFn       func(context.Context, *config.Config) (daemon.AutoUpdateCheckResult, error)
	calls       atomic.Int32
}

func (s *stubAutoUpdateTarget) ID() string                      { return s.id }
func (s *stubAutoUpdateTarget) DisplayName() string             { return s.displayName }
func (s *stubAutoUpdateTarget) Enabled(cfg *config.Config) bool { return s.enabledFn(cfg) }
func (s *stubAutoUpdateTarget) Run(ctx context.Context, cfg *config.Config) (daemon.AutoUpdateCheckResult, error) {
	s.calls.Add(1)
	return s.runFn(ctx, cfg)
}

func TestComponentAutoUpdater_AllDisabledRunsNothing(t *testing.T) {
	dir := t.TempDir()
	store := daemon.NewStateStore(daemon.Paths{
		StateFile: filepath.Join(dir, "daemon.state"),
		LogFile:   filepath.Join(dir, "daemon.log"),
		PidFile:   filepath.Join(dir, "daemon.pid"),
	})
	t1 := &stubAutoUpdateTarget{
		id:          daemon.AutoUpdateComponentSingBox,
		displayName: "sing-box",
		enabledFn:   func(cfg *config.Config) bool { return cfg.Watchdog.AutoUpdate.SingBox },
		runFn: func(context.Context, *config.Config) (daemon.AutoUpdateCheckResult, error) {
			t.Fatal("should never execute when all toggles are false")
			return daemon.AutoUpdateCheckResult{}, nil
		},
	}

	u := daemon.NewComponentAutoUpdater(daemon.AutoUpdaterOptions{
		Targets:    []daemon.AutoUpdateTarget{t1},
		StateStore: store,
	})
	res := u.RunOnce(t.Context(), &config.Config{}, false)
	if len(res) != 0 || t1.calls.Load() != 0 {
		t.Fatalf("expected 0 executions when all disabled, got res=%v calls=%d", res, t1.calls.Load())
	}
}

func TestComponentAutoUpdater_RunsEnabledInOrderAndPersistsState(t *testing.T) {
	dir := t.TempDir()
	store := daemon.NewStateStore(daemon.Paths{
		StateFile: filepath.Join(dir, "daemon.state"),
		LogFile:   filepath.Join(dir, "daemon.log"),
		PidFile:   filepath.Join(dir, "daemon.pid"),
	})

	now := time.Date(2026, 11, 27, 20, 0, 0, 0, time.UTC)
	var order []string
	var events []daemon.WatchdogEventRecord

	mk := func(id string, res daemon.AutoUpdateCheckResult) *stubAutoUpdateTarget {
		return &stubAutoUpdateTarget{
			id:          id,
			displayName: id,
			enabledFn:   func(cfg *config.Config) bool { return cfg.Watchdog.AutoUpdate.IsEnabled(id) },
			runFn: func(context.Context, *config.Config) (daemon.AutoUpdateCheckResult, error) {
				order = append(order, id)
				return res, nil
			},
		}
	}

	sb := mk(daemon.AutoUpdateComponentSingBox, daemon.AutoUpdateCheckResult{
		Component:      daemon.AutoUpdateComponentSingBox,
		Installed:      true,
		Updated:        true,
		CurrentVersion: "1.14.0",
		LatestVersion:  "1.14.1",
		Message:        "已平滑升级至 v1.14.1",
	})
	agh := mk(daemon.AutoUpdateComponentAdGuard, daemon.AutoUpdateCheckResult{
		Component: daemon.AutoUpdateComponentAdGuard,
		Installed: false,
		Skipped:   true,
	})
	ts := mk(daemon.AutoUpdateComponentTailscale, daemon.AutoUpdateCheckResult{
		Component: daemon.AutoUpdateComponentTailscale,
		Installed: true,
		Skipped:   true,
	})
	sc := mk(daemon.AutoUpdateComponentSingCtl, daemon.AutoUpdateCheckResult{
		Component:      daemon.AutoUpdateComponentSingCtl,
		Installed:      true,
		Updated:        false,
		CurrentVersion: "v1.14.206",
		LatestVersion:  "v1.14.206",
		Message:        "已是最新版本",
	})

	u := daemon.NewComponentAutoUpdater(daemon.AutoUpdaterOptions{
		Targets:    []daemon.AutoUpdateTarget{sb, agh, ts, sc},
		Now:        func() time.Time { return now },
		StateStore: store,
		OnEvent:    func(ev daemon.WatchdogEventRecord) { events = append(events, ev) },
	})

	cfg := &config.Config{}
	cfg.Watchdog.AutoUpdate = config.ComponentAutoUpdateConfig{
		SingBox:       true,
		SingCtl:       true,
		IntervalHours: 12,
	}

	results := u.RunOnce(t.Context(), cfg, false)
	if !slices.Equal(order, []string{daemon.AutoUpdateComponentSingBox, daemon.AutoUpdateComponentSingCtl}) {
		t.Fatalf("expected execution order [singbox singctl], got %v", order)
	}
	if len(results) != 2 || !results[0].Updated || results[1].Updated {
		t.Fatalf("unexpected results: %+v", results)
	}
	if agh.calls.Load() != 0 || ts.calls.Load() != 0 {
		t.Fatalf("disabled targets must not be called: agh=%d ts=%d", agh.calls.Load(), ts.calls.Load())
	}

	snap := store.Load()
	sbState := snap.AutoUpdate[daemon.AutoUpdateComponentSingBox]
	if sbState.Status != "updated" || sbState.LatestVersion != "1.14.1" || sbState.LastUpdatedAt == "" {
		t.Fatalf("expected persisted singbox updated state, got %+v", sbState)
	}
	scState := snap.AutoUpdate[daemon.AutoUpdateComponentSingCtl]
	if scState.Status != "up_to_date" || scState.LastCheckedAt == "" {
		t.Fatalf("expected persisted singctl up_to_date state, got %+v", scState)
	}
	if len(events) != 1 || events[0].Action != "AUTO_UPDATE" || !events[0].Healthy {
		t.Fatalf("expected 1 AUTO_UPDATE event for actual upgrade, got %+v", events)
	}

	// Within 12h interval -> skipped without running again
	now = now.Add(6 * time.Hour)
	if again := u.RunOnce(t.Context(), cfg, false); len(again) != 0 {
		t.Fatalf("expected skip within 12h interval, got %+v", again)
	}

	// After >=12h interval -> runs again
	now = now.Add(6*time.Hour + time.Minute)
	if again := u.RunOnce(t.Context(), cfg, false); len(again) != 2 {
		t.Fatalf("expected run after 12h interval elapsed, got %+v", again)
	}
}

func TestComponentAutoUpdater_FailureCooldownAndConcurrency(t *testing.T) {
	dir := t.TempDir()
	store := daemon.NewStateStore(daemon.Paths{
		StateFile: filepath.Join(dir, "daemon.state"),
		LogFile:   filepath.Join(dir, "daemon.log"),
		PidFile:   filepath.Join(dir, "daemon.pid"),
	})

	now := time.Date(2026, 11, 27, 20, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	failNext := true

	target := &stubAutoUpdateTarget{
		id:          daemon.AutoUpdateComponentTailscale,
		displayName: "Tailscale",
		enabledFn:   func(cfg *config.Config) bool { return cfg.Watchdog.AutoUpdate.Tailscale },
		runFn: func(context.Context, *config.Config) (daemon.AutoUpdateCheckResult, error) {
			time.Sleep(15 * time.Millisecond)
			mu.Lock()
			shouldFail := failNext
			mu.Unlock()
			if shouldFail {
				return daemon.AutoUpdateCheckResult{Component: daemon.AutoUpdateComponentTailscale, Installed: true}, errors.New("github timeout")
			}
			return daemon.AutoUpdateCheckResult{
				Component:      daemon.AutoUpdateComponentTailscale,
				Installed:      true,
				Updated:        false,
				CurrentVersion: "1.94.2",
				LatestVersion:  "1.94.2",
			}, nil
		},
	}

	u := daemon.NewComponentAutoUpdater(daemon.AutoUpdaterOptions{
		Targets:         []daemon.AutoUpdateTarget{target},
		Now:             func() time.Time { return now },
		StateStore:      store,
		FailureCooldown: 2 * time.Hour,
	})

	cfg := &config.Config{}
	cfg.Watchdog.AutoUpdate.Tailscale = true

	// Concurrent RunOnce under -race -> only 1 runs while in-flight
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u.RunOnce(t.Context(), cfg, false)
		}()
	}
	wg.Wait()
	if got := target.calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 execution under concurrent storm, got %d", got)
	}

	snap := store.Load()
	if st := snap.AutoUpdate[daemon.AutoUpdateComponentTailscale]; st.Status != "failed" || st.LastError == "" {
		t.Fatalf("expected failed status with error recorded, got %+v", st)
	}

	// Within 2h failure cooldown -> skipped
	now = now.Add(90 * time.Minute)
	if res := u.RunOnce(t.Context(), cfg, false); len(res) != 0 {
		t.Fatalf("expected skip within 2h failure cooldown, got %+v", res)
	}

	// After 2h cooldown -> retries and clears error
	mu.Lock()
	failNext = false
	mu.Unlock()
	now = now.Add(45 * time.Minute)
	if res := u.RunOnce(t.Context(), cfg, false); len(res) != 1 {
		t.Fatalf("expected retry after cooldown, got %+v", res)
	}
	snap2 := store.Load()
	if st := snap2.AutoUpdate[daemon.AutoUpdateComponentTailscale]; st.Status != "up_to_date" || st.LastError != "" {
		t.Fatalf("expected cleared error after recovery, got %+v", st)
	}
}

func TestDefaultAutoUpdateTargets_OrderHasSingCtlLast(t *testing.T) {
	targets := daemon.DefaultAutoUpdateTargets(nil)
	if len(targets) != 4 {
		t.Fatalf("expected 4 default auto-update targets, got %d", len(targets))
	}
	gotIDs := []string{targets[0].ID(), targets[1].ID(), targets[2].ID(), targets[3].ID()}
	wantIDs := []string{
		daemon.AutoUpdateComponentSingBox,
		daemon.AutoUpdateComponentAdGuard,
		daemon.AutoUpdateComponentTailscale,
		daemon.AutoUpdateComponentSingCtl,
	}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("expected target order %v, got %v", wantIDs, gotIDs)
	}
	cfg := &config.Config{}
	for _, tgt := range targets {
		if tgt.Enabled(cfg) {
			t.Fatalf("expected target %s disabled by default", tgt.ID())
		}
	}
}
