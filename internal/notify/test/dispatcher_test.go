// 文件职责：覆盖调度器防刷屏冷却、恢复通知配对放行、静默窗穿透、每日限额、有界队列降级、热更新、测试发送、环形历史与并发安全测试。
package notify_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/notify"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
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

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, desc string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

func TestDispatcherPolicyChecksAndResolvedPairing(t *testing.T) {
	var received []map[string]any
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		mu.Lock()
		received = append(received, m)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clk := newFakeClock(time.Date(2026, 11, 23, 10, 0, 0, 0, time.Local))
	opts := notify.Options{
		Enabled:         false,
		CooldownMinutes: 15,
		DailyLimit:      5,
		QuietHours:      "23:00-07:30",
		EnabledEvents: map[notify.EventType]bool{
			notify.EventWatchdogHeal:       true,
			notify.EventSafeCommitRollback: true,
			notify.EventNewDevice:          false,
		},
		Webhook: notify.WebhookConfig{Enabled: true, URL: srv.URL + "/hook"},
	}

	d := notify.NewDispatcher(opts, notify.DispatcherDeps{
		HTTPClient: srv.Client(),
		NowFunc:    clk.Now,
		Hostname:   "router.example.com",
		Logf:       func(string, ...any) {},
	})
	d.Start(t.Context())
	defer d.Close()

	// 1. Master switch disabled
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "sb", Title: "t1"}); ok || reason == "" {
		t.Fatalf("expected disabled rejection, got ok=%v reason=%q", ok, reason)
	}

	// Enable master switch, but test no channels first (must NOT consume daily quota)
	optsNoChan := opts
	optsNoChan.Enabled = true
	optsNoChan.Webhook.Enabled = false
	d.UpdateOptions(optsNoChan)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "sb", Title: "no-chan"}); ok || reason == "" {
		t.Fatalf("expected no_channels rejection, got ok=%v reason=%q", ok, reason)
	}

	// Enable webhook
	opts.Enabled = true
	d.UpdateOptions(opts)

	// 2. Event type disabled
	if ok, reason := d.Emit(notify.Event{Type: notify.EventNewDevice, Severity: notify.SeverityInfo, DedupKey: "aa:bb", Title: "new dev"}); ok || reason == "" {
		t.Fatalf("expected event_disabled rejection, got ok=%v reason=%q", ok, reason)
	}

	// 3. Quiet hours blocks non-critical, allows critical
	clk.Set(time.Date(2026, 11, 23, 23, 30, 0, 0, time.Local))
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "q1", Title: "quiet warn"}); ok || reason == "" {
		t.Fatalf("expected quiet_hours rejection for warn, got ok=%v reason=%q", ok, reason)
	}
	if ok, reason := d.Emit(notify.Event{Type: notify.EventSafeCommitRollback, Severity: notify.SeverityCritical, DedupKey: "q-crit", Title: "quiet crit"}); !ok {
		t.Fatalf("expected critical to bypass quiet hours, got reason=%q", reason)
	}

	// 4. Cooldown + Resolved:true pairing (move to daytime next day so daily limit resets cleanly!)
	clk.Set(time.Date(2026, 11, 24, 10, 0, 0, 0, time.Local))

	// Fault #1 passes (dailyCount = 1)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "sing-box", Title: "down"}); !ok {
		t.Fatalf("fault #1 should pass, got reason=%q", reason)
	}
	// Fault #2 within 15m rejected by cooldown
	clk.Advance(2 * time.Minute)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "sing-box", Title: "down again"}); ok || reason == "" {
		t.Fatalf("fault #2 within cooldown should fail, got ok=%v reason=%q", ok, reason)
	}
	// Different DedupKey is independent (dailyCount = 2)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "smartdns", Title: "dns down"}); !ok {
		t.Fatalf("independent dedup key should pass, got reason=%q", reason)
	}
	// Resolved #1 for "sing-box" within fault cooldown MUST pass once (dailyCount = 3)
	clk.Advance(1 * time.Minute)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityInfo, DedupKey: "sing-box", Title: "recovered", Resolved: true}); !ok {
		t.Fatalf("paired Resolved:true should bypass fault cooldown once, got reason=%q", reason)
	}
	// Duplicate Resolved #2 immediately after MUST be suppressed by cooldown
	clk.Advance(1 * time.Minute)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityInfo, DedupKey: "sing-box", Title: "recovered dup", Resolved: true}); ok || reason == "" {
		t.Fatalf("duplicate Resolved:true should be suppressed by cooldown, got ok=%v reason=%q", ok, reason)
	}
	// Flapping Fault #3 still within 15m of Fault #1 MUST still be suppressed
	clk.Advance(1 * time.Minute)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "sing-box", Title: "flap"}); ok || reason == "" {
		t.Fatalf("flapping fault within cooldown should be suppressed, got ok=%v reason=%q", ok, reason)
	}
	// After 15m from Fault #1, Fault #4 passes (dailyCount = 4)
	clk.Advance(11 * time.Minute)
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "sing-box", Title: "down after cooldown"}); !ok {
		t.Fatalf("fault after cooldown expiry should pass, got reason=%q", reason)
	}

	// 5. Daily limit (limit = 5): one more passes (dailyCount = 5), next rejected
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "k5", Title: "fifth"}); !ok {
		t.Fatalf("5th daily event should pass, got reason=%q", reason)
	}
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityCritical, DedupKey: "k6", Title: "sixth"}); ok || reason == "" {
		t.Fatalf("6th daily event should hit daily_limit, got ok=%v reason=%q", ok, reason)
	}

	// Next day resets daily limit
	clk.Set(time.Date(2026, 11, 25, 9, 0, 0, 0, time.Local))
	if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "k6", Title: "next day"}); !ok {
		t.Fatalf("next day event should pass after daily reset, got reason=%q", reason)
	}

	// Total accepted: 1 (Nov23 crit) + 5 (Nov24) + 1 (Nov25) = 7
	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 7
	}, "all 7 queued alerts delivered")

	hist := d.RecentHistory()
	if len(hist) != 7 {
		t.Fatalf("expected 7 history entries, got %d", len(hist))
	}
	if hist[0].Title != "next day" || !hist[0].Success {
		t.Fatalf("expected newest history entry first, got %+v", hist[0])
	}
}

func TestDispatcherQueueOverflowDropOldestAndNonBlocking(t *testing.T) {
	gate := make(chan struct{})
	var deliveredTitles []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if title, ok := m["title"].(string); ok {
			mu.Lock()
			deliveredTitles = append(deliveredTitles, title)
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var dropLogs atomic.Int32
	d := notify.NewDispatcher(notify.Options{
		Enabled:    true,
		DailyLimit: 200,
		Webhook:    notify.WebhookConfig{Enabled: true, URL: srv.URL},
	}, notify.DispatcherDeps{
		HTTPClient: srv.Client(),
		Logf: func(format string, args ...any) {
			if strings.Contains(strings.ToLower(format), "queue") || strings.Contains(strings.ToLower(format), "drop") {
				dropLogs.Add(1)
			}
		},
	})

	// Emit 60 events BEFORE Start (so queue fills past MaxQueueSize=32 without blocking!)
	const totalEmit = 60
	start := time.Now()
	for i := range totalEmit {
		ok, reason := d.Emit(notify.Event{
			Type:     notify.EventResourceGuard,
			Severity: notify.SeverityWarn,
			DedupKey: fmt.Sprintf("k-%d", i),
			Title:    fmt.Sprintf("ev-%02d", i),
		})
		if !ok {
			t.Fatalf("emit %d failed unexpectedly: %q", i, reason)
		}
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatalf("Emit blocked unexpectedly on queue overflow: %v", time.Since(start))
	}
	if dropLogs.Load() != int32(totalEmit-notify.MaxQueueSize) {
		t.Fatalf("expected %d drop warning logs, got %d", totalEmit-notify.MaxQueueSize, dropLogs.Load())
	}

	d.Start(t.Context())
	close(gate)
	waitUntil(t, 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(deliveredTitles) == notify.MaxQueueSize
	}, "all 32 retained events delivered")
	d.Close()

	mu.Lock()
	firstTitle := deliveredTitles[0]
	lastTitle := deliveredTitles[len(deliveredTitles)-1]
	mu.Unlock()
	if firstTitle != "ev-28" || lastTitle != "ev-59" {
		t.Fatalf("expected drop-oldest retaining ev-28..ev-59, got first=%q last=%q", firstTitle, lastTitle)
	}
}

func TestDispatcherSendTestBypassesPolicyAndReportsPerChannel(t *testing.T) {
	var tgHits, whHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/bot") {
			tgHits.Add(1)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		whHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clk := newFakeClock(time.Date(2026, 11, 23, 23, 45, 0, 0, time.Local)) // inside quiet hours!
	d := notify.NewDispatcher(notify.Options{
		Enabled:    false, // master switch OFF
		DailyLimit: 1,
		QuietHours: "23:00-07:30",
	}, notify.DispatcherDeps{
		HTTPClient: srv.Client(),
		NowFunc:    clk.Now,
		Hostname:   "node.example.com",
		Logf:       func(string, ...any) {},
	})

	testOpts := notify.Options{
		Enabled:    false, // even if master switch off, SendTest still works
		QuietHours: "23:00-07:30",
		DailyLimit: 1,
		Telegram:   notify.TelegramConfig{Enabled: true, BotToken: "111:demo", ChatID: "222", APIBaseURL: srv.URL},
		Webhook:    notify.WebhookConfig{Enabled: true, URL: srv.URL + "/hook"},
	}

	// 1. Target single channel
	resSingle := d.SendTest(t.Context(), testOpts, notify.ChannelTelegram)
	if len(resSingle) != 1 || resSingle[0].Channel != notify.ChannelTelegram || !resSingle[0].OK {
		t.Fatalf("targeted SendTest failed: %+v", resSingle)
	}
	if tgHits.Load() != 1 || whHits.Load() != 0 {
		t.Fatalf("expected only telegram called, tg=%d wh=%d", tgHits.Load(), whHits.Load())
	}

	// 2. All enabled channels
	resAll := d.SendTest(t.Context(), testOpts, "")
	if len(resAll) != 2 || !resAll[0].OK || !resAll[1].OK {
		t.Fatalf("SendTest all failed: %+v", resAll)
	}
	if tgHits.Load() != 2 || whHits.Load() != 1 {
		t.Fatalf("expected both called, tg=%d wh=%d", tgHits.Load(), whHits.Load())
	}

	// 3. Unknown channel
	resUnknown := d.SendTest(t.Context(), testOpts, "nonexistent")
	if len(resUnknown) != 1 || resUnknown[0].OK || resUnknown[0].Error == "" {
		t.Fatalf("expected unknown channel error result, got %+v", resUnknown)
	}

	// 4. Invalid URL reported as DeliveryResult error & disabled channel / empty options
	badOpts := notify.Options{
		Webhook: notify.WebhookConfig{Enabled: true, URL: "file:///etc/shadow"},
	}
	resBad := d.SendTest(t.Context(), badOpts, notify.ChannelWebhook)
	if len(resBad) != 1 || resBad[0].OK || resBad[0].Error == "" {
		t.Fatalf("expected invalid url error in SendTest, got %+v", resBad)
	}
	if resDis := d.SendTest(t.Context(), notify.Options{}, notify.ChannelTelegram); len(resDis) != 1 || resDis[0].OK || resDis[0].Error == "" {
		t.Fatalf("expected disabled channel error result, got %+v", resDis)
	}
	if resEmpty := d.SendTest(t.Context(), notify.Options{}, ""); len(resEmpty) != 0 {
		t.Fatalf("expected empty result slice when no channels enabled, got %+v", resEmpty)
	}

	// 5. Invalid QuietHours on UpdateOptions logs warning and falls back gracefully without blocking Emit
	d.UpdateOptions(notify.Options{
		Enabled:    true,
		DailyLimit: 2,
		QuietHours: "invalid-quiet-spec",
		Webhook:    notify.WebhookConfig{Enabled: true, URL: srv.URL + "/hook"},
	})
	if ok, reason := d.Emit(notify.Event{Type: notify.EventAuditHighRisk, Severity: notify.SeverityCritical, DedupKey: "a1", Title: "real alert"}); !ok {
		t.Fatalf("Emit should still have full daily quota after SendTest, got reason=%q", reason)
	}
	// Standalone Resolved without prior fault passes once, duplicate suppressed by cooldown
	if ok, reason := d.Emit(notify.Event{Type: notify.EventAuditHighRisk, Severity: notify.SeverityInfo, DedupKey: "standalone", Title: "res1", Resolved: true}); !ok {
		t.Fatalf("first standalone resolved should pass, got reason=%q", reason)
	}
	if ok, reason := d.Emit(notify.Event{Type: notify.EventAuditHighRisk, Severity: notify.SeverityInfo, DedupKey: "standalone", Title: "res2", Resolved: true}); ok || reason == "" {
		t.Fatalf("second standalone resolved should be rate-limited, got ok=%v reason=%q", ok, reason)
	}
}

func TestDispatcherHistoryRingCapAndDefensiveCopy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := notify.NewDispatcher(notify.Options{
		Enabled:    true,
		DailyLimit: 200,
		Webhook:    notify.WebhookConfig{Enabled: true, URL: srv.URL},
	}, notify.DispatcherDeps{
		HTTPClient: srv.Client(),
		Logf:       func(string, ...any) {},
	})
	d.Start(t.Context())
	defer d.Close()

	// Emit 65 events in batches <= 32 so none drop, testing 50-item ring cap
	for batch := range 3 {
		for j := range 22 {
			idx := batch*22 + j
			if idx >= 65 {
				break
			}
			ok, reason := d.Emit(notify.Event{
				Type:     notify.EventSubOrNodeFail,
				Severity: notify.SeverityWarn,
				DedupKey: fmt.Sprintf("sub-%d", idx),
				Title:    fmt.Sprintf("hist-%02d", idx),
			})
			if !ok {
				t.Fatalf("emit %d failed: %q", idx, reason)
			}
		}
		target := min((batch+1)*22, 65)
		waitUntil(t, 2*time.Second, func() bool {
			h := d.RecentHistory()
			if len(h) == 0 {
				return false
			}
			return h[0].Title == fmt.Sprintf("hist-%02d", target-1)
		}, fmt.Sprintf("batch %d history updated", batch))
	}

	hist := d.RecentHistory()
	if len(hist) != notify.MaxHistorySize {
		t.Fatalf("history length = %d, want %d", len(hist), notify.MaxHistorySize)
	}
	if hist[0].Title != "hist-64" || hist[notify.MaxHistorySize-1].Title != "hist-15" {
		t.Fatalf("ring buffer range wrong: newest=%q oldest=%q", hist[0].Title, hist[notify.MaxHistorySize-1].Title)
	}

	// Mutating returned slice and nested Channels slice must not corrupt internal history
	hist[0].Title = "mutated"
	hist[0].Channels[0] = "mutated-ch"
	fresh := d.RecentHistory()
	if fresh[0].Title != "hist-64" || fresh[0].Channels[0] != notify.ChannelWebhook {
		t.Fatalf("RecentHistory did not return defensive copy: %+v", fresh[0])
	}
}

func TestDispatcherLifecycleCancelTimeoutAndConcurrencyRace(t *testing.T) {
	t.Run("close_cancels_inflight_delivery_promptly", func(t *testing.T) {
		inFlight := make(chan struct{})
		stopSrv := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case inFlight <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
			case <-stopSrv:
			}
		}))
		defer srv.Close()
		defer close(stopSrv)

		d := notify.NewDispatcher(notify.Options{
			Enabled: true,
			Webhook: notify.WebhookConfig{Enabled: true, URL: srv.URL},
		}, notify.DispatcherDeps{
			HTTPClient:  srv.Client(),
			SendTimeout: 2 * time.Second,
			Logf:        func(string, ...any) {},
		})
		d.Start(t.Context())
		d.Start(t.Context()) // idempotent double Start

		if ok, reason := d.Emit(notify.Event{Type: notify.EventServerQuotaOrBan, Severity: notify.SeverityCritical, DedupKey: "q", Title: "slow"}); !ok {
			t.Fatalf("Emit failed: %q", reason)
		}
		<-inFlight

		closeStart := time.Now()
		d.Close()
		d.Close() // idempotent double Close
		if elapsed := time.Since(closeStart); elapsed > 500*time.Millisecond {
			t.Fatalf("Close took too long to cancel in-flight delivery: %v", elapsed)
		}

		// Emit after Close must fail cleanly without panic
		if ok, reason := d.Emit(notify.Event{Type: notify.EventAuditHighRisk, Severity: notify.SeverityWarn, DedupKey: "after", Title: "after-close"}); ok || reason == "" {
			t.Fatalf("Emit after Close should be rejected, got ok=%v reason=%q", ok, reason)
		}
	})

	t.Run("send_timeout_enforced", func(t *testing.T) {
		stopSrv := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-stopSrv:
			}
		}))
		defer srv.Close()
		defer close(stopSrv)

		d := notify.NewDispatcher(notify.Options{
			Enabled: true,
			Webhook: notify.WebhookConfig{Enabled: true, URL: srv.URL},
		}, notify.DispatcherDeps{
			HTTPClient:  srv.Client(),
			SendTimeout: 80 * time.Millisecond,
			Logf:        func(string, ...any) {},
		})
		start := time.Now()
		res := d.SendTest(t.Context(), notify.Options{
			Webhook: notify.WebhookConfig{Enabled: true, URL: srv.URL},
		}, notify.ChannelWebhook)
		elapsed := time.Since(start)
		if len(res) != 1 || res[0].OK || !strings.Contains(res[0].Error, "deadline") {
			t.Fatalf("expected timeout error result, got %+v", res)
		}
		if elapsed > 500*time.Millisecond {
			t.Fatalf("SendTimeout not enforced promptly: %v", elapsed)
		}
	})

	t.Run("partial_channel_failure_recorded_in_history", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/ok") {
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Error(w, "downstream err", http.StatusInternalServerError)
		}))
		defer srv.Close()

		d := notify.NewDispatcher(notify.Options{
			Enabled: true,
			Webhook: notify.WebhookConfig{Enabled: true, URL: srv.URL + "/ok"},
			WeCom:   notify.WeComConfig{Enabled: true, WebhookURL: srv.URL + "/fail"},
		}, notify.DispatcherDeps{
			HTTPClient: srv.Client(),
			Logf:       func(string, ...any) {},
		})
		d.Start(t.Context())
		defer d.Close()

		if ok, reason := d.Emit(notify.Event{Type: notify.EventWatchdogHeal, Severity: notify.SeverityWarn, DedupKey: "partial", Title: "partial-fail"}); !ok {
			t.Fatalf("Emit failed: %q", reason)
		}
		waitUntil(t, 2*time.Second, func() bool {
			return len(d.RecentHistory()) == 1
		}, "partial failure history recorded")

		rec := d.RecentHistory()[0]
		if rec.Success || !strings.Contains(rec.Error, notify.ChannelWeCom) || len(rec.Channels) != 2 {
			t.Fatalf("unexpected partial failure history record: %+v", rec)
		}
	})

	t.Run("concurrent_stress_race_free", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		baseOpts := notify.Options{
			Enabled:         true,
			CooldownMinutes: 1,
			DailyLimit:      500,
			Webhook:         notify.WebhookConfig{Enabled: true, URL: srv.URL},
		}
		d := notify.NewDispatcher(baseOpts, notify.DispatcherDeps{
			HTTPClient:  srv.Client(),
			SendTimeout: 500 * time.Millisecond,
			Logf:        func(string, ...any) {},
		})
		ctx, cancel := context.WithCancel(t.Context())
		d.Start(ctx)

		var wg sync.WaitGroup
		for worker := range 8 {
			wg.Go(func() {
				for i := range 25 {
					d.Emit(notify.Event{
						Type:     notify.EventWatchdogHeal,
						Severity: notify.SeverityWarn,
						DedupKey: fmt.Sprintf("w%d-k%d", worker, i),
						Title:    fmt.Sprintf("concurrent-%d-%d", worker, i),
					})
				}
			})
		}
		wg.Go(func() {
			for i := range 15 {
				updated := baseOpts
				updated.DailyLimit = 400 + i
				updated.EnabledEvents = map[notify.EventType]bool{notify.EventWatchdogHeal: true}
				d.UpdateOptions(updated)
				_ = d.RecentHistory()
			}
		})
		wg.Go(func() {
			for range 5 {
				_ = d.SendTest(t.Context(), baseOpts, notify.ChannelWebhook)
			}
		})

		wg.Wait()
		cancel()
		d.Close()
	})
}
