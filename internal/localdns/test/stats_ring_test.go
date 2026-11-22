// 文件职责：验证 24 小时有界滑动环形统计器的窗口滚动、低内存容量硬上限、延迟聚合、连接去重与高并发竞态安全。
package localdns_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"singctl/internal/localdns"
)

func TestStatsRing_SlidingWindowAndAggregation(t *testing.T) {
	base := time.Date(2026, 11, 22, 12, 30, 0, 0, time.UTC)
	ring := localdns.NewStatsRing(false)

	// Record events 25 hours ago (must be evicted from 24h window)
	ring.Record(base.Add(-25*time.Hour), "expired.example.com", true, 50)
	// Record events 23 hours ago (must remain inside 24h window)
	ring.Record(base.Add(-23*time.Hour), "edge.example.com", false, 10)
	// Record current hour events (case & trailing dot normalization)
	ring.Record(base, "API.Example.COM.", false, 20)
	ring.Record(base.Add(time.Minute), "api.example.com", false, 30)
	ring.Record(base.Add(90*time.Second), "api.example.com", false, 20)
	ring.Record(base.Add(2*time.Minute), "ads.example.com", true, 0)
	ring.Record(base.Add(3*time.Minute), "ads.example.com", true, 0)
	// Empty domain should be ignored cleanly
	ring.Record(base, "   ", false, 5)

	snap := ring.Snapshot(base.Add(5*time.Minute), 99)
	if snap.NumDNSQueries != 6 {
		t.Fatalf("NumDNSQueries = %d, want 6", snap.NumDNSQueries)
	}
	if snap.NumBlockedFiltering != 2 {
		t.Fatalf("NumBlockedFiltering = %d, want 2", snap.NumBlockedFiltering)
	}
	if snap.BlockedPercent != 33.3 {
		t.Fatalf("BlockedPercent = %v, want 33.3", snap.BlockedPercent)
	}
	// Latency samples: 10, 20, 30, 20 -> avg 20.0ms
	if snap.AvgProcessingMs != 20 {
		t.Fatalf("AvgProcessingMs = %v, want 20", snap.AvgProcessingMs)
	}
	if len(snap.TopQueriedDomains) == 0 || snap.TopQueriedDomains[0].Domain != "api.example.com" || snap.TopQueriedDomains[0].Count != 3 {
		t.Fatalf("unexpected TopQueriedDomains: %+v", snap.TopQueriedDomains)
	}
	if len(snap.TopBlockedDomains) != 1 || snap.TopBlockedDomains[0].Domain != "ads.example.com" || snap.TopBlockedDomains[0].Count != 2 {
		t.Fatalf("unexpected TopBlockedDomains: %+v", snap.TopBlockedDomains)
	}

	// Out-of-order stale event for an older hour in same slot must NOT overwrite newer slot
	ring.Record(base.Add(-24*time.Hour), "stale-same-slot.example.com", true, 100)
	snapAfterStale := ring.Snapshot(base.Add(5*time.Minute), 99)
	if snapAfterStale.NumDNSQueries != 6 {
		t.Fatalf("stale event corrupted newer bucket: got %d queries, want 6", snapAfterStale.NumDNSQueries)
	}

	// Fallback latency used when zero latency samples exist
	ring.Reset()
	ring.Record(base, "only-no-lat.example.com", false, 0)
	ring.SetFallbackLatencyMs(14.56)
	snapFallback := ring.Snapshot(base, ring.FallbackLatencyMs())
	if snapFallback.AvgProcessingMs != 14.6 {
		t.Fatalf("fallback AvgProcessingMs = %v, want 14.6", snapFallback.AvgProcessingMs)
	}
}

func TestStatsRing_LowMemoryCapPreventsUnboundedGrowth(t *testing.T) {
	now := time.Date(2026, 11, 22, 15, 0, 0, 0, time.UTC)
	ring := localdns.NewStatsRing(true) // low-memory cap = 256 domains/bucket

	for i := range 600 {
		dom := fmt.Sprintf("d%04d.example.com", i)
		ring.Record(now, dom, i%2 == 0, 12)
	}

	snap := ring.Snapshot(now, 0)
	if snap.NumDNSQueries != 600 || snap.NumBlockedFiltering != 300 {
		t.Fatalf("totals must remain exact even when domain map capped: got queries=%d blocked=%d",
			snap.NumDNSQueries, snap.NumBlockedFiltering)
	}
	if len(snap.TopQueriedDomains) > 8 || len(snap.TopBlockedDomains) > 12 {
		t.Fatalf("top domain lists exceeded limits: queried=%d blocked=%d",
			len(snap.TopQueriedDomains), len(snap.TopBlockedDomains))
	}
}

func TestDomainTelemetryTracker_DeduplicatesAndTracksBlocked(t *testing.T) {
	now := time.Date(2026, 11, 22, 16, 0, 0, 0, time.UTC)
	ring := localdns.NewStatsRing(true)
	tracker := localdns.NewDomainTelemetryTracker(ring, 128)

	batch1 := []localdns.DomainEvent{
		{ID: "c1", Domain: "video.example.com", Blocked: false},
		{ID: "c2", Domain: "ad.example.com", Blocked: true},
		{ID: "c3", Domain: "192.0.2.10", Blocked: false}, // bare IP ignored
	}
	if n := tracker.IngestEvents(now, batch1); n != 2 {
		t.Fatalf("batch1 ingested = %d, want 2", n)
	}
	// Repeating active connection IDs must not double-count
	batch2 := []localdns.DomainEvent{
		{ID: "c1", Domain: "video.example.com", Blocked: false},
		{ID: "c4", Domain: "news.example.com", Blocked: false},
	}
	if n := tracker.IngestEvents(now.Add(10*time.Second), batch2); n != 1 {
		t.Fatalf("batch2 ingested = %d, want 1", n)
	}

	snap := ring.Snapshot(now.Add(20*time.Second), 18.0)
	if snap.NumDNSQueries != 3 || snap.NumBlockedFiltering != 1 {
		t.Fatalf("unexpected telemetry totals: queries=%d blocked=%d", snap.NumDNSQueries, snap.NumBlockedFiltering)
	}
}

func TestStatsRing_ConcurrentRaceSafety(t *testing.T) {
	now := time.Now()
	ring := localdns.NewStatsRingWithCap(64)
	tracker := localdns.NewDomainTelemetryTracker(ring, 64)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 200 {
				ts := now.Add(time.Duration(i%3) * time.Hour)
				ring.Record(ts, fmt.Sprintf("host-%d-%d.example.com", g, i%80), i%5 == 0, float64(i%40))
				tracker.IngestEvents(ts, []localdns.DomainEvent{
					{ID: fmt.Sprintf("id-%d-%d", g, i), Domain: fmt.Sprintf("t%d.example.com", i%20), Blocked: i%3 == 0},
				})
				if i%25 == 0 {
					_ = ring.Snapshot(ts, 12.0)
				}
			}
		})
	}
	wg.Wait()

	snap := ring.Snapshot(now.Add(2*time.Hour), 12.0)
	if snap.NumDNSQueries == 0 {
		t.Fatal("expected non-zero queries after concurrent recording")
	}
}
