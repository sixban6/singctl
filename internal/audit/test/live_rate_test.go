// 文件职责：覆盖审计流实时上传/下载速度（基于真实采样时间差、新连接真实建连时间、老连接防历史突刺、防抖与并发竞态）的表驱动测试。
package audit_test

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/audit"
)

func TestCollector_LiveTransferRates_TableDriven(t *testing.T) {
	baseTime := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

	t.Run("existing_connection_real_delta_and_multi_conn_aggregation", func(t *testing.T) {
		var curNow atomic.Int64
		curNow.Store(baseTime.UnixNano())
		var payload atomic.Value
		payload.Store(`{"connections":[]}`)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload.Load().(string)))
		}))
		defer srv.Close()

		c := audit.NewCollector(nil)
		c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(t.TempDir(), "state.json"))
		c.SetNowFuncForTest(func() time.Time { return time.Unix(0, curNow.Load()).UTC() })

		// Tick 1: pre-existing connection started 1 hour ago with 10MB already uploaded -> must NOT dump 10MB into live speed!
		oldStart := baseTime.Add(-1 * time.Hour).Format(time.RFC3339Nano)
		payload.Store(fmt.Sprintf(`{
			"connections": [
				{
					"id": "conn-1",
					"upload": 10485760,
					"download": 2097152,
					"start": %q,
					"chains": ["DIRECT"],
					"metadata": {"network":"tcp","sourceIP":"192.168.1.50","destinationIP":"203.0.113.10","destinationPort":"443","host":"cloud.example.com"}
				}
			]
		}`, oldStart))

		rep1 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
		if len(rep1.Flows) != 1 {
			t.Fatalf("tick1 expected 1 flow, got %d", len(rep1.Flows))
		}
		if rep1.Flows[0].CurrentUploadBps != 0 || rep1.Flows[0].CurrentDownloadBps != 0 {
			t.Fatalf("tick1 pre-existing conn should not dump historical bytes as live rate, got up=%.1f down=%.1f",
				rep1.Flows[0].CurrentUploadBps, rep1.Flows[0].CurrentDownloadBps)
		}
		// FirstSeenUnix should incorporate real conn.Start (1 hour span = 3600s, not clamped to 60s)
		if rep1.Flows[0].ActiveSpanSec < 3590 {
			t.Fatalf("expected ActiveSpanSec to reflect real conn.Start (~3600s), got %d", rep1.Flows[0].ActiveSpanSec)
		}

		// Tick 2 (+5.0s): conn-1 uploads +500KB (100 KB/s) and downloads +1000KB (200 KB/s);
		// plus a brand new conn-2 started 2s ago (after tick 1!) uploading 100KB (50 KB/s) under the same flow key.
		t2 := baseTime.Add(5 * time.Second)
		curNow.Store(t2.UnixNano())
		newStart := t2.Add(-2 * time.Second).Format(time.RFC3339Nano)
		payload.Store(fmt.Sprintf(`{
			"connections": [
				{
					"id": "conn-1",
					"upload": %d,
					"download": %d,
					"start": %q,
					"chains": ["DIRECT"],
					"metadata": {"network":"tcp","sourceIP":"192.168.1.50","destinationIP":"203.0.113.10","destinationPort":"443","host":"cloud.example.com"}
				},
				{
					"id": "conn-2",
					"upload": %d,
					"download": %d,
					"start": %q,
					"chains": ["DIRECT"],
					"metadata": {"network":"tcp","sourceIP":"192.168.1.50","destinationIP":"203.0.113.10","destinationPort":"443","host":"cloud.example.com"}
				}
			]
		}`, 10485760+500*1024, 2097152+1000*1024, oldStart, 100*1024, 200*1024, newStart))

		rep2 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
		if len(rep2.Flows) != 1 {
			t.Fatalf("tick2 expected 1 aggregated flow, got %d", len(rep2.Flows))
		}
		// Expected: conn-1 (100 KB/s up, 200 KB/s down) + conn-2 (50 KB/s up, 100 KB/s down) = 150 KB/s up, 300 KB/s down
		wantUp := 150.0 * 1024
		wantDown := 300.0 * 1024
		if math.Abs(rep2.Flows[0].CurrentUploadBps-wantUp) > 512 {
			t.Fatalf("tick2 CurrentUploadBps = %.1f, want ~%.1f", rep2.Flows[0].CurrentUploadBps, wantUp)
		}
		if math.Abs(rep2.Flows[0].CurrentDownloadBps-wantDown) > 512 {
			t.Fatalf("tick2 CurrentDownloadBps = %.1f, want ~%.1f", rep2.Flows[0].CurrentDownloadBps, wantDown)
		}

		// Tick 3 (+100ms rapid manual refresh): debounce < 0.5s should preserve last computed live rate rather than flickering to 0!
		curNow.Store(t2.Add(100 * time.Millisecond).UnixNano())
		rep3 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
		if math.Abs(rep3.Flows[0].CurrentUploadBps-wantUp) > 512 {
			t.Fatalf("rapid refresh debounce should preserve live upload rate %.1f, got %.1f", wantUp, rep3.Flows[0].CurrentUploadBps)
		}

		// Tick 4 (+5s after tick 2, no byte growth): live speed drops cleanly to 0
		curNow.Store(t2.Add(5 * time.Second).UnixNano())
		rep4 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
		if rep4.Flows[0].CurrentUploadBps != 0 || rep4.Flows[0].CurrentDownloadBps != 0 {
			t.Fatalf("idle connection should report 0 live speed, got up=%.1f down=%.1f",
				rep4.Flows[0].CurrentUploadBps, rep4.Flows[0].CurrentDownloadBps)
		}

		// Tick 5 (+5s, connections closed): historical flow reports 0 live speed
		curNow.Store(t2.Add(10 * time.Second).UnixNano())
		payload.Store(`{"connections":[]}`)
		rep5 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
		if len(rep5.Flows) != 1 || rep5.Flows[0].ActiveConns != 0 || rep5.Flows[0].CurrentUploadBps != 0 || rep5.Flows[0].CurrentDownloadBps != 0 {
			t.Fatalf("closed flow should have 0 active conns and 0 live speed, got %+v", rep5.Flows)
		}
	})

	t.Run("concurrent_collect_and_sample_race_safety", func(t *testing.T) {
		var tick atomic.Int64
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := tick.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"connections":[{"id":"race-1","upload":%d,"download":%d,"start":"2026-11-23T11:59:00Z","chains":["DIRECT"],"metadata":{"network":"tcp","sourceIP":"192.168.1.66","destinationIP":"203.0.113.66","destinationPort":"443","host":"race.example.com"}}]}`, n*4096, n*8192)
		}))
		defer srv.Close()

		c := audit.NewCollector(nil)
		c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(t.TempDir(), "race-state.json"))
		var curSec atomic.Int64
		curSec.Store(baseTime.Unix())
		c.SetNowFuncForTest(func() time.Time { return time.Unix(curSec.Add(1), 0).UTC() })

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 5 {
					_ = c.SampleActiveConnections(t.Context())
					_ = c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
				}
			}()
		}
		wg.Wait()
	})
}
