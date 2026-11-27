package audit_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestCollector_ReadPathDebouncesDiskSaveWhileKeepingMemoryFresh(t *testing.T) {
	var downBytes atomic.Int64
	downBytes.Store(4096)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"connections": [{
				"id": "debounce-conn-1",
				"upload": 512,
				"download": %d,
				"start": "2026-11-27T12:00:00Z",
				"chains": ["DIRECT"],
				"rule": "final",
				"metadata": {
					"network": "tcp",
					"sourceIP": "192.168.89.137",
					"destinationIP": "203.0.113.20",
					"destinationPort": "443",
					"host": "cdn.example.com"
				}
			}]
		}`, downBytes.Load())
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "audit-state.json")
	c := audit.NewCollector(&config.Config{})
	c.SetLeaseFilesForTest(nil, filepath.Join(tmpDir, "missing-arp"), filepath.Join(tmpDir, "missing-hosts"))
	c.SetEndpointsForTest([]string{srv.URL}, "", statePath)

	curNow := time.Date(2026, 11, 27, 15, 0, 0, 0, time.UTC)
	c.SetNowFuncForTest(func() time.Time { return curNow })

	// First Collect creates initial state file on disk.
	rep1 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	if len(rep1.Flows) != 1 || rep1.Flows[0].DownloadBytes != 4096 {
		t.Fatalf("first collect unexpected: %+v", rep1.Flows)
	}
	info1, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("expected initial state file written: %v", err)
	}

	// 2 seconds later with new byte delta: memory report MUST reflect latest bytes,
	// while disk rewrite MUST be debounced (same inode) to keep GET /api/audit hot path fast!
	curNow = curNow.Add(2 * time.Second)
	downBytes.Store(8192)
	rep2 := c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	if len(rep2.Flows) != 1 || rep2.Flows[0].DownloadBytes != 8192 {
		t.Fatalf("second collect must reflect fresh in-memory bytes=8192, got %+v", rep2.Flows)
	}
	info2, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(info1, info2) {
		t.Fatalf("expected GET Collect hot path to debounce disk rewrite within 30s window, but inode changed")
	}

	// 35 seconds later with new delta: debounce window elapsed -> MUST flush to disk now!
	curNow = curNow.Add(35 * time.Second)
	downBytes.Store(16384)
	_ = c.Collect(t.Context(), audit.CollectOptions{Limit: -1})
	info3, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(info2, info3) {
		t.Fatalf("expected disk flush after 30s debounce window elapsed")
	}
}

func TestIdentifyApp_MemoizationAndRaceSafety(t *testing.T) {
	// Verify repeated calls across 1500 distinct targets + repeated polls are race-free & fast.
	targets := make([]string, 300)
	for i := range targets {
		targets[i] = fmt.Sprintf("edge-%03d.cdn.example.com", i)
	}
	// First pass warms memoization; second pass should be near-instant.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, host := range targets {
				_ = audit.IdentifyApp(host, "198.51.100.10", "")
			}
			if got := audit.IdentifyApp("www.youtube.com", "", ""); got != "YouTube" {
				t.Errorf("expected YouTube, got %q", got)
			}
			if got := audit.IdentifyApp("unknown.example.com", "", "rule_set=geosite-github"); got != "GitHub" {
				t.Errorf("expected GitHub from ruleStr, got %q", got)
			}
		}()
	}
	wg.Wait()

	// Ensure ruleStr differentiation isn't polluted by memoization key collision!
	a := audit.IdentifyApp("shared.example.com", "", "rule_set=geosite-github")
	b := audit.IdentifyApp("shared.example.com", "", "rule_set=geosite-netflix")
	if a != "GitHub" || b != "Netflix" || strings.EqualFold(a, b) {
		t.Fatalf("memoization key collision across different ruleStr: a=%q b=%q", a, b)
	}
}
