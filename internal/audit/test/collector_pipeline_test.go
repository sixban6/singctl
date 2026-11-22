// 文件职责：全覆盖验证 Collector 过滤/排序/截断流水线与 CloseConnections 多端点回退及并发安全。
package audit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestCloseConnections_TableDrivenFiltersAndFallback(t *testing.T) {
	var mu sync.Mutex
	var deletedPaths []string

	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer deadSrv.Close()

	liveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-sec" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id": "conn-1",
						"metadata": map[string]string{
							"network":       "tcp",
							"sourceIP":      "192.168.1.10",
							"destinationIP": "203.0.113.10",
							"host":          "video.example.com",
						},
					},
					{
						"id": "conn-2",
						"metadata": map[string]string{
							"network":       "udp",
							"sourceIP":      "192.168.1.11",
							"destinationIP": "203.0.113.20",
							"host":          "game.example.com",
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodDelete {
			mu.Lock()
			deletedPaths = append(deletedPaths, r.URL.Path)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer liveSrv.Close()

	dir := t.TempDir()
	c := audit.NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{deadSrv.URL, liveSrv.URL}, "test-sec", filepath.Join(dir, "state.json"))
	c.SetLeaseFilesForTest(nil, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))

	// 1. Scoped close by DeviceIP + Target + Network + seed ConnIDs
	res, err := c.CloseConnections(t.Context(), audit.CloseConnectionsRequest{
		ConnIDs:  []string{"seed-0", "seed-0"},
		DeviceIP: "192.168.1.10",
		Target:   "video.example.com.",
		Network:  "TCP",
	})
	if err != nil {
		t.Fatalf("scoped CloseConnections failed: %v", err)
	}
	if res.All || res.Closed != 2 {
		t.Fatalf("expected 2 connections closed (seed-0 + conn-1), got %+v", res)
	}
	mu.Lock()
	gotPaths := slices.Clone(deletedPaths)
	deletedPaths = nil
	mu.Unlock()
	if !slices.Equal(gotPaths, []string{"/connections/seed-0", "/connections/conn-1"}) {
		t.Fatalf("unexpected DELETE paths: %v", gotPaths)
	}

	// 2. Close all connections
	allRes, err := c.CloseConnections(t.Context(), audit.CloseConnectionsRequest{All: true})
	if err != nil || !allRes.All {
		t.Fatalf("CloseConnections(All=true) = (%+v, %v)", allRes, err)
	}
	mu.Lock()
	gotAllPaths := slices.Clone(deletedPaths)
	mu.Unlock()
	if !slices.Equal(gotAllPaths, []string{"/connections"}) {
		t.Fatalf("expected DELETE /connections, got %v", gotAllPaths)
	}

	// 3. Unreachable endpoints return error
	badC := audit.NewCollector(nil)
	badC.SetEndpointsForTest([]string{deadSrv.URL}, "wrong", filepath.Join(dir, "bad.json"))
	if _, err := badC.CloseConnections(t.Context(), audit.CloseConnectionsRequest{All: true}); err == nil {
		t.Fatal("expected error when all Clash endpoints fail")
	}
}

func TestSortFlows_And_CollectFilteringAndConcurrency(t *testing.T) {
	sample := []audit.FlowRecord{
		{Key: "low-active", ActiveConns: 2, RiskScore: 10, UploadBytes: 100, DownloadBytes: 5000, UploadRatio: 0.02, Threat: audit.ThreatNormal, State: audit.EnforcementObserved},
		{Key: "high-idle", ActiveConns: 0, RiskScore: 90, UploadBytes: 9000, DownloadBytes: 100, UploadRatio: 90.0, Threat: audit.ThreatHighRisk, State: audit.EnforcementObserved},
		{Key: "mid-active", ActiveConns: 1, RiskScore: 65, UploadBytes: 4000, DownloadBytes: 500, UploadRatio: 8.0, Threat: audit.ThreatSuspicious, State: audit.EnforcementObserved},
	}

	for _, tc := range []struct {
		sortBy  string
		asc     bool
		wantTop string
	}{
		{sortBy: "active", asc: false, wantTop: "mid-active"},
		{sortBy: "risk", asc: false, wantTop: "high-idle"},
		{sortBy: "risk", asc: true, wantTop: "low-active"},
		{sortBy: "upload", asc: false, wantTop: "high-idle"},
		{sortBy: "download", asc: false, wantTop: "low-active"},
		{sortBy: "ratio", asc: false, wantTop: "high-idle"},
	} {
		cloned := slices.Clone(sample)
		audit.SortFlows(cloned, tc.sortBy, tc.asc)
		if cloned[0].Key != tc.wantTop {
			t.Fatalf("SortFlows(%q, asc=%v) top=%q, want %q", tc.sortBy, tc.asc, cloned[0].Key, tc.wantTop)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{
			"connections": [
				{"id":"c1","upload":10485760,"download":65536,"chains":["Proxy"],"metadata":{"network":"udp","sourceIP":"192.168.1.20","destinationIP":"203.0.113.10","destinationPort":"19999","host":""}},
				{"id":"c2","upload":1024,"download":2097152,"chains":["Proxy"],"metadata":{"network":"tcp","sourceIP":"192.168.1.21","destinationIP":"203.0.113.20","destinationPort":"443","host":"www.youtube.com"}}
			]
		}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	c := audit.NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(dir, "race-state.json"))
	c.SetLeaseFilesForTest(nil, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))

	suspectOnly := c.Collect(t.Context(), audit.CollectOptions{OnlySuspect: true})
	if len(suspectOnly.Flows) != 1 || suspectOnly.Flows[0].DeviceIP != "192.168.1.20" {
		t.Fatalf("expected OnlySuspect to retain high-upload direct IP flow, got %+v", suspectOnly.Flows)
	}
	ytFiltered := c.Collect(t.Context(), audit.CollectOptions{DeviceFilter: "youtube"})
	if len(ytFiltered.Flows) != 1 || !strings.Contains(ytFiltered.Flows[0].Target, "youtube") {
		t.Fatalf("expected DeviceFilter=youtube to match YouTube flow, got %+v", ytFiltered.Flows)
	}
	lim1 := c.Collect(t.Context(), audit.CollectOptions{Limit: 1, SortBy: "download"})
	if len(lim1.Flows) != 1 || lim1.Flows[0].DeviceIP != "192.168.1.21" {
		t.Fatalf("expected Limit=1 SortBy=download to return YouTube flow, got %+v", lim1.Flows)
	}

	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			rep := c.Collect(t.Context(), audit.CollectOptions{})
			if !rep.Reachable {
				t.Errorf("concurrent Collect unreachable")
			}
		})
	}
	wg.Wait()
}
