// 文件职责：验证 audit.Collector.CloseConnections 对主域名后缀 (MatchSuffix) 与 IP/CIDR 网段匹配断开行为。
package audit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestCloseConnections_MatchSuffixAndCIDR(t *testing.T) {
	var mu sync.Mutex
	var deletedPaths []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/connections" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id": "conn-root",
						"metadata": map[string]string{
							"network":       "tcp",
							"sourceIP":      "192.168.1.50",
							"destinationIP": "203.0.113.10",
							"host":          "example.com",
						},
					},
					{
						"id": "conn-sub",
						"metadata": map[string]string{
							"network":       "tcp",
							"sourceIP":      "192.168.1.50",
							"destinationIP": "203.0.113.11",
							"host":          "api.example.com",
						},
					},
					{
						"id": "conn-other-domain",
						"metadata": map[string]string{
							"network":       "tcp",
							"sourceIP":      "192.168.1.50",
							"destinationIP": "203.0.113.12",
							"host":          "notexample.com",
						},
					},
					{
						"id": "conn-ip-in-cidr",
						"metadata": map[string]string{
							"network":       "udp",
							"sourceIP":      "192.168.1.60",
							"destinationIP": "198.51.100.20",
						},
					},
					{
						"id": "conn-ip-outside-cidr",
						"metadata": map[string]string{
							"network":       "udp",
							"sourceIP":      "192.168.1.60",
							"destinationIP": "203.0.113.5",
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
	defer srv.Close()

	dir := t.TempDir()
	c := audit.NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(dir, "state.json"))
	c.SetLeaseFilesForTest(nil, filepath.Join(dir, "no-arp"), filepath.Join(dir, "no-hosts"))

	// 1. MatchSuffix=false keeps exact match only.
	resExact, err := c.CloseConnections(t.Context(), audit.CloseConnectionsRequest{
		Target: "example.com",
	})
	if err != nil {
		t.Fatalf("exact CloseConnections failed: %v", err)
	}
	if resExact.Closed != 1 {
		t.Fatalf("expected 1 closed for exact example.com, got %+v", resExact)
	}
	mu.Lock()
	exactPaths := slices.Clone(deletedPaths)
	deletedPaths = nil
	mu.Unlock()
	if !slices.Equal(exactPaths, []string{"/connections/conn-root"}) {
		t.Fatalf("unexpected exact deletedPaths: %v", exactPaths)
	}

	// 2. MatchSuffix=true closes root + subdomains, not unrelated notexample.com.
	resSuffix, err := c.CloseConnections(t.Context(), audit.CloseConnectionsRequest{
		Target:      "example.com",
		MatchSuffix: true,
		DeviceIP:    "192.168.1.50",
	})
	if err != nil {
		t.Fatalf("suffix CloseConnections failed: %v", err)
	}
	if resSuffix.Closed != 2 {
		t.Fatalf("expected 2 closed for suffix example.com, got %+v", resSuffix)
	}
	mu.Lock()
	suffixPaths := slices.Clone(deletedPaths)
	deletedPaths = nil
	mu.Unlock()
	if !slices.Equal(suffixPaths, []string{"/connections/conn-root", "/connections/conn-sub"}) {
		t.Fatalf("unexpected suffix deletedPaths: %v", suffixPaths)
	}

	// 3. CIDR target closes matching destIP connections.
	resCIDR, err := c.CloseConnections(t.Context(), audit.CloseConnectionsRequest{
		Target: "198.51.100.0/24",
	})
	if err != nil {
		t.Fatalf("CIDR CloseConnections failed: %v", err)
	}
	if resCIDR.Closed != 1 {
		t.Fatalf("expected 1 closed for 198.51.100.0/24, got %+v", resCIDR)
	}
	mu.Lock()
	cidrPaths := slices.Clone(deletedPaths)
	mu.Unlock()
	if !slices.Equal(cidrPaths, []string{"/connections/conn-ip-in-cidr"}) {
		t.Fatalf("unexpected cidr deletedPaths: %v", cidrPaths)
	}
}
