package audit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/platform/rtnl"
)

func TestCollector_UsesRTNLForIPv6NeighborsZeroSubprocess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id": "c-v6-1",
					"metadata": map[string]string{
						"network":       "tcp",
						"sourceIP":      "2001:db8:10::42",
						"destinationIP": "198.51.100.8",
						"host":          "cdn.example.com",
					},
					"upload":   2048,
					"download": 4096,
				},
			},
		})
	}))
	defer srv.Close()

	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts")
	// IPv4 device with same MAC in dhcp.leases should map IPv6 client name via RTNL neighbor MAC!
	leasesFile := filepath.Join(dir, "dhcp.leases")
	if err := os.WriteFile(leasesFile, []byte("1999999999 aa:bb:cc:11:22:33 192.0.2.42 livingroom-tv *\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostsFile, nil, 0600); err != nil {
		t.Fatal(err)
	}

	mockRTNL := rtnl.NewMockClient()
	mockRTNL.Neighbors[6] = []rtnl.NeighborEntry{
		{
			IP:      netip.MustParseAddr("2001:db8:10::42"),
			MAC:     "aa:bb:cc:11:22:33",
			IfIndex: 2,
			State:   0x02,
		},
	}

	c := audit.NewCollectorWithOptions(&config.Config{}, audit.CollectorOptions{
		RTNLClient: mockRTNL,
	})
	c.SetEndpointsForTest([]string{srv.URL}, "", filepath.Join(dir, "audit-state.json"))
	c.SetLeaseFilesForTest([]string{leasesFile}, filepath.Join(dir, "missing-arp"), hostsFile)

	rep := c.Collect(t.Context(), audit.CollectOptions{})
	if !rep.Reachable || len(rep.Devices) == 0 {
		t.Fatalf("expected reachable report with resolved IPv6 device, got %+v", rep)
	}
	foundNamed := false
	for _, d := range rep.Devices {
		if d.DeviceIP == "2001:db8:10::42" && d.DeviceName == "livingroom-tv" {
			foundNamed = true
			break
		}
	}
	if !foundNamed {
		t.Fatalf("expected IPv6 neighbor to resolve to livingroom-tv via RTNL MAC, got devices=%+v", rep.Devices)
	}
}
