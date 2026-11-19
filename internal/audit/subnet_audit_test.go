package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
)

func TestValidateTargetSafety_CIDRChecks(t *testing.T) {
	cfg := &config.Config{}
	cfg.Server.ServerIP = "198.51.100.42"
	cfg.Subs = []config.Subscription{
		{Name: "demo", URL: "https://203.0.113.250/sub.yaml"},
	}

	blockedCases := []struct {
		name   string
		target string
	}{
		{name: "ipv4_too_broad", target: "203.0.0.0/8"},
		{name: "ipv6_too_broad", target: "2001:db8::/24"},
		{name: "bootstrap_dns_cidr", target: "223.5.5.0/24"},
		{name: "google_dns_cidr", target: "1.1.1.0/24"},
		{name: "private_cidr", target: "192.168.0.0/16"},
		{name: "tailscale_cgnat_cidr", target: "100.64.0.0/16"},
		{name: "fakeip_cidr", target: "198.18.0.0/16"},
		{name: "server_ip_cidr", target: "198.51.100.0/24"},
		{name: "sub_ip_cidr", target: "203.0.113.0/24"},
	}
	for _, tc := range blockedCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := ValidateTargetSafety(cfg, tc.target); err == nil {
				t.Fatalf("expected target %q to be rejected", tc.target)
			}
		})
	}

	// Clean config without 203.0.113.250 subscription allows 203.0.113.11/24 and canonicalizes it.
	cleanCfg := &config.Config{}
	norm4, isIP4, err := ValidateTargetSafety(cleanCfg, "203.0.113.11/24")
	if err != nil {
		t.Fatalf("expected valid public IPv4 CIDR to pass, got %v", err)
	}
	if !isIP4 || norm4 != "203.0.113.0/24" {
		t.Fatalf("expected canonical 203.0.113.0/24 (isIP=true), got %q (isIP=%v)", norm4, isIP4)
	}

	norm6, isIP6, err := ValidateTargetSafety(cleanCfg, "2001:db8:1::1/48")
	if err != nil {
		t.Fatalf("expected valid public IPv6 CIDR to pass, got %v", err)
	}
	if !isIP6 || norm6 != "2001:db8:1::/48" {
		t.Fatalf("expected canonical 2001:db8:1::/48 (isIP=true), got %q (isIP=%v)", norm6, isIP6)
	}
}

func TestNonlinearEngine_IsBlocked_CIDRScope(t *testing.T) {
	cfg := &config.Config{}
	cfg.CustomRules.Block = []config.BlockRule{
		{Target: "203.0.113.0/24", SourceIP: "192.168.1.50"},
		{Target: "192.0.2.0/24"},
	}
	eng := NewNonlinearEngine(cfg)

	if !eng.IsBlocked("192.168.1.50", "203.0.113.77") {
		t.Fatal("expected scoped device 192.168.1.50 -> 203.0.113.77 to match CIDR block rule")
	}
	if eng.IsBlocked("192.168.1.51", "203.0.113.77") {
		t.Fatal("expected other LAN device 192.168.1.51 not to be blocked by device-scoped CIDR")
	}
	if eng.IsBlocked("192.168.1.50", "198.51.100.77") {
		t.Fatal("expected unrelated subnet 198.51.100.77 not to match")
	}
	if !eng.IsBlocked("192.168.1.99", "192.0.2.15") {
		t.Fatal("expected global CIDR rule 192.0.2.0/24 to block all devices")
	}
}

func TestAnnotateDirectIPSubnetClusters_DetectionAndExemptions(t *testing.T) {
	eng := NewNonlinearEngine(&config.Config{})

	flows := []FlowRecord{
		// Device A: 4 non-standard port direct IPs in 203.0.113.0/24 -> suspicious cluster
		{Key: "a1", DeviceIP: "192.168.1.20", Target: "203.0.113.10", IsDirectIP: true, DestPort: 30001, UploadBytes: 400 * 1024, DownloadBytes: 50 * 1024, Network: "udp"},
		{Key: "a2", DeviceIP: "192.168.1.20", Target: "203.0.113.11", IsDirectIP: true, DestPort: 30002, UploadBytes: 300 * 1024, DownloadBytes: 40 * 1024, Network: "udp"},
		{Key: "a3", DeviceIP: "192.168.1.20", Target: "203.0.113.12", IsDirectIP: true, DestPort: 30003, UploadBytes: 250 * 1024, DownloadBytes: 30 * 1024, Network: "tcp"},
		{Key: "a4", DeviceIP: "192.168.1.20", Target: "203.0.113.13", IsDirectIP: true, DestPort: 30004, UploadBytes: 200 * 1024, DownloadBytes: 20 * 1024, Network: "udp"},
		// Device B: 4 known HTTPS infra QUIC 443 flows with low upload ratio -> NOT suspicious
		{Key: "b1", DeviceIP: "192.168.1.21", Target: "192.0.2.10", IsDirectIP: true, DestPort: 443, AppName: "Cloudflare", UploadBytes: 120 * 1024, DownloadBytes: 2 * 1024 * 1024, Network: "udp"},
		{Key: "b2", DeviceIP: "192.168.1.21", Target: "192.0.2.11", IsDirectIP: true, DestPort: 443, AppName: "Cloudflare", UploadBytes: 100 * 1024, DownloadBytes: 2 * 1024 * 1024, Network: "udp"},
		{Key: "b3", DeviceIP: "192.168.1.21", Target: "192.0.2.12", IsDirectIP: true, DestPort: 443, AppName: "Apple", UploadBytes: 90 * 1024, DownloadBytes: 1500 * 1024, Network: "udp"},
		{Key: "b4", DeviceIP: "192.168.1.21", Target: "192.0.2.13", IsDirectIP: true, DestPort: 443, AppName: "Apple", UploadBytes: 80 * 1024, DownloadBytes: 1200 * 1024, Network: "udp"},
		// Reserved / Private / FakeIP direct targets -> ignored
		{Key: "c1", DeviceIP: "192.168.1.22", Target: "10.0.0.5", IsDirectIP: true, DestPort: 9000, UploadBytes: 512 * 1024},
		{Key: "c2", DeviceIP: "192.168.1.22", Target: "100.64.0.5", IsDirectIP: true, DestPort: 9000, UploadBytes: 512 * 1024},
		{Key: "c3", DeviceIP: "192.168.1.22", Target: "198.18.0.5", IsDirectIP: true, DestPort: 9000, UploadBytes: 512 * 1024},
	}

	eng.AnnotateDirectIPSubnetClusters(flows)
	for i := range flows {
		eng.EvaluateFlow(&flows[i])
	}

	for i := range 4 {
		c := flows[i].SubnetCluster
		if c == nil || !c.Suspicious || c.UniqueIPs != 4 || c.CIDR != "203.0.113.0/24" {
			t.Fatalf("flow[%d] expected suspicious 203.0.113.0/24 cluster with 4 IPs, got %+v", i, c)
		}
		if flows[i].NonlinearFactors["direct_ip_subnet_cluster"] <= 0 {
			t.Fatalf("flow[%d] expected positive direct_ip_subnet_cluster score, factors=%+v", i, flows[i].NonlinearFactors)
		}
		hasClusterReason := false
		for _, r := range flows[i].Reasons {
			if strings.Contains(r, "同网段裸IP聚集") && strings.Contains(r, "203.0.113.0/24") {
				hasClusterReason = true
				break
			}
		}
		if !hasClusterReason {
			t.Fatalf("flow[%d] expected cluster reason, got %+v", i, flows[i].Reasons)
		}
	}

	for i := 4; i < 8; i++ {
		if flows[i].SubnetCluster != nil && flows[i].SubnetCluster.Suspicious {
			t.Fatalf("infra 443 flow[%d] should not be flagged as suspicious cluster: %+v", i, flows[i].SubnetCluster)
		}
		if flows[i].NonlinearFactors["direct_ip_subnet_cluster"] != 0 {
			t.Fatalf("infra 443 flow[%d] should have 0 cluster factor, got %v", i, flows[i].NonlinearFactors["direct_ip_subnet_cluster"])
		}
	}

	for i := 8; i < len(flows); i++ {
		if flows[i].SubnetCluster != nil {
			t.Fatalf("reserved direct IP flow[%d] (%s) should not be clustered: %+v", i, flows[i].Target, flows[i].SubnetCluster)
		}
	}
}

func TestEnforcer_BlockCIDR_KillsScopedConnections(t *testing.T) {
	var mu sync.Mutex
	var closedIDs []string

	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"connections": []map[string]any{
					{
						"id": "conn-target-dev-1",
						"metadata": map[string]string{
							"sourceIP":      "192.168.1.60",
							"destinationIP": "203.0.113.15",
						},
					},
					{
						"id": "conn-target-dev-2",
						"metadata": map[string]string{
							"sourceIP":      "192.168.1.60",
							"destinationIP": "203.0.113.88",
						},
					},
					{
						"id": "conn-other-dev",
						"metadata": map[string]string{
							"sourceIP":      "192.168.1.61",
							"destinationIP": "203.0.113.15",
						},
					},
					{
						"id": "conn-other-subnet",
						"metadata": map[string]string{
							"sourceIP":      "192.168.1.60",
							"destinationIP": "198.51.100.15",
						},
					},
				},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/connections/"):
			id := strings.TrimPrefix(r.URL.Path, "/connections/")
			mu.Lock()
			closedIDs = append(closedIDs, id)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockClash.Close()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: router\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	enf := NewEnforcer(cfg, cfgPath)
	enf.SetPathsForTest(filepath.Join(dir, "sb.json"), filepath.Join(dir, "agh.yaml"), []string{mockClash.URL}, "")

	res, err := enf.Block(t.Context(), "203.0.113.99/24", "192.168.1.60", "同网段测试封禁")
	if err != nil {
		t.Fatalf("Enforcer.Block failed: %v", err)
	}
	if res.Target != "203.0.113.0/24" || res.SourceIP != "192.168.1.60" {
		t.Fatalf("unexpected block result target/source: %+v", res)
	}
	if res.KilledConnections != 2 {
		t.Fatalf("expected 2 connections killed, got %d (closed=%v)", res.KilledConnections, closedIDs)
	}
	mu.Lock()
	gotClosed := slices.Clone(closedIDs)
	mu.Unlock()
	slices.Sort(gotClosed)
	wantClosed := []string{"conn-target-dev-1", "conn-target-dev-2"}
	if !slices.Equal(gotClosed, wantClosed) {
		t.Fatalf("expected killed IDs %v, got %v", wantClosed, gotClosed)
	}
}

func TestParseIPv6Neighbors_AndDualStackMACMerge(t *testing.T) {
	neighOut := `2001:db8:1::1234 dev br-lan lladdr AA:BB:CC:DD:EE:01 REACHABLE
2001:db8:1::9999 dev br-lan FAILED
fe80::1 dev br-lan lladdr 00:00:00:00:00:00 STALE
`
	parsed := parseIPv6Neighbors(neighOut)
	if parsed["2001:db8:1::1234"] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("expected lowercase MAC for 2001:db8:1::1234, got %+v", parsed)
	}
	if _, exists := parsed["2001:db8:1::9999"]; exists {
		t.Fatal("expected FAILED neighbor entry without lladdr to be skipped")
	}
	if _, exists := parsed["fe80::1"]; exists {
		t.Fatal("expected zero MAC entry to be skipped")
	}

	dir := t.TempDir()
	leasesPath := filepath.Join(dir, "dhcp.leases")
	if err := os.WriteFile(leasesPath, []byte("1700000000 aa:bb:cc:dd:ee:01 192.168.1.33 MyPhone *\n"), 0600); err != nil {
		t.Fatal(err)
	}

	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"connections": []map[string]any{
				{
					"id":       "v4-c1",
					"upload":   1024,
					"download": 4096,
					"chains":   []string{"#DC"},
					"metadata": map[string]string{
						"network":         "tcp",
						"sourceIP":        "192.168.1.33",
						"destinationPort": "443",
						"host":            "v4.example.com",
					},
				},
				{
					"id":       "v6-c1",
					"upload":   2048,
					"download": 8192,
					"chains":   []string{"#DC"},
					"metadata": map[string]string{
						"network":         "tcp",
						"sourceIP":        "2001:db8:1::1234",
						"destinationPort": "443",
						"host":            "v6.example.com",
					},
				},
			},
		})
	}))
	defer mockClash.Close()

	c := NewCollector(&config.Config{})
	c.SetEndpointsForTest([]string{mockClash.URL}, "", filepath.Join(dir, "audit-state.json"))
	c.SetLeaseFilesForTest([]string{leasesPath}, "", "")
	c.ipv6NeighCmdFunc = func() ([]byte, error) {
		return []byte(neighOut), nil
	}

	rep := c.Collect(t.Context(), CollectOptions{})
	if len(rep.Devices) != 1 {
		t.Fatalf("expected dual-stack v4+v6 flows from same MAC to merge into 1 device summary, got %d: %+v", len(rep.Devices), rep.Devices)
	}
	dev := rep.Devices[0]
	if dev.DeviceName != "MyPhone" || dev.DeviceIP != "192.168.1.33" || dev.DeviceMAC != "aa:bb:cc:dd:ee:01" || dev.FlowCount != 2 {
		t.Fatalf("unexpected merged device summary: %+v", dev)
	}
	if dev.UploadBytes != 3072 || dev.DownloadBytes != 12288 {
		t.Fatalf("expected combined upload=3072 download=12288, got %+v", dev)
	}
}
