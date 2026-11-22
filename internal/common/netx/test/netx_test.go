// 文件职责：验证 netx 本机私网筛选、ECS 子网映射、DNS 解析、带宽折算与可注入公网 IP / GeoTag 探针。
package netx_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"singctl/internal/common/netx"
)

func TestSelectPrimaryLANIPv4_Subnet_And_DNS(t *testing.T) {
	if !netx.IsPrivateIP("192.168.1.1") || !netx.IsPrivateIP("10.0.0.1") || !netx.IsPrivateIP("172.16.5.4") || netx.IsPrivateIP("198.51.100.10") {
		t.Fatal("IsPrivateIP classification mismatch")
	}
	if got := netx.ToIPv4Subnet24("202.101.172.35"); got != "202.101.172.0/24" {
		t.Fatalf("ToIPv4Subnet24 = %q", got)
	}
	if !netx.IsPublicAnycastDNS("223.5.5.5") || netx.IsPublicAnycastDNS("202.101.172.35") {
		t.Fatal("IsPublicAnycastDNS mismatch")
	}
	if got := netx.ResolveClientSubnet(t.Context(), "202.101.172.35"); got != "202.101.172.0/24" {
		t.Fatalf("ResolveClientSubnet = %q", got)
	}
	if got := netx.LookupRegionalISPSubnet("浙江", "杭州", "电信"); got != "202.101.172.0/24" {
		t.Fatalf("LookupRegionalISPSubnet = %q", got)
	}
	r, c, i := netx.ParseIPIPNetOutput("当前 IP：198.51.100.2  来自于：中国 浙江 杭州  电信")
	if r != "浙江" || c != "杭州" || i != "电信" {
		t.Fatalf("ParseIPIPNetOutput = (%q, %q, %q)", r, c, i)
	}

	cands := []netx.InterfaceCandidate{
		{Name: "pppoe-wan", Up: true, IPv4Addrs: []string{"203.0.113.5"}},
		{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.0.1"}},
		{Name: "br-lan", Up: true, IPv4Addrs: []string{"192.168.1.1"}},
	}
	if got := netx.SelectPrimaryLANIPv4(cands, "pppoe-wan"); got != "192.168.1.1" {
		t.Fatalf("SelectPrimaryLANIPv4 = %q", got)
	}
	if got := netx.ParseUbusLANStatusIP([]byte(`{"ipv4-address":[{"address":"192.168.8.1"}]}`)); got != "192.168.8.1" {
		t.Fatalf("ParseUbusLANStatusIP = %q", got)
	}

	ubusDNS := netx.ParseUbusInterfaceDNS([]byte(`{"interface":[{"interface":"wan","up":true,"dns-server":["127.0.0.1","202.101.172.35"]}]}`))
	if !slices.Equal(ubusDNS, []string{"202.101.172.35"}) {
		t.Fatalf("ParseUbusInterfaceDNS = %v", ubusDNS)
	}
	resolvedConf := filepath.Join(t.TempDir(), "resolved.conf")
	_ = os.WriteFile(resolvedConf, []byte("[Resolve]\nDNS=223.5.5.5#dns.alidns.com\n"), 0600)
	if dns, err := netx.ParseSystemdResolvedConf(resolvedConf); err != nil || !slices.Equal(dns, []string{"223.5.5.5"}) {
		t.Fatalf("ParseSystemdResolvedConf = (%v, %v)", dns, err)
	}
}

func TestInjectableProber_PublicIP_LocationTag_And_Bandwidth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/echo-ip":
			_, _ = w.Write([]byte("203.0.113.42\n"))
		case "/geo/203.0.113.42":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":      "success",
				"country":     "Japan",
				"countryCode": "JP",
				"city":        "Tokyo",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	prober := &netx.Prober{
		HTTPClient:        srv.Client(),
		PublicIPEndpoints: []string{srv.URL + "/echo-ip"},
		IPAPIBaseURL:      srv.URL + "/geo/",
	}
	ip := prober.DiscoverPublicIP(t.Context())
	if ip != "203.0.113.42" {
		t.Fatalf("Prober.DiscoverPublicIP = %q, want 203.0.113.42", ip)
	}
	tag := prober.DiscoverLocationTag(t.Context(), ip)
	if tag != "jp" {
		t.Fatalf("Prober.DiscoverLocationTag = %q, want jp", tag)
	}

	// Private/loopback IP must never trigger external GeoIP lookup
	if got := prober.DiscoverLocationTag(t.Context(), "192.168.1.1"); got != "" {
		t.Fatalf("expected empty tag for private IP, got %q", got)
	}

	// Test CityCountryToTag & SanitizeTag
	if netx.CityCountryToTag("Los Angeles", "US") != "los" || netx.CityCountryToTag("Singapore", "SG") != "sg" {
		t.Fatal("CityCountryToTag mismatch")
	}
	if netx.SanitizeTag("  US-West_01!! ") != "us-west_01" {
		t.Fatalf("SanitizeTag = %q", netx.SanitizeTag("  US-West_01!! "))
	}

	// Package-level test overrides
	t.Cleanup(func() {
		netx.ResetDiscoveredPublicIPForTest()
		netx.ResetDiscoveredLocationTagForTest()
	})
	netx.ResetDiscoveredLocationTagForTest()
	if netx.CachedLocationTag() != "" {
		t.Fatalf("expected empty CachedLocationTag after reset, got %q", netx.CachedLocationTag())
	}
	netx.SetDiscoveredPublicIPForTest("198.51.100.9")
	netx.SetDiscoveredLocationTagForTest("sea")
	if netx.CachedLocationTag() != "sea" || netx.DiscoverPublicIP() != "198.51.100.9" || netx.DiscoverLocationTag("") != "sea" {
		t.Fatal("test override helpers failed")
	}

	// Bandwidth calculation with stubbed SpeedTestFn
	origSpeed := netx.SpeedTestFn
	t.Cleanup(func() { netx.SpeedTestFn = origSpeed })
	netx.SpeedTestFn = func() (float64, float64, time.Duration, string, error) {
		return 50.0, 200.0, 10 * time.Millisecond, "Mock", nil
	}
	up, down, err := netx.MeasureHy2Bandwidth()
	if err != nil || up != 40 || down != 180 {
		t.Fatalf("MeasureHy2Bandwidth = (%d, %d, %v)", up, down, err)
	}
}
