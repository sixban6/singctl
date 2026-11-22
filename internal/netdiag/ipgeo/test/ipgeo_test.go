// 文件职责：覆盖 ipgeo 子包的国家映射、双通道批量解析回退、/24 网段共享、0600 持久化与并发竞态单测。
package ipgeo_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"singctl/internal/netdiag/ipgeo"
)

func TestCountryHelpersAndAddressGuards(t *testing.T) {
	flagCases := []struct {
		code string
		want string
	}{
		{"US", "🇺🇸"},
		{"jp", "🇯🇵"},
		{"SG", "🇸🇬"},
		{"", ""},
		{"X", ""},
		{"12", ""},
		{"INVALID", ""},
	}
	for _, tc := range flagCases {
		if got := ipgeo.CountryCodeToFlag(tc.code); got != tc.want {
			t.Errorf("CountryCodeToFlag(%q) = %q, want %q", tc.code, got, tc.want)
		}
	}

	if got := ipgeo.FormatGeoLabel("US", "United States", "Los Angeles"); got != "美国 · Los Angeles" {
		t.Fatalf("unexpected FormatGeoLabel: %q", got)
	}
	if got := ipgeo.FormatGeoLabel("SG", "Singapore", "Singapore"); got != "新加坡" {
		t.Fatalf("expected duplicate city/country deduplicated, got %q", got)
	}
	if got := ipgeo.ComputeSubnetCIDR("198.51.100.42"); got != "198.51.100.0/24" {
		t.Fatalf("unexpected IPv4 subnet CIDR: %q", got)
	}
	if got := ipgeo.ComputeSubnetCIDR("2001:db8:abcd:1234::1"); got != "2001:db8:abcd::/48" {
		t.Fatalf("unexpected IPv6 subnet CIDR: %q", got)
	}
	if got := ipgeo.ComputeSubnetCIDR("not-an-ip"); got != "" {
		t.Fatalf("expected empty CIDR for malformed IP, got %q", got)
	}

	if !ipgeo.IsPrivateOrLoopbackIP("127.0.0.1") || !ipgeo.IsPrivateOrLoopbackIP("192.168.1.1") || !ipgeo.IsPrivateOrLoopbackIP("invalid") {
		t.Fatal("expected loopback/private/invalid IPs classified as private/loopback")
	}
	if !ipgeo.IsRFC5737DocumentationIP("192.0.2.1") || !ipgeo.IsRFC5737DocumentationIP("198.51.100.5") || !ipgeo.IsRFC5737DocumentationIP("203.0.113.9") {
		t.Fatal("expected RFC 5737 documentation ranges recognized")
	}
}

func TestResolver_DualChannelBatchFallbackSubnetSharingAnd0600Persistence(t *testing.T) {
	ipAPISrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var queries []string
		_ = json.NewDecoder(r.Body).Decode(&queries)
		// Simulate partial success: resolve first IP, fail second IP so GeoJS fallback triggers
		type respItem struct {
			Status      string `json:"status"`
			Query       string `json:"query"`
			Country     string `json:"country"`
			CountryCode string `json:"countryCode"`
			City        string `json:"city"`
			ISP         string `json:"isp"`
		}
		var out []respItem
		for _, q := range queries {
			if q == "8.8.8.8" {
				out = append(out, respItem{
					Status:      "success",
					Query:       "8.8.8.8",
					Country:     "United States",
					CountryCode: "US",
					City:        "Mountain View",
					ISP:         "Google LLC",
				})
			} else {
				out = append(out, respItem{Status: "fail", Query: q})
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer ipAPISrv.Close()

	geoJSSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{
			{
				"ip":                "1.1.1.1",
				"country":           "Australia",
				"country_code":      "AU",
				"city":              "Sydney",
				"organization_name": "Cloudflare",
			},
		})
	}))
	defer geoJSSrv.Close()

	cacheFile := filepath.Join(t.TempDir(), "geo_cache.json")
	r := ipgeo.NewResolver(cacheFile)
	r.HTTPClient = ipAPISrv.Client()
	r.IPAPIBatchURL = ipAPISrv.URL
	r.GeoJSBatchURL = geoJSSrv.URL

	// 1. Loopback & private fast path
	loop := r.Resolve("127.0.0.1")
	if loop.Country != "本地" || loop.Geo != "本地网络" {
		t.Fatalf("unexpected loopback geo: %+v", loop)
	}

	// 2. Dual-channel ResolveBatch (8.8.8.8 via ip-api, 1.1.1.1 via geojs fallback)
	batch := r.ResolveBatch(t.Context(), []string{"8.8.8.8", "1.1.1.1", "10.0.0.1"})
	if batch["8.8.8.8"].CountryCode != "US" || batch["8.8.8.8"].Flag != "🇺🇸" {
		t.Fatalf("expected US from primary ip-api, got %+v", batch["8.8.8.8"])
	}
	if batch["1.1.1.1"].CountryCode != "AU" || batch["1.1.1.1"].ISP != "Cloudflare" {
		t.Fatalf("expected AU from geojs fallback, got %+v", batch["1.1.1.1"])
	}
	if batch["10.0.0.1"].Country != "本地" {
		t.Fatalf("expected local private IP in batch, got %+v", batch["10.0.0.1"])
	}

	// 3. Same /24 subnet sharing (8.8.8.99 inherits US country from 8.8.8.8 immediately)
	subShared := r.ResolveCachedOrEnqueue([]string{"8.8.8.99"})
	if subShared["8.8.8.99"].CountryCode != "US" {
		t.Fatalf("expected /24 subnet fallback US for 8.8.8.99, got %+v", subShared["8.8.8.99"])
	}

	// 4. Flush 0600 & reload into fresh instance (zero global singleton leakage)
	r.Flush()
	st, err := os.Stat(cacheFile)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 geo cache file, got info=%v err=%v", st, err)
	}

	r2 := ipgeo.NewResolver(cacheFile)
	if got := r2.Resolve("1.1.1.1"); got.CountryCode != "AU" || r2.Revision() == 0 {
		t.Fatalf("expected reloaded cache entry AU and non-zero revision, got %+v rev=%d", got, r2.Revision())
	}

	// 5. Concurrent -race stress test
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			ip := fmt.Sprintf("198.51.100.%d", i+1)
			r.SeedCountry(ip, "JP")
			_ = r.Resolve(ip)
			_ = r.ResolveCachedOrEnqueue([]string{ip, "203.0.113.10"})
			r.Flush()
		})
	}
	wg.Wait()
}
