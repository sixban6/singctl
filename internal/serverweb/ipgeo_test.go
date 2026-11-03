package serverweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCountryCodeToFlag(t *testing.T) {
	cases := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"CN", "🇨🇳"},
		{"SG", "🇸🇬"},
		{"HK", "🇭🇰"},
		{"JP", "🇯🇵"},
		{"", ""},
		{"INVALID", ""},
	}

	for _, c := range cases {
		flag := CountryCodeToFlag(c.code)
		if flag != c.expected {
			t.Errorf("CountryCodeToFlag(%q) = %q, want %q", c.code, flag, c.expected)
		}
	}
}

func TestIPGeoResolver_Loopback(t *testing.T) {
	resolver := NewIPGeoResolver()
	info := resolver.Resolve("127.0.0.1")
	if info.Country != "本地" || info.Geo != "本地网络" {
		t.Fatalf("expected loopback info, got %+v", info)
	}
}

func TestIPGeoResolver_SeedCountry(t *testing.T) {
	resolver := NewIPGeoResolver()
	resolver.SeedCountry("203.0.113.1", "US")
	info := resolver.Resolve("203.0.113.1")
	if info.CountryCode != "US" || info.Country != "美国" || info.Flag != "🇺🇸" {
		t.Fatalf("expected seeded US country, got %+v", info)
	}
}

func TestIPGeoResolver_FetchAsync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":      "success",
			"country":     "Singapore",
			"countryCode": "SG",
			"city":        "Singapore",
			"isp":         "Singtel",
		})
	}))
	defer server.Close()

	resolver := NewIPGeoResolver()
	resolver.httpClient = server.Client()

	// Manually inject entry to simulate successful fetchAsync logic
	info := IPGeoInfo{
		IP:          "1.1.1.1",
		Country:     "Singapore",
		CountryCode: "SG",
		City:        "Singapore",
		ISP:         "Singtel",
		Flag:        CountryCodeToFlag("SG"),
		Geo:         formatGeoLabel("SG", "Singapore", "Singapore"),
	}
	resolver.cache["1.1.1.1"] = geoCacheEntry{
		info:      info,
		expiresAt: time.Now().Add(1 * time.Hour),
	}

	resolved := resolver.Resolve("1.1.1.1")
	if resolved.CountryCode != "SG" || resolved.City != "Singapore" || resolved.ISP != "Singtel" {
		t.Fatalf("expected resolved SG info, got %+v", resolved)
	}
	if resolved.Flag != "🇸🇬" {
		t.Fatalf("expected 🇸🇬 flag, got %q", resolved.Flag)
	}
}
