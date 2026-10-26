package config

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	discoveredLocationTag string
	discoverLocationOnce  sync.Once
)

// SetDiscoveredLocationTagForTest allows mocking the discovered location tag during tests.
func SetDiscoveredLocationTagForTest(tag string) {
	discoveredLocationTag = tag
	discoverLocationOnce.Do(func() {})
}

// ResetDiscoveredLocationTagForTest resets the cached location tag for tests.
func ResetDiscoveredLocationTagForTest() {
	discoveredLocationTag = ""
	discoverLocationOnce = sync.Once{}
}

type ipAPIResponse struct {
	Status      string `json:"status"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
}

type ipWhoisResponse struct {
	Success     bool   `json:"success"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
}

// DiscoverLocationTag probes GeoIP providers using the server's public IP to determine the location tag.
func DiscoverLocationTag(ip string) string {
	if discoveredLocationTag != "" {
		return discoveredLocationTag
	}

	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = DiscoverPublicIP()
	}
	if ip == "" {
		return ""
	}

	// Validate public IP
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() {
		return ""
	}

	discoverLocationOnce.Do(func() {
		client := &http.Client{
			Timeout: 2 * time.Second,
		}

		// Provider 1: ip-api.com
		req1, err := http.NewRequest(http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,country,countryCode,city", nil)
		if err == nil {
			req1.Header.Set("User-Agent", "curl/7.88.1")
			resp, err := client.Do(req1)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				var r ipAPIResponse
				if json.Unmarshal(body, &r) == nil && strings.EqualFold(r.Status, "success") {
					if tag := CityCountryToTag(r.City, r.CountryCode); tag != "" {
						discoveredLocationTag = tag
						return
					}
				}
			}
		}

		// Provider 2: ipwho.is fallback
		req2, err := http.NewRequest(http.MethodGet, "https://ipwho.is/"+ip, nil)
		if err == nil {
			req2.Header.Set("User-Agent", "curl/7.88.1")
			resp, err := client.Do(req2)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				var r ipWhoisResponse
				if json.Unmarshal(body, &r) == nil && r.Success {
					if tag := CityCountryToTag(r.City, r.CountryCode); tag != "" {
						discoveredLocationTag = tag
						return
					}
				}
			}
		}
	})

	return discoveredLocationTag
}

// CityCountryToTag converts city and country code to a standard clean abbreviation.
func CityCountryToTag(city, countryCode string) string {
	c := strings.ToLower(strings.TrimSpace(city))
	cc := strings.ToLower(strings.TrimSpace(countryCode))

	// 1. Common specific cities & regions
	switch {
	case strings.Contains(c, "los angeles"):
		return "los"
	case strings.Contains(c, "san jose") || strings.Contains(c, "santa clara") || strings.Contains(c, "fremont") || strings.Contains(c, "sunnyvale") || strings.Contains(c, "san francisco"):
		return "sj"
	case strings.Contains(c, "seattle"):
		return "sea"
	case strings.Contains(c, "new york") || strings.Contains(c, "brooklyn") || strings.Contains(c, "manhattan") || strings.Contains(c, "queens") || strings.Contains(c, "newark"):
		return "ny"
	case strings.Contains(c, "chicago"):
		return "chi"
	case strings.Contains(c, "dallas") || strings.Contains(c, "fort worth"):
		return "dal"
	case strings.Contains(c, "atlanta"):
		return "atl"
	case strings.Contains(c, "miami"):
		return "mia"
	case strings.Contains(c, "phoenix"):
		return "phx"
	case strings.Contains(c, "ashburn") || strings.Contains(c, "reston") || strings.Contains(c, "herndon"):
		return "ash"
	case strings.Contains(c, "tokyo"):
		return "jp"
	case strings.Contains(c, "osaka"):
		return "osaka"
	case strings.Contains(c, "singapore"):
		return "sg"
	case strings.Contains(c, "hong kong"):
		return "hk"
	case strings.Contains(c, "taipei"):
		return "tw"
	case strings.Contains(c, "seoul"):
		return "kr"
	case strings.Contains(c, "london"):
		return "lon"
	case strings.Contains(c, "frankfurt"):
		return "fra"
	case strings.Contains(c, "paris"):
		return "par"
	case strings.Contains(c, "amsterdam"):
		return "ams"
	case strings.Contains(c, "sydney"):
		return "syd"
	}

	// 2. If country code is not US, default to 2-letter country code (e.g. "sg", "hk", "jp", "tw", "kr", "de", "gb", "fr", etc.)
	if cc != "" && cc != "us" {
		return cc
	}

	// 3. Fallback for US or others with a known city name: use first 3 alphanumeric characters of city
	cleanCity := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, c)
	if len(cleanCity) >= 3 {
		return cleanCity[:3]
	}
	if cc != "" {
		return cc
	}
	return ""
}

// sanitizeTag normalizes a tag string by lowercasing and keeping only alphanumeric and underscores.
func sanitizeTag(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	var sb strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		}
	}
	return strings.Trim(sb.String(), "_-")
}
