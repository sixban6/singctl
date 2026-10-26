package config

import (
	"testing"
)

func TestCityCountryToTag(t *testing.T) {
	tests := []struct {
		city        string
		countryCode string
		expected    string
	}{
		{"Los Angeles", "US", "los"},
		{"los angeles", "us", "los"},
		{"Singapore", "SG", "sg"},
		{"Hong Kong", "HK", "hk"},
		{"Tokyo", "JP", "jp"},
		{"Osaka", "JP", "osaka"},
		{"San Jose", "US", "sj"},
		{"Santa Clara", "US", "sj"},
		{"Fremont", "US", "sj"},
		{"Seattle", "US", "sea"},
		{"New York", "US", "ny"},
		{"Chicago", "US", "chi"},
		{"Dallas", "US", "dal"},
		{"London", "GB", "lon"},
		{"Frankfurt", "DE", "fra"},
		{"Paris", "FR", "par"},
		{"Amsterdam", "NL", "ams"},
		{"Sydney", "AU", "syd"},
		{"Taipei", "TW", "tw"},
		{"Seoul", "KR", "kr"},
		{"Zurich", "CH", "ch"},
		{"Unknown City", "AU", "au"},
	}

	for _, tc := range tests {
		got := CityCountryToTag(tc.city, tc.countryCode)
		if got != tc.expected {
			t.Errorf("CityCountryToTag(%q, %q) = %q, expected %q", tc.city, tc.countryCode, got, tc.expected)
		}
	}
}

func TestServerConfig_GetNodeTag_Explicit(t *testing.T) {
	s := &ServerConfig{
		NodeTag: "los",
	}
	if tag := s.GetNodeTag(); tag != "los" {
		t.Errorf("expected 'los', got '%s'", tag)
	}
}

func TestServerConfig_GetNodeTag_Discovered(t *testing.T) {
	ResetDiscoveredLocationTagForTest()
	defer ResetDiscoveredLocationTagForTest()

	SetDiscoveredLocationTagForTest("sg")
	s := &ServerConfig{}
	if tag := s.GetNodeTag(); tag != "sg" {
		t.Errorf("expected 'sg', got '%s'", tag)
	}
}

func TestServerConfig_GetNodeTag_Fallback(t *testing.T) {
	ResetDiscoveredLocationTagForTest()
	defer ResetDiscoveredLocationTagForTest()

	s := &ServerConfig{
		ServerIP:   "127.0.0.1",
		NodeDomain: "cdn.s1.example.com",
	}
	if tag := s.GetNodeTag(); tag != "cdn" {
		t.Errorf("expected 'cdn', got '%s'", tag)
	}
}
