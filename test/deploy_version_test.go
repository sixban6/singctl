package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/util/github"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.14.3", "1.14.3"},
		{"1.14.3", "1.14.3"},
		{"  v2.11.7\n", "2.11.7"},
		{"v0.0.1-rc.1", "0.0.1-rc.1"},
		{"", ""},
	}

	for _, tt := range tests {
		got := deploy.NormalizeVersion(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeVersion(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestParseCaddyVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "v2.11.7 h1:yj0Y4fYZGPkSvibBJ1sTWE33xC0fxztVyXEW5iIdUT4=\n",
			expected: "2.11.7",
		},
		{
			input:    "v2.8.4",
			expected: "2.8.4",
		},
		{
			input:    "caddy v2.9.1 h1:xxxx\n",
			expected: "2.9.1",
		},
		{
			input:    "2.11.7",
			expected: "2.11.7",
		},
	}

	for _, tt := range tests {
		got, err := deploy.ParseCaddyVersion(tt.input)
		if err != nil {
			t.Errorf("ParseCaddyVersion(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.expected {
			t.Errorf("ParseCaddyVersion(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}

	// Test invalid input
	if _, err := deploy.ParseCaddyVersion(""); err == nil {
		t.Error("expected error on empty input, got nil")
	}
}

func TestParseWireproxyVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "wireproxy, version 1.1.3\n",
			expected: "1.1.3",
		},
		{
			input:    "wireproxy, version v1.1.3",
			expected: "1.1.3",
		},
		{
			input:    "wireproxy v1.0.8-dev",
			expected: "1.0.8-dev",
		},
		{
			input:    "1.1.3",
			expected: "1.1.3",
		},
	}

	for _, tt := range tests {
		got, err := deploy.ParseWireproxyVersion(tt.input)
		if err != nil {
			t.Errorf("ParseWireproxyVersion(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.expected {
			t.Errorf("ParseWireproxyVersion(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}

	// Test invalid input
	if _, err := deploy.ParseWireproxyVersion(""); err == nil {
		t.Error("expected error on empty input, got nil")
	}
}

func TestCheckComponentVersion_MockServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rel := github.Release{TagName: "v2.11.7"}
		_ = json.NewEncoder(w).Encode(rel)
	}))
	defer server.Close()

	// Inject test client
	deploy.ReleaseClient = server.Client()
	defer func() { deploy.ReleaseClient = nil }()

	cfg := &config.Config{
		GitHub: config.GitHubConfig{
			MirrorURL: server.URL,
		},
	}

	info, err := deploy.CheckComponentVersion(cfg, "caddy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Name != "caddy" {
		t.Errorf("expected info.Name 'caddy', got %q", info.Name)
	}
	if info.LatestVersion != "2.11.7" {
		t.Errorf("expected LatestVersion '2.11.7', got %q", info.LatestVersion)
	}
}
