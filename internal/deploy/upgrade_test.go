package deploy

import (
	"testing"
)

func TestIsNewerVersion(t *testing.T) {
	tests := []struct {
		local    string
		remote   string
		expected bool
	}{
		{"1.14.4", "1.14.4", false},
		{"v1.14.4", "1.14.4", false},
		{"1.14.4", "v1.14.4", false},
		{"1.14.4", "1.14.5", true},
		{"1.14.4", "1.15.0", true},
		{"1.14.4", "2.0.0", true},
		{"1.14.10", "1.14.9", false},
		{"1.14.9", "1.14.10", true},
		{"2.11.7", "2.11.7", false},
		{"2.11.7", "2.12.0", true},
		{"2.34.1", "2.34.2", true},
		{"2.34.2", "2.34.1", false},
		{"", "1.0.0", false},
		{"1.0.0", "", false},
		{"", "", false},
	}

	for _, tt := range tests {
		got := isNewerVersion(tt.local, tt.remote)
		if got != tt.expected {
			t.Errorf("isNewerVersion(%q, %q) = %v; want %v", tt.local, tt.remote, got, tt.expected)
		}
	}
}
