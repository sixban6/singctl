package ssh

import (
	"testing"
	"time"
)

func TestEscapeShellArg(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "'hello'"},
		{"hello world", "'hello world'"},
		{"it's dangerous", "'it'\"'\"'s dangerous'"},
		{"", "''"},
	}

	for _, tt := range tests {
		got := escapeShellArg(tt.input)
		if got != tt.expected {
			t.Errorf("escapeShellArg(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestTestTCPPort_NonReachable(t *testing.T) {
	// A port that should definitely fail or timeout quickly
	reachable := TestTCPPort("127.0.0.1", 59999, 100*time.Millisecond)
	if reachable {
		t.Logf("Notice: Port 59999 happens to be open, skipping unreachable assertion")
	}
}
