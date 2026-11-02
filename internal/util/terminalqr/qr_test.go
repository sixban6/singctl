package terminalqr

import (
	"strings"
	"testing"
)

func TestRenderString(t *testing.T) {
	out, err := RenderString("vless://test-sample-link")
	if err != nil {
		t.Fatalf("RenderString failed: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("expected non-empty output")
	}
	if !strings.Contains(out, " ") && !strings.Contains(out, "▀") {
		t.Fatalf("output does not appear to contain QR block characters: %q", out)
	}
}
