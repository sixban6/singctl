package test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"singctl/internal/scripts"
)

func TestEmbeddedScripts(t *testing.T) {
	// Test getting script content
	startScript := scripts.GetStartScript()
	if startScript == "" {
		t.Error("Start script content is empty")
	}

	stopScript := scripts.GetStopScript()
	if stopScript == "" {
		t.Error("Stop script content is empty")
	}

	hasValidShebang := func(s string) bool {
		return strings.HasPrefix(s, "#!/bin/sh") || strings.HasPrefix(s, "#!/bin/bash")
	}

	// Test OS-specific script selection
	switch runtime.GOOS {
	case "darwin":
		if !hasValidShebang(startScript) || !hasValidShebang(stopScript) {
			t.Error("macOS scripts should start with #!/bin/sh or #!/bin/bash")
		}
		if !strings.Contains(startScript, "macOS sing-box TUN模式") {
			t.Error("macOS start script should contain TUN mode description")
		}
		if !strings.Contains(stopScript, "macOS sing-box TUN模式") {
			t.Error("macOS stop script should contain TUN mode description")
		}
	case "windows":
		if !strings.Contains(strings.ToLower(startScript), "sing-box") {
			t.Error("Windows start script should reference sing-box")
		}
	default:
		if !hasValidShebang(startScript) {
			t.Error("Linux start script doesn't contain valid shebang (#!/bin/sh or #!/bin/bash)")
		}
		if !hasValidShebang(stopScript) {
			t.Error("Linux stop script doesn't contain valid shebang (#!/bin/sh or #!/bin/bash)")
		}
		if !strings.Contains(startScript, "OpenWrt sing-box TProxy模式") && !strings.Contains(startScript, "Debian sing-box TProxy模式") {
			t.Error("Linux start script should contain TProxy mode description")
		}
	}
}

func TestWriteScripts(t *testing.T) {
	tempDir := t.TempDir()

	// Test writing start script
	startPath := filepath.Join(tempDir, "test_start.sh")
	if err := scripts.WriteStartScript(startPath); err != nil {
		t.Fatalf("Failed to write start script: %v", err)
	}

	// Verify file exists and is executable
	info, err := os.Stat(startPath)
	if err != nil {
		t.Fatalf("Start script file not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("Start script is not executable")
	}

	// Test writing stop script
	stopPath := filepath.Join(tempDir, "test_stop.sh")
	if err := scripts.WriteStopScript(stopPath); err != nil {
		t.Fatalf("Failed to write stop script: %v", err)
	}

	// Verify file exists and is executable
	info, err = os.Stat(stopPath)
	if err != nil {
		t.Fatalf("Stop script file not found: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("Stop script is not executable")
	}
}
