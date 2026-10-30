package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateTemplate(t *testing.T) {
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "ssh-init.yaml")

	// 1. Generate template
	if err := GenerateTemplate(outPath, false); err != nil {
		t.Fatalf("GenerateTemplate failed: %v", err)
	}

	// 2. File should exist
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("Expected file %s to exist, but got: %v", outPath, err)
	}

	// 3. Generating again without force should fail
	if err := GenerateTemplate(outPath, false); err == nil {
		t.Fatalf("Expected error when overwriting without force, but got nil")
	}

	// 4. Generating with force should succeed
	if err := GenerateTemplate(outPath, true); err != nil {
		t.Fatalf("GenerateTemplate with force failed: %v", err)
	}

	// 5. Template should be loadable
	cfg, hosts, err := LoadConfig(outPath)
	if err != nil {
		t.Fatalf("Failed to parse generated template: %v", err)
	}

	if len(hosts) != 4 {
		t.Fatalf("Expected 4 sample hosts, got %d", len(hosts))
	}

	if cfg.Defaults.TargetPort != 2222 {
		t.Errorf("Expected default target port 2222, got %d", cfg.Defaults.TargetPort)
	}
}
