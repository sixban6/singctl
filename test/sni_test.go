package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/deploy"
)

// TestConfig_SniDefault verifies that a config without sni gets the default value.
func TestConfig_SniDefault(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"x.com\"\n"), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Sni != "swdist.apple.com" {
		t.Errorf("expected default SNI 'swdist.apple.com', got '%s'", cfg.Server.Sni)
	}
}

// TestConfig_SniCustom verifies that an explicit sni value is preserved.
func TestConfig_SniCustom(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sni: \"cdn.custom.com\"\n"), 0644)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Sni != "cdn.custom.com" {
		t.Errorf("expected 'cdn.custom.com', got '%s'", cfg.Server.Sni)
	}
}

// TestRender_CaddyfileWithSni verifies that PreviewCaddyfile injects the Sni value correctly.
func TestRender_CaddyfileWithSni(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "sub.example.com",
			Sni:      "test.sni.com",
		},
	}

	content, err := deploy.PreviewCaddyfile(cfg)
	if err != nil {
		t.Fatalf("render caddyfile: %v", err)
	}

	if !strings.Contains(content, "sni test.sni.com") {
		t.Errorf("Caddyfile missing expected SNI line. Got:\n%s", content)
	}
}
