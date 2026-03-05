package test

import (
	"os"
	"path/filepath"
	"singctl/internal/config"
	"testing"
)

func TestLoad(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")

	yamlContent := `
subs:
  - name:"main"
    url:"https://test.com"
    skip_tls_verify:false
    correct: "value"
github:
  mirror_url:"https://proxy.example.com"
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Subs) != 1 {
		t.Fatalf("Expected 1 subscription, got %d", len(cfg.Subs))
	}

	sub := cfg.Subs[0]
	if sub.Name != "main" {
		t.Errorf("Expected sub.Name to be 'main', got '%s'", sub.Name)
	}
	if sub.URL != "https://test.com" {
		t.Errorf("Expected sub.URL to be 'https://test.com', got '%s'", sub.URL)
	}
	if sub.SkipTlsVerify != false {
		t.Errorf("Expected sub.SkipTlsVerify to be false, got true")
	}

	if cfg.GitHub.MirrorURL != "https://proxy.example.com" {
		t.Errorf("Expected GitHub.MirrorURL to be 'https://proxy.example.com', got '%s'", cfg.GitHub.MirrorURL)
	}
}

func TestLoad_NormalConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl_normal.yaml")

	yamlContent := `
subs:
  - name: "normal"
    url: "https://normal.com"
    skip_tls_verify: true
`

	err := os.WriteFile(configPath, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Subs) != 1 {
		t.Fatalf("Expected 1 subscription, got %d", len(cfg.Subs))
	}

	sub := cfg.Subs[0]
	if sub.Name != "normal" {
		t.Errorf("Expected sub.Name to be 'normal', got '%s'", sub.Name)
	}
	if sub.URL != "https://normal.com" {
		t.Errorf("Expected sub.URL to be 'https://normal.com', got '%s'", sub.URL)
	}
	if sub.SkipTlsVerify != true {
		t.Errorf("Expected sub.SkipTlsVerify to be true, got false")
	}
}
