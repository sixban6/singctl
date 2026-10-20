package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/deploy"
)

// TestResetServerCmd_Help verifies that the reset subcommand is registered under server/sr.
func TestResetServerCmd_Help(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	if serverCmd == nil {
		t.Fatal("expected NewServerCmd to return non-nil")
	}

	found := false
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "reset" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'reset' subcommand to be registered in server command")
	}
}

// TestResetServerCmd_InvalidTarget verifies that reset rejects unknown targets.
func TestResetServerCmd_InvalidTarget(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	serverCmd.SetArgs([]string{"reset", "unknown_target"})
	err := serverCmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "unknown target") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestSingBoxServer_RegenerateCredentials verifies that credentials change upon regeneration.
func TestSingBoxServer_RegenerateCredentials(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "test.example.com",
			Sni:      "swdist.apple.com",
		},
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	firstUUID := sbs.HyUUID()
	firstPubKey := sbs.PublicKey()
	firstShortID := sbs.ShortID()
	firstHy2Link := sbs.ShareLinkHy2
	firstVlessLink := sbs.ShareLinkVless

	if firstUUID == "" || firstPubKey == "" || firstShortID == "" {
		t.Fatalf("expected non-empty initial credentials, got uuid=%q pub=%q sid=%q", firstUUID, firstPubKey, firstShortID)
	}

	if err := sbs.RegenerateCredentials(); err != nil {
		t.Fatalf("RegenerateCredentials failed: %v", err)
	}

	secondUUID := sbs.HyUUID()
	secondPubKey := sbs.PublicKey()
	secondShortID := sbs.ShortID()
	secondHy2Link := sbs.ShareLinkHy2
	secondVlessLink := sbs.ShareLinkVless

	if secondUUID == firstUUID {
		t.Errorf("expected UUID to change after regeneration, got %q", secondUUID)
	}
	if secondPubKey == firstPubKey {
		t.Errorf("expected public key to change after regeneration, got %q", secondPubKey)
	}
	if secondShortID == firstShortID {
		t.Errorf("expected short ID to change after regeneration, got %q", secondShortID)
	}
	if secondHy2Link == firstHy2Link {
		t.Errorf("expected Hysteria2 link to change after regeneration")
	}
	if secondVlessLink == firstVlessLink {
		t.Errorf("expected VLESS link to change after regeneration")
	}
}

// TestSubstore_UpdateSubstoreConfig verifies that sub-store.json is correctly updated.
func TestSubstore_UpdateSubstoreConfig(t *testing.T) {
	tempDir := t.TempDir()
	substoreFile := filepath.Join(tempDir, "sub-store.json")

	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "test.example.com",
			Sni:      "swdist.apple.com",
		},
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	sbt := &deploy.Substore{
		Config:       cfg,
		SubstorePath: substoreFile,
	}

	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		t.Fatalf("UpdateSubstoreConfig failed: %v", err)
	}

	// Verify file was written
	data, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore file: %v", err)
	}

	var root struct {
		Subs []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"subs"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		t.Fatalf("failed to parse substore json: %v", err)
	}

	if len(root.Subs) < 2 {
		t.Fatalf("expected at least 2 subscriptions, got %d", len(root.Subs))
	}

	var hyContent, vlessContent string
	for _, s := range root.Subs {
		if s.Name == "auto_generated_hy2" {
			hyContent = s.Content
		} else if s.Name == "auto_generated_vless" {
			vlessContent = s.Content
		}
	}

	if hyContent != sbs.ShareLinkHy2 {
		t.Errorf("expected Hy2 link %q, got %q", sbs.ShareLinkHy2, hyContent)
	}
	if vlessContent != sbs.ShareLinkVless {
		t.Errorf("expected Vless link %q, got %q", sbs.ShareLinkVless, vlessContent)
	}

	// Test second reset: regenerate credentials and update substore again
	if err := sbs.RegenerateCredentials(); err != nil {
		t.Fatalf("RegenerateCredentials failed: %v", err)
	}

	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		t.Fatalf("second UpdateSubstoreConfig failed: %v", err)
	}

	data2, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read updated substore file: %v", err)
	}

	if err := json.Unmarshal(data2, &root); err != nil {
		t.Fatalf("failed to parse updated substore json: %v", err)
	}

	for _, s := range root.Subs {
		if s.Name == "auto_generated_hy2" && s.Content != sbs.ShareLinkHy2 {
			t.Errorf("expected updated Hy2 link %q, got %q", sbs.ShareLinkHy2, s.Content)
		}
		if s.Name == "auto_generated_vless" && s.Content != sbs.ShareLinkVless {
			t.Errorf("expected updated Vless link %q, got %q", sbs.ShareLinkVless, s.Content)
		}
	}
}

// TestPreviewServerConfigWithRegeneratedCredentials verifies that PreviewServerConfig outputs valid JSON
// containing the newly generated credentials.
func TestPreviewServerConfigWithRegeneratedCredentials(t *testing.T) {
	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "test.example.com",
			Sni:      "swdist.apple.com",
		},
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}

	if err := sbs.RegenerateCredentials(); err != nil {
		t.Fatalf("RegenerateCredentials failed: %v", err)
	}

	content, err := sbs.PreviewServerConfig()
	if err != nil {
		t.Fatalf("PreviewServerConfig failed: %v", err)
	}

	if !strings.Contains(content, sbs.HyUUID()) {
		t.Errorf("expected server config to contain UUID %q", sbs.HyUUID())
	}
	if !strings.Contains(content, sbs.ShortID()) {
		t.Errorf("expected server config to contain ShortID %q", sbs.ShortID())
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		t.Fatalf("rendered server config is not valid JSON: %v", err)
	}
}
