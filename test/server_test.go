package test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"strings"
	"testing"
)

// TestReinstallServerCmd_Registered verifies that the reinstall subcommand is registered with alias ri.
func TestReinstallServerCmd_Registered(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	if serverCmd == nil {
		t.Fatal("expected NewServerCmd to return non-nil")
	}

	var reinstallCmdFound bool
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "reinstall" {
			reinstallCmdFound = true
			hasRiAlias := false
			for _, alias := range sub.Aliases {
				if alias == "ri" {
					hasRiAlias = true
					break
				}
			}
			if !hasRiAlias {
				t.Errorf("expected 'ri' alias on reinstall command, got %v", sub.Aliases)
			}
			break
		}
	}
	if !reinstallCmdFound {
		t.Error("expected 'reinstall' subcommand to be registered in server command")
	}
}

// TestReinstallServerCmd_InvalidTarget verifies that reinstall rejects unknown targets.
func TestReinstallServerCmd_InvalidTarget(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n  cf_dns_key: \"test_token\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	serverCmd.SetArgs([]string{"reinstall", "invalid_component"})
	err := serverCmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown target, got nil")
	}
	if !strings.Contains(err.Error(), "unknown target") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestReinstallServerCmd_MissingRequiredConfig verifies validation before uninstallation.
func TestReinstallServerCmd_MissingRequiredConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	serverCmd.SetArgs([]string{"reinstall", "all"})
	err := serverCmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing required config, got nil")
	}
	if !strings.Contains(err.Error(), "and server.cf_dns_key are required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestReinstallServerCmd_ForceFlag verifies that -f / --force flag is registered on reinstall command.
func TestReinstallServerCmd_ForceFlag(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n  cf_dns_key: \"test_token\"\n"), 0644)

	reinstallCmd := cmd.NewReinstallServerCmd(configPath)
	flag := reinstallCmd.Flags().Lookup("force")
	if flag == nil {
		t.Fatal("expected 'force' flag on reinstall command")
	}
	if flag.Shorthand != "f" {
		t.Errorf("expected shorthand 'f' for force flag, got %q", flag.Shorthand)
	}
}

// TestCfTokenCmd_Registered verifies that cf-token is registered with aliases cf, token, cftoken.
func TestCfTokenCmd_Registered(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	var found bool
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "cf-token" {
			found = true
			expectedAliases := []string{"cf", "token", "cftoken"}
			for _, expected := range expectedAliases {
				hasAlias := false
				for _, alias := range sub.Aliases {
					if alias == expected {
						hasAlias = true
						break
					}
				}
				if !hasAlias {
					t.Errorf("expected alias %s not found in %v", expected, sub.Aliases)
				}
			}
			break
		}
	}
	if !found {
		t.Error("expected 'cf-token' subcommand to be registered in server command")
	}
}

// TestCfTokenCmd_MissingArg verifies that running cf-token without args fails.
func TestCfTokenCmd_MissingArg(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n  cf_dns_key: \"old_token\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	serverCmd.SetArgs([]string{"cf-token"})
	err := serverCmd.Execute()
	if err == nil {
		t.Fatal("expected error when no token argument is provided")
	}
}

// TestCfTokenCmd_EmptyToken verifies whitespace-only token is rejected.
func TestCfTokenCmd_EmptyToken(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n  cf_dns_key: \"old_token\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	serverCmd.SetArgs([]string{"cf-token", "   "})
	err := serverCmd.Execute()
	if err == nil {
		t.Fatal("expected error when empty token is provided")
	}
	if !strings.Contains(err.Error(), "cloudflare api token cannot be empty") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestCfTokenCmd_UpdatesConfig verifies that config file is updated with the new token.
func TestCfTokenCmd_UpdatesConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	initialContent := "server:\n  sb_domain: \"test.example.com\"\n  cf_dns_key: \"old_token_xyz\"\n"
	if err := os.WriteFile(configPath, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfCmd := cmd.NewCfTokenCmd(configPath)
	// We call Execute with new token. It might fail at deploy.RotateCloudflareToken if not root or on macOS,
	// but the config file write happens before deploy.
	cfCmd.SetArgs([]string{"new_token_123456"})
	_ = cfCmd.Execute()

	updatedCfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("failed to reload config: %v", err)
	}
	if updatedCfg.Server.CFDNSKey != "new_token_123456" {
		t.Errorf("expected updated CFDNSKey 'new_token_123456', got '%s'", updatedCfg.Server.CFDNSKey)
	}

	// Verify PreviewCaddyfile includes the new token
	caddyContent, err := deploy.PreviewCaddyfile(updatedCfg)
	if err != nil {
		t.Fatalf("preview caddyfile failed: %v", err)
	}
	if !strings.Contains(caddyContent, "dns cloudflare new_token_123456") {
		t.Errorf("rendered caddyfile does not contain new token. Got:\n%s", caddyContent)
	}
}

// TestUninstallCaddyScript_UnholdScript verifies that uninstall_caddy.sh contains apt-mark unhold caddy.
func TestUninstallCaddyScript_UnholdScript(t *testing.T) {
	content, err := os.ReadFile("../internal/deploy/scripts/uninstall_caddy.sh")
	if err != nil {
		t.Fatalf("failed to read uninstall_caddy.sh: %v", err)
	}
	if !strings.Contains(string(content), "apt-mark unhold caddy") {
		t.Error("uninstall_caddy.sh must contain 'apt-mark unhold caddy'")
	}
}

// TestInstallCaddyScript_StandaloneNoAptRepo verifies that install_caddy.sh deploys Caddy as a standalone
// systemd service without registering caddy in APT/dpkg or adding caddy-stable.list.
func TestInstallCaddyScript_StandaloneNoAptRepo(t *testing.T) {
	content, err := os.ReadFile("../internal/deploy/scripts/install_caddy.sh")
	if err != nil {
		t.Fatalf("failed to read install_caddy.sh: %v", err)
	}
	script := string(content)
	if !strings.Contains(script, "/etc/systemd/system/caddy.service") {
		t.Error("install_caddy.sh must install standalone /etc/systemd/system/caddy.service")
	}
	if strings.Contains(script, "caddy-stable.list") || strings.Contains(script, "apt-get install -y caddy") {
		t.Error("install_caddy.sh must not add caddy-stable.list or register caddy in APT/dpkg")
	}
}

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

	var parsed struct {
		Inbounds []struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		t.Fatalf("rendered server config is not valid JSON: %v", err)
	}

	foundInbounds := make(map[string]bool)
	for _, in := range parsed.Inbounds {
		foundInbounds[in.Type] = true
		if in.Listen != "127.0.0.1" {
			t.Errorf("inbound %s (%s) should listen on 127.0.0.1, got %s", in.Tag, in.Type, in.Listen)
		}
	}
	for _, expectedType := range []string{"vless", "hysteria2"} {
		if !foundInbounds[expectedType] {
			t.Errorf("expected inbound type %q not found in rendered server config", expectedType)
		}
	}
}

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

// TestSyncServerCmd_Registered verifies that the sync subcommand is registered with aliases ss and sync-substore.
func TestSyncServerCmd_Registered(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	if serverCmd == nil {
		t.Fatal("expected NewServerCmd to return non-nil")
	}

	var syncCmdFound bool
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "sync" {
			syncCmdFound = true
			expectedAliases := []string{"ss"}
			for _, expected := range expectedAliases {
				hasAlias := false
				for _, alias := range sub.Aliases {
					if alias == expected {
						hasAlias = true
						break
					}
				}
				if !hasAlias {
					t.Errorf("expected alias %s not found in %v", expected, sub.Aliases)
				}
			}

			// Bilingual check
			if !strings.Contains(sub.Short, "/") {
				t.Errorf("expected bilingual Short description containing '/', got: %q", sub.Short)
			}
			break
		}
	}
	if !syncCmdFound {
		t.Error("expected 'sync' subcommand to be registered in server command")
	}
}

// TestSyncServerCmd_RestartFlag verifies that the --restart / -r flag is present and defaults to true.
func TestSyncServerCmd_RestartFlag(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	syncCmd := cmd.NewSyncServerCmd(configPath)
	flag := syncCmd.Flags().Lookup("restart")
	if flag == nil {
		t.Fatal("expected 'restart' flag on sync command")
	}
	if flag.Shorthand != "r" {
		t.Errorf("expected shorthand 'r' for restart flag, got %q", flag.Shorthand)
	}
	if flag.DefValue != "true" {
		t.Errorf("expected default value 'true' for restart flag, got %q", flag.DefValue)
	}
}

// TestSyncServerCmd_NoArgs verifies that sync rejects extra positional arguments.
func TestSyncServerCmd_NoArgs(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	syncCmd := cmd.NewSyncServerCmd(configPath)
	syncCmd.SetArgs([]string{"unexpected_arg"})
	if err := syncCmd.Execute(); err == nil {
		t.Fatal("expected error for unexpected positional argument, got nil")
	}
}

// TestSync_LoadExistingCredentialsAndSyncSubstore verifies end-to-end credential loading and substore writing.
func TestSync_LoadExistingCredentialsAndSyncSubstore(t *testing.T) {
	tempDir := t.TempDir()
	sbConfigFile := filepath.Join(tempDir, "config.json")
	substoreFile := filepath.Join(tempDir, "sub-store.json")

	// Mock deployed sing-box config with specific UUID, private_key, short_id
	const testUUID = "11111111-2222-3333-4444-555555555555"
	const testPrivKey = "uLpIe_G30f3L8v5F0T3C8W7N2M1K4H6B9Z0X5V2P1E8"
	const testShortID = "abcd1234ef567890"

	mockSingBoxConfig := `{
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": 8443,
      "users": [
        {
          "uuid": "` + testUUID + `",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "swdist.apple.com",
        "reality": {
          "enabled": true,
          "private_key": "` + testPrivKey + `",
          "short_id": [
            "` + testShortID + `"
          ]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "HYSTERIA2",
      "listen": "127.0.0.1",
      "listen_port": 52021,
      "users": [
        {
          "password": "` + testUUID + `"
        }
      ]
    }
  ]
}`
	if err := os.WriteFile(sbConfigFile, []byte(mockSingBoxConfig), 0644); err != nil {
		t.Fatalf("failed to write mock sing-box config: %v", err)
	}

	cfg := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "ssr.example.com",
			Sni:      "swdist.apple.com",
		},
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		t.Fatalf("NewSingBoxServer failed: %v", err)
	}
	sbs.ConfigFile = sbConfigFile

	// 1. Load existing credentials
	if err := sbs.LoadExistingCredentials(); err != nil {
		t.Fatalf("LoadExistingCredentials failed: %v", err)
	}

	// 2. Verify share links were updated to reflect the loaded credentials
	if !strings.Contains(sbs.ShareLinkHy2, testUUID) {
		t.Errorf("ShareLinkHy2 does not contain expected UUID: %s", sbs.ShareLinkHy2)
	}
	if !strings.Contains(sbs.ShareLinkVless, testUUID) {
		t.Errorf("ShareLinkVless does not contain expected UUID: %s", sbs.ShareLinkVless)
	}
	if !strings.Contains(sbs.ShareLinkVless, testShortID) {
		t.Errorf("ShareLinkVless does not contain expected short ID: %s", sbs.ShareLinkVless)
	}

	// 3. Sync to Sub-Store config
	sbt := deploy.NewSubstore(cfg, "")
	sbt.SubstorePath = substoreFile
	sbt.SkipRestart = true

	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		t.Fatalf("UpdateSubstoreConfig failed: %v", err)
	}

	// 4. Read back substore json and verify contents
	data, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore file: %v", err)
	}

	var substoreMap map[string]interface{}
	if err := json.Unmarshal(data, &substoreMap); err != nil {
		t.Fatalf("failed to parse substore json: %v", err)
	}

	subs, ok := substoreMap["subs"].([]interface{})
	if !ok || len(subs) == 0 {
		t.Fatalf("expected non-empty subs in substore json")
	}

	var foundHy2, foundVless bool
	for _, s := range subs {
		subObj, ok := s.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := subObj["name"].(string)
		content, _ := subObj["content"].(string)

		if name == "auto_generated_hy2" {
			foundHy2 = true
			if !strings.Contains(content, testUUID) {
				t.Errorf("auto_generated_hy2 missing UUID in content: %s", content)
			}
		}
		if name == "auto_generated_vless" {
			foundVless = true
			if !strings.Contains(content, testUUID) {
				t.Errorf("auto_generated_vless missing UUID in content: %s", content)
			}
			if !strings.Contains(content, testShortID) {
				t.Errorf("auto_generated_vless missing ShortID in content: %s", content)
			}
		}
	}

	if !foundHy2 {
		t.Error("expected auto_generated_hy2 in substore subs")
	}
	if !foundVless {
		t.Error("expected auto_generated_vless in substore subs")
	}
}

// TestSync_PreserveOtherNodesWhenSyncingCurrentVPS verifies that syncing a VPS only overwrites
// the current VPS's node information and preserves other VPS nodes in Sub-Store.
func TestSync_PreserveOtherNodesWhenSyncingCurrentVPS(t *testing.T) {
	tempDir := t.TempDir()
	substoreFile := filepath.Join(tempDir, "sub-store.json")

	// Pre-populate sub-store.json with an existing node from VPS-A
	const vpsA_Domain = "vps-a.example.com"
	const vpsA_Hy2 = "hysteria2://vps-a-uuid@" + vpsA_Domain + "/?sni=" + vpsA_Domain + "&alpn=h3&insecure=0#sec_vps-a_hy2"
	const vpsA_Vless = "vless://vps-a-uuid@" + vpsA_Domain + ":443?type=tcp&security=reality&sni=swdist.apple.com#sec_vps-a_vr"

	initialSubstore := map[string]interface{}{
		"subs": []interface{}{
			map[string]interface{}{
				"name":        "auto_generated_hy2",
				"displayName": "Hysteria2 Auto",
				"content":     vpsA_Hy2,
			},
			map[string]interface{}{
				"name":        "auto_generated_vless",
				"displayName": "VLESS Reality Auto",
				"content":     vpsA_Vless,
			},
		},
		"collections": []interface{}{
			map[string]interface{}{
				"name":          "all",
				"subscriptions": []interface{}{"auto_generated_hy2", "auto_generated_vless"},
			},
		},
	}
	initialData, err := json.Marshal(initialSubstore)
	if err != nil {
		t.Fatalf("failed to marshal initial substore: %v", err)
	}
	if err := os.WriteFile(substoreFile, initialData, 0644); err != nil {
		t.Fatalf("failed to write initial substore: %v", err)
	}

	// Now sync VPS-B (the current VPS)
	cfgB := &config.Config{
		Server: config.ServerConfig{
			SBDomain: "vps-b.example.com",
			Sni:      "swdist.apple.com",
		},
	}
	sbsB, err := deploy.NewSingBoxServer(cfgB)
	if err != nil {
		t.Fatalf("NewSingBoxServer for VPS-B failed: %v", err)
	}

	sbtB := deploy.NewSubstore(cfgB, "")
	sbtB.SubstorePath = substoreFile
	sbtB.SkipRestart = true

	if err := sbtB.UpdateSubstoreConfig(sbsB); err != nil {
		t.Fatalf("UpdateSubstoreConfig for VPS-B failed: %v", err)
	}

	// Verify both VPS-A and VPS-B exist
	dataB, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore after VPS-B sync: %v", err)
	}
	var resB struct {
		Subs []struct {
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"subs"`
	}
	if err := json.Unmarshal(dataB, &resB); err != nil {
		t.Fatalf("failed to parse substore after VPS-B sync: %v", err)
	}

	for _, sub := range resB.Subs {
		lines := strings.Split(sub.Content, "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines in %s, got %d: %q", sub.Name, len(lines), sub.Content)
		}
		if lines[0] != vpsA_Hy2 && lines[0] != vpsA_Vless {
			t.Errorf("expected line 0 to preserve VPS-A node, got %q", lines[0])
		}
		if sub.Name == "auto_generated_hy2" && lines[1] != sbsB.ShareLinkHy2 {
			t.Errorf("expected line 1 to be VPS-B hy2 %q, got %q", sbsB.ShareLinkHy2, lines[1])
		}
		if sub.Name == "auto_generated_vless" && lines[1] != sbsB.ShareLinkVless {
			t.Errorf("expected line 1 to be VPS-B vless %q, got %q", sbsB.ShareLinkVless, lines[1])
		}
	}

	// Now re-sync VPS-B with regenerated credentials (testing overwrite of current VPS only)
	if err := sbsB.RegenerateCredentials(); err != nil {
		t.Fatalf("RegenerateCredentials for VPS-B failed: %v", err)
	}
	if err := sbtB.UpdateSubstoreConfig(sbsB); err != nil {
		t.Fatalf("second UpdateSubstoreConfig for VPS-B failed: %v", err)
	}

	dataB2, err := os.ReadFile(substoreFile)
	if err != nil {
		t.Fatalf("failed to read substore after second sync: %v", err)
	}
	if err := json.Unmarshal(dataB2, &resB); err != nil {
		t.Fatalf("failed to parse substore after second sync: %v", err)
	}

	for _, sub := range resB.Subs {
		lines := strings.Split(sub.Content, "\n")
		if len(lines) != 2 {
			t.Fatalf("expected 2 lines in %s after second sync, got %d", sub.Name, len(lines))
		}
		// VPS-A MUST still be preserved!
		if lines[0] != vpsA_Hy2 && lines[0] != vpsA_Vless {
			t.Errorf("VPS-A node was overwritten! line 0: %q", lines[0])
		}
		// VPS-B MUST be updated to the new credentials
		if sub.Name == "auto_generated_hy2" && lines[1] != sbsB.ShareLinkHy2 {
			t.Errorf("VPS-B hy2 was not updated! line 1: %q, expected: %q", lines[1], sbsB.ShareLinkHy2)
		}
		if sub.Name == "auto_generated_vless" && lines[1] != sbsB.ShareLinkVless {
			t.Errorf("VPS-B vless was not updated! line 1: %q, expected: %q", lines[1], sbsB.ShareLinkVless)
		}
	}
}

// TestInfoServerCmd_Registered verifies that the info subcommand is registered in server command.
func TestInfoServerCmd_Registered(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "singctl.yaml")
	_ = os.WriteFile(configPath, []byte("server:\n  sb_domain: \"test.example.com\"\n"), 0644)

	serverCmd := cmd.NewServerCmd(configPath)
	if serverCmd == nil {
		t.Fatal("expected NewServerCmd to return non-nil")
	}

	found := false
	for _, sub := range serverCmd.Commands() {
		if sub.Name() == "info" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'info' subcommand to be registered in server command")
	}
}
