package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/deploy"
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

// TestInstallCaddyScript_UnholdScript verifies that install_caddy.sh contains apt-mark unhold caddy before install.
func TestInstallCaddyScript_UnholdScript(t *testing.T) {
	content, err := os.ReadFile("../internal/deploy/scripts/install_caddy.sh")
	if err != nil {
		t.Fatalf("failed to read install_caddy.sh: %v", err)
	}
	if !strings.Contains(string(content), "apt-mark unhold caddy") {
		t.Error("install_caddy.sh must contain 'apt-mark unhold caddy'")
	}
}
