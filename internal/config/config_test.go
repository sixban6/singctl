package config

import (
	"os"
	"strings"
	"testing"
)

func TestServerConfig_GetServerIP_Explicit(t *testing.T) {
	s := &ServerConfig{
		ServerIP: "1.2.3.4",
	}
	if ip := s.GetServerIP(); ip != "1.2.3.4" {
		t.Errorf("expected 1.2.3.4, got %s", ip)
	}
}

func TestServerConfig_GetServerIP_MockDiscovered(t *testing.T) {
	ResetDiscoveredPublicIPForTest()
	defer ResetDiscoveredPublicIPForTest()

	SetDiscoveredPublicIPForTest("5.6.7.8")
	s := &ServerConfig{}
	if ip := s.GetServerIP(); ip != "5.6.7.8" {
		t.Errorf("expected 5.6.7.8, got %s", ip)
	}
}

func TestMigrateConfig_PreserveNodeDomainAndServerFields(t *testing.T) {
	oldYAML := `
server:
  sb_domain: "sub.example.com"
  node_domain: "cdn.l1.example.com"
  substore_domain: "l-s.example.com"
  server_ip: "198.51.100.1"
  cf_dns_key: "my_token"
  sni: "swdist.apple.com"
`
	// Template that does NOT contain node_domain or substore_domain
	templateYAML := `
server:
  sb_domain: "template.example.com"
  cf_dns_key: "template_token"
`
	tmpFile, err := os.CreateTemp("", "singctl_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := MigrateConfig(tmpFile.Name(), []byte(templateYAML)); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "cdn.l1.example.com" {
		t.Errorf("expected node_domain 'cdn.l1.example.com', got '%s'", loaded.Server.NodeDomain)
	}
	if loaded.Server.SubstoreDomain != "l-s.example.com" {
		t.Errorf("expected substore_domain 'l-s.example.com', got '%s'", loaded.Server.SubstoreDomain)
	}
	if loaded.Server.ServerIP != "198.51.100.1" {
		t.Errorf("expected server_ip '198.51.100.1', got '%s'", loaded.Server.ServerIP)
	}
	if loaded.Server.SBDomain != "sub.example.com" {
		t.Errorf("expected sb_domain 'sub.example.com', got '%s'", loaded.Server.SBDomain)
	}
	if loaded.Server.CFDNSKey != "my_token" {
		t.Errorf("expected cf_dns_key 'my_token', got '%s'", loaded.Server.CFDNSKey)
	}
	if loaded.Server.Sni != "swdist.apple.com" {
		t.Errorf("expected sni 'swdist.apple.com', got '%s'", loaded.Server.Sni)
	}
}

func TestMigrateConfig_VPSGC1(t *testing.T) {
	vpsYAML := `subs:
    - name: main
      url: ""
      skip_tls_verify: false
      remove-emoji: true
github:
    mirror_url: "https://gh-proxy.com"
hy2:
    up: 20
    down: 200
tailscale:
    auth_key: ""
    subnets: ""
    use_build: false
server:
    node_domain: "cdn.s1.example.com"
    substore_domain: "s-s.example.com"
    cf_dns_key: "mock_cf_token_value_123456"
    sni: ""
watchdog:
    interval: 180
    confirm_wait: 30
    max_restarts: 3
`
	templateBytes, err := os.ReadFile("../../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_vps_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(vpsYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	resultBytes, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Migrated YAML:\n%s", string(resultBytes))

	loaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "cdn.s1.example.com" {
		t.Errorf("expected node_domain 'cdn.s1.example.com', got '%s'", loaded.Server.NodeDomain)
	}
	if loaded.Server.SubstoreDomain != "s-s.example.com" {
		t.Errorf("expected substore_domain 's-s.example.com', got '%s'", loaded.Server.SubstoreDomain)
	}
}

func TestMigrateConfig_LegacySBDomainMigration(t *testing.T) {
	legacyYAML := `
server:
  sb_domain: "legacy.example.com"
  cf_dns_key: "my_key"
`
	templateBytes, err := os.ReadFile("../../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_legacy_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(legacyYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "legacy.example.com" {
		t.Errorf("expected node_domain 'legacy.example.com', got '%s'", loaded.Server.NodeDomain)
	}
	if loaded.Server.CFDNSKey != "my_key" {
		t.Errorf("expected cf_dns_key 'my_key', got '%s'", loaded.Server.CFDNSKey)
	}
}

func TestLoad_StringPorts(t *testing.T) {
	yamlContent := `
hy2:
  up: "30"
  down: "300"
server:
  node_domain: "node.example.com"
  anytls_port: "443"
  web_terminal:
    enabled: true
    port: "18080"
    path: "/ops-shell-123"
watchdog:
  interval: "180"
  confirm_wait: "30"
  max_restarts: "5"
`
	tmpFile, err := os.CreateTemp("", "singctl_str_ports_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	loaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load with string ports failed: %v", err)
	}

	if loaded.Server.WebTerminal.Port != 18080 {
		t.Errorf("expected WebTerminal.Port 18080, got %d", loaded.Server.WebTerminal.Port)
	}
	if loaded.Hy2.Up != 30 || loaded.Hy2.Down != 300 {
		t.Errorf("expected Hy2 30/300, got %d/%d", loaded.Hy2.Up, loaded.Hy2.Down)
	}
	if loaded.Watchdog.Interval != 180 || loaded.Watchdog.MaxRestarts != 5 {
		t.Errorf("expected Watchdog 180/5, got %d/%d", loaded.Watchdog.Interval, loaded.Watchdog.MaxRestarts)
	}
}

func TestMigrateConfig_AnyTLSPortPurgedAndResilient(t *testing.T) {
	oldYAML := `
server:
  node_domain: "node.example.com"
  anytls_port: "443"
`
	templateBytes, err := os.ReadFile("../../configs/singctl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "singctl_migrate_port_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := MigrateConfig(tmpFile.Name(), templateBytes); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "anytls_port") {
		t.Errorf("expected anytls_port to be purged from migrated config, but found it in:\n%s", string(content))
	}

	loaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.NodeDomain != "node.example.com" {
		t.Errorf("expected node_domain 'node.example.com', got '%s'", loaded.Server.NodeDomain)
	}
}

func TestGenerateRandomAdminPath(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := GenerateRandomAdminPath()
		if !strings.HasPrefix(p, "/sr/") {
			t.Fatalf("expected prefix /sr/, got %s", p)
		}
		token := strings.TrimPrefix(p, "/sr/")
		if len(token) != 24 {
			t.Fatalf("expected token length 24, got %d (%s)", len(token), token)
		}

		hasUpper := false
		hasLower := false
		hasDigit := false
		for _, r := range token {
			switch {
			case r >= 'A' && r <= 'Z':
				hasUpper = true
			case r >= 'a' && r <= 'z':
				hasLower = true
			case r >= '0' && r <= '9':
				hasDigit = true
			default:
				t.Fatalf("unexpected char %c in token %s", r, token)
			}
		}
		if !hasUpper || !hasLower || !hasDigit {
			t.Fatalf("token %s must contain upper, lower, and digit", token)
		}
	}
}

func TestEnsureWebAdminCredentials_PathUpgrade(t *testing.T) {
	s := &ServerConfig{
		WebAdmin: WebAdminConfig{
			Path: "/sr_3002961010c61739", // old hex path
		},
	}
	changed := s.EnsureWebAdminCredentials()
	if !changed {
		t.Fatalf("expected changed=true when upgrading old hex path")
	}
	if !strings.HasPrefix(s.WebAdmin.Path, "/sr/") {
		t.Fatalf("expected upgraded path with /sr/ prefix, got %s", s.WebAdmin.Path)
	}
	token := strings.TrimPrefix(s.WebAdmin.Path, "/sr/")
	if len(token) != 24 {
		t.Fatalf("expected 24-char token, got %s (len %d)", token, len(token))
	}
}

func TestEnsureWebAdminCredentials_Generates16CharPassword(t *testing.T) {
	s := &ServerConfig{}
	if !s.EnsureWebAdminCredentials() {
		t.Fatal("expected credentials to be generated")
	}
	if len(s.WebAdmin.Password) != 16 {
		t.Fatalf("expected 16-char password, got %q", s.WebAdmin.Password)
	}
	if !s.WebAdmin.PasswordPendingAck {
		t.Fatal("expected newly generated password to require acknowledgement")
	}
	if !validatePasswordChars(s.WebAdmin.Password) {
		t.Fatalf("password %q missing required character classes", s.WebAdmin.Password)
	}
}

func validatePasswordChars(pass string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, r := range pass {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func TestMigrateConfig_PreserveWebAdmin(t *testing.T) {
	oldYAML := `
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  web_admin:
    enabled: true
    port: 8092
    path: "/sr/ExistingPath987654321012"
    username: "singctl"
    password: "MySecurePassword123"
`
	templateYAML := `
server:
  node_domain: "template.example.com"
  # web_admin:
  #   enabled: true
`
	tmpFile, err := os.CreateTemp("", "singctl_test_webadmin_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(oldYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	if err := MigrateConfig(tmpFile.Name(), []byte(templateYAML)); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	loaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load migrated config failed: %v", err)
	}

	if loaded.Server.WebAdmin.Path != "/sr/ExistingPath987654321012" {
		t.Errorf("expected web_admin.path '/sr/ExistingPath987654321012', got '%s'", loaded.Server.WebAdmin.Path)
	}
	if loaded.Server.WebAdmin.Password != "MySecurePassword123" {
		t.Errorf("expected web_admin.password 'MySecurePassword123', got '%s'", loaded.Server.WebAdmin.Password)
	}
}

func TestSave_PasswordPendingAckFlip(t *testing.T) {
	initialYAML := `server:
  web_admin:
    enabled: true
    port: 8092
    path: /sr/ExistingPath987654321012
    username: singctl
    password: MySecurePassword123
    password_pending_ack: true
`
	tmpFile, err := os.CreateTemp("", "singctl_test_ack_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(initialYAML); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("expected password_pending_ack to be true initially")
	}

	// Flip to false and save
	cfg.Server.WebAdmin.PasswordPendingAck = false
	if err := Save(tmpFile.Name(), cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file content directly
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "password_pending_ack: true") {
		t.Fatalf("expected password_pending_ack to be false in YAML, got:\n%s", string(content))
	}
	if !strings.Contains(string(content), "password_pending_ack: false") {
		t.Fatalf("expected password_pending_ack: false in YAML, got:\n%s", string(content))
	}

	// Reload and verify
	reloaded, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Server.WebAdmin.PasswordPendingAck {
		t.Fatal("expected reloaded password_pending_ack to be false")
	}
}

