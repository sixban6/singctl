package config

import (
	"os"
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
