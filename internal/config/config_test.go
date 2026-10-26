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
  tuic_domain: "cdn.l2.example.com"
  server_ip: "107.172.89.197"
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
	if loaded.Server.TuicDomain != "cdn.l2.example.com" {
		t.Errorf("expected tuic_domain 'cdn.l2.example.com', got '%s'", loaded.Server.TuicDomain)
	}
	if loaded.Server.ServerIP != "107.172.89.197" {
		t.Errorf("expected server_ip '107.172.89.197', got '%s'", loaded.Server.ServerIP)
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
