package config

import (
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
