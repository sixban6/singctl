package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/configs"
)

func TestGatewayConfig_DefaultsToMain(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	raw := `subs:
  - name: "main"
    url: "https://example.com/sub"
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got := cfg.Gateway.EffectiveMode(); got != "main" {
		t.Fatalf("expected default EffectiveMode=main, got %q", got)
	}
	if cfg.Gateway.IsSideRouter() {
		t.Fatal("expected IsSideRouter=false by default")
	}
	if !cfg.Gateway.IsEmpty() {
		t.Fatal("expected omitted gateway config to report IsEmpty=true")
	}
}

func TestGatewayConfig_LoadSaveAndColonFix(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	// 故意省略冒号后空格，验证 knownYAMLKeys 自动修复生效
	raw := `subs:
  - name: "main"
    url: "https://example.com/sub"
gateway:
  mode:"side"
  main_router_ip:"192.168.100.1"
  lan_iface:"eth0"
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got := cfg.Gateway.EffectiveMode(); got != "side" {
		t.Fatalf("expected EffectiveMode=side, got %q", got)
	}
	if !cfg.Gateway.IsSideRouter() {
		t.Fatal("expected IsSideRouter=true")
	}
	if cfg.Gateway.MainRouterIP != "192.168.100.1" {
		t.Fatalf("expected MainRouterIP=192.168.100.1, got %q", cfg.Gateway.MainRouterIP)
	}
	if cfg.Gateway.LANIface != "eth0" {
		t.Fatalf("expected LANIface=eth0, got %q", cfg.Gateway.LANIface)
	}

	outPath := filepath.Join(dir, "saved.yaml")
	if err := Save(outPath, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	st, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", perm)
	}

	reloaded, err := Load(outPath)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !reloaded.Gateway.IsSideRouter() || reloaded.Gateway.MainRouterIP != "192.168.100.1" || reloaded.Gateway.LANIface != "eth0" {
		t.Fatalf("reloaded gateway mismatch: %+v", reloaded.Gateway)
	}
}

func TestMigrateConfig_PreservesSideRouterAndKeepsClientClean(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	oldYAML := `subs:
  - name: "main"
    url: "https://example.com/sub"
gateway:
  mode: "side"
  main_router_ip: "192.168.100.1"
  lan_iface: "br-lan"
`
	if err := os.WriteFile(cfgPath, []byte(oldYAML), 0600); err != nil {
		t.Fatalf("write old config: %v", err)
	}

	if err := MigrateConfig(cfgPath, configs.DefaultConfigYAML); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	mergedRaw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	if strings.Contains(string(mergedRaw), "\nserver:") {
		t.Fatalf("client-only config migration should not inject server section:\n%s", string(mergedRaw))
	}

	migrated, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load migrated failed: %v", err)
	}
	if migrated.Gateway.EffectiveMode() != "side" {
		t.Fatalf("expected migrated mode=side, got %q", migrated.Gateway.EffectiveMode())
	}
	if migrated.Gateway.MainRouterIP != "192.168.100.1" {
		t.Fatalf("expected migrated MainRouterIP=192.168.100.1, got %q", migrated.Gateway.MainRouterIP)
	}
	if migrated.Gateway.LANIface != "br-lan" {
		t.Fatalf("expected migrated LANIface=br-lan, got %q", migrated.Gateway.LANIface)
	}
}
