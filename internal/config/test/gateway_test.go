// 文件职责：验证网关模式（main/side）配置的默认值、缺失空格修复、0600 落盘权限及版本迁移保真。
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/configs"
	"singctl/internal/config"
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

	cfg, err := config.Load(cfgPath)
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

	cfg, err := config.Load(cfgPath)
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
	if err := config.Save(outPath, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	st, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat saved file: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", perm)
	}

	reloaded, err := config.Load(outPath)
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

	if err := config.MigrateConfig(cfgPath, configs.DefaultConfigYAML); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}

	mergedRaw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	if strings.Contains(string(mergedRaw), "\nserver:") {
		t.Fatalf("client-only config migration should not inject server section:\n%s", string(mergedRaw))
	}

	migrated, err := config.Load(cfgPath)
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

func TestGatewayWorkMode_NormalizeEffectiveSaveAndMigrate(t *testing.T) {
	normCases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"", config.WorkModeAuto, true},
		{"auto", config.WorkModeAuto, true},
		{"basic", config.WorkModeBasic, true},
		{"dns_only", config.WorkModeBasic, true},
		{"audit", config.WorkModeAudit, true},
		{"direct_audit", config.WorkModeAudit, true},
		{"proxy", config.WorkModeProxy, true},
		{"invalid_mode", "", false},
	}
	for _, tc := range normCases {
		got, ok := config.NormalizeWorkMode(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("NormalizeWorkMode(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}

	noSubAuto := &config.Config{}
	if noSubAuto.EffectiveWorkMode() != config.WorkModeBasic || !noSubAuto.IsBasicMode() || noSubAuto.NeedsSingBox() {
		t.Fatalf("empty subs auto should resolve to basic (NeedsSingBox=false), got %q", noSubAuto.EffectiveWorkMode())
	}

	noSubAudit := &config.Config{Gateway: config.GatewayConfig{WorkMode: config.WorkModeAudit}}
	if noSubAudit.EffectiveWorkMode() != config.WorkModeAudit || !noSubAudit.IsDirectAuditMode() || !noSubAudit.NeedsSingBox() {
		t.Fatalf("empty subs audit should resolve to audit (NeedsSingBox=true), got %q", noSubAudit.EffectiveWorkMode())
	}

	withSubAuto := &config.Config{Subs: []config.Subscription{{Name: "s1", URL: "https://example.com/s1"}}}
	if withSubAuto.EffectiveWorkMode() != config.WorkModeProxy || !withSubAuto.NeedsSingBox() {
		t.Fatalf("with subs auto should resolve to proxy, got %q", withSubAuto.EffectiveWorkMode())
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := config.Save(cfgPath, noSubAudit); err != nil {
		t.Fatalf("Save zero-sub audit config failed: %v", err)
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load zero-sub audit config failed: %v", err)
	}
	if reloaded.Gateway.WorkMode != config.WorkModeAudit || !reloaded.IsDirectAuditMode() {
		t.Fatalf("reloaded work_mode mismatch: %+v", reloaded.Gateway)
	}
}
