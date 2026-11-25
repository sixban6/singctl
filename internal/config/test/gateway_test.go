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
		{"basic", config.WorkModeAudit, true},
		{"dns_only", config.WorkModeAudit, true},
		{"lite", config.WorkModeAudit, true},
		{"audit", config.WorkModeAudit, true},
		{"direct_audit", config.WorkModeAudit, true},
		{"proxy", config.WorkModeProxy, true},
		{"delegated", config.WorkModeDelegated, true},
		{"side_delegated", config.WorkModeDelegated, true},
		{"passthrough", config.WorkModeDelegated, true},
		{"invalid_mode", "", false},
	}
	for _, tc := range normCases {
		got, ok := config.NormalizeWorkMode(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("NormalizeWorkMode(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}

	noSubAuto := &config.Config{}
	if noSubAuto.EffectiveWorkMode() != config.WorkModeAudit || !noSubAuto.IsDirectAuditMode() || !noSubAuto.NeedsSingBox() {
		t.Fatalf("empty subs auto should resolve to audit (NeedsSingBox=true), got %q", noSubAuto.EffectiveWorkMode())
	}

	legacyBasic := &config.Config{Gateway: config.GatewayConfig{WorkMode: "basic"}}
	if legacyBasic.EffectiveWorkMode() != config.WorkModeAudit || !legacyBasic.IsDirectAuditMode() || !legacyBasic.NeedsSingBox() {
		t.Fatalf("legacy basic work_mode should map smoothly to audit, got %q", legacyBasic.EffectiveWorkMode())
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

func TestGatewayDelegatedAndSideRouterConfig(t *testing.T) {
	mainDelegated := &config.Config{
		Subs: []config.Subscription{{Name: "s1", URL: "https://example.com/s1"}},
		Gateway: config.GatewayConfig{
			Mode:         "main",
			WorkMode:     "delegated",
			SideRouterIP: "192.168.55.88",
		},
	}
	if mainDelegated.EffectiveWorkMode() != config.WorkModeDelegated {
		t.Fatalf("expected EffectiveWorkMode=delegated, got %q", mainDelegated.EffectiveWorkMode())
	}
	if !mainDelegated.IsDelegatedMode() {
		t.Fatal("expected IsDelegatedMode=true on main router")
	}
	if mainDelegated.NeedsSingBox() {
		t.Fatal("expected NeedsSingBox=false in delegated mode even with subs configured")
	}
	if !mainDelegated.Gateway.IsSideRouterFailoverEnabled() {
		t.Fatal("expected IsSideRouterFailoverEnabled=true by default")
	}
	if mainDelegated.Gateway.IsEmpty() {
		t.Fatal("expected Gateway.IsEmpty=false when SideRouterIP/WorkMode is set")
	}

	// Side router misconfigured as delegated must fall back safely to normal auto resolution (proxy/audit).
	sideMisconfigured := &config.Config{
		Subs: []config.Subscription{{Name: "s1", URL: "https://example.com/s1"}},
		Gateway: config.GatewayConfig{
			Mode:     "side",
			WorkMode: config.WorkModeDelegated,
		},
	}
	if sideMisconfigured.EffectiveWorkMode() != config.WorkModeProxy || !sideMisconfigured.NeedsSingBox() || sideMisconfigured.IsDelegatedMode() {
		t.Fatalf("side router misconfigured with delegated must fall back to proxy, got %q", sideMisconfigured.EffectiveWorkMode())
	}

	// Explicit false failover pointer must deep-clone independently.
	f := false
	mainDelegated.Gateway.SideRouterFailover = &f
	cloned := mainDelegated.Clone()
	*cloned.Gateway.SideRouterFailover = true
	if mainDelegated.Gateway.IsSideRouterFailoverEnabled() {
		t.Fatal("mutating cloned SideRouterFailover mutated original snapshot")
	}

	// Verify Save/Load + colonSpaceFix + MigrateConfig preserve side_router_ip & side_router_failover.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	raw := `subs: []
gateway:
  mode: "main"
  work_mode: "delegated"
  side_router_ip:"192.168.55.88"
  side_router_failover:false
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load delegated config failed: %v", err)
	}
	if loaded.Gateway.SideRouterIP != "192.168.55.88" || loaded.Gateway.IsSideRouterFailoverEnabled() {
		t.Fatalf("unexpected loaded gateway: %+v", loaded.Gateway)
	}

	if err := config.MigrateConfig(cfgPath, configs.DefaultConfigYAML); err != nil {
		t.Fatalf("MigrateConfig failed: %v", err)
	}
	migrated, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load migrated failed: %v", err)
	}
	if migrated.Gateway.WorkMode != config.WorkModeDelegated ||
		migrated.Gateway.SideRouterIP != "192.168.55.88" ||
		migrated.Gateway.IsSideRouterFailoverEnabled() {
		t.Fatalf("migrated delegated gateway fields lost: %+v", migrated.Gateway)
	}
}
