// 文件职责：测试客户端核心组件自动更新配置（watchdog.auto_update）的默认值、边界裁剪、深拷贝、AST 持久化与模板迁移。
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/configs"
	"singctl/internal/config"
)

func TestWatchdogAutoUpdateConfig_DefaultsAndBoundaries(t *testing.T) {
	var zero config.Config
	au := zero.Watchdog.AutoUpdate

	if au.SingCtl || au.SingBox || au.AdGuardHome || au.Tailscale {
		t.Fatalf("expected all 4 auto-update toggles to default to false, got %+v", au)
	}
	if au.AnyEnabled() {
		t.Fatal("expected AnyEnabled()==false by default")
	}
	if !au.IsEmpty() {
		t.Fatal("expected IsEmpty()==true by default")
	}
	if got := au.EffectiveIntervalHours(); got != 24 {
		t.Fatalf("expected default EffectiveIntervalHours()==24, got %d", got)
	}
	if got := au.EffectiveInterval(); got != 24*time.Hour {
		t.Fatalf("expected default EffectiveInterval()==24h, got %v", got)
	}

	clampCases := []struct {
		name  string
		input int
		want  int
	}{
		{name: "zero_defaults_24", input: 0, want: 24},
		{name: "negative_defaults_24", input: -10, want: 24},
		{name: "below_min_clamps_6", input: 1, want: 6},
		{name: "min_boundary_6", input: 6, want: 6},
		{name: "mid_value_12", input: 12, want: 12},
		{name: "max_boundary_168", input: 168, want: 168},
		{name: "above_max_clamps_168", input: 500, want: 168},
	}
	for _, tc := range clampCases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.ComponentAutoUpdateConfig{IntervalHours: tc.input}
			if got := c.EffectiveIntervalHours(); got != tc.want {
				t.Fatalf("IntervalHours=%d: got %d, want %d", tc.input, got, tc.want)
			}
			if got := c.EffectiveInterval(); got != time.Duration(tc.want)*time.Hour {
				t.Fatalf("EffectiveInterval=%v, want %dh", got, tc.want)
			}
		})
	}

	enableCases := []struct {
		id     string
		cfg    config.ComponentAutoUpdateConfig
		expect bool
	}{
		{id: "singctl", cfg: config.ComponentAutoUpdateConfig{SingCtl: true}, expect: true},
		{id: "singbox", cfg: config.ComponentAutoUpdateConfig{SingBox: true}, expect: true},
		{id: "adguard_home", cfg: config.ComponentAutoUpdateConfig{AdGuardHome: true}, expect: true},
		{id: "tailscale", cfg: config.ComponentAutoUpdateConfig{Tailscale: true}, expect: true},
		{id: "singctl", cfg: config.ComponentAutoUpdateConfig{}, expect: false},
		{id: "unknown", cfg: config.ComponentAutoUpdateConfig{SingCtl: true, SingBox: true, AdGuardHome: true, Tailscale: true}, expect: false},
	}
	for _, tc := range enableCases {
		if got := tc.cfg.IsEnabled(tc.id); got != tc.expect {
			t.Fatalf("IsEnabled(%q) on %+v: got %v, want %v", tc.id, tc.cfg, got, tc.expect)
		}
		if tc.expect && (!tc.cfg.AnyEnabled() || tc.cfg.IsEmpty()) {
			t.Fatalf("expected AnyEnabled()==true and IsEmpty()==false for %+v", tc.cfg)
		}
	}
}

func TestWatchdogAutoUpdateConfig_CloneSaveMigrateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, configs.DefaultConfigYAML, 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}

	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load template: %v", err)
	}
	if loaded.Watchdog.AutoUpdate.AnyEnabled() {
		t.Fatalf("expected default template auto_update disabled, got %+v", loaded.Watchdog.AutoUpdate)
	}

	// Clone isolation
	cloned := loaded.Clone()
	cloned.Watchdog.AutoUpdate = config.ComponentAutoUpdateConfig{
		SingCtl:       true,
		SingBox:       true,
		AdGuardHome:   false,
		Tailscale:     true,
		IntervalHours: 12,
	}
	if loaded.Watchdog.AutoUpdate.AnyEnabled() {
		t.Fatal("mutating cloned Watchdog.AutoUpdate leaked to original")
	}

	// Save with enabled toggles -> reload preserves exact values
	if err := config.Save(cfgPath, cloned); err != nil {
		t.Fatalf("save enabled auto_update: %v", err)
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload enabled auto_update: %v", err)
	}
	want := config.ComponentAutoUpdateConfig{
		SingCtl:       true,
		SingBox:       true,
		AdGuardHome:   false,
		Tailscale:     true,
		IntervalHours: 12,
	}
	if reloaded.Watchdog.AutoUpdate != want {
		t.Fatalf("reloaded AutoUpdate=%+v, want %+v", reloaded.Watchdog.AutoUpdate, want)
	}

	// Migrate preserves auto_update block across template refresh
	if err := config.MigrateConfig(cfgPath, configs.DefaultConfigYAML); err != nil {
		t.Fatalf("migrate with auto_update: %v", err)
	}
	migrated, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("load after migrate: %v", err)
	}
	if migrated.Watchdog.AutoUpdate != want {
		t.Fatalf("migrated AutoUpdate=%+v, want %+v", migrated.Watchdog.AutoUpdate, want)
	}

	// Turn all toggles off & clear interval -> AST save drops stale auto_update key cleanly
	migrated.Watchdog.AutoUpdate = config.ComponentAutoUpdateConfig{}
	if err := config.Save(cfgPath, migrated); err != nil {
		t.Fatalf("save cleared auto_update: %v", err)
	}
	reloadedOff, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload cleared auto_update: %v", err)
	}
	if reloadedOff.Watchdog.AutoUpdate.AnyEnabled() || !reloadedOff.Watchdog.AutoUpdate.IsEmpty() {
		t.Fatalf("expected cleared auto_update to be empty, got %+v", reloadedOff.Watchdog.AutoUpdate)
	}
	rawBytes, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(rawBytes), "singbox: true") || strings.Contains(string(rawBytes), "singctl: true") {
		t.Fatalf("expected stale true keys removed after clearing auto_update:\n%s", string(rawBytes))
	}
}
