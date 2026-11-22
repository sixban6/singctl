// 文件职责：验证审计黑名单对双引擎（adguard / smartdns）本地 DNS 层的解耦同步及未安装兜底行为。
package audit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/platform/servicemgr"
)

func TestSyncDNSBlockRulesForEngine_DualEngines(t *testing.T) {
	ctx := t.Context()

	t.Run("uninstalled_auto_or_legacy_singbox_returns_not_installed", func(t *testing.T) {
		tmpDir := t.TempDir()
		for _, eng := range []string{constant.DNSEngineAuto, "singbox"} {
			cfg := &config.Config{
				DNS: config.ClientDNSConfig{Engine: eng},
			}
			applied, mode, err := audit.SyncDNSBlockRulesForEngine(ctx, cfg, audit.DNSBlockSyncOptions{
				AdGuardBinPath:    filepath.Join(tmpDir, "missing-agh"),
				AdGuardConfigPath: filepath.Join(tmpDir, "missing-agh.yaml"),
				SmartDNSBinPath:   filepath.Join(tmpDir, "missing-sd"),
			}, []config.BlockRule{
				{Target: "tracker.example.com"},
			})
			if err != nil || applied || mode != "not_installed" {
				t.Fatalf("engine=%q: got applied=%v mode=%q err=%v; want false, not_installed, nil", eng, applied, mode, err)
			}
		}
	})

	t.Run("smartdns_engine_writes_audit_block_conf_and_preserves_whitelist_rewrites", func(t *testing.T) {
		tmpDir := t.TempDir()
		binPath := filepath.Join(tmpDir, "smartdns")
		confPath := filepath.Join(tmpDir, "smartdns.conf")
		rulesDir := filepath.Join(tmpDir, "smartdns-rules.d")
		if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho smartdns\n"), 0755); err != nil {
			t.Fatal(err)
		}

		mockSvc := servicemgr.NewMock()
		_ = mockSvc.Start(ctx, constant.SmartDNSServiceName)

		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "S", URL: "https://sub.example.com/feed"}},
			DNS: config.ClientDNSConfig{
				Engine:    constant.DNSEngineSmartDNS,
				Whitelist: []string{"good.example.com"},
				Rewrites:  []config.DNSRewriteRule{{Domain: "nas.example.com", Answer: "192.0.2.20"}},
			},
		}
		blocks := []config.BlockRule{
			{Target: "pcdn-evil.example.com"},
			{Target: "ruleset:block-builtin-pcdn"},
			{Target: "198.51.100.77"},
		}

		applied, mode, err := audit.SyncDNSBlockRulesForEngine(ctx, cfg, audit.DNSBlockSyncOptions{
			SmartDNSBinPath:    binPath,
			SmartDNSConfigFile: confPath,
			SmartDNSRulesDir:   rulesDir,
			ServiceMgr:         mockSvc,
		}, blocks)
		if err != nil || !applied || mode != "smartdns_rules" {
			t.Fatalf("got applied=%v mode=%q err=%v; want true, smartdns_rules, nil", applied, mode, err)
		}

		auditRaw, err := os.ReadFile(filepath.Join(rulesDir, "audit_block.conf"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(auditRaw), "address /pcdn-evil.example.com/#") {
			t.Fatalf("expected pcdn-evil.example.com in audit_block.conf, got:\n%s", string(auditRaw))
		}
		if strings.Contains(string(auditRaw), "198.51.100.77") || strings.Contains(string(auditRaw), "ruleset:") {
			t.Fatalf("IP/ruleset entries should not leak into SmartDNS domain blocklist:\n%s", string(auditRaw))
		}

		wlRaw, err := os.ReadFile(filepath.Join(rulesDir, "whitelist.conf"))
		if err != nil || !strings.Contains(string(wlRaw), "good.example.com") || !strings.Contains(string(wlRaw), "sub.example.com") {
			t.Fatalf("expected whitelist and sub domain preserved, err=%v raw=%s", err, string(wlRaw))
		}
		rwRaw, err := os.ReadFile(filepath.Join(rulesDir, "rewrites.conf"))
		if err != nil || !strings.Contains(string(rwRaw), "nas.example.com/192.0.2.20") {
			t.Fatalf("expected rewrites preserved, err=%v raw=%s", err, string(rwRaw))
		}
	})

	t.Run("adguard_engine_writes_user_rules_yaml", func(t *testing.T) {
		tmpDir := t.TempDir()
		aghCfg := filepath.Join(tmpDir, "AdGuardHome.yaml")
		if err := os.WriteFile(aghCfg, []byte("dns:\n  port: 5353\nuser_rules:\n  - '@@||keep.example.com^$important'\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cfg := &config.Config{
			DNS: config.ClientDNSConfig{Engine: constant.DNSEngineAdGuard},
		}
		applied, mode, err := audit.SyncDNSBlockRulesForEngine(ctx, cfg, audit.DNSBlockSyncOptions{
			AdGuardConfigPath: aghCfg,
		}, []config.BlockRule{{Target: "bad.example.com"}})
		if err != nil || !applied || mode != "yaml_file" {
			t.Fatalf("got applied=%v mode=%q err=%v; want true, yaml_file, nil", applied, mode, err)
		}
		raw, _ := os.ReadFile(aghCfg)
		if !strings.Contains(string(raw), "||bad.example.com^$important") || !strings.Contains(string(raw), "@@||keep.example.com^$important") {
			t.Fatalf("unexpected AdGuardHome.yaml:\n%s", string(raw))
		}
	})
}
