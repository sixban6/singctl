// 文件职责：验证 YAML AST 无损合并保存引擎（SaveConfigBytesAST / Save）的注释保留、陈旧键清理规则、0600 落盘与并发幂等性。
package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
	"singctl/configs"
	"singctl/internal/config"
)

func TestSaveAST_TableDrivenBoundaries(t *testing.T) {
	t.Run("preserves_template_comments_separates_roles_and_supports_custom_rule", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/1"}},
			Hy2:  config.Hy2Config{Up: 50, Down: 300},
		}
		customRan := false
		extraRule := config.ASTSubtreeCleanupRule{
			Name:      "strip_custom_temp",
			TargetDoc: "dst",
			ParentKey: "gateway",
			DropChild: func(_ *config.Config, childKey string) bool {
				if childKey == "main_router_ip" {
					customRan = true
					return true
				}
				return false
			},
		}

		out, err := config.SaveConfigBytesAST(configs.ClientConfigYAML, cfg, extraRule)
		if err != nil {
			t.Fatalf("SaveConfigBytesAST failed: %v", err)
		}
		if !customRan {
			t.Fatalf("expected custom ASTSubtreeCleanupRule to run")
		}
		outStr := string(out)
		if strings.Contains(outStr, "\nserver:\n") || strings.HasPrefix(outStr, "server:") {
			t.Fatalf("expected client save not to inject server section")
		}
		if !strings.Contains(outStr, "#") {
			t.Fatalf("expected template YAML comments preserved")
		}
	})

	t.Run("clearing_slices_and_maps_removes_stale_keys_from_ast", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		seed := `subs:
  - name: "main"
    url: "https://sub.example.com/1"
custom_rules:
  block:
    - target: "bad.example.com"
audit:
  whitelist:
    - "ok.example.com"
  pcdn_block: false
firewall:
  whitelist:
    - "198.51.100.5"
watchdog:
  interval: 120
  failover:
    enabled: false
    groups: ["Proxy"]
tailscale:
  auth_key: ""
  p2p_assist:
    enabled: true
`
		if err := os.WriteFile(cfgPath, []byte(seed), 0644); err != nil {
			t.Fatal(err)
		}

		loaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		loaded.CustomRules.Block = nil
		loaded.Audit.Whitelist = nil
		loaded.Audit.SetPCDNBlock(true)
		loaded.Firewall.Whitelist = nil
		loaded.Watchdog.Failover = config.WatchdogFailoverConfig{}
		loaded.Tailscale.P2PAssist = config.TailscaleP2PAssistConfig{}

		if err := config.Save(cfgPath, loaded); err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		fi, err := os.Stat(cfgPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected saved config mode 0600, got %v (err=%v)", fi.Mode().Perm(), err)
		}

		reloaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("reload failed: %v", err)
		}
		if len(reloaded.CustomRules.Block) != 0 ||
			len(reloaded.Audit.Whitelist) != 0 ||
			!reloaded.Audit.IsPCDNBlockEnabled() ||
			len(reloaded.Firewall.Whitelist) != 0 ||
			!reloaded.Watchdog.Failover.IsEmpty() ||
			!reloaded.Tailscale.P2PAssist.IsZero() {
			t.Fatalf("stale cleared fields survived Save: %+v", reloaded)
		}
	})

	t.Run("nil_cfg_corrupted_existing_file_and_UpdateHy2Bandwidth", func(t *testing.T) {
		out, err := config.SaveConfigBytesAST([]byte(":\n  - [corrupt"), nil)
		if err != nil || len(out) == 0 {
			t.Fatalf("expected fallback valid YAML when existing AST invalid, got err=%v", err)
		}

		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "hy2.yaml")
		if err := os.WriteFile(cfgPath, []byte("hy2:\n  up: 10\n  down: 100\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := config.UpdateHy2Bandwidth(cfgPath, 75, 500); err != nil {
			t.Fatalf("UpdateHy2Bandwidth failed: %v", err)
		}
		b, _ := os.ReadFile(cfgPath)
		var parsed config.Config
		if err := yaml.Unmarshal(b, &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.Hy2.Up != 75 || parsed.Hy2.Down != 500 {
			t.Fatalf("unexpected Hy2 after update: %+v", parsed.Hy2)
		}
	})

	t.Run("idempotent_save_and_concurrent_crypto_and_ast_race_safe", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/1"}},
			Hy2:  config.Hy2Config{Up: 30, Down: 300},
		}
		pass1, err := config.SaveConfigBytesAST(configs.ClientConfigYAML, cfg)
		if err != nil {
			t.Fatalf("pass1 failed: %v", err)
		}
		pass2, err := config.SaveConfigBytesAST(pass1, cfg)
		if err != nil {
			t.Fatalf("pass2 failed: %v", err)
		}
		if string(pass1) != string(pass2) {
			t.Fatalf("SaveConfigBytesAST not idempotent")
		}

		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				tok := config.DeriveGatewayToken("/sr/testpanel")
				if len(tok) != 64 {
					t.Errorf("unexpected token length %d", len(tok))
				}
				if _, err := config.SaveConfigBytesAST(configs.ClientConfigYAML, cfg); err != nil {
					t.Errorf("concurrent SaveConfigBytesAST failed: %v", err)
				}
			}()
		}
		wg.Wait()
	})
}
