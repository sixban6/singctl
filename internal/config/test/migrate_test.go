// 文件职责：验证 YAML AST 配置迁移引擎（MigrateConfigBytes）的角色隔离、自定义 OCP 阶段、畸形输入容错与并发幂等性。
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

func TestMigrateConfigBytes_TableDrivenBoundaries(t *testing.T) {
	t.Run("pure_client_preserves_fields_and_strips_server", func(t *testing.T) {
		oldYAML := `# client config
subs:
  - name: "main"
    url: "https://sub.example.com/api/v1/client?token=test-sub-token"
    include: "JP|SG"
    exclude: "Expire"
hy2:
  up: 100
  down: 500
dns:
  enabled: false
  dns_port: 5353
  web_port: 3000
  username: "admin"
  password: "dns-test-password"
tailscale:
  auth_key: "test-ts-key-placeholder"
  subnets: "192.0.2.0/24"
  use_build: true
  p2p_assist:
    enabled: true
watchdog:
  interval: 25
  max_restarts: 6
  sub_sync_interval: 300
custom_rules:
  direct_domains:
    - "direct.example.com"
gateway:
  lan_cidr: "192.0.2.0/24"
`
		out, err := config.MigrateConfigBytes([]byte(oldYAML), configs.DefaultConfigYAML)
		if err != nil {
			t.Fatalf("MigrateConfigBytes failed: %v", err)
		}
		outStr := string(out)
		if strings.Contains(outStr, "\nserver:\n") || strings.HasPrefix(outStr, "server:") {
			t.Fatalf("expected server block stripped from pure client migration, got:\n%s", outStr)
		}
		var cfg config.Config
		if err := yaml.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("yaml.Unmarshal failed: %v", err)
		}
		if len(cfg.Subs) != 1 || cfg.Subs[0].Include != "JP|SG" {
			t.Fatalf("subs lost: %+v", cfg.Subs)
		}
		if cfg.DNS.Enabled == nil || *cfg.DNS.Enabled {
			t.Fatalf("expected explicit dns.enabled=false preserved, got %v", cfg.DNS.Enabled)
		}
		if cfg.Watchdog.SubSyncInterval != 300 || !cfg.Tailscale.UseBuild {
			t.Fatalf("client fields lost: watchdog=%+v tailscale=%+v", cfg.Watchdog, cfg.Tailscale)
		}
	})

	t.Run("pure_server_migrates_legacy_domain_and_supports_custom_ocp_stage", func(t *testing.T) {
		oldServer := `server:
  node_tag: "us-edge-01"
  sb_domain: "node.example.com"
  substore_domain: "sub.example.com"
  server_ip: "198.51.100.10"
  cf_dns_key: "cf-test-token"
  hy2_port: 8443
  vless_port: 443
  cors_allowed_origins: "https://panel.example.com"
  warp_routing:
    enabled: true
`
		customApplied := false
		extraStage := config.ConfigMigrationStage{
			Name: "custom_note",
			Apply: func(mc *config.MigrationContext) {
				customApplied = true
				mc.SetOrAddField("server", "node_tag", "us-edge-01-ocp")
			},
		}
		out, err := config.MigrateConfigBytes([]byte(oldServer), configs.DefaultConfigYAML, extraStage)
		if err != nil {
			t.Fatalf("MigrateConfigBytes failed: %v", err)
		}
		if !customApplied {
			t.Fatalf("expected custom OCP migration stage to execute")
		}
		outStr := string(out)
		if strings.Contains(outStr, "\nsubs:\n") || strings.Contains(outStr, "\nwatchdog:\n") {
			t.Fatalf("expected client sections omitted from pure server migration, got:\n%s", outStr)
		}
		var cfg config.Config
		if err := yaml.Unmarshal(out, &cfg); err != nil {
			t.Fatalf("yaml.Unmarshal failed: %v", err)
		}
		if cfg.Server.NodeDomain != "node.example.com" || cfg.Server.NodeTag != "us-edge-01-ocp" {
			t.Fatalf("unexpected server migration result: %+v", cfg.Server)
		}
	})

	t.Run("empty_old_invalid_yaml_non_mapping_and_file_rollback_0600", func(t *testing.T) {
		emptyOut, err := config.MigrateConfigBytes([]byte(""), configs.ClientConfigYAML)
		if err != nil || len(emptyOut) == 0 {
			t.Fatalf("empty oldData migration = (%d bytes, %v)", len(emptyOut), err)
		}
		if _, err := config.MigrateConfigBytes([]byte(":\n  - [unclosed"), configs.ClientConfigYAML); err == nil {
			t.Fatalf("expected error on malformed old YAML")
		}
		if _, err := config.MigrateConfigBytes([]byte("hy2:\n  up: 100\n"), []byte(":\n  - [broken")); err == nil {
			t.Fatalf("expected error on malformed template YAML")
		}
		if _, err := config.MigrateConfigBytes([]byte("- list-root"), configs.ClientConfigYAML); err == nil {
			t.Fatalf("expected error when old YAML root is not a mapping")
		}
		if _, err := config.MigrateConfigBytes([]byte("hy2:\n  up: 100\n"), []byte("")); err == nil {
			t.Fatalf("expected error on empty template AST")
		}

		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "singctl.yaml")
		origContent := []byte("hy2:\n  up: 100\n  down: 500\n")
		if err := os.WriteFile(cfgPath, origContent, 0644); err != nil {
			t.Fatal(err)
		}
		if err := config.MigrateConfig(cfgPath, []byte("invalid: [yaml")); err == nil {
			t.Fatalf("expected MigrateConfig failure on invalid template")
		}
		gotAfterFail, _ := os.ReadFile(cfgPath)
		if string(gotAfterFail) != string(origContent) {
			t.Fatalf("expected original file untouched on failure, got %q", string(gotAfterFail))
		}

		if err := config.MigrateConfig(cfgPath, configs.ClientConfigYAML); err != nil {
			t.Fatalf("MigrateConfig valid failed: %v", err)
		}
		fi, err := os.Stat(cfgPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected migrated config perm 0600, got %v (err=%v)", fi.Mode().Perm(), err)
		}
	})

	t.Run("idempotency_and_concurrent_race_safety", func(t *testing.T) {
		seed := []byte("subs:\n  - name: n1\n    url: https://sub.example.com/1\nhy2:\n  up: 80\n  down: 200\n")
		pass1, err := config.MigrateConfigBytes(seed, configs.ClientConfigYAML)
		if err != nil {
			t.Fatalf("pass1 failed: %v", err)
		}
		pass2, err := config.MigrateConfigBytes(pass1, configs.ClientConfigYAML)
		if err != nil {
			t.Fatalf("pass2 failed: %v", err)
		}
		pass3, err := config.MigrateConfigBytes(pass2, configs.ClientConfigYAML)
		if err != nil {
			t.Fatalf("pass3 failed: %v", err)
		}
		if string(pass2) != string(pass3) {
			t.Fatalf("migration did not converge to fixed point across repeated passes:\npass2:\n%s\npass3:\n%s", string(pass2), string(pass3))
		}

		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := config.MigrateConfigBytes(seed, configs.DefaultConfigYAML)
				if err != nil || len(res) == 0 {
					t.Errorf("concurrent MigrateConfigBytes failed: %v", err)
				}
			}()
		}
		wg.Wait()
	})
}
