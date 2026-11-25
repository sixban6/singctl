// 文件职责：验证 YAML AST 配置迁移引擎（MigrateConfigBytes）的角色隔离、自定义 OCP 阶段、畸形输入容错与并发幂等性。
package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
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

func TestMigrateConfigBytes_PreservesNotifySafeCommitFirewallAndFullDNS(t *testing.T) {
	t.Run("client_preserves_telegram_notify_safe_commit_firewall_and_dual_dns", func(t *testing.T) {
		oldYAML := `subs:
  - name: "main"
    url: "https://sub.example.com/client?token=test-sub-token"
dns:
  enabled: true
  engine: "smartdns"
  dns_port: 5353
  web_port: 3000
  username: "admin"
  password: "dns-test-password"
  upstreams:
    - "https://223.5.5.5/dns-query"
    - "tls://1.1.1.1"
  upstream_mode: "parallel"
  whitelist:
    - "trusted.example.com"
  rewrites:
    - domain: "nas.example.com"
      answer: "192.168.1.20"
  block_aaaa: true
  adblock_disabled_until: -1
  disabled_ad_rule_sets:
    - "geosite-ad2"
  smartdns_filters:
    - "https://example.com/ad.conf"
firewall:
  ban_timeout_days: 7
  ping_limit_per_sec: 12
  whitelist:
    - "198.51.100.1"
  extra_forever_ban:
    - "203.0.113.99"
  protected_ports:
    - 443
    - 8443
notify:
  enabled: true
  cooldown_minutes: 30
  daily_limit: 80
  quiet_hours: "23:00-07:30"
  events:
    watchdog_heal: true
    safe_commit_rollback: true
    resource_guard: false
    audit_high_risk: true
    new_device: false
    sub_or_node_fail: true
    server_quota_or_ban: false
  channels:
    telegram:
      enabled: true
      bot_token: "123456:test_telegram_bot_token"
      chat_id: "-1001234567890"
      api_base_url: "https://tg-proxy.example.com"
    bark:
      enabled: true
      server_url: "https://bark.example.com"
      device_key: "test_bark_device_key"
      group: "RouterAlert"
    feishu:
      enabled: false
      webhook_url: "https://open.feishu.cn/open-apis/bot/v2/hook/test_hook"
      secret: "test_feishu_secret"
    wecom:
      enabled: false
      webhook_url: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=test_wecom_key"
    webhook:
      enabled: true
      url: "https://hooks.example.com/notify"
      header_name: "Authorization"
      header_value: "Bearer test_webhook_token"
safe_commit:
  default_ttl_sec: 240
  protect_tailscale_oom: false
`
		out, err := config.MigrateConfigBytes([]byte(oldYAML), configs.DefaultConfigYAML)
		if err != nil {
			t.Fatalf("MigrateConfigBytes failed: %v", err)
		}
		var got config.Config
		if err := yaml.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal migrated yaml failed: %v", err)
		}

		// Notify + Telegram must survive migration intact
		if !got.Notify.Enabled || got.Notify.CooldownMinutes != 30 || got.Notify.DailyLimit != 80 || got.Notify.QuietHours != "23:00-07:30" {
			t.Fatalf("notify global settings lost: %+v", got.Notify)
		}
		tg := got.Notify.Channels.Telegram
		if !tg.Enabled || tg.BotToken != "123456:test_telegram_bot_token" || tg.ChatID != "-1001234567890" || tg.APIBaseURL != "https://tg-proxy.example.com" {
			t.Fatalf("telegram notify config lost after migration: %+v", tg)
		}
		if !got.Notify.Channels.Bark.Enabled || got.Notify.Channels.Bark.DeviceKey != "test_bark_device_key" {
			t.Fatalf("bark notify config lost: %+v", got.Notify.Channels.Bark)
		}
		if got.Notify.Channels.Webhook.HeaderValue != "Bearer test_webhook_token" {
			t.Fatalf("webhook notify config lost: %+v", got.Notify.Channels.Webhook)
		}
		if got.Notify.Events.ResourceGuard || got.Notify.Events.NewDevice || !got.Notify.Events.WatchdogHeal {
			t.Fatalf("notify explicit events lost: %+v", got.Notify.Events)
		}

		// SafeCommit must survive
		if got.SafeCommit.EffectiveTTLSec() != 240 || got.SafeCommit.IsProtectTailscaleOOM() {
			t.Fatalf("safe_commit lost: %+v", got.SafeCommit)
		}

		// Firewall must survive
		if got.Firewall.BanTimeoutDays != 7 || got.Firewall.PingLimitPerSec != 12 || !slices.Equal(got.Firewall.ProtectedPorts, []int{443, 8443}) {
			t.Fatalf("firewall lost: %+v", got.Firewall)
		}

		// Full DNS dual-engine fields must survive
		if got.DNS.Engine != "smartdns" || got.DNS.UpstreamMode != "parallel" || !got.DNS.BlockAAAA || got.DNS.AdblockDisabledUntil != -1 {
			t.Fatalf("dns dual-engine fields lost: %+v", got.DNS)
		}
		if !slices.Equal(got.DNS.Upstreams, []string{"https://223.5.5.5/dns-query", "tls://1.1.1.1"}) ||
			!slices.Equal(got.DNS.Whitelist, []string{"trusted.example.com"}) ||
			len(got.DNS.Rewrites) != 1 || got.DNS.Rewrites[0].Domain != "nas.example.com" ||
			!slices.Equal(got.DNS.SmartDNSFilters, []string{"https://example.com/ad.conf"}) {
			t.Fatalf("dns list/rewrite fields lost: %+v", got.DNS)
		}

		// Repeated migration converges identically (idempotent)
		out2, err := config.MigrateConfigBytes(out, configs.DefaultConfigYAML)
		if err != nil {
			t.Fatalf("second MigrateConfigBytes failed: %v", err)
		}
		if string(out) != string(out2) {
			t.Fatalf("migration not idempotent with notify/safe_commit/firewall/dns:\npass1:\n%s\npass2:\n%s", string(out), string(out2))
		}
	})

	t.Run("server_also_preserves_notify_safe_commit_and_firewall", func(t *testing.T) {
		oldServer := `server:
  node_domain: "node.example.com"
  cf_dns_key: "cf-test-token"
firewall:
  ban_timeout_days: 14
notify:
  enabled: true
  channels:
    telegram:
      enabled: true
      bot_token: "999999:server_test_token"
      chat_id: "100200300"
safe_commit:
  default_ttl_sec: 300
`
		out, err := config.MigrateConfigBytes([]byte(oldServer), configs.DefaultConfigYAML)
		if err != nil {
			t.Fatalf("MigrateConfigBytes server failed: %v", err)
		}
		var got config.Config
		if err := yaml.Unmarshal(out, &got); err != nil {
			t.Fatalf("unmarshal server migrated yaml failed: %v", err)
		}
		if !got.Notify.Enabled || got.Notify.Channels.Telegram.BotToken != "999999:server_test_token" {
			t.Fatalf("server notify lost: %+v", got.Notify)
		}
		if got.Firewall.BanTimeoutDays != 14 || got.SafeCommit.EffectiveTTLSec() != 300 {
			t.Fatalf("server firewall/safe_commit lost: fw=%+v sc=%+v", got.Firewall, got.SafeCommit)
		}
	})

	t.Run("all_config_top_level_yaml_keys_survive_migration_guard", func(t *testing.T) {
		// Reflection guard: every top-level YAML key on config.Config must be present in a populated migration output.
		fullYAML := `low_memory: "on"
subs:
  - name: "main"
    url: "https://sub.example.com/client"
github:
  mirror_url: "https://mirror.example.com"
hy2:
  up: 50
  down: 300
dns:
  enabled: true
  engine: "smartdns"
gateway:
  mode: "side"
  main_router_ip: "192.168.1.1"
tailscale:
  auth_key: "test-ts-key"
watchdog:
  interval: 90
firewall:
  ban_timeout_days: 5
audit:
  whitelist:
    - "safe.example.com"
custom_rules:
  block:
    - target: "ads.example.com"
traffic_routing:
  presets:
    openai:
      enabled: true
      outbound: "#VPS"
home_domain:
  suffix: "home"
  devices:
    - alias: "nas"
      ip: "192.0.2.10"
notify:
  enabled: true
  channels:
    telegram:
      enabled: true
      bot_token: "111:guard_token"
      chat_id: "222"
safe_commit:
  default_ttl_sec: 120
`
		out, err := config.MigrateConfigBytes([]byte(fullYAML), configs.ClientConfigYAML)
		if err != nil {
			t.Fatalf("MigrateConfigBytes full client failed: %v", err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(out, &doc); err != nil {
			t.Fatalf("unmarshal doc failed: %v", err)
		}
		cfgType := reflect.TypeFor[config.Config]()
		for i := range cfgType.NumField() {
			field := cfgType.Field(i)
			tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" || tag == "server" {
				continue
			}
			if _, ok := doc[tag]; !ok {
				t.Errorf("top-level Config field %s (yaml:%q) was dropped by MigrateConfigBytes!", field.Name, tag)
			}
		}
	})
}

func TestWatchdogAutoStartConfig(t *testing.T) {
	t.Run("default_enabled_and_clone_isolation", func(t *testing.T) {
		var zeroCfg config.Config
		if zeroCfg.Watchdog.AutoStart != nil {
			t.Fatalf("expected zero AutoStart to be nil, got %v", *zeroCfg.Watchdog.AutoStart)
		}
		if !zeroCfg.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected zero Watchdog.IsAutoStartEnabled() == true by default")
		}

		zeroCfg.Watchdog.SetAutoStart(false)
		if zeroCfg.Watchdog.AutoStart == nil || zeroCfg.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected SetAutoStart(false) to disable AutoStart")
		}

		cloned := zeroCfg.Clone()
		cloned.Watchdog.SetAutoStart(true)
		if zeroCfg.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected Clone() to isolate Watchdog.AutoStart pointer from original")
		}
		if !cloned.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected cloned AutoStart to be true")
		}
	})

	t.Run("load_and_migrate_preserves_explicit_false_and_true", func(t *testing.T) {
		for _, want := range []bool{false, true} {
			raw := "subs:\n  - name: \"main\"\n    url: \"https://sub.example.com/1\"\nwatchdog:\n  interval: 180\n  auto_start: false\n"
			if want {
				raw = "subs:\n  - name: \"main\"\n    url: \"https://sub.example.com/1\"\nwatchdog:\n  interval: 180\n  auto_start: true\n"
			}
			migrated, err := config.MigrateConfigBytes([]byte(raw), configs.ClientConfigYAML)
			if err != nil {
				t.Fatalf("MigrateConfigBytes(want=%v) failed: %v", want, err)
			}
			var got config.Config
			if err := yaml.Unmarshal(migrated, &got); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got.Watchdog.AutoStart == nil || got.Watchdog.IsAutoStartEnabled() != want {
				t.Fatalf("migrated Watchdog.AutoStart mismatch: got ptr=%v val=%v, want %v",
					got.Watchdog.AutoStart, got.Watchdog.IsAutoStartEnabled(), want)
			}
		}
	})

	t.Run("ast_save_round_trip_toggle_with_0600_mode", func(t *testing.T) {
		cfgPath := filepath.Join(t.TempDir(), "singctl.yaml")
		if err := os.WriteFile(cfgPath, configs.ClientConfigYAML, 0600); err != nil {
			t.Fatal(err)
		}

		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("initial Load failed: %v", err)
		}
		if !cfg.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected initial template config to default IsAutoStartEnabled() == true")
		}

		cfg.Watchdog.SetAutoStart(false)
		if err := config.Save(cfgPath, cfg); err != nil {
			t.Fatalf("Save(false) failed: %v", err)
		}
		fi, err := os.Stat(cfgPath)
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions, got %v (err=%v)", fi.Mode().Perm(), err)
		}
		reloaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("Load after Save(false) failed: %v", err)
		}
		if reloaded.Watchdog.AutoStart == nil || reloaded.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected reloaded AutoStart == false, got ptr=%v", reloaded.Watchdog.AutoStart)
		}

		reloaded.Watchdog.SetAutoStart(true)
		if err := config.Save(cfgPath, reloaded); err != nil {
			t.Fatalf("Save(true) failed: %v", err)
		}
		reloaded2, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("Load after Save(true) failed: %v", err)
		}
		if reloaded2.Watchdog.AutoStart == nil || !reloaded2.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected reloaded2 AutoStart == true, got ptr=%v", reloaded2.Watchdog.AutoStart)
		}

		reloaded2.Watchdog.AutoStart = nil
		if err := config.Save(cfgPath, reloaded2); err != nil {
			t.Fatalf("Save(nil) failed: %v", err)
		}
		reloaded3, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("Load after Save(nil) failed: %v", err)
		}
		if reloaded3.Watchdog.AutoStart != nil || !reloaded3.Watchdog.IsAutoStartEnabled() {
			t.Fatalf("expected reloaded3 AutoStart nil & default true, got ptr=%v", reloaded3.Watchdog.AutoStart)
		}
	})
}
