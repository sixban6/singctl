// 文件职责：定义核心 Config 聚合根结构、配置加载（Load）、基础校验（ValidateSubs / ValidateCustomRules）、已知键注册表及版本迁移入口（MigrateConfig）。
//
// 架构设计原则：
//   - 领域拆分清晰：客户端域（config_client.go）、服务端域（config_server.go）、凭据原语（credentials.go）、
//     公网探测（public_ip.go）与 AST 无损保存（save_ast.go）各司其职，本文件仅作为轻量化协调门面。
//   - 敏感落盘强制 0600：MigrateConfig 新建或迁移写入均使用临时文件原子替换并强制收紧权限为 0600。
package config

import (
	"cmp"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"singctl/configs"
	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

// TemplateForCommandArgs 根据用户执行的命令行参数识别服务端或客户端角色，返回对应的精简初始化模板。
func TemplateForCommandArgs(args []string) []byte {
	for i := 1; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if arg == "-c" || arg == "--config" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		switch arg {
		case "sr", "server", "reinstall", "cftoken", "terminal", "fleet", "fl":
			return configs.ServerConfigYAML
		default:
			return configs.ClientConfigYAML
		}
	}
	return configs.ClientConfigYAML
}

// HasRealSubs 判断配置中是否包含非空的客户端订阅地址。
func (c *Config) HasRealSubs() bool {
	if c == nil {
		return false
	}
	for _, s := range c.Subs {
		if strings.TrimSpace(s.URL) != "" {
			return true
		}
	}
	return false
}

// HasActiveServerConfig 判断配置中是否包含有效的服务端参数（排除未修改的模板占位值）。
func (c *Config) HasActiveServerConfig() bool {
	if c == nil {
		return false
	}
	s := c.Server
	nd := strings.TrimSpace(s.NodeDomain)
	if nd != "" && nd != "node.example.com" && nd != "node.yourdomain.com" {
		return true
	}
	sbd := strings.TrimSpace(s.SBDomain)
	if sbd != "" && sbd != "sub.yourdomain.com" && sbd != "node.example.com" && sbd != "node.yourdomain.com" {
		return true
	}
	cfKey := strings.TrimSpace(s.CFDNSKey)
	if cfKey != "" && cfKey != "your_cloudflare_api_token" {
		return true
	}
	return strings.TrimSpace(s.SubstoreDomain) != "" ||
		strings.TrimSpace(s.ServerIP) != "" ||
		strings.TrimSpace(s.NodeTag) != "" ||
		s.Hy2Port > 0 ||
		s.VlessPort > 0 ||
		s.WebAdmin.Enabled ||
		strings.TrimSpace(s.WebAdmin.Path) != "" ||
		strings.TrimSpace(s.WebAdmin.Password) != "" ||
		s.WebTerminal.Enabled ||
		strings.TrimSpace(s.WebTerminal.Path) != "" ||
		s.WebTerminal.SSHPort > 0
}

type Config struct {
	sourcePath     string               `yaml:"-" json:"-"`
	LowMemory      LowMemoryMode        `yaml:"low_memory,omitempty" json:"low_memory,omitempty"`
	Subs           []Subscription       `yaml:"subs"`
	GitHub         GitHubConfig         `yaml:"github"`
	Hy2            Hy2Config            `yaml:"hy2"`
	DNS            ClientDNSConfig      `yaml:"dns,omitempty"`
	Gateway        GatewayConfig        `yaml:"gateway,omitempty" json:"gateway,omitzero"`
	Tailscale      TailscaleConfig      `yaml:"tailscale"`
	Server         ServerConfig         `yaml:"server"`
	Watchdog       WatchdogConfig       `yaml:"watchdog"`
	Firewall       FirewallConfig       `yaml:"firewall,omitempty" json:"firewall,omitzero"`
	Audit          AuditConfig          `yaml:"audit,omitempty" json:"audit,omitzero"`
	CustomRules    CustomRulesConfig    `yaml:"custom_rules,omitempty"`
	TrafficRouting TrafficRoutingConfig `yaml:"traffic_routing,omitempty" json:"traffic_routing,omitzero"`
	Notify         NotifyConfig         `yaml:"notify,omitempty" json:"notify,omitzero"`
	SafeCommit     SafeCommitConfig     `yaml:"safe_commit,omitempty" json:"safe_commit,omitzero"`
}

func parseIntAny(v any) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int64:
		return int(val), nil
	case float64:
		return int(val), nil
	case string:
		trimmed := strings.TrimSpace(val)
		if trimmed == "" {
			return 0, nil
		}
		return strconv.Atoi(trimmed)
	default:
		return 0, fmt.Errorf("unsupported type %T for integer conversion", v)
	}
}

func parseInt64Any(v any) (int64, error) {
	switch val := v.(type) {
	case int:
		return int64(val), nil
	case int64:
		return val, nil
	case uint64:
		return int64(val), nil
	case float64:
		return int64(val), nil
	case string:
		trimmed := strings.TrimSpace(val)
		if trimmed == "" {
			return 0, nil
		}
		return strconv.ParseInt(trimmed, 10, 64)
	default:
		return 0, fmt.Errorf("unsupported type %T for int64 conversion", v)
	}
}

func cleanStringSlice(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

var knownYAMLKeys = []string{
	"low_memory",
	"subs", "name", "url", "skip_tls_verify", "remove-emoji",
	"include", "exclude", "rename", "match", "replace",
	"github", "mirror_url", "hy2", "up", "down",
	"tailscale", "auth_key", "use_build", constant.TailscaleSubnets,
	"p2p_assist", "jit_window_sec", "cooldown_sec", "payload_filter", "sandbox_ujail", "listen_port", "peers", "id", "tailscale_ip", "jit_enabled", "access_mode", "bidirectional_until", "allowed_lan_targets",
	"server", "node_tag", "sb_domain", "node_domain", "hy2_port", "vless_port", "substore_domain", "server_ip",
	"cf_dns_key", "sni", "cors_allowed_origins",
	"web_terminal", "mtls_ca", "ssh_tunnel_port", "ssh_tunnel_path", "ssh_port",
	"web_admin", "enabled", "port", "path", "username", "password", "password_pending_ack",
	"warp_routing", "mode", "presets", "warp_domains", "warp_cidrs", "direct_domains", "direct_cidrs",
	"watchdog", "interval", "confirm_wait", "max_restarts", "sub_sync_interval", "preserve_manual_config",
	"failover", "groups", "patrol_interval", "probe_timeout_ms", "confirm_retries", "failback_cooldown", "max_failback_delay_ms", "probe_urls",
	"custom_rules", "block", "target", "source_ip", "reason", "ruleset_url", "rule_count", "preview", "created_at",
	"outbounds", "tag", "default", "tolerance", "interrupt_exist_connections",
	"route", "dns", "dns_port", "web_port", "engine", "upstreams", "upstream_mode", "rewrites", "domain", "answer", "block_aaaa", "adblock_disabled_until", "disabled_ad_rule_sets", "smartdns_filters",
	"gateway", "main_router_ip", "lan_iface", "ipv6_mode",
	"audit", "whitelist", "pcdn_block", "throttles", "rate_kbps", "comment", "ai", "endpoint", "api_key", "model",
	"firewall", "ban_timeout_days", "ping_limit_per_sec", "extra_forever_ban", "protected_ports",
	"traffic_routing", "outbound",
	"notify", "cooldown_minutes", "daily_limit", "quiet_hours", "events",
	"watchdog_heal", "safe_commit_rollback", "resource_guard", "audit_high_risk", "new_device", "sub_or_node_fail", "server_quota_or_ban",
	"channels", "telegram", "bot_token", "chat_id", "api_base_url",
	"bark", "server_url", "device_key", "group",
	"feishu", "webhook_url", "secret",
	"wecom", "webhook", "header_name", "header_value",
	"safe_commit", "default_ttl_sec", "protect_tailscale_oom",
}

var colonSpaceFixRegex = regexp.MustCompile(
	fmt.Sprintf("(?m)^([ \\t-]*(?:%s)):([^\\s].*)", strings.Join(knownYAMLKeys, "|")),
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Pre-process the YAML to fix common syntax errors such as missing spaces after colons.
	// For example: `url:"https://test.com"` -> `url: "https://test.com"`
	// We only match known keys to avoid accidentally modifying strings containing colons.
	data = colonSpaceFixRegex.ReplaceAll(data, []byte("$1: $2"))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.GitHub.MirrorURL = cmp.Or(cfg.GitHub.MirrorURL, "https://gh-proxy.com")
	if cfg.Hy2.Up == 0 {
		cfg.Hy2.Up = 21
	}
	if cfg.Hy2.Down == 0 {
		cfg.Hy2.Down = 200
	}
	if cfg.Server.Sni == "" {
		cfg.Server.Sni = "swdist.apple.com"
	}
	if cfg.Server.NodeDomain == "" && cfg.Server.SBDomain != "" {
		cfg.Server.NodeDomain = cfg.Server.SBDomain
	}
	if cfg.Server.SubstoreDomain == "" && cfg.Server.SBDomain != "" {
		cfg.Server.SubstoreDomain = cfg.Server.SBDomain
	}
	if cfg.Watchdog.Interval <= 0 {
		cfg.Watchdog.Interval = 180
	}
	if cfg.Watchdog.ConfirmWait <= 0 {
		cfg.Watchdog.ConfirmWait = 30
	}
	if cfg.Watchdog.MaxRestarts <= 0 {
		cfg.Watchdog.MaxRestarts = 3
	}
	if cfg.Watchdog.SubSyncInterval == 0 {
		cfg.Watchdog.SubSyncInterval = 600
	}
	cfg.sourcePath = path

	return &cfg, nil
}

func (c *Config) ValidateSubs() error {
	if len(c.Subs) == 0 {
		return fmt.Errorf("no subscriptions configured")
	}

	nameMap := make(map[string]int)

	for i, sub := range c.Subs {
		if sub.URL == "" {
			return fmt.Errorf("subscription[%d]: URL is required", i)
		}

		// 验证Name字段：如果有多个订阅但Name为空，则报错
		if len(c.Subs) > 1 && sub.Name == "" {
			return fmt.Errorf("subscription[%d]: Name is required when using multiple subscriptions", i)
		}

		// 验证Name字段：不能重复
		if sub.Name != "" {
			if existingIndex, exists := nameMap[sub.Name]; exists {
				return fmt.Errorf("subscription[%d]: Name '%s' is already used by subscription[%d]", i, sub.Name, existingIndex)
			}
			nameMap[sub.Name] = i
		}

		// 验证节点过滤/重命名正则表达式
		if sub.Include != "" {
			if _, err := regexp.Compile(sub.Include); err != nil {
				return fmt.Errorf("subscription[%d]: invalid include regex %q: %w", i, sub.Include, err)
			}
		}
		if sub.Exclude != "" {
			if _, err := regexp.Compile(sub.Exclude); err != nil {
				return fmt.Errorf("subscription[%d]: invalid exclude regex %q: %w", i, sub.Exclude, err)
			}
		}
		for j, rr := range sub.Rename {
			if rr.Match != "" {
				if _, err := regexp.Compile(rr.Match); err != nil {
					return fmt.Errorf("subscription[%d].rename[%d]: invalid match regex %q: %w", i, j, rr.Match, err)
				}
			}
		}
	}

	return c.ValidateCustomRules()
}

// ValidateCustomRules 校验 custom_rules.outbounds 中的出站组标签与过滤正则表达式。
func (c *Config) ValidateCustomRules() error {
	if c == nil {
		return nil
	}
	for i, ob := range c.CustomRules.Outbounds {
		if strings.TrimSpace(ob.Tag) == "" {
			return fmt.Errorf("custom_rules.outbounds[%d]: tag is required", i)
		}
		if ob.Include != "" {
			if _, err := regexp.Compile(ob.Include); err != nil {
				return fmt.Errorf("custom_rules.outbounds[%d] (%s): invalid include regex %q: %w", i, ob.Tag, ob.Include, err)
			}
		}
		if ob.Exclude != "" {
			if _, err := regexp.Compile(ob.Exclude); err != nil {
				return fmt.Errorf("custom_rules.outbounds[%d] (%s): invalid exclude regex %q: %w", i, ob.Tag, ob.Exclude, err)
			}
		}
	}
	return nil
}

// MigrateConfig reads the existing config file and merges it into the baseline template using YAML AST.
// It preserves structure, `#` comments from the template, and intentional user zero-values.
func MigrateConfig(configPath string, templateData []byte) error {
	oldData, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// If no old config, simply write the template
			// 0600：含 tailscale auth_key / cloudflare token 等密钥
			if wErr := os.WriteFile(configPath, templateData, 0600); wErr != nil {
				return wErr
			}
			_ = os.Chmod(configPath, 0600)
			return nil
		}
		return fmt.Errorf("failed to read old config: %w", err)
	}

	newData, err := MigrateConfigBytes(oldData, templateData)
	if err != nil {
		return err
	}

	// If identical to old string, exit early to avoid noisy writes
	if string(oldData) == string(newData) {
		_ = os.Chmod(configPath, 0600)
		return nil
	}

	// Create backup
	backupPath := configPath + ".bak"
	_ = os.WriteFile(backupPath, oldData, 0600)
	_ = os.Chmod(backupPath, 0600)

	// Write Atomically with explicit 0600 mode regardless of process umask
	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write tmp config: %w", err)
	}
	_ = os.Chmod(tempPath, 0600)

	if err := os.Rename(tempPath, configPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("failed to rename tmp config to target: %w", err)
	}

	return nil
}
