package config

import (
	"cmp"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Subs        []Subscription    `yaml:"subs"`
	GitHub      GitHubConfig      `yaml:"github"`
	//GUI       GUIConfig       `yaml:"gui"`
	Hy2         Hy2Config         `yaml:"hy2"`
	Tailscale   TailscaleConfig   `yaml:"tailscale"`
	Server      ServerConfig      `yaml:"server"`
	Watchdog    WatchdogConfig    `yaml:"watchdog"`
	CustomRules CustomRulesConfig `yaml:"custom_rules,omitempty"`
}

type CustomRulesConfig struct {
	Route []map[string]any `yaml:"route,omitempty"`
	DNS   []map[string]any `yaml:"dns,omitempty"`
}
type Subscription struct {
	Name          string `yaml:"name"`
	URL           string `yaml:"url"`
	SkipTlsVerify bool   `yaml:"skip_tls_verify"`
	RemoveEmoji   bool   `yaml:"remove-emoji"`
}

type GitHubConfig struct {
	MirrorURL string `yaml:"mirror_url"`
}
type Hy2Config struct {
	Up   int `yaml:"up"`
	Down int `yaml:"down"`
}

type TailscaleConfig struct {
	AuthKey  string `yaml:"auth_key"`
	UseBuild bool   `yaml:"use_build"`
	Subnets  string `yaml:"subnets"`
}

type ServerConfig struct {
	NodeTag            string            `yaml:"node_tag"`        // (可选) 节点地区/名称标识 (例如: los, sg, hk)，留空自动根据公网 IP 智能识别
	SBDomain           string            `yaml:"sb_domain"`       // 兼容旧配置：默认主域名
	NodeDomain         string            `yaml:"node_domain"`     // 节点主域名 (Hysteria 2 / VLESS 分享链接主机)
	SubstoreDomain     string            `yaml:"substore_domain"` // Sub-Store 专属域名
	ServerIP           string            `yaml:"server_ip"`       // 公网 IP 地址（选填，未填写时自动探测用于申请 Let's Encrypt 原生 IP 证书）
	CFDNSKey           string            `yaml:"cf_dns_key"`
	Sni                string            `yaml:"sni"`
	CorsAllowedOrigins string            `yaml:"cors_allowed_origins"`
	WebTerminal        WebTerminalConfig `yaml:"web_terminal,omitempty"`
}

type WebTerminalConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Port          int    `yaml:"port,omitempty"`            // 默认 18080 (GoTTY)
	Path          string `yaml:"path,omitempty"`            // 隐蔽访问路径，如 /ops-shell-8f9a
	MtlsCA        string `yaml:"mtls_ca,omitempty"`         // CA 证书路径，默认 /etc/caddy/mtls/ca.crt
	Password      string `yaml:"password,omitempty"`        // client.p12 证书导出密码
	SSHTunnelPort int    `yaml:"ssh_tunnel_port,omitempty"` // wstunnel 本地监听端口，默认 18081
	SSHTunnelPath string `yaml:"ssh_tunnel_path,omitempty"` // wstunnel 访问路径，默认 /ssh-ws
	SSHPort       int    `yaml:"ssh_port,omitempty"`        // 目标 SSH 端口 (e.g. 2222)
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

func (w *WebTerminalConfig) UnmarshalYAML(node *yaml.Node) error {
	var a struct {
		Enabled       bool   `yaml:"enabled"`
		Port          any    `yaml:"port"`
		Path          string `yaml:"path"`
		MtlsCA        string `yaml:"mtls_ca"`
		Password      string `yaml:"password"`
		SSHTunnelPort any    `yaml:"ssh_tunnel_port"`
		SSHTunnelPath string `yaml:"ssh_tunnel_path"`
		SSHPort       any    `yaml:"ssh_port"`
	}
	if err := node.Decode(&a); err != nil {
		return err
	}
	w.Enabled = a.Enabled
	w.Path = a.Path
	w.MtlsCA = a.MtlsCA
	w.Password = a.Password
	w.SSHTunnelPath = a.SSHTunnelPath
	if a.Port != nil {
		if p, err := parseIntAny(a.Port); err == nil {
			w.Port = p
		}
	}
	if a.SSHTunnelPort != nil {
		if p, err := parseIntAny(a.SSHTunnelPort); err == nil {
			w.SSHTunnelPort = p
		}
	}
	if a.SSHPort != nil {
		if p, err := parseIntAny(a.SSHPort); err == nil {
			w.SSHPort = p
		}
	}
	return nil
}

func (h *Hy2Config) UnmarshalYAML(node *yaml.Node) error {
	var a struct {
		Up   any `yaml:"up"`
		Down any `yaml:"down"`
	}
	if err := node.Decode(&a); err != nil {
		return err
	}
	if a.Up != nil {
		if v, err := parseIntAny(a.Up); err == nil {
			h.Up = v
		}
	}
	if a.Down != nil {
		if v, err := parseIntAny(a.Down); err == nil {
			h.Down = v
		}
	}
	return nil
}

func (w *WatchdogConfig) UnmarshalYAML(node *yaml.Node) error {
	var a struct {
		Interval    any `yaml:"interval"`
		ConfirmWait any `yaml:"confirm_wait"`
		MaxRestarts any `yaml:"max_restarts"`
	}
	if err := node.Decode(&a); err != nil {
		return err
	}
	if a.Interval != nil {
		if v, err := parseIntAny(a.Interval); err == nil {
			w.Interval = v
		}
	}
	if a.ConfirmWait != nil {
		if v, err := parseIntAny(a.ConfirmWait); err == nil {
			w.ConfirmWait = v
		}
	}
	if a.MaxRestarts != nil {
		if v, err := parseIntAny(a.MaxRestarts); err == nil {
			w.MaxRestarts = v
		}
	}
	return nil
}

var (
	discoveredPublicIP string
	discoverIPOnce     sync.Once
)

// DiscoverPublicIP probes multiple fast IP echo services to determine the public IP.
func DiscoverPublicIP() string {
	discoverIPOnce.Do(func() {
		endpoints := []string{
			"https://api.ipify.org",
			"https://ip.sb",
			"https://icanhazip.com",
			"https://ifconfig.me/ip",
		}
		client := &http.Client{
			Timeout: 2 * time.Second,
		}
		for _, endpoint := range endpoints {
			resp, err := client.Get(endpoint)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				continue
			}
			ip := strings.TrimSpace(string(body))
			if parsed := net.ParseIP(ip); parsed != nil {
				discoveredPublicIP = ip
				return
			}
		}
	})
	return discoveredPublicIP
}

// SetDiscoveredPublicIPForTest allows mocking the discovered IP during tests.
func SetDiscoveredPublicIPForTest(ip string) {
	discoveredPublicIP = ip
	discoverIPOnce.Do(func() {})
}

// ResetDiscoveredPublicIPForTest resets the cached IP for tests.
func ResetDiscoveredPublicIPForTest() {
	discoveredPublicIP = ""
	discoverIPOnce = sync.Once{}
}

// GetServerIP returns the server's public IP address.
// If ServerIP is explicitly set in config, it returns that value.
// Otherwise, it attempts to discover the public IP automatically.
func (s *ServerConfig) GetServerIP() string {
	if s.ServerIP != "" {
		return strings.TrimSpace(s.ServerIP)
	}
	return DiscoverPublicIP()
}

// GetNodeDomain returns the domain for proxy nodes (Hy2 / VLESS).
// Falls back to SBDomain if NodeDomain is not set.
func (s *ServerConfig) GetNodeDomain() string {
	if s.NodeDomain != "" {
		return strings.TrimSpace(s.NodeDomain)
	}
	return strings.TrimSpace(s.SBDomain)
}

// GetSubstoreDomain returns the domain for Sub-Store.
// Falls back to SBDomain if SubstoreDomain is not set.
func (s *ServerConfig) GetSubstoreDomain() string {
	if s.SubstoreDomain != "" {
		return strings.TrimSpace(s.SubstoreDomain)
	}
	return strings.TrimSpace(s.SBDomain)
}

// GetNodeTag returns the location/name tag for server nodes (e.g. "los", "sg").
// If node_tag is explicitly configured, it returns that value.
// Otherwise, it discovers the location from the server's public IP GeoIP.
// If discovery fails, it falls back to the first segment of node_domain or "node".
func (s *ServerConfig) GetNodeTag() string {
	if s != nil && strings.TrimSpace(s.NodeTag) != "" {
		tag := sanitizeTag(s.NodeTag)
		if tag != "" {
			return tag
		}
	}

	if discoveredLocationTag != "" {
		return discoveredLocationTag
	}

	var ip string
	if s != nil {
		ip = s.GetServerIP()
	} else {
		ip = DiscoverPublicIP()
	}
	if ip != "" {
		if tag := DiscoverLocationTag(ip); tag != "" {
			return tag
		}
	}

	if s != nil {
		nodeDomain := s.GetNodeDomain()
		if nodeDomain != "" {
			first, _, _ := strings.Cut(nodeDomain, ".")
			first = sanitizeTag(first)
			if first != "" {
				return first
			}
		}
	}
	return "node"
}

type WatchdogConfig struct {
	Interval    int `yaml:"interval"`     // 检查间隔(秒), 默认 180
	ConfirmWait int `yaml:"confirm_wait"` // 二次确认等待(秒), 默认 30
	MaxRestarts int `yaml:"max_restarts"` // 每小时最大自动重启次数, 默认 3
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	// Pre-process the YAML to fix common syntax errors such as missing spaces after colons.
	// For example: `url:"https://test.com"` -> `url: "https://test.com"`
	// We only match known keys to avoid accidentally modifying strings containing colons.
	keys := []string{
		"subs", "name", "url", "skip_tls_verify", "remove-emoji",
		"github", "mirror_url", "hy2", "up", "down",
		"tailscale", "auth_key", "use_build", constant.TailscaleSubnets,
		"server", "node_tag", "sb_domain", "node_domain", "substore_domain", "cf_dns_key", "sni", "cors_allowed_origins", "web_terminal", "ssh_tunnel_port", "ssh_tunnel_path", "ssh_port",
		"watchdog", "interval", "confirm_wait", "max_restarts",
		"custom_rules", "route", "dns",
	}
	pattern := fmt.Sprintf("(?m)^([ \\t-]*(?:%s)):([^\\s].*)", strings.Join(keys, "|"))
	re := regexp.MustCompile(pattern)
	data = re.ReplaceAll(data, []byte("$1: $2"))

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
			return os.WriteFile(configPath, templateData, 0600)
		}
		return fmt.Errorf("failed to read old config: %w", err)
	}

	// Pre-process the old YAML to fix common syntax errors such as missing spaces after colons.
	// This ensures `oldCfg` populates zero-values properly instead of treating the whole line as a string.
	keys := []string{
		"subs", "name", "url", "skip_tls_verify", "remove-emoji",
		"github", "mirror_url", "hy2", "up", "down",
		"tailscale", "auth_key", "use_build", constant.TailscaleSubnets,
		"server", "node_tag", "sb_domain", "node_domain", "substore_domain", "server_ip", "cf_dns_key", "sni", "cors_allowed_origins", "web_terminal", "ssh_tunnel_port", "ssh_tunnel_path", "ssh_port",
		"watchdog", "interval", "confirm_wait", "max_restarts",
		"custom_rules", "route", "dns",
	}
	pattern := fmt.Sprintf("(?m)^([ \\t-]*(?:%s)):([^\\s].*)", strings.Join(keys, "|"))
	re := regexp.MustCompile(pattern)
	cleanOldData := re.ReplaceAll(oldData, []byte("$1: $2"))

	var oldCfg Config
	if err := yaml.Unmarshal(cleanOldData, &oldCfg); err != nil {
		return fmt.Errorf("failed to parse old config: %w", err)
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(templateData, &rootNode); err != nil {
		return fmt.Errorf("failed to parse template AST: %w", err)
	}

	if len(rootNode.Content) == 0 {
		return fmt.Errorf("template AST is empty")
	}

	docNode := rootNode.Content[0]

	// Helper to replace an entire top-level node (like 'subs' array)
	replaceNode := func(parent *yaml.Node, key string, val interface{}) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				var newNode yaml.Node
				b, _ := yaml.Marshal(val)
				_ = yaml.Unmarshal(b, &newNode)
				if len(newNode.Content) > 0 {
					originalNode := parent.Content[i+1]
					newNodeChild := newNode.Content[0]
					newNodeChild.HeadComment = originalNode.HeadComment
					newNodeChild.LineComment = originalNode.LineComment
					newNodeChild.FootComment = originalNode.FootComment

					if originalNode.Kind == yaml.ScalarNode && newNodeChild.Kind == yaml.ScalarNode {
						originalNode.Value = newNodeChild.Value
					} else {
						parent.Content[i+1] = newNodeChild
					}
				}
				return
			}
		}
	}

	// Helper to set or add a scalar field under a specific map
	setOrAddField := func(parent *yaml.Node, parentKey, childKey, childVal string) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == parentKey {
				mapNode := parent.Content[i+1]
				if mapNode.Kind != yaml.MappingNode {
					return
				}
				for j := 0; j < len(mapNode.Content); j += 2 {
					if mapNode.Content[j].Value == childKey {
						mapNode.Content[j+1].Value = childVal
						if _, err := strconv.Atoi(childVal); err == nil {
							mapNode.Content[j+1].Tag = "!!int"
						} else if childVal == "true" || childVal == "false" {
							mapNode.Content[j+1].Tag = "!!bool"
						}
						return
					}
				}
				// If not found in template, append new scalar node pair!
				tag := "!!str"
				if _, err := strconv.Atoi(childVal); err == nil {
					tag = "!!int"
				} else if childVal == "true" || childVal == "false" {
					tag = "!!bool"
				}
				keyNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: childKey,
				}
				valNode := &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   tag,
					Value: childVal,
				}
				mapNode.Content = append(mapNode.Content, keyNode, valNode)
				return
			}
		}
	}

	// Helper to remove a key-value pair from a map node
	removeField := func(parent *yaml.Node, parentKey, childKey string) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == parentKey {
				mapNode := parent.Content[i+1]
				if mapNode.Kind != yaml.MappingNode {
					return
				}
				for j := 0; j < len(mapNode.Content); j += 2 {
					if mapNode.Content[j].Value == childKey {
						mapNode.Content = append(mapNode.Content[:j], mapNode.Content[j+2:]...)
						return
					}
				}
			}
		}
	}

	// 1. Merge Subs (only if user actually configured something)
	if len(oldCfg.Subs) > 0 {
		hasRealSub := false
		for _, s := range oldCfg.Subs {
			if s.URL != "" || s.Name != "" {
				hasRealSub = true
				break
			}
		}
		if hasRealSub {
			replaceNode(docNode, "subs", oldCfg.Subs)
		}
	}

	// 2. Merge GitHub Mirror URL (Preserve even if it's explicitly empty)
	if strings.Contains(string(oldData), "mirror_url:") {
		setOrAddField(docNode, "github", "mirror_url", oldCfg.GitHub.MirrorURL)
	}

	// 3. Merge Hy2
	if strings.Contains(string(oldData), "hy2:") {
		setOrAddField(docNode, "hy2", "up", fmt.Sprintf("%d", oldCfg.Hy2.Up))
		setOrAddField(docNode, "hy2", "down", fmt.Sprintf("%d", oldCfg.Hy2.Down))
	}

	// 4. Merge Tailscale
	if strings.Contains(string(oldData), "tailscale:") {
		setOrAddField(docNode, "tailscale", "auth_key", oldCfg.Tailscale.AuthKey)
		setOrAddField(docNode, "tailscale", "subnets", oldCfg.Tailscale.Subnets)
		if oldCfg.Tailscale.UseBuild {
			setOrAddField(docNode, "tailscale", "use_build", "true")
		} else {
			setOrAddField(docNode, "tailscale", "use_build", "false")
		}
	}

	// 5. Merge Server (全量保留所有字段，包括 node_domain, substore_domain 等)
	if strings.Contains(string(oldData), "server:") {
		if oldCfg.Server.NodeTag != "" {
			setOrAddField(docNode, "server", "node_tag", oldCfg.Server.NodeTag)
		} else if strings.Contains(string(oldData), "node_tag:") {
			setOrAddField(docNode, "server", "node_tag", "")
		}

		// 平滑迁移：如果旧配置只有 sb_domain，则将其迁移到 node_domain
		nodeDomain := oldCfg.Server.NodeDomain
		if nodeDomain == "" && oldCfg.Server.SBDomain != "" {
			nodeDomain = oldCfg.Server.SBDomain
		}
		if nodeDomain != "" {
			setOrAddField(docNode, "server", "node_domain", nodeDomain)
		} else if strings.Contains(string(oldData), "node_domain:") {
			setOrAddField(docNode, "server", "node_domain", "")
		}

		if oldCfg.Server.SubstoreDomain != "" {
			setOrAddField(docNode, "server", "substore_domain", oldCfg.Server.SubstoreDomain)
		} else if strings.Contains(string(oldData), "substore_domain:") {
			setOrAddField(docNode, "server", "substore_domain", "")
		}

		removeField(docNode, "server", "tuic_domain")
		removeField(docNode, "server", "tuic_port")
		removeField(docNode, "server", "anytls_port")

		if oldCfg.Server.ServerIP != "" {
			setOrAddField(docNode, "server", "server_ip", oldCfg.Server.ServerIP)
		} else if strings.Contains(string(oldData), "server_ip:") {
			setOrAddField(docNode, "server", "server_ip", "")
		}

		if oldCfg.Server.CFDNSKey != "" {
			setOrAddField(docNode, "server", "cf_dns_key", oldCfg.Server.CFDNSKey)
		} else if strings.Contains(string(oldData), "cf_dns_key:") {
			setOrAddField(docNode, "server", "cf_dns_key", "")
		}

		if strings.Contains(string(oldData), "sni:") {
			setOrAddField(docNode, "server", "sni", oldCfg.Server.Sni)
		}
		if strings.Contains(string(oldData), "cors_allowed_origins:") {
			setOrAddField(docNode, "server", "cors_allowed_origins", oldCfg.Server.CorsAllowedOrigins)
		}

		// 处理旧版兼容字段 sb_domain：若旧配置包含则保留，否则从模板中移除，绝不注入虚假默认域名
		if strings.Contains(string(oldData), "sb_domain:") {
			setOrAddField(docNode, "server", "sb_domain", oldCfg.Server.SBDomain)
		} else {
			removeField(docNode, "server", "sb_domain")
		}
	}

	// 6. Merge Watchdog
	if strings.Contains(string(oldData), "watchdog:") {
		setOrAddField(docNode, "watchdog", "interval", fmt.Sprintf("%d", oldCfg.Watchdog.Interval))
		setOrAddField(docNode, "watchdog", "confirm_wait", fmt.Sprintf("%d", oldCfg.Watchdog.ConfirmWait))
		setOrAddField(docNode, "watchdog", "max_restarts", fmt.Sprintf("%d", oldCfg.Watchdog.MaxRestarts))
	}

	// 7. Merge CustomRules
	if strings.Contains(string(oldData), "custom_rules:") {
		replaceNode(docNode, "custom_rules", oldCfg.CustomRules)
	}

	newData, err := yaml.Marshal(&rootNode)
	if err != nil {
		return fmt.Errorf("failed to marshal merged AST: %w", err)
	}

	// If identical to old string, exit early to avoid noisy writes
	if string(oldData) == string(newData) {
		return nil
	}

	// Create backup
	backupPath := configPath + ".bak"
	_ = os.WriteFile(backupPath, oldData, 0600)

	// Write Atomically
	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, newData, 0600); err != nil {
		return fmt.Errorf("failed to write tmp config: %w", err)
	}

	if err := os.Rename(tempPath, configPath); err != nil {
		return fmt.Errorf("failed to rename tmp config to target: %w", err)
	}

	return nil
}

// Save serializes cfg to YAML and writes it to path.
// Note: YAML comments are not preserved by this operation.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
