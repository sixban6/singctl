package config

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Subs   []Subscription `yaml:"subs"`
	GitHub GitHubConfig   `yaml:"github"`
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
	WebAdmin           WebAdminConfig    `yaml:"web_admin,omitempty"`
}

type WebAdminConfig struct {
	Enabled            bool   `yaml:"enabled"`
	Port               int    `yaml:"port,omitempty"`                 // 默认 8092
	Path               string `yaml:"path,omitempty"`                 // 随机隐藏路径，如 /sr/<24位>
	Username           string `yaml:"username,omitempty"`             // 管理员账号，默认 singctl
	Password           string `yaml:"password,omitempty"`             // 随机生成的强管理密码
	PasswordPendingAck bool   `yaml:"password_pending_ack"`           // 安装生成的密码尚未在面板确认保存
}

func (s *ServerConfig) GetWebAdminPort() int {
	if s.WebAdmin.Port > 0 {
		return s.WebAdmin.Port
	}
	return 8092
}

func (s *ServerConfig) GetWebAdminPath() string {
	p := strings.TrimSpace(s.WebAdmin.Path)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}

func (s *ServerConfig) GetWebAdminUsername() string {
	if strings.TrimSpace(s.WebAdmin.Username) != "" {
		return strings.TrimSpace(s.WebAdmin.Username)
	}
	return "singctl"
}

func (s *ServerConfig) GetWebAdminPassword() string {
	return strings.TrimSpace(s.WebAdmin.Password)
}

// IsHashedPassword 判断密码字段是否已经采用 bcrypt 哈希存储
func IsHashedPassword(secret string) bool {
	trimmed := strings.TrimSpace(secret)
	return strings.HasPrefix(trimmed, "$2a$") ||
		strings.HasPrefix(trimmed, "$2b$") ||
		strings.HasPrefix(trimmed, "$2y$")
}

// HashPassword 使用 bcrypt 对明文密码进行单向哈希；若已是哈希值则原样返回。
func HashPassword(plain string) (string, error) {
	trimmed := strings.TrimSpace(plain)
	if trimmed == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if IsHashedPassword(trimmed) {
		return trimmed, nil
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(trimmed), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hashed), nil
}

// VerifyPassword 同时兼容校验 bcrypt 哈希密码与初始明文密码（常量时间比对）。
func VerifyPassword(stored, candidate string) bool {
	stored = strings.TrimSpace(stored)
	if stored == "" || candidate == "" {
		return false
	}
	if IsHashedPassword(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(candidate)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(candidate)) == 1
}

// DeriveGatewayToken 基于随机管理路径派生 Caddy -> ServerWeb 内部网关鉴权令牌。
func DeriveGatewayToken(adminPath string) string {
	p := strings.TrimSpace(adminPath)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("singctl-caddy-gateway-v1"))
	_, _ = mac.Write([]byte(p))
	return hex.EncodeToString(mac.Sum(nil))
}

// GenerateAdminToken 生成 16 位包含数字、大写字母与小写字母的高熵安全 Token
func GenerateAdminToken(length int) string {
	if length < 16 {
		length = 16
	}
	const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const lower = "abcdefghijklmnopqrstuvwxyz"
	const digits = "0123456789"
	const all = upper + lower + digits

	buf := make([]byte, length)
	buf[0] = upper[cryptoRandInt(len(upper))]
	buf[1] = lower[cryptoRandInt(len(lower))]
	buf[2] = digits[cryptoRandInt(len(digits))]

	for i := 3; i < length; i++ {
		buf[i] = all[cryptoRandInt(len(all))]
	}
	for i := length - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

// GenerateRandomAdminPath 生成 /sr/ 加上 24 位包含大小写字母和数字的高熵路径，例如 /sr/3aB9kLmN2pQrSt8XWk9Lp2Zx
func GenerateRandomAdminPath() string {
	return "/sr/" + GenerateAdminToken(24)
}

// GenerateSecurePassword 生成包含大写字母、小写字母和数字的随机密码。length 小于 8 时按 8 位生成。
func GenerateSecurePassword(length int) string {
	if length < 8 {
		length = 8
	}
	const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const lower = "abcdefghijkmnopqrstuvwxyz"
	const digits = "23456789"
	const all = upper + lower + digits

	buf := make([]byte, length)
	buf[0] = upper[cryptoRandInt(len(upper))]
	buf[1] = lower[cryptoRandInt(len(lower))]
	buf[2] = digits[cryptoRandInt(len(digits))]

	for i := 3; i < length; i++ {
		buf[i] = all[cryptoRandInt(len(all))]
	}
	for i := length - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	b := make([]byte, 1)
	for {
		_, _ = rand.Read(b)
		val := int(b[0])
		if val < 256-(256%n) {
			return val % n
		}
	}
}

// EnsureWebAdminCredentials 确保 Web 管理面板拥有随机安全路径、用户名与强随机密码
func (s *ServerConfig) EnsureWebAdminCredentials() bool {
	changed := false
	if s.WebAdmin.Port <= 0 {
		s.WebAdmin.Port = 8092
		changed = true
	}
	// 如果为空、包含过时的 admin 标识、缺少 /sr/ 前缀或随机长度不足 16 位，则升级生成全新 /sr/<16位> 路径
	trimmedPath := strings.TrimSpace(s.WebAdmin.Path)
	cleanPath := strings.Trim(trimmedPath, "/")
	parts := strings.Split(cleanPath, "/")
	if trimmedPath == "" || strings.Contains(trimmedPath, "admin") || len(parts) != 2 || parts[0] != "sr" || len(parts[1]) < 16 {
		s.WebAdmin.Path = GenerateRandomAdminPath()
		changed = true
	}
	// 如果为空或者为旧默认 admin，则换为非 admin 用户名
	if strings.TrimSpace(s.WebAdmin.Username) == "" || strings.TrimSpace(s.WebAdmin.Username) == "admin" {
		s.WebAdmin.Username = "singctl"
		changed = true
	}
	// 如果密码为空，生成 16 位混合大小写和数字的随机密码，并要求首次登录后确认已保存
	if strings.TrimSpace(s.WebAdmin.Password) == "" {
		s.WebAdmin.Password = GenerateSecurePassword(16)
		s.WebAdmin.PasswordPendingAck = true
		changed = true
	}
	if !s.WebAdmin.Enabled {
		s.WebAdmin.Enabled = true
		changed = true
	}
	return changed
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

var knownYAMLKeys = []string{
	"subs", "name", "url", "skip_tls_verify", "remove-emoji",
	"github", "mirror_url", "hy2", "up", "down",
	"tailscale", "auth_key", "use_build", constant.TailscaleSubnets,
	"server", "node_tag", "sb_domain", "node_domain", "substore_domain", "server_ip",
	"cf_dns_key", "sni", "cors_allowed_origins",
	"web_terminal", "mtls_ca", "ssh_tunnel_port", "ssh_tunnel_path", "ssh_port",
	"web_admin", "enabled", "port", "path", "username", "password", "password_pending_ack",
	"watchdog", "interval", "confirm_wait", "max_restarts",
	"custom_rules", "route", "dns",
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
	cleanOldData := colonSpaceFixRegex.ReplaceAll(oldData, []byte("$1: $2"))

	var oldCfg Config
	if err := yaml.Unmarshal(cleanOldData, &oldCfg); err != nil {
		return fmt.Errorf("failed to parse old config: %w", err)
	}

	var oldRootNode yaml.Node
	if err := yaml.Unmarshal(cleanOldData, &oldRootNode); err != nil {
		return fmt.Errorf("failed to parse old config AST: %w", err)
	}
	var oldDocNode *yaml.Node
	if len(oldRootNode.Content) > 0 && oldRootNode.Content[0].Kind == yaml.MappingNode {
		oldDocNode = oldRootNode.Content[0]
	}

	hasYAMLKey := func(mapNode *yaml.Node, key string) bool {
		if mapNode == nil || mapNode.Kind != yaml.MappingNode {
			return false
		}
		for i := 0; i+1 < len(mapNode.Content); i += 2 {
			if mapNode.Content[i].Value == key {
				return true
			}
		}
		return false
	}

	getYAMLSubMap := func(mapNode *yaml.Node, key string) *yaml.Node {
		if mapNode == nil || mapNode.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(mapNode.Content); i += 2 {
			if mapNode.Content[i].Value == key && mapNode.Content[i+1].Kind == yaml.MappingNode {
				return mapNode.Content[i+1]
			}
		}
		return nil
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(templateData, &rootNode); err != nil {
		return fmt.Errorf("failed to parse template AST: %w", err)
	}

	if len(rootNode.Content) == 0 {
		return fmt.Errorf("template AST is empty")
	}

	docNode := rootNode.Content[0]

	// Helper to replace or append an entire top-level node (like 'subs' array or 'custom_rules')
	replaceNode := func(parent *yaml.Node, key string, val any) {
		var newNode yaml.Node
		b, err := yaml.Marshal(val)
		if err != nil {
			return
		}
		if err := yaml.Unmarshal(b, &newNode); err != nil || len(newNode.Content) == 0 {
			return
		}
		newNodeChild := newNode.Content[0]

		for i := 0; i+1 < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				originalNode := parent.Content[i+1]
				newNodeChild.HeadComment = originalNode.HeadComment
				newNodeChild.LineComment = originalNode.LineComment
				newNodeChild.FootComment = originalNode.FootComment

				if originalNode.Kind == yaml.ScalarNode && newNodeChild.Kind == yaml.ScalarNode {
					originalNode.Value = newNodeChild.Value
				} else {
					parent.Content[i+1] = newNodeChild
				}
				return
			}
		}

		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
		parent.Content = append(parent.Content, keyNode, newNodeChild)
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

	// Helper to set or add an entire mapping node under a specific map
	setOrAddMapping := func(parent *yaml.Node, parentKey, childKey string, val interface{}) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == parentKey {
				mapNode := parent.Content[i+1]
				if mapNode.Kind != yaml.MappingNode {
					return
				}
				var newNode yaml.Node
				b, _ := yaml.Marshal(val)
				_ = yaml.Unmarshal(b, &newNode)
				if len(newNode.Content) == 0 {
					return
				}
				childNode := newNode.Content[0]
				for j := 0; j < len(mapNode.Content); j += 2 {
					if mapNode.Content[j].Value == childKey {
						mapNode.Content[j+1] = childNode
						return
					}
				}
				keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: childKey}
				mapNode.Content = append(mapNode.Content, keyNode, childNode)
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
	if oldGitHub := getYAMLSubMap(oldDocNode, "github"); hasYAMLKey(oldGitHub, "mirror_url") {
		setOrAddField(docNode, "github", "mirror_url", oldCfg.GitHub.MirrorURL)
	}

	// 3. Merge Hy2
	if oldHy2 := getYAMLSubMap(oldDocNode, "hy2"); oldHy2 != nil {
		if hasYAMLKey(oldHy2, "up") {
			setOrAddField(docNode, "hy2", "up", strconv.Itoa(oldCfg.Hy2.Up))
		}
		if hasYAMLKey(oldHy2, "down") {
			setOrAddField(docNode, "hy2", "down", strconv.Itoa(oldCfg.Hy2.Down))
		}
	}

	// 4. Merge Tailscale
	if oldTS := getYAMLSubMap(oldDocNode, "tailscale"); oldTS != nil {
		if hasYAMLKey(oldTS, "auth_key") {
			setOrAddField(docNode, "tailscale", "auth_key", oldCfg.Tailscale.AuthKey)
		}
		if hasYAMLKey(oldTS, "subnets") {
			setOrAddField(docNode, "tailscale", "subnets", oldCfg.Tailscale.Subnets)
		}
		if hasYAMLKey(oldTS, "use_build") {
			setOrAddField(docNode, "tailscale", "use_build", strconv.FormatBool(oldCfg.Tailscale.UseBuild))
		}
	}

	// 5. Merge Server (全量保留所有字段，包括 node_domain, substore_domain, web_terminal, web_admin 等)
	if oldServer := getYAMLSubMap(oldDocNode, "server"); oldServer != nil {
		if oldCfg.Server.NodeTag != "" {
			setOrAddField(docNode, "server", "node_tag", oldCfg.Server.NodeTag)
		} else if hasYAMLKey(oldServer, "node_tag") {
			setOrAddField(docNode, "server", "node_tag", "")
		}

		// 平滑迁移：如果旧配置只有 sb_domain，则将其迁移到 node_domain
		nodeDomain := oldCfg.Server.NodeDomain
		if nodeDomain == "" && oldCfg.Server.SBDomain != "" {
			nodeDomain = oldCfg.Server.SBDomain
		}
		if nodeDomain != "" {
			setOrAddField(docNode, "server", "node_domain", nodeDomain)
		} else if hasYAMLKey(oldServer, "node_domain") {
			setOrAddField(docNode, "server", "node_domain", "")
		}

		if oldCfg.Server.SubstoreDomain != "" {
			setOrAddField(docNode, "server", "substore_domain", oldCfg.Server.SubstoreDomain)
		} else if hasYAMLKey(oldServer, "substore_domain") {
			setOrAddField(docNode, "server", "substore_domain", "")
		}

		removeField(docNode, "server", "tuic_domain")
		removeField(docNode, "server", "tuic_port")
		removeField(docNode, "server", "anytls_port")

		if oldCfg.Server.ServerIP != "" {
			setOrAddField(docNode, "server", "server_ip", oldCfg.Server.ServerIP)
		} else if hasYAMLKey(oldServer, "server_ip") {
			setOrAddField(docNode, "server", "server_ip", "")
		}

		if oldCfg.Server.CFDNSKey != "" {
			setOrAddField(docNode, "server", "cf_dns_key", oldCfg.Server.CFDNSKey)
		} else if hasYAMLKey(oldServer, "cf_dns_key") {
			setOrAddField(docNode, "server", "cf_dns_key", "")
		}

		if hasYAMLKey(oldServer, "sni") {
			setOrAddField(docNode, "server", "sni", oldCfg.Server.Sni)
		}
		if hasYAMLKey(oldServer, "cors_allowed_origins") {
			setOrAddField(docNode, "server", "cors_allowed_origins", oldCfg.Server.CorsAllowedOrigins)
		}

		// 处理旧版兼容字段 sb_domain：若旧配置包含则保留，否则从模板中移除，绝不注入虚假默认域名
		if hasYAMLKey(oldServer, "sb_domain") {
			setOrAddField(docNode, "server", "sb_domain", oldCfg.Server.SBDomain)
		} else {
			removeField(docNode, "server", "sb_domain")
		}

		if hasYAMLKey(oldServer, "web_terminal") {
			setOrAddMapping(docNode, "server", "web_terminal", oldCfg.Server.WebTerminal)
		}

		if hasYAMLKey(oldServer, "web_admin") && (oldCfg.Server.WebAdmin.Path != "" || oldCfg.Server.WebAdmin.Enabled || oldCfg.Server.WebAdmin.Password != "") {
			setOrAddMapping(docNode, "server", "web_admin", oldCfg.Server.WebAdmin)
		}
	}

	// 6. Merge Watchdog
	if oldWD := getYAMLSubMap(oldDocNode, "watchdog"); oldWD != nil {
		if hasYAMLKey(oldWD, "interval") {
			setOrAddField(docNode, "watchdog", "interval", strconv.Itoa(oldCfg.Watchdog.Interval))
		}
		if hasYAMLKey(oldWD, "confirm_wait") {
			setOrAddField(docNode, "watchdog", "confirm_wait", strconv.Itoa(oldCfg.Watchdog.ConfirmWait))
		}
		if hasYAMLKey(oldWD, "max_restarts") {
			setOrAddField(docNode, "watchdog", "max_restarts", strconv.Itoa(oldCfg.Watchdog.MaxRestarts))
		}
	}

	// 7. Merge CustomRules (only when uncommented in old config, never triggered by `# custom_rules:` comments)
	if hasYAMLKey(oldDocNode, "custom_rules") && (len(oldCfg.CustomRules.Route) > 0 || len(oldCfg.CustomRules.DNS) > 0) {
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
// When path already exists and contains a valid YAML mapping document, Save merges
// the updated fields into the existing YAML AST so comments and unreferenced keys are preserved.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if existingData, err := os.ReadFile(path); err == nil && len(existingData) > 0 {
		var oldRoot, newRoot yaml.Node
		if errOld := yaml.Unmarshal(existingData, &oldRoot); errOld == nil {
			if errNew := yaml.Unmarshal(data, &newRoot); errNew == nil {
				if mergeYAMLDocument(&oldRoot, &newRoot) {
					if mergedData, errMarshal := yaml.Marshal(&oldRoot); errMarshal == nil {
						data = mergedData
					}
				}
			}
		}
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err == nil {
		if err := os.Rename(tmpPath, path); err == nil {
			return nil
		}
		_ = os.Remove(tmpPath)
	}
	return os.WriteFile(path, data, 0600)
}

func mergeYAMLDocument(dstRoot, srcRoot *yaml.Node) bool {
	if dstRoot.Kind != yaml.DocumentNode || srcRoot.Kind != yaml.DocumentNode {
		return false
	}
	if len(dstRoot.Content) == 0 || len(srcRoot.Content) == 0 {
		return false
	}
	dstDoc := dstRoot.Content[0]
	srcDoc := srcRoot.Content[0]
	if dstDoc.Kind != yaml.MappingNode || srcDoc.Kind != yaml.MappingNode {
		return false
	}
	mergeYAMLMapping(dstDoc, srcDoc)
	return true
}

func mergeYAMLMapping(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		srcKey := src.Content[i]
		srcVal := src.Content[i+1]

		found := false
		for j := 0; j+1 < len(dst.Content); j += 2 {
			dstKey := dst.Content[j]
			dstVal := dst.Content[j+1]
			if dstKey.Value == srcKey.Value {
				found = true
				if dstVal.Kind == yaml.MappingNode && srcVal.Kind == yaml.MappingNode {
					mergeYAMLMapping(dstVal, srcVal)
				} else {
					head, line, foot := dstVal.HeadComment, dstVal.LineComment, dstVal.FootComment
					*dstVal = *srcVal
					if dstVal.HeadComment == "" {
						dstVal.HeadComment = head
					}
					if dstVal.LineComment == "" {
						dstVal.LineComment = line
					}
					if dstVal.FootComment == "" {
						dstVal.FootComment = foot
					}
				}
				break
			}
		}
		if !found {
			dst.Content = append(dst.Content, srcKey, srcVal)
		}
	}
}

// UpdateHy2Bandwidth updates hy2.up and hy2.down in the given YAML file while preserving comments and structure.
func UpdateHy2Bandwidth(configPath string, up, down int) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}

	var rootNode yaml.Node
	if err := yaml.Unmarshal(data, &rootNode); err != nil {
		return fmt.Errorf("parse yaml AST: %w", err)
	}

	if len(rootNode.Content) == 0 {
		return fmt.Errorf("empty yaml document")
	}

	docNode := rootNode.Content[0]
	if docNode.Kind != yaml.MappingNode {
		return fmt.Errorf("invalid yaml root kind")
	}

	// find hy2 node
	var hy2Map *yaml.Node
	for i := 0; i < len(docNode.Content); i += 2 {
		if docNode.Content[i].Value == "hy2" {
			hy2Map = docNode.Content[i+1]
			break
		}
	}

	if hy2Map == nil {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "hy2"}
		hy2Map = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		docNode.Content = append(docNode.Content, keyNode, hy2Map)
	}

	setScalar := func(m *yaml.Node, key, val string) {
		for j := 0; j < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				m.Content[j+1].Value = val
				m.Content[j+1].Tag = "!!int"
				return
			}
		}
		k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
		v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: val}
		m.Content = append(m.Content, k, v)
	}

	setScalar(hy2Map, "up", strconv.Itoa(up))
	setScalar(hy2Map, "down", strconv.Itoa(down))

	newData, err := yaml.Marshal(&rootNode)
	if err != nil {
		return fmt.Errorf("marshal updated AST: %w", err)
	}

	tempPath := configPath + ".tmp"
	if err := os.WriteFile(tempPath, newData, 0600); err != nil {
		return fmt.Errorf("write tmp config: %w", err)
	}
	return os.Rename(tempPath, configPath)
}
