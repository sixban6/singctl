package adguard

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"singctl/internal/config"
	"singctl/internal/util/netinfo"

	"gopkg.in/yaml.v3"
)

// ConfigParams 定义生成初始 AdGuardHome.yaml 所需的参数。
type ConfigParams struct {
	LANIP        string   // Web 面板绑定的局域网 IPv4（严禁 0.0.0.0）
	WebPort      int      // Web 面板端口，默认 3000
	DNSPort      int      // 本地 DNS 监听端口，默认 5353
	Username     string   // 管理面板登录用户名，默认 root
	PasswordHash string   // bcrypt 哈希密码（非空，以直接跳过首次引导向导）
	IsOpenWrt    bool     // OpenWrt 下默认关闭查询日志落盘以保护闪存
	SubURLs      []string // 订阅链接列表（自动将其域名加入放行白名单，防止误拦截）
}

// SyncOptions 定义对已存在的 AdGuardHome.yaml 进行非破坏性同步的选项。
type SyncOptions struct {
	LANIP        string
	WebPort      int
	DNSPort      int
	Username     string // 非空且 UpdateAuth=true 时同步更新用户名
	PasswordHash string // 非空且 UpdateAuth=true 时同步更新密码哈希
	UpdateAuth   bool
}

// sanitizeWebBindIP 确保 Web 面板绑定的 IP 合法且绝不为 0.0.0.0 / ::。
func sanitizeWebBindIP(ipStr string) string {
	trimmed := strings.TrimSpace(ipStr)
	ip := net.ParseIP(trimmed)
	if ip == nil || ip.IsUnspecified() {
		fallback := netinfo.GetPrimaryLANIPv4()
		if parsed := net.ParseIP(fallback); parsed != nil && !parsed.IsUnspecified() {
			return parsed.String()
		}
		return "127.0.0.1"
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return "127.0.0.1"
}

// extractSubWhitelistRules 提取订阅 URL 中的域名并生成 AdGuard 强放行规则。
func extractSubWhitelistRules(subURLs []string) []string {
	seen := make(map[string]struct{})
	var rules []string
	for _, raw := range subURLs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(strings.TrimSpace(u.Hostname()))
		if host == "" || net.ParseIP(host) != nil || host == "localhost" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		rules = append(rules, fmt.Sprintf("@@||%s^$important", host))
	}
	return rules
}

// BuildInitialConfigYAML 生成可直接跳过首次初始化向导的 AdGuardHome.yaml 内容。
//
// 采用 schema_version: 29（兼容 AdGuard Home v0.107.52 至最新 v0.107.80+，
// 启动时由 AdGuardHome 内置 migrator 无缝升级至当前二进制最新 schema）。
func BuildInitialConfigYAML(p ConfigParams) ([]byte, error) {
	bindIP := sanitizeWebBindIP(p.LANIP)
	webPort := p.WebPort
	if webPort <= 0 || webPort > 65535 {
		webPort = 3000
	}
	dnsPort := p.DNSPort
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}
	username := strings.TrimSpace(p.Username)
	if username == "" {
		username = "root"
	}
	if strings.TrimSpace(p.PasswordHash) == "" || !config.IsHashedPassword(p.PasswordHash) {
		return nil, fmt.Errorf("PasswordHash must be a valid bcrypt hash")
	}

	queryLogFileEnabled := !p.IsOpenWrt
	queryLogInterval := "72h"
	if p.IsOpenWrt {
		queryLogInterval = "24h"
	}

	userRules := extractSubWhitelistRules(p.SubURLs)

	doc := map[string]any{
		"http": map[string]any{
			"address":     net.JoinHostPort(bindIP, strconv.Itoa(webPort)),
			"session_ttl": "720h",
			"pprof": map[string]any{
				"enabled": false,
				"port":    6060,
			},
		},
		"users": []map[string]any{
			{
				"name":     username,
				"password": p.PasswordHash,
			},
		},
		"auth_attempts":  5,
		"block_auth_min": 15,
		"http_proxy":     "",
		"language":       "zh-cn",
		"theme":          "auto",
		"dns": map[string]any{
			"bind_hosts":            []string{"127.0.0.1"},
			"port":                  dnsPort,
			"anonymize_client_ip":   false,
			"ratelimit":             0, // 0=不限速（sing-box 所有请求均来自 127.0.0.1，严禁触发单 IP 限流）
			"ratelimit_whitelist":   []string{},
			"refuse_any":            true,
			"upstream_dns": []string{
				"https://223.5.5.5/dns-query",
				"https://223.6.6.6/dns-query",
				"https://1.12.12.12/dns-query",
				"tls://223.5.5.5",
				"tls://1.12.12.12",
			},
			"upstream_dns_file": "",
			"bootstrap_dns": []string{
				"223.5.5.5",
				"119.29.29.29",
			},
			"fallback_dns": []string{
				"tls://223.6.6.6",
				"tls://120.53.53.53",
			},
			"upstream_mode":      "parallel",
			"fastest_timeout":    "1s",
			"allowed_clients":    []string{},
			"disallowed_clients": []string{},
			"blocked_hosts": []string{
				"version.bind",
				"id.server",
				"hostname.bind",
			},
			"trusted_proxies": []string{
				"127.0.0.0/8",
				"::1/128",
			},
			"cache_size":       4194304,
			"cache_ttl_min":    0,
			"cache_ttl_max":    86400,
			"cache_optimistic": true,
			"bogus_nxdomain":   []string{},
			"aaaa_disabled":    false,
			"enable_dnssec":    false,
			"edns_client_subnet": map[string]any{
				"custom_ip":  "",
				"enabled":    true,
				"use_custom": false,
			},
			"max_goroutines":            300,
			"handle_ddr":                true,
			"ipset":                     []string{},
			"ipset_file":                "",
			"bootstrap_prefer_ipv6":     false,
			"upstream_timeout":          "5s",
			"private_networks":          []string{},
			"use_private_ptr_resolvers": true,
			"local_ptr_upstreams":       []string{},
			"use_dns64":                 false,
			"dns64_prefixes":            []string{},
			"serve_http3":               false,
			"use_http3_upstreams":       false, // 禁用 HTTP/3 DoH，防止 UDP 443 被运营商 QoS 或防火墙拦截
			"serve_plain_dns":           true,
			"hostsfile_enabled":         true,
		},
		"tls": map[string]any{
			"enabled":               false,
			"server_name":           "",
			"force_https":           false,
			"port_https":            0,
			"port_dns_over_tls":     0,
			"port_dns_over_quic":    0,
			"port_dnscrypt":         0,
			"dnscrypt_config_file":  "",
			"allow_unencrypted_doh": false,
			"certificate_chain":     "",
			"private_key":           "",
			"certificate_path":      "",
			"private_key_path":      "",
			"strict_sni_check":      false,
		},
		"querylog": map[string]any{
			"dir_path":     "",
			"ignored":      []string{},
			"interval":     queryLogInterval,
			"size_memory":  1000,
			"enabled":      true,
			"file_enabled": queryLogFileEnabled,
		},
		"statistics": map[string]any{
			"dir_path": "",
			"ignored":  []string{},
			"interval": "24h",
			"enabled":  true,
		},
		"filters": []map[string]any{
			{
				"enabled": true,
				"url":     "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
				"name":    "AdGuard DNS filter",
				"id":      1,
			},
		},
		"whitelist_filters": []any{},
		"user_rules":        userRules,
		"dhcp": map[string]any{
			"enabled":        false,
			"interface_name": "",
			"local_domain_name": "lan",
			"dhcpv4": map[string]any{
				"gateway_ip":     "",
				"subnet_mask":    "",
				"range_start":    "",
				"range_end":      "",
				"lease_duration": 86400,
			},
			"dhcpv6": map[string]any{
				"range_start":    "",
				"lease_duration": 86400,
			},
		},
		"filtering": map[string]any{
			"blocking_ipv4":               "",
			"blocking_ipv6":               "",
			"blocked_services":            map[string]any{"schedule": map[string]any{"time_zone": "Local"}, "ids": []string{}},
			"protection_enabled":          true,
			"filtering_enabled":           true,
			"blocking_mode":               "default",
			"edns_cs_enabled":             false,
			"edns_cs_use_custom":          false,
			"edns_cs_custom_ip":           "",
			"disable_ipv6":                false,
			"dnssec_enabled":              false,
			"parental_enabled":            false,
			"safebrowsing_enabled":        false,
			"rewrites":                    []any{},
			"safe_fs_patterns":            []string{},
			"safebrowsing_cache_size":     1048576,
			"safesearch_cache_size":       1048576,
			"parental_cache_size":         1048576,
			"cache_time":                  30,
			"filters_update_interval":     24,
			"blocked_response_ttl":        10,
			"filtering_goroutines_max":    0,
			"rewrites_enabled":            true,
			"safe_search": map[string]any{
				"enabled":    false,
				"bing":       true,
				"duckduckgo": true,
				"google":     true,
				"pixabay":    true,
				"yandex":     true,
				"youtube":    true,
			},
		},
		"clients": map[string]any{
			"runtime_sources": map[string]any{
				"whois": false,
				"arp":   true,
				"rdns":  false,
				"dhcp":  true,
				"hosts": true,
			},
			"persistent": []any{},
		},
		"log": map[string]any{
			"enabled":     true,
			"file":        "",
			"max_backups": 0,
			"max_size":    20,
			"max_age":     3,
			"compress":    true,
			"local_time":  true,
			"verbose":     false,
		},
		"os": map[string]any{
			"group":         "",
			"user":          "",
			"rlimit_nofile": 0,
		},
		"schema_version": 29,
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal AdGuardHome.yaml: %w", err)
	}
	return out, nil
}

// WriteConfigAtomically 以 0700 目录权限和 0600 文件权限原子写入 AdGuardHome.yaml。
func WriteConfigAtomically(configPath string, data []byte) error {
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)

	tmpPath := configPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	_ = os.Chmod(tmpPath, 0600)
	if err := os.Rename(tmpPath, configPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, configPath, err)
	}
	return os.Chmod(configPath, 0600)
}

// SyncExistingConfig 对已存在的 AdGuardHome.yaml 做最小 AST 更新（同步局域网监听地址、127.0.0.1 DNS 端口及可选账号密码），
// 完整保留用户在面板中添加的过滤规则、重写与 schema_version。
func SyncExistingConfig(configPath string, opts SyncOptions) (bool, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}

	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return false, fmt.Errorf("parse existing AdGuardHome.yaml: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return false, fmt.Errorf("invalid AdGuardHome.yaml root node")
	}
	doc := root.Content[0]
	changed := false

	bindIP := sanitizeWebBindIP(opts.LANIP)
	webPort := opts.WebPort
	if webPort <= 0 || webPort > 65535 {
		webPort = 3000
	}
	wantHTTPAddr := net.JoinHostPort(bindIP, strconv.Itoa(webPort))

	httpMap := ensureYAMLSubMap(doc, "http")
	if setYAMLScalar(httpMap, "address", wantHTTPAddr, "!!str") {
		changed = true
	}

	dnsPort := opts.DNSPort
	if dnsPort <= 0 || dnsPort > 65535 {
		dnsPort = 5353
	}
	dnsMap := ensureYAMLSubMap(doc, "dns")
	if setYAMLScalar(dnsMap, "port", strconv.Itoa(dnsPort), "!!int") {
		changed = true
	}
	if setYAMLScalar(dnsMap, "ratelimit", "0", "!!int") {
		changed = true
	}
	if setYAMLStringSlice(dnsMap, "bind_hosts", []string{"127.0.0.1"}) {
		changed = true
	}

	if opts.UpdateAuth && strings.TrimSpace(opts.Username) != "" && config.IsHashedPassword(opts.PasswordHash) {
		usersSeq := &yaml.Node{
			Kind: yaml.SequenceNode,
			Tag:  "!!seq",
			Content: []*yaml.Node{
				{
					Kind: yaml.MappingNode,
					Tag:  "!!map",
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: strings.TrimSpace(opts.Username)},
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "password"},
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: opts.PasswordHash},
					},
				},
			},
		}
		setYAMLNode(doc, "users", usersSeq)
		changed = true
	}

	if !changed {
		_ = os.Chmod(configPath, 0600)
		return false, nil
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return false, fmt.Errorf("marshal synced AdGuardHome.yaml: %w", err)
	}
	if err := WriteConfigAtomically(configPath, out); err != nil {
		return false, err
	}
	return true, nil
}

// ReadCurrentHTTPAddress 从现有 AdGuardHome.yaml 中读取 http.address 字段。
func ReadCurrentHTTPAddress(configPath string) string {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return ""
	}
	var parsed struct {
		HTTP struct {
			Address string `yaml:"address"`
		} `yaml:"http"`
	}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return ""
	}
	return strings.TrimSpace(parsed.HTTP.Address)
}

func ensureYAMLSubMap(parent *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			if parent.Content[i+1].Kind == yaml.MappingNode {
				return parent.Content[i+1]
			}
			m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			parent.Content[i+1] = m
			return m
		}
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	parent.Content = append(parent.Content, k, m)
	return m
}

func setYAMLScalar(parent *yaml.Node, key, val, tag string) bool {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			if parent.Content[i+1].Kind == yaml.ScalarNode && parent.Content[i+1].Value == val {
				return false
			}
			parent.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: val}
			return true
		}
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: val},
	)
	return true
}

func setYAMLStringSlice(parent *yaml.Node, key string, vals []string) bool {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key && parent.Content[i+1].Kind == yaml.SequenceNode {
			seq := parent.Content[i+1]
			if len(seq.Content) == len(vals) {
				same := true
				for idx, item := range seq.Content {
					if item.Value != vals[idx] {
						same = false
						break
					}
				}
				if same {
					return false
				}
			}
		}
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range vals {
		seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v})
	}
	setYAMLNode(parent, key, seq)
	return true
}

func setYAMLNode(parent *yaml.Node, key string, node *yaml.Node) {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key {
			parent.Content[i+1] = node
			return
		}
	}
	parent.Content = append(parent.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		node,
	)
}
