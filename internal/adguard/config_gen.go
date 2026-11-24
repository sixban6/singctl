// 文件职责：基于内嵌 YAML 基底模板与 yaml.Node AST 补丁生成及无损同步 AdGuardHome.yaml。
package adguard

import (
	"cmp"
	_ "embed"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/common/netx"
	"singctl/internal/config"

	"gopkg.in/yaml.v3"
)

//go:embed templates/adguard_base.yaml
var adguardBaseYAML []byte

// ConfigParams 定义生成初始 AdGuardHome.yaml 所需的参数。
type ConfigParams struct {
	LANIP             string   // Web 面板绑定的局域网 IPv4（严禁 0.0.0.0）
	WebPort           int      // Web 面板端口，默认 3000
	DNSPort           int      // 本地 DNS 监听端口，默认 5353
	Username          string   // 管理面板登录用户名，默认 root
	PasswordHash      string   // bcrypt 哈希密码（非空，以直接跳过首次引导向导）
	IsOpenWrt         bool     // OpenWrt 下默认关闭查询日志落盘以保护闪存
	DisablePrivatePTR bool     // 已弃用（始终禁用私网 PTR 以防止与 dnsmasq 形成死循环）；保留字段以兼容既有调用方
	SubURLs           []string // 订阅链接列表（自动将其域名加入放行白名单，防止误拦截）
	WhitelistDomains  []string // 可选：额外需预置放行的安全域名（内置防误杀基线 + 用户 DNS 白名单）
}

// SyncOptions 定义对已存在的 AdGuardHome.yaml 进行非破坏性同步的选项。
type SyncOptions struct {
	LANIP             string
	WebPort           int
	DNSPort           int
	Username          string // 非空且 UpdateAuth=true 时同步更新用户名
	PasswordHash      string // 非空且 UpdateAuth=true 时同步更新密码哈希
	UpdateAuth        bool
	DisablePrivatePTR *bool // 保留字段以兼容调用方（SyncExistingConfig 始终强制关闭 use_private_ptr_resolvers 防回环）
}

// sanitizeWebBindIP 确保 Web 面板绑定的 IP 合法且绝不为 0.0.0.0 / ::。
func sanitizeWebBindIP(ipStr string) string {
	trimmed := strings.TrimSpace(ipStr)
	ip := net.ParseIP(trimmed)
	if ip == nil || ip.IsUnspecified() {
		fallback := netx.GetPrimaryLANIPv4()
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

// extractSubWhitelistRules 提取订阅 URL 与附加域名列表并生成去重后的 AdGuard 强放行规则。
func extractSubWhitelistRules(subURLs []string, extraDomains ...string) []string {
	seen := make(map[string]struct{})
	var rules []string
	addHost := func(host string) {
		h := strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
		if h == "" || net.ParseIP(h) != nil || h == "localhost" {
			return
		}
		if _, ok := seen[h]; ok {
			return
		}
		seen[h] = struct{}{}
		rules = append(rules, fmt.Sprintf("@@||%s^$important", h))
	}
	for _, raw := range subURLs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" {
			continue
		}
		addHost(u.Hostname())
	}
	for _, raw := range extraDomains {
		d := normalizeAdGuardTarget(raw)
		if d == "" || !validRewriteDomainRe.MatchString(d) {
			continue
		}
		addHost(d)
	}
	return rules
}

// BuildInitialConfigYAML 基于内嵌 schema v29 基底模板与 AST 补丁生成可直接跳过首次初始化向导的 AdGuardHome.yaml。
func BuildInitialConfigYAML(p ConfigParams) ([]byte, error) {
	if strings.TrimSpace(p.PasswordHash) == "" || !config.IsHashedPassword(p.PasswordHash) {
		return nil, fmt.Errorf("PasswordHash must be a valid bcrypt hash")
	}

	var root yaml.Node
	if err := yaml.Unmarshal(adguardBaseYAML, &root); err != nil {
		return nil, fmt.Errorf("parse embedded adguard_base.yaml: %w", err)
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("invalid embedded adguard_base.yaml root node")
	}
	doc := root.Content[0]

	applySyncASTNodes(doc, SyncOptions{
		LANIP:        p.LANIP,
		WebPort:      p.WebPort,
		DNSPort:      p.DNSPort,
		Username:     cmp.Or(strings.TrimSpace(p.Username), "root"),
		PasswordHash: p.PasswordHash,
		UpdateAuth:   true,
	})

	queryLogInterval := "72h"
	if p.IsOpenWrt {
		queryLogInterval = "24h"
	}
	queryLogMap := ensureYAMLSubMap(doc, "querylog")
	setYAMLScalar(queryLogMap, "interval", queryLogInterval, "!!str")
	setYAMLScalar(queryLogMap, "file_enabled", strconv.FormatBool(!p.IsOpenWrt), "!!bool")
	setYAMLStringSlice(doc, "user_rules", extractSubWhitelistRules(p.SubURLs, p.WhitelistDomains...))

	out, err := yaml.Marshal(&root)
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
	return fsx.WriteAtomic0600(configPath, data)
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
	if !applySyncASTNodes(root.Content[0], opts) {
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

func applySyncASTNodes(doc *yaml.Node, opts SyncOptions) bool {
	changed := false

	bindIP := sanitizeWebBindIP(opts.LANIP)
	webPort := opts.WebPort
	if webPort <= 0 || webPort > 65535 {
		webPort = 3000
	}
	httpMap := ensureYAMLSubMap(doc, "http")
	if setYAMLScalar(httpMap, "address", net.JoinHostPort(bindIP, strconv.Itoa(webPort)), "!!str") {
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
	// 始终强制关闭私网 PTR 反查，避免 AdGuard 经 dnsmasq ↔ sing-box 形成指数放大环路。
	if setYAMLScalar(dnsMap, "use_private_ptr_resolvers", "false", "!!bool") {
		changed = true
	}

	for _, section := range []string{"querylog", "statistics"} {
		secMap := ensureYAMLSubMap(doc, section)
		if setYAMLScalar(secMap, "ignored_enabled", "true", "!!bool") {
			changed = true
		}
		if ensureYAMLStringSliceContains(secMap, "ignored", "localhost") {
			changed = true
		}
	}

	if opts.UpdateAuth && strings.TrimSpace(opts.Username) != "" && config.IsHashedPassword(opts.PasswordHash) {
		setYAMLNode(doc, "users", buildUsersSequenceNode(strings.TrimSpace(opts.Username), opts.PasswordHash))
		changed = true
	}
	return changed
}

func buildUsersSequenceNode(username, passwordHash string) *yaml.Node {
	return &yaml.Node{
		Kind: yaml.SequenceNode,
		Tag:  "!!seq",
		Content: []*yaml.Node{
			{
				Kind: yaml.MappingNode,
				Tag:  "!!map",
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: username},
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "password"},
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: passwordHash},
				},
			},
		},
	}
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

func ensureYAMLStringSliceContains(parent *yaml.Node, key, val string) bool {
	for i := 0; i+1 < len(parent.Content); i += 2 {
		if parent.Content[i].Value == key && parent.Content[i+1].Kind == yaml.SequenceNode {
			seq := parent.Content[i+1]
			for _, item := range seq.Content {
				if item.Value == val {
					return false
				}
			}
			seq.Content = append(seq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val})
			return true
		}
	}
	return setYAMLStringSlice(parent, key, []string{val})
}

// NeedsHardeningSync 检测现有 AdGuardHome.yaml 是否仍存在易引发回环的 use_private_ptr_resolvers: true，
// 或尚未过滤 localhost 探活统计噪声，供 Watchdog 自动无损自愈。
func NeedsHardeningSync(configPath string) bool {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var parsed struct {
		DNS struct {
			UsePrivatePTR *bool `yaml:"use_private_ptr_resolvers"`
		} `yaml:"dns"`
		QueryLog struct {
			Ignored        []string `yaml:"ignored"`
			IgnoredEnabled bool     `yaml:"ignored_enabled"`
		} `yaml:"querylog"`
		Statistics struct {
			Ignored        []string `yaml:"ignored"`
			IgnoredEnabled bool     `yaml:"ignored_enabled"`
		} `yaml:"statistics"`
	}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return false
	}
	if parsed.DNS.UsePrivatePTR == nil || *parsed.DNS.UsePrivatePTR {
		return true
	}
	if !parsed.QueryLog.IgnoredEnabled || !slices.Contains(parsed.QueryLog.Ignored, "localhost") {
		return true
	}
	if !parsed.Statistics.IgnoredEnabled || !slices.Contains(parsed.Statistics.Ignored, "localhost") {
		return true
	}
	return false
}
