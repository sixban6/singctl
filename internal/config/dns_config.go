// 文件职责：定义客户端双引擎防劫持本地 DNS 配置模型（auto / smartdns / adguard）、向后兼容反序列化与凭据初始化。
package config

import (
	"strings"
	"time"

	"singctl/internal/constant"

	"gopkg.in/yaml.v3"
)

const (
	DNSUpstreamModeFastestIP   = "fastest_ip"
	DNSUpstreamModeParallel    = "parallel"
	DNSUpstreamModeLoadBalance = "load_balance"
)

// DNSRewriteRule 定义内网自定义 DNS 解析重写规则（精确域名或 *. 通配域名映射至固定 IP）。
type DNSRewriteRule struct {
	Domain string `yaml:"domain" json:"domain"`
	Answer string `yaml:"answer" json:"answer"`
}

// IsValidDNSEngine 判断给定 DNS 引擎名称是否属于合法的双引擎契约值（"" / auto / smartdns / adguard）。
func IsValidDNSEngine(engine string) bool {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "", constant.DNSEngineAuto, constant.DNSEngineSmartDNS, constant.DNSEngineAdGuard:
		return true
	default:
		return false
	}
}

type ClientDNSConfig struct {
	Enabled              *bool            `yaml:"enabled,omitempty"`                // nil 或 true 视为启用；显式 false 禁用
	Engine               string           `yaml:"engine,omitempty"`                 // "" / "auto" / "smartdns" / "adguard"（历史 "singbox" 自动兼容归一化为 "auto"）
	DNSPort              int              `yaml:"dns_port,omitempty"`               // 本地 DNS 端口，默认 5353 (127.0.0.1)
	WebPort              int              `yaml:"web_port,omitempty"`               // Web 管理面板端口，默认 3000 (本机局域网 IP)
	Username             string           `yaml:"username,omitempty"`               // 管理账号，默认 root
	Password             string           `yaml:"password,omitempty"`               // 管理密码，首次安装留空时自动生成 16 位强密码
	Upstreams            []string         `yaml:"upstreams,omitempty"`              // 统一加密上游池（https/tls/quic/h3）
	UpstreamMode         string           `yaml:"upstream_mode,omitempty"`          // fastest_ip / parallel / load_balance（默认 fastest_ip）
	Whitelist            []string         `yaml:"whitelist,omitempty"`              // 受管放行域名列表
	Rewrites             []DNSRewriteRule `yaml:"rewrites,omitempty"`               // 内网自定义解析重写列表
	BlockAAAA            bool             `yaml:"block_aaaa,omitempty"`             // 历史兼容保留字段（实际 AAAA 策略由 gateway.ipv6_mode 单一数据源派生）
	AdblockDisabledUntil int64            `yaml:"adblock_disabled_until,omitempty"` // 临时暂停去广告截止时间戳（Unix 秒，0 未暂停，<0 手动持续暂停）
	DisabledAdRuleSets   []string             `yaml:"disabled_ad_rule_sets,omitempty"`  // 历史兼容保留字段
	SmartDNSFilters      []string             `yaml:"smartdns_filters,omitempty"`       // SmartDNS 启用的轻量去广告规则集 URL 列表
	BypassGuard          DNSBypassGuardConfig `yaml:"bypass_guard,omitempty"`           // 分层防 DNS 绕过拦截策略（L1~L4 + 横向源 IP 豁免）
}

func (c *ClientDNSConfig) IsEnabled() bool {
	if c == nil || c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

func (c *ClientDNSConfig) SetEnabled(v bool) {
	c.Enabled = &v
}

// GetEngine 返回归一化后的防劫持 DNS 引擎名称（空值、历史 "singbox" 或未知值均平滑兼容归一化为 "auto"）。
func (c *ClientDNSConfig) GetEngine() string {
	if c == nil {
		return constant.DNSEngineAuto
	}
	switch norm := strings.ToLower(strings.TrimSpace(c.Engine)); norm {
	case constant.DNSEngineSmartDNS, constant.DNSEngineAdGuard:
		return norm
	default:
		return constant.DNSEngineAuto
	}
}

// SetEngine 归一化并设置防劫持 DNS 引擎（空值、历史 "singbox" 或非法值均归一化为 "auto"）。
func (c *ClientDNSConfig) SetEngine(engine string) {
	if c == nil {
		return
	}
	switch norm := strings.ToLower(strings.TrimSpace(engine)); norm {
	case constant.DNSEngineAuto, constant.DNSEngineSmartDNS, constant.DNSEngineAdGuard:
		c.Engine = norm
	default:
		c.Engine = constant.DNSEngineAuto
	}
}

// GetUpstreamMode 返回归一化后的加密上游调度模式（默认 "fastest_ip"）。
func (c *ClientDNSConfig) GetUpstreamMode() string {
	if c == nil {
		return DNSUpstreamModeFastestIP
	}
	switch norm := strings.ToLower(strings.TrimSpace(c.UpstreamMode)); norm {
	case DNSUpstreamModeFastestIP, DNSUpstreamModeParallel, DNSUpstreamModeLoadBalance:
		return norm
	default:
		return DNSUpstreamModeFastestIP
	}
}

// IsAdblockPaused 判断在 now 时刻去广告保护是否处于暂停态（<0 手动持续关闭，>0 且未到期临时暂停）。
func (c *ClientDNSConfig) IsAdblockPaused(now time.Time) bool {
	if c == nil {
		return false
	}
	if c.AdblockDisabledUntil < 0 {
		return true
	}
	if c.AdblockDisabledUntil > 0 {
		return now.Unix() < c.AdblockDisabledUntil
	}
	return false
}

func (c *ClientDNSConfig) GetDNSPort() int {
	if c != nil && c.DNSPort > 0 && c.DNSPort <= 65535 {
		return c.DNSPort
	}
	return 5353
}

func (c *ClientDNSConfig) GetWebPort() int {
	if c != nil && c.WebPort > 0 && c.WebPort <= 65535 {
		return c.WebPort
	}
	return 3000
}

func (c *ClientDNSConfig) GetUsername() string {
	if c != nil && strings.TrimSpace(c.Username) != "" {
		return strings.TrimSpace(c.Username)
	}
	return "root"
}

func (c *ClientDNSConfig) GetPassword() string {
	if c == nil {
		return ""
	}
	return strings.TrimSpace(c.Password)
}

// EnsureCredentials 确保客户端 AdGuard Home 拥有合法端口、管理员用户名（默认 root）与 16 位强随机密码。
func (c *ClientDNSConfig) EnsureCredentials(preferredUsername string) bool {
	changed := false
	if c.Enabled == nil {
		enabled := true
		c.Enabled = &enabled
		changed = true
	}
	if c.DNSPort <= 0 || c.DNSPort > 65535 {
		c.DNSPort = 5353
		changed = true
	}
	if c.WebPort <= 0 || c.WebPort > 65535 {
		c.WebPort = 3000
		changed = true
	}
	preferred := strings.TrimSpace(preferredUsername)
	if preferred != "" {
		if c.Username != preferred {
			c.Username = preferred
			changed = true
		}
	} else if strings.TrimSpace(c.Username) == "" {
		c.Username = "root"
		changed = true
	}
	if strings.TrimSpace(c.Password) == "" {
		c.Password = GenerateSecurePassword(16)
		changed = true
	}
	return changed
}

func (c *ClientDNSConfig) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		Enabled              *bool            `yaml:"enabled"`
		Engine               string           `yaml:"engine"`
		DNSPort              any              `yaml:"dns_port"`
		WebPort              any              `yaml:"web_port"`
		Username             string           `yaml:"username"`
		Password             string           `yaml:"password"`
		Upstreams            []string         `yaml:"upstreams"`
		UpstreamMode         string           `yaml:"upstream_mode"`
		Whitelist            []string         `yaml:"whitelist"`
		Rewrites             []DNSRewriteRule `yaml:"rewrites"`
		BlockAAAA            bool             `yaml:"block_aaaa"`
		AdblockDisabledUntil any                  `yaml:"adblock_disabled_until"`
		DisabledAdRuleSets   []string             `yaml:"disabled_ad_rule_sets"`
		SmartDNSFilters      []string             `yaml:"smartdns_filters"`
		BypassGuard          DNSBypassGuardConfig `yaml:"bypass_guard"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	c.Enabled = raw.Enabled
	c.Engine = strings.ToLower(strings.TrimSpace(raw.Engine))
	c.Username = strings.TrimSpace(raw.Username)
	c.Password = strings.TrimSpace(raw.Password)
	c.Upstreams = cleanStringSlice(raw.Upstreams)
	c.UpstreamMode = strings.ToLower(strings.TrimSpace(raw.UpstreamMode))
	c.Whitelist = cleanStringSlice(raw.Whitelist)
	if len(raw.Rewrites) > 0 {
		rewrites := make([]DNSRewriteRule, 0, len(raw.Rewrites))
		for _, r := range raw.Rewrites {
			d := strings.TrimSpace(r.Domain)
			a := strings.TrimSpace(r.Answer)
			if d != "" && a != "" {
				rewrites = append(rewrites, DNSRewriteRule{Domain: d, Answer: a})
			}
		}
		if len(rewrites) > 0 {
			c.Rewrites = rewrites
		}
	}
	c.BlockAAAA = raw.BlockAAAA
	c.DisabledAdRuleSets = cleanStringSlice(raw.DisabledAdRuleSets)
	c.SmartDNSFilters = cleanStringSlice(raw.SmartDNSFilters)
	c.BypassGuard = raw.BypassGuard.Clone()
	if len(c.BypassGuard.AppGroups) > 0 {
		normGroups := make(map[string]bool, len(c.BypassGuard.AppGroups))
		for k, v := range c.BypassGuard.AppGroups {
			nk := strings.ToLower(strings.TrimSpace(k))
			if nk != "" {
				normGroups[nk] = v
			}
		}
		c.BypassGuard.AppGroups = normGroups
	}
	c.BypassGuard.ExemptSourceIPs = cleanStringSlice(c.BypassGuard.ExemptSourceIPs)
	if raw.DNSPort != nil {
		if v, err := parseIntAny(raw.DNSPort); err == nil {
			c.DNSPort = v
		}
	}
	if raw.WebPort != nil {
		if v, err := parseIntAny(raw.WebPort); err == nil {
			c.WebPort = v
		}
	}
	if raw.AdblockDisabledUntil != nil {
		if v, err := parseInt64Any(raw.AdblockDisabledUntil); err == nil {
			c.AdblockDisabledUntil = v
		}
	}
	return nil
}
