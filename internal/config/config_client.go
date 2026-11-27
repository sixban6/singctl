// 文件职责：集中定义客户端侧全部配置模型与业务默认值方法（网关拓扑、设备审计、防火墙、自定义规则、订阅、Hy2、本地 DNS、Tailscale、Watchdog 故障切换）。
//
// 架构设计原则：
//   - 领域内聚拆 file：按客户端路由/防护域与服务端 VPS 域分离配置模型，降低单一文件认知负荷，同时保持 config 包对外类型签名 100% 向后兼容。
//   - 契约弹性（UnmarshalYAML）：通过 parseIntAny 宽容解析客户端配置中常见的数字/字符串混写，保证历史配置文件升级不中断。
package config

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	GatewayIPv6Off    = "off"
	GatewayIPv6CNOnly = "cn_only"
	GatewayIPv6Full   = "full"

	WorkModeAuto      = "auto"      // 自动：有订阅=代理模式，无订阅=审计模式
	WorkModeAudit     = "audit"     // 审计模式（免订阅：设备行为审计 + PCDN 拦截 + 强劫持防绕过 DNS）
	WorkModeProxy     = "proxy"     // 代理模式（需订阅：透明代理分流 + 完整审计 + 强劫持防绕过 DNS）
	WorkModeDelegated = "delegated" // 旁路由托管（主路由专用：停用本机 sing-box 与全局 TProxy，按子网策略路由交由旁路由分流）
)

// NormalizeWorkMode 校验并归一化客户端运行工作模式（auto / audit / proxy / delegated）；
// 历史配置中的 basic / dns_only / lite 自动平滑兼容归一化为 audit。
func NormalizeWorkMode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", WorkModeAuto:
		return WorkModeAuto, true
	case WorkModeAudit, "basic", "dns_only", "dns-only", "lite", "direct_audit", "direct-audit", "direct":
		return WorkModeAudit, true
	case WorkModeProxy, "full":
		return WorkModeProxy, true
	case WorkModeDelegated, "side_delegated", "side-delegated", "passthrough":
		return WorkModeDelegated, true
	default:
		return "", false
	}
}

// NormalizeGatewayIPv6Mode 校验并归一化客户端 IPv6 双栈分流策略（off / cn_only / full）。
// 空字符串视为默认值 off 并返回合法；其余未识别值返回 false。
func NormalizeGatewayIPv6Mode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", GatewayIPv6Off:
		return GatewayIPv6Off, true
	case GatewayIPv6CNOnly, "cn", "cn-only":
		return GatewayIPv6CNOnly, true
	case GatewayIPv6Full, "all", "dual":
		return GatewayIPv6Full, true
	default:
		return "", false
	}
}

// GatewayConfig 定义客户端网关部署拓扑模式（默认主路由 main，可选单臂旁路由 side）、工作模式（audit/proxy/delegated）与 IPv6 双栈分流策略。
type GatewayConfig struct {
	Mode               string `yaml:"mode,omitempty" json:"mode,omitempty"`
	WorkMode           string `yaml:"work_mode,omitempty" json:"workMode,omitempty"`
	MainRouterIP       string `yaml:"main_router_ip,omitempty" json:"main_router_ip,omitempty"`
	SideRouterIP       string `yaml:"side_router_ip,omitempty" json:"side_router_ip,omitempty"`
	SideRouterFailover *bool  `yaml:"side_router_failover,omitempty" json:"side_router_failover,omitempty"`
	ModemIP            string `yaml:"modem_ip,omitempty" json:"modemIP,omitempty"`
	LANIface           string `yaml:"lan_iface,omitempty" json:"lan_iface,omitempty"`
	IPv6Mode           string `yaml:"ipv6_mode,omitempty" json:"ipv6_mode,omitempty"`
}

// IsSideRouterFailoverEnabled 返回旁路由离线时是否自动摘除策略路由回退主路由直连（默认 true）。
func (g GatewayConfig) IsSideRouterFailoverEnabled() bool {
	if g.SideRouterFailover == nil {
		return true
	}
	return *g.SideRouterFailover
}

// SetSideRouterFailover 显式设置旁路由离线自动回退开关（true 时置 nil 回归默认值）。
func (g *GatewayConfig) SetSideRouterFailover(enabled bool) {
	if g == nil {
		return
	}
	if enabled {
		g.SideRouterFailover = nil
		return
	}
	v := false
	g.SideRouterFailover = &v
}

// EffectiveMode 返回归一化后的生效模式：默认始终为 "main"，仅当显式配置为 "side" 时返回 "side"。
func (g GatewayConfig) EffectiveMode() string {
	if strings.EqualFold(strings.TrimSpace(g.Mode), "side") {
		return "side"
	}
	return "main"
}

// ConfiguredWorkMode 返回归一化后的用户显式配置工作模式（auto / basic / audit / proxy）。
func (g GatewayConfig) ConfiguredWorkMode() string {
	if norm, ok := NormalizeWorkMode(g.WorkMode); ok {
		return norm
	}
	return WorkModeAuto
}

// EffectiveIPv6Mode 返回归一化后的 IPv6 分流模式（off / cn_only / full），默认 "off"。
func (g GatewayConfig) EffectiveIPv6Mode() string {
	if norm, ok := NormalizeGatewayIPv6Mode(g.IPv6Mode); ok {
		return norm
	}
	return GatewayIPv6Off
}

// IsSideRouter 判断当前配置是否显式启用了旁路由（单臂网关）模式。
func (g GatewayConfig) IsSideRouter() bool {
	return g.EffectiveMode() == "side"
}

// IsEmpty 判断是否未显式设置任何网关配置字段。
func (g GatewayConfig) IsEmpty() bool {
	return strings.TrimSpace(g.Mode) == "" &&
		strings.TrimSpace(g.WorkMode) == "" &&
		strings.TrimSpace(g.MainRouterIP) == "" &&
		strings.TrimSpace(g.SideRouterIP) == "" &&
		g.SideRouterFailover == nil &&
		strings.TrimSpace(g.ModemIP) == "" &&
		strings.TrimSpace(g.LANIface) == "" &&
		strings.TrimSpace(g.IPv6Mode) == ""
}

// ConfiguredWorkMode 返回当前配置显式选择的工作模式（auto / basic / audit / proxy / delegated）。
func (c *Config) ConfiguredWorkMode() string {
	if c == nil {
		return WorkModeAuto
	}
	return c.Gateway.ConfiguredWorkMode()
}

// EffectiveWorkMode 解析当前实际生效的工作模式（audit / proxy / delegated）：
//   - 主路由 (main) 只要绑定了 side_router_ip（或显式为 delegated），即自动进入旁路由托管直通模式；
//   - 其余情况（未托管主路由 / 旁路由）完全按是否配置有效订阅自动推导：有订阅=proxy，无订阅=audit（不再被历史 work_mode 锁死）。
func (c *Config) EffectiveWorkMode() string {
	if c == nil {
		return WorkModeAudit
	}
	if !c.Gateway.IsSideRouter() &&
		(strings.TrimSpace(c.Gateway.SideRouterIP) != "" || c.Gateway.ConfiguredWorkMode() == WorkModeDelegated) {
		return WorkModeDelegated
	}
	if c.HasRealSubs() {
		return WorkModeProxy
	}
	return WorkModeAudit
}

// IsDelegatedMode 判断当前主路由是否处于「旁路由托管（纯网关直通）」模式。
func (c *Config) IsDelegatedMode() bool {
	return c.EffectiveWorkMode() == WorkModeDelegated
}

// IsDirectAuditMode 判断当前是否处于「审计模式」（免订阅、纯直连零节点 sing-box 透明嗅探与 PCDN/黑名单拦截）。
func (c *Config) IsDirectAuditMode() bool {
	return c.EffectiveWorkMode() == WorkModeAudit
}

// NeedsSingBox 判断当前工作模式是否需要运行 sing-box 内核（审计模式恒为 true；代理模式需配置有效订阅；旁路由托管模式为 false）。
func (c *Config) NeedsSingBox() bool {
	switch c.EffectiveWorkMode() {
	case WorkModeAudit:
		return true
	case WorkModeProxy:
		return c != nil && c.HasRealSubs()
	case WorkModeDelegated:
		return false
	default:
		return true
	}
}

// AuditThrottleRule 定义单目标"限速不拉黑"防护策略（通过 nftables limit 对特定域名/IP 上行速率封顶而不掐断连接）。
type AuditThrottleRule struct {
	Target    string `yaml:"target" json:"target"`
	Port      int    `yaml:"port,omitempty" json:"port,omitempty"`
	RateKBps  int    `yaml:"rate_kbps" json:"rateKbps"`
	Comment   string `yaml:"comment,omitempty" json:"comment,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty" json:"createdAt,omitempty"`
}

// AuditConfig 定义客户端设备行为审计与可选 AI 深度研判配置。
type AuditConfig struct {
	Whitelist     []string            `yaml:"whitelist,omitempty" json:"whitelist,omitempty"`           // 额外信任的域名后缀或 IP/CIDR 白名单
	PCDNBlock     *bool               `yaml:"pcdn_block,omitempty" json:"pcdn_block,omitempty"`         // nil 或 true 默认开启内置防 PCDN 规则集拦截；显式 false 关闭
	DirectDevices []string            `yaml:"direct_devices,omitempty" json:"direct_devices,omitempty"` // 禁止走海外代理的局域网设备 IP 列表（强制全部走 Direct 出站 + dns_local）
	Throttles     []AuditThrottleRule `yaml:"throttles,omitempty" json:"throttles,omitempty"`           // 按目标上行限速防爆列表（不断网限速）
	AI            AuditAIConfig       `yaml:"ai,omitempty" json:"ai,omitempty"`                         // 可选 L2 AI 语义研判配置 (OpenAI 兼容接口)
}

func normalizeAuditDirectDeviceIP(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if p, err := netip.ParsePrefix(s); err == nil && p.IsSingleIP() {
		return p.Addr().Unmap().String()
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String()
	}
	return ""
}

// IsDeviceDirect 判断指定设备 IP 是否已被限制禁止走海外代理（全量 Direct 直出）。
func (a AuditConfig) IsDeviceDirect(rawIP string) bool {
	target := normalizeAuditDirectDeviceIP(rawIP)
	if target == "" {
		return false
	}
	for _, item := range a.DirectDevices {
		if normalizeAuditDirectDeviceIP(item) == target {
			return true
		}
	}
	return false
}

// IsDeviceOverseasAllowed 判断指定设备是否允许访问海外外网（走 sing-box 代理分流规则）。
func (a AuditConfig) IsDeviceOverseasAllowed(rawIP string) bool {
	return !a.IsDeviceDirect(rawIP)
}

// SetDeviceOverseasAllowed 设置单设备是否允许走海外分流（false=加入 direct_devices 强制直连，true=移除并恢复分流）。
func (a *AuditConfig) SetDeviceOverseasAllowed(rawIP string, allowOverseas bool) bool {
	if a == nil {
		return false
	}
	target := normalizeAuditDirectDeviceIP(rawIP)
	if target == "" {
		return false
	}

	cleaned := make([]string, 0, len(a.DirectDevices))
	seen := make(map[string]struct{}, len(a.DirectDevices))
	existed := false
	for _, item := range a.DirectDevices {
		norm := normalizeAuditDirectDeviceIP(item)
		if norm == "" {
			continue
		}
		if norm == target {
			existed = true
			if allowOverseas {
				continue
			}
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		cleaned = append(cleaned, norm)
	}

	if allowOverseas {
		if len(cleaned) == 0 {
			a.DirectDevices = nil
		} else {
			a.DirectDevices = cleaned
		}
		return existed
	}

	if existed {
		a.DirectDevices = cleaned
		return false
	}
	a.DirectDevices = append(cleaned, target)
	return true
}

// IsPCDNBlockEnabled 返回是否开启内置防 PCDN 规则集拦截（默认开启）。
func (a AuditConfig) IsPCDNBlockEnabled() bool {
	return a.PCDNBlock == nil || *a.PCDNBlock
}

// SetPCDNBlock 设置内置防 PCDN 规则集开关（开启时置为 nil 回归默认，显式关闭写入 false）。
func (a *AuditConfig) SetPCDNBlock(enabled bool) {
	if enabled {
		a.PCDNBlock = nil
		return
	}
	v := false
	a.PCDNBlock = &v
}

func (a AuditConfig) IsEmpty() bool {
	return len(a.Whitelist) == 0 &&
		a.PCDNBlock == nil &&
		len(a.DirectDevices) == 0 &&
		len(a.Throttles) == 0 &&
		!a.AI.Enabled &&
		strings.TrimSpace(a.AI.Endpoint) == "" &&
		strings.TrimSpace(a.AI.APIKey) == "" &&
		strings.TrimSpace(a.AI.Model) == ""
}

// AuditAIConfig 定义用于二次确认可疑上传的 OpenAI 兼容大模型接口参数。
type AuditAIConfig struct {
	Enabled  bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Endpoint string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"` // 如 https://api.deepseek.com/v1 或 http://127.0.0.1:11434/v1
	APIKey   string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	Model    string `yaml:"model,omitempty" json:"model,omitempty"` // 如 deepseek-chat / gpt-4o-mini
}

// FirewallConfig 定义 nftables inet security 防火墙加固的持久化策略（模式、黑/白名单、诱捕端口与周期）。
type FirewallConfig struct {
	Mode            string   `yaml:"mode,omitempty" json:"mode,omitempty"`                          // "standard" (默认) | "minimal"
	BanTimeoutDays  int      `yaml:"ban_timeout_days,omitempty" json:"banTimeoutDays,omitempty"`    // 默认 7 (范围 1~30)
	PingLimitPerSec int      `yaml:"ping_limit_per_sec,omitempty" json:"pingLimitPerSec,omitempty"` // 默认 10 (范围 1~100)
	Whitelist       []string `yaml:"whitelist,omitempty" json:"whitelist,omitempty"`                // 用户自定义信任 IP/CIDR
	ExtraForeverBan []string `yaml:"extra_forever_ban,omitempty" json:"extraForeverBan,omitempty"`  // 用户自定义永久封禁 IPv4/CIDR
	ProtectedPorts  []int    `yaml:"protected_ports,omitempty" json:"protectedPorts,omitempty"`     // 自定义高危诱捕端口列表（空表示使用默认高危端口集）
}

// EffectiveMode 返回归一化后的防火墙模式（"standard" | "minimal"）。
func (f FirewallConfig) EffectiveMode() string {
	if strings.EqualFold(strings.TrimSpace(f.Mode), "minimal") {
		return "minimal"
	}
	return "standard"
}

// EffectiveBanTimeoutDays 返回动态黑名单封禁天数（默认 7，限定 1~30）。
func (f FirewallConfig) EffectiveBanTimeoutDays() int {
	if f.BanTimeoutDays <= 0 {
		return 7
	}
	return min(30, max(1, f.BanTimeoutDays))
}

// EffectivePingLimitPerSec 返回每秒 ICMP Ping 放行上限（默认 10，限定 1~100）。
func (f FirewallConfig) EffectivePingLimitPerSec() int {
	if f.PingLimitPerSec <= 0 {
		return 10
	}
	return min(100, max(1, f.PingLimitPerSec))
}

// IsEmpty 判断是否未显式设置任何防火墙自定义字段。
func (f FirewallConfig) IsEmpty() bool {
	return strings.TrimSpace(f.Mode) == "" &&
		f.BanTimeoutDays == 0 &&
		f.PingLimitPerSec == 0 &&
		len(f.Whitelist) == 0 &&
		len(f.ExtraForeverBan) == 0 &&
		len(f.ProtectedPorts) == 0
}

// BlockRule 定义由设备审计或用户一键拉黑生成的阻断规则。
// 同时作用于 sing-box 路由层 (action: reject)、sing-box DNS 层与自建 AdGuard Home 黑名单。
// 当 Target 以 "ruleset:<tag>" 开头时，代表整包导入并封禁的 sing-box 规则集（单行聚合展示，不展开刷屏）。
type BlockRule struct {
	Target     string `yaml:"target" json:"target"`                               // 被拉黑的目标域名、IP/CIDR 或 "ruleset:<tag>"
	SourceIP   string `yaml:"source_ip,omitempty" json:"source_ip,omitempty"`     // 可选：仅限制特定局域网设备 IP
	Reason     string `yaml:"reason,omitempty" json:"reason,omitempty"`           // 拉黑原因备注
	RuleSetURL string `yaml:"ruleset_url,omitempty" json:"ruleset_url,omitempty"` // 规则集原始导入 URL (支持一键刷新)
	RuleCount  int    `yaml:"rule_count,omitempty" json:"rule_count,omitempty"`   // 规则集包含的规则总数摘要
	Preview    string `yaml:"preview,omitempty" json:"preview,omitempty"`         // 规则集前几条域名预览摘要
	CreatedAt  string `yaml:"created_at,omitempty" json:"created_at,omitempty"`
}

type CustomRulesConfig struct {
	Block     []BlockRule      `yaml:"block,omitempty" json:"block,omitempty"`
	Outbounds []OutboundRule   `yaml:"outbounds,omitempty" json:"outbounds,omitempty"`
	Route     []map[string]any `yaml:"route,omitempty" json:"route,omitempty"`
	DNS       []map[string]any `yaml:"dns,omitempty" json:"dns,omitempty"`
}

func (c CustomRulesConfig) IsEmpty() bool {
	return len(c.Block) == 0 && len(c.Outbounds) == 0 && len(c.Route) == 0 && len(c.DNS) == 0
}

// OutboundRule 定义针对 sing-box 出站策略组 (urltest / selector) 的定制与节点过滤规则。
// 可在 singctl.yaml 的 custom_rules.outbounds 中按 tag 覆写策略组测速参数并按正则过滤候选节点，
// 从而在不修改通用 singgen 模板的前提下实现本地个性化策略注入。
type OutboundRule struct {
	Tag                       string   `yaml:"tag" json:"tag"`
	Include                   string   `yaml:"include,omitempty" json:"include,omitempty"`
	Exclude                   string   `yaml:"exclude,omitempty" json:"exclude,omitempty"`
	Outbounds                 []string `yaml:"outbounds,omitempty" json:"outbounds,omitempty"`
	Default                   string   `yaml:"default,omitempty" json:"default,omitempty"`
	URL                       string   `yaml:"url,omitempty" json:"url,omitempty"`
	Interval                  string   `yaml:"interval,omitempty" json:"interval,omitempty"`
	Tolerance                 int      `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
	InterruptExistConnections *bool    `yaml:"interrupt_exist_connections,omitempty" json:"interrupt_exist_connections,omitempty"`
}

type RenameRule struct {
	Match   string `yaml:"match" json:"match"`
	Replace string `yaml:"replace" json:"replace"`
}

type Subscription struct {
	Name          string       `yaml:"name"`
	URL           string       `yaml:"url"`
	SkipTlsVerify bool         `yaml:"skip_tls_verify"`
	RemoveEmoji   bool         `yaml:"remove-emoji"`
	Include       string       `yaml:"include,omitempty"`
	Exclude       string       `yaml:"exclude,omitempty"`
	Rename        []RenameRule `yaml:"rename,omitempty"`
}

type GitHubConfig struct {
	MirrorURL string `yaml:"mirror_url"`
}

type Hy2Config struct {
	Up   int `yaml:"up"`
	Down int `yaml:"down"`
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

const (
	TailscaleAccessOutboundOnly       = "outbound_only"
	TailscaleAccessBidirectionalTimed = "bidirectional_timed"
	TailscaleAccessBidirectional      = "bidirectional"

	TailscaleScopeAll       = "all"
	TailscaleScopeAllowlist = "allowlist"
	TailscaleScopeDenylist  = "denylist"
)

// NormalizeTailscaleSubnetScope 校验并归一化本地网段的设备参与模式（all / allowlist / denylist）。
func NormalizeTailscaleSubnetScope(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", TailscaleScopeAll:
		return TailscaleScopeAll, true
	case TailscaleScopeAllowlist:
		return TailscaleScopeAllowlist, true
	case TailscaleScopeDenylist:
		return TailscaleScopeDenylist, true
	default:
		return "", false
	}
}

// TailscaleLocalSubnetRule 定义单个本机/下级网段内部的具体设备级允许或排除策略。
type TailscaleLocalSubnetRule struct {
	CIDR    string   `yaml:"cidr" json:"cidr"`
	Scope   string   `yaml:"scope,omitempty" json:"scope,omitempty"`
	Devices []string `yaml:"devices,omitempty" json:"devices,omitempty"`
}

// NormalizeTailscaleAccessMode 校验并归一化 Tailscale 异地子网双向互访模式。
// 空字符串视为默认值 outbound_only 并返回合法；其余未识别值返回 false。
func NormalizeTailscaleAccessMode(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", TailscaleAccessOutboundOnly:
		return TailscaleAccessOutboundOnly, true
	case TailscaleAccessBidirectionalTimed:
		return TailscaleAccessBidirectionalTimed, true
	case TailscaleAccessBidirectional:
		return TailscaleAccessBidirectional, true
	default:
		return "", false
	}
}

// TailscaleP2PPeerConfig 定义纳入 P2P 零常驻暴露与双向边界管控的远端设备策略。
// 未列入此列表的管理员终端（笔记本、手机等）保持 24/7 全量放行不受限制。
type TailscaleP2PPeerConfig struct {
	ID                 string   `yaml:"id,omitempty" json:"id,omitempty"`
	Name               string   `yaml:"name" json:"name"`
	TailscaleIP        string   `yaml:"tailscale_ip,omitempty" json:"tailscale_ip,omitempty"`
	JITEnabled         bool     `yaml:"jit_enabled" json:"jit_enabled"`
	AccessMode         string   `yaml:"access_mode,omitempty" json:"access_mode,omitempty"`
	BidirectionalUntil string   `yaml:"bidirectional_until,omitempty" json:"bidirectional_until,omitempty"`
	AllowedLANTargets  []string `yaml:"allowed_lan_targets,omitempty" json:"allowed_lan_targets,omitempty"`
}

// RemainingBidirectional 返回限时双向探亲互访窗口在 now 时刻的剩余有效期；未启用或已过期返回 0。
func (p TailscaleP2PPeerConfig) RemainingBidirectional(now time.Time) time.Duration {
	norm, ok := NormalizeTailscaleAccessMode(p.AccessMode)
	if !ok || norm != TailscaleAccessBidirectionalTimed {
		return 0
	}
	raw := strings.TrimSpace(p.BidirectionalUntil)
	if raw == "" {
		return 0
	}
	until, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return 0
	}
	rem := until.Sub(now)
	if rem <= 0 {
		return 0
	}
	return rem
}

// EffectiveAccessMode 返回在 now 时刻真正生效的访问模式；限时过期或无效时间戳自动降级为 outbound_only。
func (p TailscaleP2PPeerConfig) EffectiveAccessMode(now time.Time) string {
	norm, ok := NormalizeTailscaleAccessMode(p.AccessMode)
	if !ok {
		return TailscaleAccessOutboundOnly
	}
	switch norm {
	case TailscaleAccessBidirectional:
		return TailscaleAccessBidirectional
	case TailscaleAccessBidirectionalTimed:
		if p.RemainingBidirectional(now) > 0 {
			return TailscaleAccessBidirectionalTimed
		}
		return TailscaleAccessOutboundOnly
	default:
		return TailscaleAccessOutboundOnly
	}
}

// TailscaleP2PAssistConfig 控制 Tailscale WAN 口零常驻暴露的 JIT 瞬时打洞与入向最小权限防护。
type TailscaleP2PAssistConfig struct {
	Enabled          bool                       `yaml:"enabled" json:"enabled"`
	RoleMode         string                     `yaml:"role_mode,omitempty" json:"role_mode,omitempty"`
	JITWindowSec     int                        `yaml:"jit_window_sec,omitempty" json:"jit_window_sec,omitempty"`
	CooldownSec      int                        `yaml:"cooldown_sec,omitempty" json:"cooldown_sec,omitempty"`
	PayloadFilter    *bool                      `yaml:"payload_filter,omitempty" json:"payload_filter,omitempty"`
	DownstreamAssist *bool                      `yaml:"downstream_assist,omitempty" json:"downstream_assist,omitempty"`
	SandboxUjail     bool                       `yaml:"sandbox_ujail,omitempty" json:"sandbox_ujail,omitempty"`
	ListenPort       int                        `yaml:"listen_port,omitempty" json:"listen_port,omitempty"`
	LocalRules       []TailscaleLocalSubnetRule `yaml:"local_rules,omitempty" json:"local_rules,omitempty"`
	Peers            []TailscaleP2PPeerConfig   `yaml:"peers,omitempty" json:"peers,omitempty"`
}

func (c TailscaleP2PAssistConfig) EffectiveDownstreamAssist() bool {
	if c.DownstreamAssist == nil {
		return true
	}
	return *c.DownstreamAssist
}

func (c TailscaleP2PAssistConfig) IsZero() bool {
	return !c.Enabled &&
		c.RoleMode == "" &&
		c.JITWindowSec == 0 &&
		c.CooldownSec == 0 &&
		c.PayloadFilter == nil &&
		c.DownstreamAssist == nil &&
		!c.SandboxUjail &&
		c.ListenPort == 0 &&
		len(c.LocalRules) == 0 &&
		len(c.Peers) == 0
}

func (c TailscaleP2PAssistConfig) EffectiveJITWindowSec() int {
	if c.JITWindowSec <= 0 {
		return 5
	}
	return min(max(3, c.JITWindowSec), 10)
}

func (c TailscaleP2PAssistConfig) EffectiveCooldownSec() int {
	if c.CooldownSec <= 0 {
		return 300
	}
	return min(max(30, c.CooldownSec), 3600)
}

func (c TailscaleP2PAssistConfig) EffectivePayloadFilter() bool {
	if c.PayloadFilter == nil {
		return true
	}
	return *c.PayloadFilter
}

func (c TailscaleP2PAssistConfig) EffectiveListenPort() int {
	if c.ListenPort <= 0 || c.ListenPort > 65535 {
		return 41641
	}
	return c.ListenPort
}

type TailscaleConfig struct {
	AuthKey   string                   `yaml:"auth_key"`
	UseBuild  bool                     `yaml:"use_build"`
	Subnets   string                   `yaml:"subnets"`
	P2PAssist TailscaleP2PAssistConfig `yaml:"p2p_assist,omitempty" json:"p2p_assist,omitzero"`
}

// DefaultWatchdogFailoverGroups 默认参与自动故障切换守护的核心 Selector 策略组列表（不含底层闲置单节点池 #Nodes，避免误报乱切）。
var DefaultWatchdogFailoverGroups = []string{"Proxy", "AI", "#VPS"}

// DefaultWatchdogProbeURLs 默认策略组存活探测 URL 列表（前后端统一，采用轻量无反爬限流的 HTTPS 204 端点）。
var DefaultWatchdogProbeURLs = []string{
	"https://www.gstatic.com/generate_204",
	"https://cp.cloudflare.com/generate_204",
}

// WatchdogFailoverConfig 策略组自动故障切换与恢复回切配置（默认开启）。
type WatchdogFailoverConfig struct {
	Enabled            *bool    `yaml:"enabled,omitempty" json:"enabled,omitempty"`                             // 是否启用策略组自动故障切换, 默认 true
	Groups             []string `yaml:"groups,omitempty" json:"groups,omitempty"`                               // 守护的 Selector 策略组列表, 留空使用默认核心组
	PatrolInterval     int      `yaml:"patrol_interval,omitempty" json:"patrol_interval,omitempty"`             // 巡检间隔(秒), 默认 300 (5分钟)
	ProbeTimeoutMs     int      `yaml:"probe_timeout_ms,omitempty" json:"probe_timeout_ms,omitempty"`           // 单次测速超时(毫秒), 默认 5000
	ConfirmRetries     int      `yaml:"confirm_retries,omitempty" json:"confirm_retries,omitempty"`             // 切备前复测确认次数, 默认 2 (设为 -1 表示不复测立即切)
	FailbackCooldown   int      `yaml:"failback_cooldown,omitempty" json:"failback_cooldown,omitempty"`         // 切备后自动回切冷却期(秒), 默认 180 (设为 -1 关闭自动回切)
	MaxFailbackDelayMs int      `yaml:"max_failback_delay_ms,omitempty" json:"max_failback_delay_ms,omitempty"` // 原主选恢复回切最高允许延迟(毫秒), 默认 600
	ProbeURLs          []string `yaml:"probe_urls,omitempty" json:"probe_urls,omitempty"`                       // 自定义测速探测 URL, 留空使用默认列表
}

func (f WatchdogFailoverConfig) IsEmpty() bool {
	return f.Enabled == nil &&
		len(f.Groups) == 0 &&
		f.PatrolInterval == 0 &&
		f.ProbeTimeoutMs == 0 &&
		f.ConfirmRetries == 0 &&
		f.FailbackCooldown == 0 &&
		f.MaxFailbackDelayMs == 0 &&
		len(f.ProbeURLs) == 0
}

// IsEnabled 返回是否开启故障切换（默认开启）。
func (f WatchdogFailoverConfig) IsEnabled() bool {
	return f.Enabled == nil || *f.Enabled
}

func (f WatchdogFailoverConfig) EffectiveGroups() []string {
	if cleaned := cleanStringSlice(f.Groups); len(cleaned) > 0 {
		return cleaned
	}
	return slices.Clone(DefaultWatchdogFailoverGroups)
}

func (f WatchdogFailoverConfig) EffectivePatrolInterval() time.Duration {
	if f.PatrolInterval <= 0 {
		return 300 * time.Second
	}
	return time.Duration(max(10, f.PatrolInterval)) * time.Second
}

func (f WatchdogFailoverConfig) EffectiveProbeTimeout() time.Duration {
	if f.ProbeTimeoutMs <= 0 {
		return 5000 * time.Millisecond
	}
	ms := min(max(500, f.ProbeTimeoutMs), 15000)
	return time.Duration(ms) * time.Millisecond
}

func (f WatchdogFailoverConfig) EffectiveConfirmRetries() int {
	if f.ConfirmRetries < 0 {
		return 0
	}
	if f.ConfirmRetries == 0 {
		return 2
	}
	return min(f.ConfirmRetries, 5)
}

func (f WatchdogFailoverConfig) AutoFailbackEnabled() bool {
	return f.FailbackCooldown >= 0
}

func (f WatchdogFailoverConfig) EffectiveFailbackCooldown() time.Duration {
	if f.FailbackCooldown < 0 {
		return -1
	}
	if f.FailbackCooldown == 0 {
		return 180 * time.Second
	}
	return time.Duration(f.FailbackCooldown) * time.Second
}

func (f WatchdogFailoverConfig) EffectiveMaxFailbackDelayMs() int {
	if f.MaxFailbackDelayMs <= 0 {
		return 600
	}
	return min(max(100, f.MaxFailbackDelayMs), 5000)
}

func (f WatchdogFailoverConfig) EffectiveProbeURLs() []string {
	if cleaned := cleanStringSlice(f.ProbeURLs); len(cleaned) > 0 {
		return cleaned
	}
	return slices.Clone(DefaultWatchdogProbeURLs)
}

func (f *WatchdogFailoverConfig) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		Enabled            *bool    `yaml:"enabled"`
		Groups             []string `yaml:"groups"`
		PatrolInterval     any      `yaml:"patrol_interval"`
		ProbeTimeoutMs     any      `yaml:"probe_timeout_ms"`
		ConfirmRetries     any      `yaml:"confirm_retries"`
		FailbackCooldown   any      `yaml:"failback_cooldown"`
		MaxFailbackDelayMs any      `yaml:"max_failback_delay_ms"`
		ProbeURLs          []string `yaml:"probe_urls"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	f.Enabled = raw.Enabled
	f.Groups = cleanStringSlice(raw.Groups)
	f.ProbeURLs = cleanStringSlice(raw.ProbeURLs)
	if raw.PatrolInterval != nil {
		if v, err := parseIntAny(raw.PatrolInterval); err == nil {
			f.PatrolInterval = v
		}
	}
	if raw.ProbeTimeoutMs != nil {
		if v, err := parseIntAny(raw.ProbeTimeoutMs); err == nil {
			f.ProbeTimeoutMs = v
		}
	}
	if raw.ConfirmRetries != nil {
		if v, err := parseIntAny(raw.ConfirmRetries); err == nil {
			f.ConfirmRetries = v
		}
	}
	if raw.FailbackCooldown != nil {
		if v, err := parseIntAny(raw.FailbackCooldown); err == nil {
			f.FailbackCooldown = v
		}
	}
	if raw.MaxFailbackDelayMs != nil {
		if v, err := parseIntAny(raw.MaxFailbackDelayMs); err == nil {
			f.MaxFailbackDelayMs = v
		}
	}
	return nil
}

type WatchdogConfig struct {
	Interval             int                    `yaml:"interval"`                         // 检查间隔(秒), 默认 180
	ConfirmWait          int                    `yaml:"confirm_wait"`                     // 二次确认等待(秒), 默认 30
	MaxRestarts          int                    `yaml:"max_restarts"`                     // 每小时最大自动重启次数, 默认 3
	SubSyncInterval      int                    `yaml:"sub_sync_interval,omitempty"`      // 订阅节点指纹自动热同步间隔(秒), 默认 600; 设为 -1 关闭
	PreserveManualConfig *bool                  `yaml:"preserve_manual_config,omitempty"` // 刷新订阅或更新版本时是否自动保留 config.json 手动修改(默认 true)
	AutoStart            *bool                  `yaml:"auto_start,omitempty"`             // 是否启用路由器开机自启动与掉电恢复（nil 默认 true）
	Failover             WatchdogFailoverConfig `yaml:"failover,omitempty"`               // 策略组自动故障切换配置(默认开启)
}

func (w WatchdogConfig) ShouldPreserveManualConfig() bool {
	if w.PreserveManualConfig == nil {
		return true
	}
	return *w.PreserveManualConfig
}

func (w *WatchdogConfig) SetPreserveManualConfig(preserve bool) {
	if preserve {
		w.PreserveManualConfig = nil
		return
	}
	v := false
	w.PreserveManualConfig = &v
}

// IsAutoStartEnabled 返回是否启用开机自启动与掉电恢复（未配置时默认开启）。
func (w WatchdogConfig) IsAutoStartEnabled() bool {
	if w.AutoStart == nil {
		return true
	}
	return *w.AutoStart
}

// SetAutoStart 显式设置开机自启动开关值。
func (w *WatchdogConfig) SetAutoStart(enabled bool) {
	if w == nil {
		return
	}
	v := enabled
	w.AutoStart = &v
}

func (w *WatchdogConfig) UnmarshalYAML(node *yaml.Node) error {
	var a struct {
		Interval             any                    `yaml:"interval"`
		ConfirmWait          any                    `yaml:"confirm_wait"`
		MaxRestarts          any                    `yaml:"max_restarts"`
		SubSyncInterval      any                    `yaml:"sub_sync_interval"`
		PreserveManualConfig *bool                  `yaml:"preserve_manual_config"`
		AutoStart            *bool                  `yaml:"auto_start"`
		Failover             WatchdogFailoverConfig `yaml:"failover"`
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
	if a.SubSyncInterval != nil {
		if v, err := parseIntAny(a.SubSyncInterval); err == nil {
			w.SubSyncInterval = v
		}
	}
	w.PreserveManualConfig = a.PreserveManualConfig
	w.AutoStart = a.AutoStart
	w.Failover = a.Failover
	return nil
}
