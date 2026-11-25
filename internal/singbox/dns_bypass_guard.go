// 文件职责：实现声明式四层防 DNS 绕过拦截引擎（L1 DoT/DoQ、L2 国内外公共 DoH、L3 云厂商 HTTPDNS SDK、L4 大厂 App 自建 HTTPDNS）及横向源 IP 豁免与白名单优先编译。
package singbox

import (
	"net/netip"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

// DNSBypassAppGroupMeta 描述 L4 层单个大厂 App 自建 HTTPDNS 分组的元数据与受管域名/专用 VIP IP 清单。
type DNSBypassAppGroupMeta struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Desc           string   `json:"desc"`
	Risk           string   `json:"risk"` // "medium" | "high"
	DefaultEnabled bool     `json:"defaultEnabled"`
	Enabled        bool     `json:"enabled"`
	Domains        []string `json:"domains"`
	IPs            []string `json:"ips,omitempty"`
}

// DNSBypassLayerMeta 描述 L1~L4 单个防绕过拦截层的展示元数据与生效状态。
type DNSBypassLayerMeta struct {
	ID             string   `json:"id"`
	Level          string   `json:"level"`
	Name           string   `json:"name"`
	Desc           string   `json:"desc"`
	Ports          []uint16 `json:"ports"`
	Risk           string   `json:"risk"`
	DefaultEnabled bool     `json:"defaultEnabled"`
	Enabled        bool     `json:"enabled"`
	IPCount        int      `json:"ipCount"`
	DomainCount    int      `json:"domainCount"`
}

// DNSBypassGuardSnapshot 汇总四层防绕过策略目录、当前生效配置与横向豁免清单（供 WebUI 控制面展示与编辑）。
type DNSBypassGuardSnapshot struct {
	Enabled         bool                    `json:"enabled"`
	Layers          []DNSBypassLayerMeta    `json:"layers"`
	AppGroups       []DNSBypassAppGroupMeta `json:"appGroups"`
	ExemptSourceIPs []string                `json:"exemptSourceIps"`
	ActiveRuleCount int                     `json:"activeRuleCount"`
}

// L2 国内外公共 DoH/DoT IP 清单（443 / 853）
var publicDoHIPCIDRs = []string{
	// 国内公共 DNS (IPv4)
	"223.5.5.5/32",
	"223.6.6.6/32",
	"119.29.29.29/32",
	"119.28.28.28/32",
	"120.53.53.53/32",
	"1.12.12.12/32",
	"114.114.114.114/32",
	"114.114.115.115/32",
	"180.76.76.76/32",
	"180.184.1.1/32",
	"180.184.2.2/32",
	// 国内公共 DNS (IPv6)
	"2400:3200::1/128",
	"2400:3200:baba::1/128",
	"2402:4e00::/128",
	"2402:4e00:1::/128",
	"240c::6666/128",
	"240c::6644/128",
	// 海外公共 DNS (IPv4)
	"1.1.1.1/32",
	"1.0.0.1/32",
	"8.8.8.8/32",
	"8.8.4.4/32",
	"9.9.9.9/32",
	"149.112.112.112/32",
	"94.140.14.14/32",
	"94.140.15.15/32",
	"208.67.222.222/32",
	"208.67.220.220/32",
	// 海外公共 DNS (IPv6)
	"2606:4700:4700::1111/128",
	"2606:4700:4700::1001/128",
	"2001:4860:4860::8888/128",
	"2001:4860:4860::8844/128",
	"2620:fe::fe/128",
	"2620:fe::9/128",
}

// L2 国内外公共 DoH/DoT 域名清单（443 / 853）
var publicDoHDomains = []string{
	// 国内
	"dns.alidns.com",
	"doh.pub",
	"dns.pub",
	"sm2.doh.pub",
	"dot.pub",
	"doh.360.cn",
	"dns.360.cn",
	// 海外
	"dns.google",
	"dns.google.com",
	"cloudflare-dns.com",
	"mozilla.cloudflare-dns.com",
	"one.one.one.one",
	"dns.quad9.net",
	"dns.nextdns.io",
	"dns.adguard-dns.com",
	"dns.adguard.com",
	"doh.opendns.com",
}

// L3 国内云厂商通用 HTTPDNS SDK IP 清单（补齐 80 + 443 双端口）
var sdkHTTPDNSIPCIDRs = []string{
	"203.107.1.0/24",  // 阿里云 HTTPDNS (淘宝/高德/优酷/钉钉/微博/B站等大批 App 共用)
	"119.29.29.29/32", // 腾讯云 DNSPod HTTPDNS (80/443)
	"119.28.28.28/32", // 腾讯云 DNSPod HTTPDNS 备 (80/443)
	"180.76.76.76/32", // 百度云 HTTPDNS (80/443)
	"180.76.76.112/32", // 百度云 HTTPDNS 专用调度 VIP (httpsdns.baidu.com)
	"180.184.1.1/32",  // 火山引擎 HTTPDNS (80/443)
	"180.184.2.2/32",  // 火山引擎 HTTPDNS 备 (80/443)
}

// L3 国内云厂商通用 HTTPDNS SDK 域名清单（80 / 443）
var sdkHTTPDNSDomains = []string{
	"httpdns.alicdn.com",
	"httpdns-api.aliyuncs.com",
	"httpdns.aliyuncs.com",
	"httpdns-sc.aliyuncs.com",
	"resolvers-cn.httpdns.aliyuncs.com",
	"httpdns.qcloud.com",
	"httpdns.baidubce.com",
	"httpsdns.baidu.com",
	"httpdns.volcengineapi.com",
	"dig.bdurl.net",
	"httpdns.platform.dbankcloud.com",
	"httpdns.platform.dbankcloud.cn",
}

// L4 国内大厂 App 自建 HTTPDNS 声明式注册表（OCP 扩展点：新增 App 仅追加表项）
var appHTTPDNSGroupCatalog = []DNSBypassAppGroupMeta{
	{
		ID:             "bilibili",
		Name:           "B 站 (Bilibili)",
		Desc:           "拦截 B 站自建视频/API HTTPDNS，回退网关 DNS 统一审计与去广告",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains:        []string{"httpdns.bilivideo.com", "httpdns.biliapi.net"},
	},
	{
		ID:             "bytedance",
		Name:           "字节 / 抖音系",
		Desc:           "拦截字节自建 HTTPDNS（不触碰 tnc* 业务配置接口）",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains:        []string{"httpdns.bytedance.com"},
	},
	{
		ID:             "jd",
		Name:           "京东 (JD)",
		Desc:           "拦截京东内置 HTTPDNS 调度",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains:        []string{"dns.jd.com"},
	},
	{
		ID:             "netease",
		Name:           "网易系",
		Desc:           "拦截网易云音乐/新闻等通用 HTTPDNS",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains:        []string{"httpdns.n.netease.com"},
	},
	{
		ID:             "meituan",
		Name:           "美团 / 点评",
		Desc:           "拦截美团/点评自建 HTTPDNS 域名及专用 VIP 直连 IP（不触碰共享业务 API VIP）",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains: []string{
			"httpdns.meituan.com",
			"httpdnsvip.meituan.com",
			"httpdnsmultiapi.meituan.com",
			"httpdnsmultiapivip.meituan.com",
		},
		// 仅收录已实测验证仅响应 /fetch HTTPDNS 接口、对业务 API Host 返回 404 的专用 VIP IP，
		// 严禁收录 inf-wan.vip.meituan.com 共享业务入口 IP 以免误伤点餐/支付。
		IPs: []string{
			"103.37.155.60/32",
			"103.37.152.97/32",
			"103.37.152.224/32",
			"203.76.217.49/32",
			"2405:1480:2000:3::5/128",
		},
	},
	{
		ID:             "ctrip",
		Name:           "携程",
		Desc:           "拦截携程自建 HTTPDNS",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains:        []string{"httpdns.ctrip.com"},
	},
	{
		ID:             "oem",
		Name:           "华为 / OV / 小米",
		Desc:           "拦截手机厂商应用 HTTPDNS（刻意保留小米系统推送不误杀）",
		Risk:           "medium",
		DefaultEnabled: true,
		Domains: []string{
			"httpdns.c.cdnhwc2.com",
			"httpdns.push.oppomobile.com",
			"httpdns.vivo.com.cn",
			"httpdns.music.xiaomi.com",
		},
	},
	{
		ID:             "wechat",
		Name:           "微信专有调度 (高风险)",
		Desc:           "拦截微信内置 HTTPDNS；高误伤风险：可能导致搜一搜表情加载慢或裂图，默认关闭",
		Risk:           "high",
		DefaultEnabled: false,
		Domains:        []string{"dns.weixin.qq.com", "dns.weixin.qq.com.cn", "aedns.weixin.qq.com"},
	},
}

// 预计算的受管特征集合，用于精准识别并清理历史/当前受管规则而不伤及用户自定义规则。
var (
	managedBypassAllCIDRSet   = buildBypassCIDRSet()
	managedBypassAllDomainSet = buildBypassDomainSet()
)

func buildBypassCIDRSet() map[string]struct{} {
	set := make(map[string]struct{}, len(publicDoHIPCIDRs)+len(sdkHTTPDNSIPCIDRs)+8)
	for _, s := range publicDoHIPCIDRs {
		set[s] = struct{}{}
	}
	for _, s := range sdkHTTPDNSIPCIDRs {
		set[s] = struct{}{}
	}
	for _, g := range appHTTPDNSGroupCatalog {
		for _, ip := range g.IPs {
			set[ip] = struct{}{}
		}
	}
	return set
}

func buildBypassDomainSet() map[string]struct{} {
	set := make(map[string]struct{}, len(publicDoHDomains)+len(sdkHTTPDNSDomains)+16)
	for _, s := range publicDoHDomains {
		set[s] = struct{}{}
	}
	for _, s := range sdkHTTPDNSDomains {
		set[s] = struct{}{}
	}
	for _, g := range appHTTPDNSGroupCatalog {
		for _, d := range g.Domains {
			set[d] = struct{}{}
		}
	}
	return set
}

// WeChatProprietaryHTTPDNSDomains 返回微信专有 HTTPDNS 域名清单副本（用于与去广告默认白名单互斥联动）。
func WeChatProprietaryHTTPDNSDomains() []string {
	for _, g := range appHTTPDNSGroupCatalog {
		if g.ID == "wechat" {
			return slices.Clone(g.Domains)
		}
	}
	return nil
}

// IsWeChatHTTPDNSRejectActive 判断当前配置是否显式开启了 L4 微信专有 HTTPDNS 拦截。
func IsWeChatHTTPDNSRejectActive(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	bg := cfg.DNS.BypassGuard
	return bg.IsEnabled() && bg.LayerAppHTTPDNS() && bg.IsAppGroupEnabled("wechat")
}

func buildWhitelistDomainSet(cfg *config.Config) map[string]struct{} {
	set := make(map[string]struct{})
	if cfg == nil {
		return set
	}
	for _, raw := range cfg.DNS.Whitelist {
		if dom, ok := NormalizeWhitelistDomain(raw); ok {
			set[dom] = struct{}{}
		}
	}
	for _, raw := range cfg.Audit.Whitelist {
		if dom, ok := NormalizeWhitelistDomain(raw); ok {
			set[dom] = struct{}{}
		}
	}
	return set
}

func filterNonWhitelistedDomains(domains []string, wl map[string]struct{}) []string {
	if len(domains) == 0 {
		return nil
	}
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if _, exempt := wl[strings.ToLower(strings.TrimSpace(d))]; exempt {
			continue
		}
		out = append(out, d)
	}
	return out
}

func normalizeExemptCIDRsSafe(raw []string) []string {
	norm, err := config.NormalizeExemptSourceIPs(raw)
	if err == nil {
		return norm
	}
	// 兜底逐条保留合法项，避免脏配置文件阻断编译
	var out []string
	for _, item := range raw {
		s := strings.TrimSpace(item)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			if p, pErr := netip.ParsePrefix(s); pErr == nil && p.Bits() > 0 {
				out = append(out, p.Masked().String())
			}
		} else if a, aErr := netip.ParseAddr(s); aErr == nil && !a.IsLoopback() && !a.IsUnspecified() {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()).String())
		}
	}
	return out
}

func wrapWithExemptSourceIPs(rule sboption.RouteRule, exemptCIDRs []string) sboption.RouteRule {
	if len(exemptCIDRs) == 0 {
		return rule
	}
	base := rule.Clone()
	action := base.Action
	base.Action = ""
	inv := true
	return sboption.RouteRule{
		Type:   "logical",
		Mode:   "and",
		Action: action,
		Rules: []sboption.RouteRule{
			base,
			{
				Invert:       &inv,
				SourceIPCIDR: sboption.ListOf(exemptCIDRs...),
			},
		},
	}
}

func buildDNSBypassRouteRules(cfg *config.Config) []sboption.RouteRule {
	var bg config.DNSBypassGuardConfig
	if cfg != nil {
		bg = cfg.DNS.BypassGuard
	}
	if !bg.IsEnabled() {
		return nil
	}

	wl := buildWhitelistDomainSet(cfg)
	exempt := normalizeExemptCIDRsSafe(bg.ExemptSourceIPs)
	var rules []sboption.RouteRule

	// L1: 全量 DoT / DoQ 专用 853 端口
	if bg.LayerDoTDoQ() {
		rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
			Action: "reject",
			Port:   sboption.ScalarOf[uint16](853),
		}, exempt))
	}

	// L2: 国内外公共 DoH IP + 域名 (443 / 853)
	if bg.LayerPublicDoH() {
		rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
			Action: "reject",
			IPCIDR: sboption.ListOf(publicDoHIPCIDRs...),
			Port:   sboption.ListOf[uint16](443, 853),
		}, exempt))
		if doms := filterNonWhitelistedDomains(publicDoHDomains, wl); len(doms) > 0 {
			rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
				Action: "reject",
				Domain: sboption.ListOf(doms...),
				Port:   sboption.ListOf[uint16](443, 853),
			}, exempt))
		}
	}

	// L3: 国内云厂商通用 HTTPDNS SDK (80 / 443)
	if bg.LayerSDKHTTPDNS() {
		rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
			Action: "reject",
			IPCIDR: sboption.ListOf(sdkHTTPDNSIPCIDRs...),
			Port:   sboption.ListOf[uint16](80, 443),
		}, exempt))
		if doms := filterNonWhitelistedDomains(sdkHTTPDNSDomains, wl); len(doms) > 0 {
			rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
				Action: "reject",
				Domain: sboption.ListOf(doms...),
				Port:   sboption.ListOf[uint16](80, 443),
			}, exempt))
		}
	}

	// L4: 大厂 App 自建 HTTPDNS (80 / 443，按家族细粒度拼装域名 + 专用 VIP 直连 IP)
	if bg.LayerAppHTTPDNS() {
		var appDomains []string
		var appIPs []string
		for _, grp := range appHTTPDNSGroupCatalog {
			if !bg.IsAppGroupEnabled(grp.ID) {
				continue
			}
			appDomains = append(appDomains, grp.Domains...)
			appIPs = append(appIPs, grp.IPs...)
		}
		if len(appIPs) > 0 {
			rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
				Action: "reject",
				IPCIDR: sboption.ListOf(appIPs...),
				Port:   sboption.ListOf[uint16](80, 443),
			}, exempt))
		}
		if doms := filterNonWhitelistedDomains(appDomains, wl); len(doms) > 0 {
			rules = append(rules, wrapWithExemptSourceIPs(sboption.RouteRule{
				Action: "reject",
				Domain: sboption.ListOf(doms...),
				Port:   sboption.ListOf[uint16](80, 443),
			}, exempt))
		}
	}

	return rules
}

func allInSet(items []string, set map[string]struct{}) bool {
	if len(items) == 0 {
		return false
	}
	for _, s := range items {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func isPortPairExact(ports []uint16, a, b uint16) bool {
	return len(ports) == 2 && ((ports[0] == a && ports[1] == b) || (ports[0] == b && ports[1] == a))
}

func isPureInvertSourceIPRouteRule(r sboption.RouteRule) bool {
	if r.Invert == nil || !*r.Invert || r.Type != "" || r.Action != "" || r.SourceIPCIDR.IsEmpty() || len(r.Extra) > 0 {
		return false
	}
	return r.RuleSet.IsEmpty() && r.Domain.IsEmpty() && r.DomainSuffix.IsEmpty() &&
		r.DomainKeyword.IsEmpty() && r.DomainRegex.IsEmpty() && r.IPCIDR.IsEmpty() &&
		r.Network.IsEmpty() && r.Protocol.IsEmpty() && r.Port.IsEmpty() && r.PortRange.IsEmpty() &&
		r.IPIsPrivate == nil && r.ClashMode == ""
}

func isManagedBypassBaseMatcher(r sboption.RouteRule) bool {
	if r.Type != "" || r.Outbound != "" || r.Invert != nil || len(r.Extra) > 0 {
		return false
	}
	if !r.SourceIPCIDR.IsEmpty() || !r.RuleSet.IsEmpty() || !r.DomainSuffix.IsEmpty() ||
		!r.DomainKeyword.IsEmpty() || !r.DomainRegex.IsEmpty() || !r.Network.IsEmpty() ||
		!r.Protocol.IsEmpty() || !r.PortRange.IsEmpty() || r.IPIsPrivate != nil || r.ClashMode != "" {
		return false
	}
	ports := r.Port.Slice()
	// L1: port 853 only
	if slices.Equal(ports, []uint16{853}) && r.IPCIDR.IsEmpty() && r.Domain.IsEmpty() {
		return true
	}
	// L2 (443/853) or L3/L4 (80/443)
	if isPortPairExact(ports, 443, 853) || isPortPairExact(ports, 80, 443) {
		if !r.IPCIDR.IsEmpty() && r.Domain.IsEmpty() && allInSet(r.IPCIDR.Slice(), managedBypassAllCIDRSet) {
			return true
		}
		if !r.Domain.IsEmpty() && r.IPCIDR.IsEmpty() && allInSet(r.Domain.Slice(), managedBypassAllDomainSet) {
			return true
		}
	}
	return false
}

// IsManagedLayeredDNSBypassRouteRule 精准识别当前 L1~L4 与历史旧版受管防 DNS 绕过 reject 规则（绝不误删用户规则）。
func IsManagedLayeredDNSBypassRouteRule(r sboption.RouteRule) bool {
	if r.Action != "reject" {
		return false
	}
	if sboption.IsManagedDNSBypassRejectRouteRule(r, cnPublicDoHIPCIDRs, cnPublicDoHDomains) {
		return true
	}
	if r.Type == "" {
		return isManagedBypassBaseMatcher(r)
	}
	if r.Type == "logical" && r.Mode == "and" && len(r.Rules) == 2 {
		head := r.Rules[0]
		tail := r.Rules[1]
		return head.Action == "" && isManagedBypassBaseMatcher(head) && isPureInvertSourceIPRouteRule(tail)
	}
	return false
}

// ApplyDNSBypassGuardToDoc 在 *sboption.Document 内存树上幂等同步四层防 DNS 绕过规则。
func ApplyDNSBypassGuardToDoc(doc *sboption.Document, cfg *config.Config) bool {
	if doc == nil || doc.Route == nil {
		return false
	}
	origLen := len(doc.Route.Rules)
	cleaned := make([]sboption.RouteRule, 0, origLen)
	removed := 0
	for _, r := range doc.Route.Rules {
		if IsManagedLayeredDNSBypassRouteRule(r) {
			removed++
			continue
		}
		cleaned = append(cleaned, r)
	}

	desired := buildDNSBypassRouteRules(cfg)
	if removed == 0 && len(desired) == 0 {
		return false
	}

	insertAt := sboption.DNSBypassRejectInsertIndex(cleaned)
	nextRules := slices.Insert(slices.Clone(cleaned), insertAt, desired...)

	// 比较是否发生真实变更以保持严格幂等
	if len(nextRules) == len(doc.Route.Rules) {
		beforeDoc := &sboption.Document{Route: &sboption.RouteOptions{Rules: doc.Route.Rules}}
		afterDoc := &sboption.Document{Route: &sboption.RouteOptions{Rules: nextRules}}
		if b1, err1 := beforeDoc.MarshalCompact(); err1 == nil {
			if b2, err2 := afterDoc.MarshalCompact(); err2 == nil && b1 == b2 {
				return false
			}
		}
	}

	doc.Route.Rules = nextRules
	return true
}

// ApplyDNSBypassGuardToConfigJSON 离线/在线差量更新 sing-box config.json 中的分层防 DNS 绕过规则。
func ApplyDNSBypassGuardToConfigJSON(rawJSON string, cfg *config.Config) (string, bool, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, false, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", false, err
	}
	if !ApplyDNSBypassGuardToDoc(doc, cfg) {
		return rawJSON, false, nil
	}
	out, err := doc.MarshalPretty()
	if err != nil {
		return "", false, err
	}
	return out, true, nil
}

// InspectDNSBypassGuardStatus 生成供 WebUI 展示的四层防绕过目录与当前生效快照。
func InspectDNSBypassGuardStatus(cfg *config.Config) DNSBypassGuardSnapshot {
	var bg config.DNSBypassGuardConfig
	if cfg != nil {
		bg = cfg.DNS.BypassGuard
	}
	groups := make([]DNSBypassAppGroupMeta, 0, len(appHTTPDNSGroupCatalog))
	enabledAppDomainCount := 0
	enabledAppIPCount := 0
	for _, g := range appHTTPDNSGroupCatalog {
		item := g
		item.Domains = slices.Clone(g.Domains)
		item.IPs = slices.Clone(g.IPs)
		item.Enabled = bg.IsAppGroupEnabled(g.ID)
		if item.Enabled {
			enabledAppDomainCount += len(item.Domains)
			enabledAppIPCount += len(item.IPs)
		}
		groups = append(groups, item)
	}

	layers := []DNSBypassLayerMeta{
		{
			ID:             "dot_doq",
			Level:          "L1",
			Name:           "DoT / DoQ 专用端口层",
			Desc:           "拦截全量 TCP/UDP 853 加密 DNS 专用端口，逼退系统自动私人 DNS 回落至网关 :53",
			Ports:          []uint16{853},
			Risk:           "low",
			DefaultEnabled: true,
			Enabled:        bg.LayerDoTDoQ(),
		},
		{
			ID:             "public_doh",
			Level:          "L2",
			Name:           "国内外公共 DoH 层",
			Desc:           "拦截阿里/腾讯/114/百度/火山/360 与 Cloudflare/Google/Quad9/NextDNS/AdGuard 等公共 DoH",
			Ports:          []uint16{443, 853},
			Risk:           "low",
			DefaultEnabled: true,
			Enabled:        bg.LayerPublicDoH(),
			IPCount:        len(publicDoHIPCIDRs),
			DomainCount:    len(publicDoHDomains),
		},
		{
			ID:             "sdk_httpdns",
			Level:          "L3",
			Name:           "云厂商通用 HTTPDNS SDK 层",
			Desc:           "补齐 80/443 双端口，拦截阿里云 (203.107.1.0/24)、腾讯云、百度/火山/华为云通用 HTTPDNS SDK",
			Ports:          []uint16{80, 443},
			Risk:           "low",
			DefaultEnabled: true,
			Enabled:        bg.LayerSDKHTTPDNS(),
			IPCount:        len(sdkHTTPDNSIPCIDRs),
			DomainCount:    len(sdkHTTPDNSDomains),
		},
		{
			ID:             "app_httpdns",
			Level:          "L4",
			Name:           "大厂 App 自建 HTTPDNS 层",
			Desc:           "默认关闭（按需手动开启）：按 App 家族细粒度勾选拦截 B 站、字节、京东、网易、美团、携程、手机厂商及微信专有 HTTPDNS，避免封锁过死影响体验",
			Ports:          []uint16{80, 443},
			Risk:           "medium",
			DefaultEnabled: false,
			Enabled:        bg.LayerAppHTTPDNS(),
			IPCount:        enabledAppIPCount,
			DomainCount:    enabledAppDomainCount,
		},
	}

	exempt := slices.Clone(bg.ExemptSourceIPs)
	if exempt == nil {
		exempt = []string{}
	}

	return DNSBypassGuardSnapshot{
		Enabled:         bg.IsEnabled(),
		Layers:          layers,
		AppGroups:       groups,
		ExemptSourceIPs: exempt,
		ActiveRuleCount: len(buildDNSBypassRouteRules(cfg)),
	}
}
