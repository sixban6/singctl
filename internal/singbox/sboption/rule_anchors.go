// 文件职责：提供类型化的 sing-box 路由与 DNS 规则谓词及确定性锚点插入定位器，消除手写下标扫描与字典长度盲猜。
package sboption

import (
	"slices"
	"strings"
)

// IsSniffRouteRule 判断是否为协议嗅探引导规则。
func IsSniffRouteRule(r RouteRule) bool {
	return strings.EqualFold(strings.TrimSpace(r.Action), "sniff")
}

// IsHijackDNSRouteRule 判断是否为 DNS 劫持引导规则。
func IsHijackDNSRouteRule(r RouteRule) bool {
	return strings.EqualFold(strings.TrimSpace(r.Action), "hijack-dns")
}

// IsPrivateIPRouteRule 判断是否显式声明了 ip_is_private 规则字段。
func IsPrivateIPRouteRule(r RouteRule) bool {
	return r.IPIsPrivate != nil
}

func routeRuleHasAnyRuleSetTag(r RouteRule, targets ...string) bool {
	for _, tag := range r.RuleSet.Slice() {
		if slices.Contains(targets, tag) {
			return true
		}
	}
	if r.Type == "logical" && r.Mode == "and" {
		for _, sub := range r.Rules {
			if routeRuleHasAnyRuleSetTag(sub, targets...) {
				return true
			}
		}
	}
	return false
}

// IsAdBlockRouteRule 判断是否为内置去广告规则集拦截规则（geosite-ad1 / geosite-ad2，含白名单逻辑反选包装态）。
func IsAdBlockRouteRule(r RouteRule) bool {
	if !strings.EqualFold(strings.TrimSpace(r.Action), "reject") {
		return false
	}
	return routeRuleHasAnyRuleSetTag(r, "geosite-ad1", "geosite-ad2")
}

// IsRegionSplitRouteRule 判断是否为国内/海外兜底分流规则（geosite-cn / geosite-geolocation-!cn / geoip-cn）。
func IsRegionSplitRouteRule(r RouteRule) bool {
	for _, tag := range r.RuleSet.Slice() {
		if tag == "geosite-cn" || tag == "geosite-geolocation-!cn" || tag == "geoip-cn" {
			return true
		}
	}
	return false
}

// BlockRouteInsertIndex 返回审计黑名单阻断规则的高优挂载下标：
// 紧随 sniff / hijack-dns / ip_is_private / clash_mode 引导规则之后，排在所有业务与规则集之前。
func BlockRouteInsertIndex(rules []RouteRule) int {
	idx := 0
	for i, r := range rules {
		if IsSniffRouteRule(r) || IsHijackDNSRouteRule(r) || IsPrivateIPRouteRule(r) || strings.TrimSpace(r.ClashMode) != "" {
			idx = i + 1
		}
	}
	return idx
}

// DNSBypassRejectInsertIndex 返回防 DoT/公共 DoH 绕过拦截规则的挂载下标（sniff / hijack-dns / ip_is_private=true 之后）。
func DNSBypassRejectInsertIndex(rules []RouteRule) int {
	idx := 0
	for i, r := range rules {
		isPrivTrue := r.IPIsPrivate != nil && *r.IPIsPrivate
		if isPrivTrue || IsHijackDNSRouteRule(r) || IsSniffRouteRule(r) {
			idx = i + 1
		}
	}
	return idx
}

// CustomRouteInsertIndex 返回用户 custom_rules.route 的挂载下标：
// 优先插在 geosite-ad1 之前；若无 geosite-ad1 则回退到首条 ip_is_private 之后，否则追加至末尾。
func CustomRouteInsertIndex(rules []RouteRule) int {
	privateIdx := -1
	for i, r := range rules {
		if IsPrivateIPRouteRule(r) && privateIdx < 0 {
			privateIdx = i + 1
		}
		if routeRuleHasAnyRuleSetTag(r, "geosite-ad1") {
			return i
		}
	}
	if privateIdx >= 0 {
		return privateIdx
	}
	return len(rules)
}

// TrafficRouteInsertIndex 返回智能分流预设路由规则的挂载下标：
// 首选 geosite-ad1/ad2 拦截之后；次选国内/海外兜底规则之前；保底跳过前序系统级/reject 规则。
func TrafficRouteInsertIndex(rules []RouteRule) int {
	for i, r := range rules {
		if IsAdBlockRouteRule(r) {
			return i + 1
		}
	}
	for i, r := range rules {
		if IsRegionSplitRouteRule(r) {
			return i
		}
	}
	idx := 0
	for i, r := range rules {
		act := strings.ToLower(strings.TrimSpace(r.Action))
		if act == "sniff" || act == "hijack-dns" || act == "reject" || strings.TrimSpace(r.ClashMode) != "" || IsPrivateIPRouteRule(r) {
			idx = i + 1
		}
	}
	return idx
}

// IsCatchAllUDPDirectRouteRule 判断是否为通用大端口段 UDP 直连兜底规则（udp 1024:65535 -> #DC）。
func IsCatchAllUDPDirectRouteRule(r RouteRule, isDirect func(string) bool) bool {
	act := strings.TrimSpace(r.Action)
	if act != "" && act != "route" {
		return false
	}
	if !slices.Equal(lowerTrimmedSlice(r.Network.Slice()), []string{"udp"}) {
		return false
	}
	if isDirect == nil || !isDirect(r.Outbound) {
		return false
	}
	if !slices.Contains(r.PortRange.Slice(), "1024:65535") {
		return false
	}
	return r.Domain.IsEmpty() && r.DomainSuffix.IsEmpty() && r.RuleSet.IsEmpty() && r.IPCIDR.IsEmpty()
}

// STUNRejectInsertIndex 返回海外 WebRTC STUN 防泄漏规则的挂载下标：
// 在 geoip-cn/geoip-private 直连规则之后、通用 udp 1024:65535 直连兜底之前。
func STUNRejectInsertIndex(rules []RouteRule, isDirect func(string) bool) int {
	afterGeoIPCN := -1
	for i, r := range rules {
		if IsCatchAllUDPDirectRouteRule(r, isDirect) {
			return i
		}
		act := strings.TrimSpace(r.Action)
		if (act == "" || act == "route") && isDirect != nil && isDirect(r.Outbound) {
			rs := r.RuleSet.Slice()
			if slices.Contains(rs, "geoip-cn") || slices.Contains(rs, "geoip-private") {
				afterGeoIPCN = i + 1
			}
		}
	}
	if afterGeoIPCN >= 0 {
		return afterGeoIPCN
	}
	return len(rules)
}

// CustomDNSInsertIndex 返回黑名单与自定义 DNS 规则的挂载下标（clash_mode 与 dns_tailscale 之后）。
func CustomDNSInsertIndex(rules []DNSRule) int {
	idx := 0
	for i, r := range rules {
		if strings.TrimSpace(r.ClashMode) != "" || strings.TrimSpace(r.Server) == "dns_tailscale" {
			idx = i + 1
		}
	}
	return idx
}

// TrafficDNSInsertIndex 返回智能分流预设 DNS 规则的挂载下标（geosite-cn/!cn 之前，否则 clash_mode/reject 之后）。
func TrafficDNSInsertIndex(rules []DNSRule) int {
	for i, r := range rules {
		for _, tag := range r.RuleSet.Slice() {
			if tag == "geosite-cn" || tag == "geosite-geolocation-!cn" {
				return i
			}
		}
	}
	idx := 0
	for i, r := range rules {
		if strings.TrimSpace(r.ClashMode) != "" || strings.EqualFold(strings.TrimSpace(r.Action), "reject") {
			idx = i + 1
		}
	}
	return idx
}

// BeforeGeositeCNDNSInsertIndex 返回 geosite-cn / geosite-geolocation-!cn 之前的 DNS 规则插入下标。
func BeforeGeositeCNDNSInsertIndex(rules []DNSRule) int {
	for i, r := range rules {
		rs := r.RuleSet.Slice()
		if slices.Contains(rs, "geosite-cn") || slices.Contains(rs, "geosite-geolocation-!cn") {
			return i
		}
	}
	return len(rules)
}

// hasOnlyRouteMatchers 校验路由规则除 allowed 集合外不包含任何其他匹配条件或未知扩展属性，
// 用显式语义契约替代旧代码中脆弱的 len(rule) == 2 / len(rule) == 3 字典长度猜测。
func hasOnlyRouteMatchers(r RouteRule, allowed ...string) bool {
	if len(r.Extra) > 0 || r.Type != "" || r.Mode != "" || len(r.Rules) > 0 || r.Outbound != "" {
		return false
	}
	has := func(k string) bool { return slices.Contains(allowed, k) }
	if r.ClashMode != "" && !has("clash_mode") {
		return false
	}
	if r.Invert != nil && !has("invert") {
		return false
	}
	if r.IPIsPrivate != nil && !has("ip_is_private") {
		return false
	}
	if !r.Network.IsEmpty() && !has("network") {
		return false
	}
	if !r.Protocol.IsEmpty() && !has("protocol") {
		return false
	}
	if !r.Port.IsEmpty() && !has("port") {
		return false
	}
	if !r.PortRange.IsEmpty() && !has("port_range") {
		return false
	}
	if !r.RuleSet.IsEmpty() && !has("rule_set") {
		return false
	}
	if !r.Domain.IsEmpty() && !has("domain") {
		return false
	}
	if !r.DomainSuffix.IsEmpty() && !has("domain_suffix") {
		return false
	}
	if !r.DomainKeyword.IsEmpty() && !has("domain_keyword") {
		return false
	}
	if !r.DomainRegex.IsEmpty() && !has("domain_regex") {
		return false
	}
	if !r.IPCIDR.IsEmpty() && !has("ip_cidr") {
		return false
	}
	if !r.SourceIPCIDR.IsEmpty() && !has("source_ip_cidr") {
		return false
	}
	return true
}

// IsManagedDNSBypassRejectRouteRule 显式识别受管 DoT 853 / 国内公共 DoH 拦截规则。
func IsManagedDNSBypassRejectRouteRule(r RouteRule, dohCIDRs, dohDomains []string) bool {
	if r.Action != "reject" {
		return false
	}
	ports := r.Port.Slice()
	if slices.Equal(ports, []uint16{853}) && hasOnlyRouteMatchers(r, "port") {
		return true
	}
	if isPortPair16(ports, 443, 853) {
		if slices.Equal(r.IPCIDR.Slice(), dohCIDRs) && hasOnlyRouteMatchers(r, "port", "ip_cidr") {
			return true
		}
		if slices.Equal(r.Domain.Slice(), dohDomains) && hasOnlyRouteMatchers(r, "port", "domain") {
			return true
		}
	}
	return false
}

// IsManagedSTUNRejectRouteRule 显式识别受管 STUN 防泄漏拦截规则。
func IsManagedSTUNRejectRouteRule(r RouteRule) bool {
	if r.Action != "reject" {
		return false
	}
	if slices.Equal(r.Protocol.Slice(), []string{"stun"}) && hasOnlyRouteMatchers(r, "protocol") {
		return true
	}
	if slices.Equal(r.Network.Slice(), []string{"udp"}) {
		if slices.Equal(r.Port.Slice(), []uint16{3478, 3479, 5349}) && hasOnlyRouteMatchers(r, "network", "port") {
			return true
		}
		if slices.Equal(r.PortRange.Slice(), []string{"19302:19309"}) && hasOnlyRouteMatchers(r, "network", "port_range") {
			return true
		}
	}
	return false
}

// IsManagedIPv6RejectRouteRule 显式识别受管 IPv6 (::/0) 阻断规则（含逻辑 AND 孪生规则与历史平铺规则）。
func IsManagedIPv6RejectRouteRule(r RouteRule) bool {
	if r.Action != "reject" {
		return false
	}
	if slices.Equal(r.IPCIDR.Slice(), []string{"::/0"}) {
		return true
	}
	if r.Type != "logical" || r.Mode != "and" || len(r.Rules) != 2 {
		return false
	}
	tail := r.Rules[1]
	return tail.Action == "" && slices.Equal(tail.IPCIDR.Slice(), []string{"::/0"}) && hasOnlyRouteMatchers(tail, "ip_cidr")
}

// IsManagedAAAASuppressDNSRule 识别受管 AAAA / AAAA+HTTPS NOERROR 抑制规则（含旧版兼容）。
func IsManagedAAAASuppressDNSRule(r DNSRule) bool {
	if r.Action != "predefined" || !strings.EqualFold(r.Rcode, "NOERROR") || !r.Answer.IsEmpty() || r.Invert != nil {
		return false
	}
	qts := upperTrimmedSlice(r.QueryType.Slice())
	switch len(qts) {
	case 1:
		return qts[0] == "AAAA"
	case 2:
		return (qts[0] == "AAAA" && qts[1] == "HTTPS") || (qts[0] == "HTTPS" && qts[1] == "AAAA")
	default:
		return false
	}
}

// IsManagedCNDirectDNSRule 识别自动补齐到 dns_local 的国内直连规则集规则。
func IsManagedCNDirectDNSRule(r DNSRule, extraCNRuleSets []string) bool {
	if r.Server != "dns_local" || r.Action != "" || r.ClashMode != "" || r.Type != "" || len(r.Rules) > 0 || len(r.Extra) > 0 {
		return false
	}
	if r.Strategy != "" || r.DisableCache != nil || r.RewriteTTL != nil || r.Rcode != "" || !r.Answer.IsEmpty() || r.Invert != nil {
		return false
	}
	if !r.Domain.IsEmpty() || !r.DomainSuffix.IsEmpty() || !r.DomainKeyword.IsEmpty() ||
		!r.DomainRegex.IsEmpty() || !r.SourceIPCIDR.IsEmpty() || !r.QueryType.IsEmpty() {
		return false
	}
	tags := r.RuleSet.Slice()
	if len(tags) == 0 {
		return false
	}
	for _, tag := range tags {
		if !slices.Contains(extraCNRuleSets, tag) {
			return false
		}
	}
	return true
}

// IsManagedPrivatePTRDNSRule 识别受管 RFC 6303 私网反查与 DNS-SD 浏览域本地 NXDOMAIN 规则。
func IsManagedPrivatePTRDNSRule(r DNSRule, ptrSuffixes []string, dnsSDKeyword string) (isSuffix, isKeyword bool) {
	if r.Action != "predefined" || !strings.EqualFold(r.Rcode, "NXDOMAIN") {
		return false, false
	}
	return slices.Equal(r.DomainSuffix.Slice(), ptrSuffixes), slices.Equal(r.DomainKeyword.Slice(), []string{dnsSDKeyword})
}

func isPortPair16(ports []uint16, a, b uint16) bool {
	return len(ports) == 2 && ((ports[0] == a && ports[1] == b) || (ports[0] == b && ports[1] == a))
}

func lowerTrimmedSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

func upperTrimmedSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToUpper(strings.TrimSpace(s))
	}
	return out
}
