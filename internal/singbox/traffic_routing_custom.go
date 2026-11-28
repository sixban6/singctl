// 文件职责：将客户端自定义定向出口规则编译为 sing-box 路由与 DNS 规则，并支持热更新精准剥离旧规则。
package singbox

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

type customTrafficSignatures struct {
	routeJSONs map[string]bool
	dnsJSONs   map[string]bool
}

func formatCustomSourceIPCIDR(rawIP string) (string, bool) {
	s := strings.TrimSpace(rawIP)
	if s == "" {
		return "", false
	}
	if pfx, err := netip.ParsePrefix(s); err == nil && pfx.IsSingleIP() {
		u := pfx.Addr().Unmap()
		return netip.PrefixFrom(u, u.BitLen()).String(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		u := addr.Unmap()
		return netip.PrefixFrom(u, u.BitLen()).String(), true
	}
	return "", false
}

func resolveCustomRuleOutbound(outbound string, groupTags []string, directTag string) (targetOutbound string, isDirect bool, ok bool) {
	ob := strings.TrimSpace(outbound)
	if ob == "" {
		return "", false, false
	}
	effDirect := cmp.Or(strings.TrimSpace(directTag), "#DC")
	if strings.EqualFold(ob, config.TrafficOutboundDirect) || ob == effDirect {
		return effDirect, true, true
	}
	if slices.Contains(groupTags, ob) {
		return ob, false, true
	}
	return "", false, false
}

func orderCustomTrafficRules(rules []config.TrafficCustomRule) []config.TrafficCustomRule {
	if len(rules) == 0 {
		return nil
	}
	normalized := make([]config.TrafficCustomRule, 0, len(rules))
	for _, raw := range rules {
		if nr, err := config.NormalizeTrafficCustomRule(raw); err == nil {
			normalized = append(normalized, nr)
		}
	}
	// 设备限定规则优先于全局规则；同作用域内按 domain -> domain_suffix -> ip_cidr 排序。
	matchRank := func(mt string) int {
		switch mt {
		case config.TrafficMatchDomain:
			return 0
		case config.TrafficMatchDomainSuffix:
			return 1
		case config.TrafficMatchIPCIDR:
			return 2
		default:
			return 3
		}
	}
	slices.SortStableFunc(normalized, func(a, b config.TrafficCustomRule) int {
		aScoped := 1
		if a.SourceIP != "" {
			aScoped = 0
		}
		bScoped := 1
		if b.SourceIP != "" {
			bScoped = 0
		}
		if c := cmp.Compare(aScoped, bScoped); c != 0 {
			return c
		}
		return cmp.Compare(matchRank(a.MatchType), matchRank(b.MatchType))
	})
	return normalized
}

func compileSingleCustomRouteRule(
	nr config.TrafficCustomRule,
	groupTags []string,
	directTag string,
	isIOS bool,
) (sboption.RouteRule, bool) {
	if isIOS && nr.SourceIP != "" {
		return sboption.RouteRule{}, false
	}
	targetOutbound, _, ok := resolveCustomRuleOutbound(nr.Outbound, groupTags, directTag)
	if !ok {
		return sboption.RouteRule{}, false
	}
	rule := sboption.RouteRule{
		Action:   "route",
		Outbound: targetOutbound,
	}
	switch nr.MatchType {
	case config.TrafficMatchDomain:
		rule.Domain = sboption.ListOf(nr.Target)
	case config.TrafficMatchDomainSuffix:
		rule.DomainSuffix = sboption.ListOf(nr.Target)
	case config.TrafficMatchIPCIDR:
		rule.IPCIDR = sboption.ListOf(nr.Target)
	default:
		return sboption.RouteRule{}, false
	}
	if srcCIDR, hasSrc := formatCustomSourceIPCIDR(nr.SourceIP); hasSrc {
		rule.SourceIPCIDR = sboption.ListOf(srcCIDR)
	}
	return rule, true
}

func compileCustomTrafficRouteRules(
	rules []config.TrafficCustomRule,
	groupTags []string,
	directTag string,
	isIOS bool,
) []sboption.RouteRule {
	ordered := orderCustomTrafficRules(rules)
	out := make([]sboption.RouteRule, 0, len(ordered))
	for _, nr := range ordered {
		if r, ok := compileSingleCustomRouteRule(nr, groupTags, directTag, isIOS); ok {
			out = append(out, r)
		}
	}
	return out
}

func compileSingleCustomDNSRule(
	nr config.TrafficCustomRule,
	groupTags []string,
	directTag, proxyDNS, directDNS string,
	isIOS bool,
) (sboption.DNSRule, bool) {
	if isIOS && nr.SourceIP != "" {
		return sboption.DNSRule{}, false
	}
	if nr.MatchType != config.TrafficMatchDomain && nr.MatchType != config.TrafficMatchDomainSuffix {
		return sboption.DNSRule{}, false
	}
	_, isDirect, ok := resolveCustomRuleOutbound(nr.Outbound, groupTags, directTag)
	if !ok {
		return sboption.DNSRule{}, false
	}
	server := proxyDNS
	if isDirect {
		server = directDNS
	}
	if strings.TrimSpace(server) == "" {
		return sboption.DNSRule{}, false
	}
	rule := sboption.DNSRule{Server: server}
	if nr.MatchType == config.TrafficMatchDomain {
		rule.Domain = sboption.ListOf(nr.Target)
	} else {
		rule.DomainSuffix = sboption.ListOf(nr.Target)
	}
	if srcCIDR, hasSrc := formatCustomSourceIPCIDR(nr.SourceIP); hasSrc {
		rule.SourceIPCIDR = sboption.ListOf(srcCIDR)
	}
	return rule, true
}

func compileCustomTrafficDNSRules(
	rules []config.TrafficCustomRule,
	groupTags []string,
	directTag, proxyDNS, directDNS string,
	isIOS bool,
) []sboption.DNSRule {
	ordered := orderCustomTrafficRules(rules)
	out := make([]sboption.DNSRule, 0, len(ordered))
	for _, nr := range ordered {
		if d, ok := compileSingleCustomDNSRule(nr, groupTags, directTag, proxyDNS, directDNS, isIOS); ok {
			out = append(out, d)
		}
	}
	return out
}

func buildCustomTrafficRuleSignatures(
	prevRules, curRules []config.TrafficCustomRule,
	groupTags []string,
	directTag, proxyDNS, directDNS string,
	isIOS bool,
) customTrafficSignatures {
	sig := customTrafficSignatures{
		routeJSONs: make(map[string]bool),
		dnsJSONs:   make(map[string]bool),
	}
	addAll := func(rules []config.TrafficCustomRule) {
		for _, r := range compileCustomTrafficRouteRules(rules, groupTags, directTag, isIOS) {
			if c, err := sboption.CanonicalJSON(r); err == nil {
				sig.routeJSONs[c] = true
			}
		}
		for _, d := range compileCustomTrafficDNSRules(rules, groupTags, directTag, proxyDNS, directDNS, isIOS) {
			if c, err := sboption.CanonicalJSON(d); err == nil {
				sig.dnsJSONs[c] = true
			}
		}
	}
	addAll(prevRules)
	addAll(curRules)
	return sig
}

func stripCustomTrafficRouteRules(rules []sboption.RouteRule, sig map[string]bool, crSig customSignature) []sboption.RouteRule {
	if len(sig) == 0 {
		return rules
	}
	out := make([]sboption.RouteRule, 0, len(rules))
	for _, r := range rules {
		if !isProtectedRule(r, crSig.routeJSONs) && isProtectedRule(r, sig) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func stripCustomTrafficDNSRules(rules []sboption.DNSRule, sig map[string]bool, crSig customSignature) []sboption.DNSRule {
	if len(sig) == 0 {
		return rules
	}
	out := make([]sboption.DNSRule, 0, len(rules))
	for _, d := range rules {
		if !isProtectedRule(d, crSig.dnsJSONs) && isProtectedRule(d, sig) {
			continue
		}
		out = append(out, d)
	}
	return out
}
