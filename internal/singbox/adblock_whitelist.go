// 文件职责：维护去广告规则集（geosite-ad1/ad2）反选放行白名单的编译阶段注入与在线差量热同步。
package singbox

import (
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox/sboption"
)

var adBlockWhitelistDomainRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)+$`)

// NormalizeWhitelistDomain 规范化白名单域名并剔除 IP、CIDR、localhost 与非法控制字符。
func NormalizeWhitelistDomain(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsAny(s, " \t\r\n\x00;'\"`\\") {
		return "", false
	}
	s = strings.TrimPrefix(s, "@@")
	s = strings.TrimPrefix(s, "||")
	if idx := strings.IndexByte(s, '^'); idx >= 0 {
		s = s[:idx]
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
			s = u.Hostname()
		}
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
			return "", false
		}
		s = s[:idx]
	}
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	s = strings.Trim(s, "[]")
	s = strings.TrimPrefix(s, "*.")
	s = strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 || s == "localhost" || net.ParseIP(s) != nil || strings.Contains(s, "..") {
		return "", false
	}
	if !adBlockWhitelistDomainRe.MatchString(s) {
		return "", false
	}
	return s, true
}

// EffectiveAdBlockWhitelist 汇总当前配置下应豁免 geosite-ad1/ad2 拦截的规范化域名集合：
// 内置防误杀基线（剔除 custom_rules.block 显式拉黑项） ∪ dns.whitelist ∪ audit.whitelist 域名项 ∪ 订阅域名。
func EffectiveAdBlockWhitelist(cfg *config.Config) []string {
	explicitlyBlocked := make(map[string]struct{})
	if cfg != nil {
		for _, b := range cfg.CustomRules.Block {
			if strings.TrimSpace(b.SourceIP) != "" {
				continue
			}
			norm, isIP := NormalizeBlockTarget(b.Target)
			if isIP || norm == "" || strings.HasPrefix(norm, "ruleset:") {
				continue
			}
			explicitlyBlocked[norm] = struct{}{}
		}
	}

	seen := make(map[string]struct{}, len(constant.DefaultAdBlockSafeDomains)+8)
	addDomain := func(raw string) {
		dom, ok := NormalizeWhitelistDomain(raw)
		if !ok {
			return
		}
		seen[dom] = struct{}{}
	}

	for _, safeDom := range constant.DefaultAdBlockSafeDomains {
		if dom, ok := NormalizeWhitelistDomain(safeDom); ok {
			if _, blocked := explicitlyBlocked[dom]; !blocked {
				seen[dom] = struct{}{}
			}
		}
	}
	if cfg != nil {
		for _, d := range cfg.DNS.Whitelist {
			addDomain(d)
		}
		for _, item := range cfg.Audit.Whitelist {
			addDomain(item)
		}
		for _, subDom := range ExtractSubscriptionDomains(cfg) {
			addDomain(subDom)
		}
	}

	out := make([]string, 0, len(seen))
	for dom := range seen {
		out = append(out, dom)
	}
	slices.Sort(out)
	return out
}

func toNormalizedDomainSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, raw := range items {
		if dom, ok := NormalizeWhitelistDomain(raw); ok {
			set[dom] = struct{}{}
		}
	}
	return set
}

func sortedDomainSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for dom := range set {
		out = append(out, dom)
	}
	slices.Sort(out)
	return out
}

func ruleSetTagsHaveAdBlock(tags []string) bool {
	return slices.Contains(tags, "geosite-ad1") || slices.Contains(tags, "geosite-ad2")
}

func mergeInvertSuffixList(existing []string, oldSet, newSet map[string]struct{}) []string {
	merged := make(map[string]struct{}, len(existing)+len(newSet))
	for _, raw := range existing {
		dom, ok := NormalizeWhitelistDomain(raw)
		if !ok {
			trimmed := strings.TrimSpace(raw)
			if trimmed != "" {
				merged[trimmed] = struct{}{}
			}
			continue
		}
		if _, wasOld := oldSet[dom]; wasOld {
			if _, keep := newSet[dom]; keep {
				merged[dom] = struct{}{}
			}
			continue
		}
		merged[dom] = struct{}{}
	}
	for dom := range newSet {
		merged[dom] = struct{}{}
	}
	return sortedDomainSet(merged)
}

func isPureInvertDomainSuffixDNSRule(r sboption.DNSRule) bool {
	if r.Invert == nil || !*r.Invert || r.Type != "" || r.Action != "" || len(r.Extra) > 0 {
		return false
	}
	return r.RuleSet.IsEmpty() && r.Domain.IsEmpty() && r.DomainKeyword.IsEmpty() &&
		r.DomainRegex.IsEmpty() && r.SourceIPCIDR.IsEmpty() && r.QueryType.IsEmpty() && r.ClashMode == ""
}

func isPureInvertDomainSuffixRouteRule(r sboption.RouteRule) bool {
	if r.Invert == nil || !*r.Invert || r.Type != "" || r.Action != "" || len(r.Extra) > 0 {
		return false
	}
	return r.RuleSet.IsEmpty() && r.Domain.IsEmpty() && r.DomainKeyword.IsEmpty() &&
		r.DomainRegex.IsEmpty() && r.IPCIDR.IsEmpty() && r.SourceIPCIDR.IsEmpty() &&
		r.Network.IsEmpty() && r.Protocol.IsEmpty() && r.Port.IsEmpty() && r.PortRange.IsEmpty() &&
		r.IPIsPrivate == nil && r.ClashMode == ""
}

func syncDNSAdBlockRule(r sboption.DNSRule, oldSet, newSet map[string]struct{}) (sboption.DNSRule, bool) {
	if !strings.EqualFold(strings.TrimSpace(r.Action), "reject") {
		return r, false
	}

	// 情况 A：平铺去广告规则 {"rule_set": ["geosite-ad1", ...], "action": "reject"}
	if r.Type == "" && ruleSetTagsHaveAdBlock(r.RuleSet.Slice()) {
		if len(newSet) == 0 {
			return r, false
		}
		base := r.Clone()
		base.Action = ""
		inv := true
		return sboption.DNSRule{
			Type:   "logical",
			Mode:   "and",
			Action: r.Action,
			Rules: []sboption.DNSRule{
				base,
				{
					Invert:       &inv,
					DomainSuffix: sboption.ListOf(sortedDomainSet(newSet)...),
				},
			},
		}, true
	}

	// 情况 B：已包装的 logical AND 规则（兼容现网已有订阅域名的反选豁免）
	if r.Type != "logical" || r.Mode != "and" || len(r.Rules) == 0 {
		return r, false
	}
	hasAdSub := false
	invIdx := -1
	for i, sub := range r.Rules {
		if ruleSetTagsHaveAdBlock(sub.RuleSet.Slice()) {
			hasAdSub = true
		}
		if invIdx < 0 && sub.Invert != nil && *sub.Invert && (!sub.DomainSuffix.IsEmpty() || isPureInvertDomainSuffixDNSRule(sub)) {
			invIdx = i
		}
	}
	if !hasAdSub {
		return r, false
	}

	out := r.Clone()
	if invIdx >= 0 {
		prevSuffixes := out.Rules[invIdx].DomainSuffix.Slice()
		merged := mergeInvertSuffixList(prevSuffixes, oldSet, newSet)
		if len(merged) == 0 && isPureInvertDomainSuffixDNSRule(out.Rules[invIdx]) {
			out.Rules = slices.Delete(out.Rules, invIdx, invIdx+1)
			if len(out.Rules) == 1 && out.Rules[0].Type == "" {
				unwrapped := out.Rules[0].Clone()
				unwrapped.Action = out.Action
				return unwrapped, true
			}
			return out, true
		}
		if slices.Equal(prevSuffixes, merged) {
			return r, false
		}
		out.Rules[invIdx].DomainSuffix = sboption.ListOf(merged...)
		return out, true
	}

	if len(newSet) == 0 {
		return r, false
	}
	inv := true
	out.Rules = append(out.Rules, sboption.DNSRule{
		Invert:       &inv,
		DomainSuffix: sboption.ListOf(sortedDomainSet(newSet)...),
	})
	return out, true
}

func syncRouteAdBlockRule(r sboption.RouteRule, oldSet, newSet map[string]struct{}) (sboption.RouteRule, bool) {
	if !strings.EqualFold(strings.TrimSpace(r.Action), "reject") {
		return r, false
	}

	// 情况 A：平铺去广告路由规则
	if r.Type == "" && ruleSetTagsHaveAdBlock(r.RuleSet.Slice()) {
		if len(newSet) == 0 {
			return r, false
		}
		base := r.Clone()
		base.Action = ""
		inv := true
		return sboption.RouteRule{
			Type:   "logical",
			Mode:   "and",
			Action: r.Action,
			Rules: []sboption.RouteRule{
				base,
				{
					Invert:       &inv,
					DomainSuffix: sboption.ListOf(sortedDomainSet(newSet)...),
				},
			},
		}, true
	}

	// 情况 B：已包装的 logical AND 路由规则
	if r.Type != "logical" || r.Mode != "and" || len(r.Rules) == 0 {
		return r, false
	}
	hasAdSub := false
	invIdx := -1
	for i, sub := range r.Rules {
		if ruleSetTagsHaveAdBlock(sub.RuleSet.Slice()) {
			hasAdSub = true
		}
		if invIdx < 0 && sub.Invert != nil && *sub.Invert && (!sub.DomainSuffix.IsEmpty() || isPureInvertDomainSuffixRouteRule(sub)) {
			invIdx = i
		}
	}
	if !hasAdSub {
		return r, false
	}

	out := r.Clone()
	if invIdx >= 0 {
		prevSuffixes := out.Rules[invIdx].DomainSuffix.Slice()
		merged := mergeInvertSuffixList(prevSuffixes, oldSet, newSet)
		if len(merged) == 0 && isPureInvertDomainSuffixRouteRule(out.Rules[invIdx]) {
			out.Rules = slices.Delete(out.Rules, invIdx, invIdx+1)
			if len(out.Rules) == 1 && out.Rules[0].Type == "" {
				unwrapped := out.Rules[0].Clone()
				unwrapped.Action = out.Action
				return unwrapped, true
			}
			return out, true
		}
		if slices.Equal(prevSuffixes, merged) {
			return r, false
		}
		out.Rules[invIdx].DomainSuffix = sboption.ListOf(merged...)
		return out, true
	}

	if len(newSet) == 0 {
		return r, false
	}
	inv := true
	out.Rules = append(out.Rules, sboption.RouteRule{
		Invert:       &inv,
		DomainSuffix: sboption.ListOf(sortedDomainSet(newSet)...),
	})
	return out, true
}

// ApplyAdBlockWhitelistToDoc 在单树 *sboption.Document 上对 DNS 与 Route 全部 geosite-ad1/ad2 拦截规则执行白名单反选同步。
func ApplyAdBlockWhitelistToDoc(doc *sboption.Document, oldManaged, newManaged []string) bool {
	if doc == nil {
		return false
	}
	oldSet := toNormalizedDomainSet(oldManaged)
	newSet := toNormalizedDomainSet(newManaged)
	changed := false

	if doc.DNS != nil {
		for i := range doc.DNS.Rules {
			if updated, ok := syncDNSAdBlockRule(doc.DNS.Rules[i], oldSet, newSet); ok {
				doc.DNS.Rules[i] = updated
				changed = true
			}
		}
	}
	if doc.Route != nil {
		for i := range doc.Route.Rules {
			if updated, ok := syncRouteAdBlockRule(doc.Route.Rules[i], oldSet, newSet); ok {
				doc.Route.Rules[i] = updated
				changed = true
			}
		}
	}
	return changed
}

// SyncAdBlockWhitelistInConfigJSON 对磁盘/运行态 sing-box config.json 执行去广告白名单差量同步（无损保留非受管订阅域名）。
func SyncAdBlockWhitelistInConfigJSON(rawJSON string, oldManaged, newManaged []string) (string, bool, error) {
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", false, err
	}
	if !ApplyAdBlockWhitelistToDoc(doc, oldManaged, newManaged) {
		return rawJSON, false, nil
	}
	out, err := doc.MarshalPretty()
	if err != nil {
		return "", false, err
	}
	return out, true, nil
}
