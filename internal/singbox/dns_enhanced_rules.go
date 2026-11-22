// 文件职责：承载 sing-box 加强版 DNS 的纯内存规则编排器（内网重写、去广告/PCDN 白名单逻辑反选与暂停还原、屏蔽 AAAA 规则幂等管理）。
package singbox

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

func computeDisabledAdRuleSetTags(dnsCfg config.ClientDNSConfig, now time.Time) map[string]bool {
	disabled := make(map[string]bool)
	if dnsCfg.IsAdblockPaused(now) {
		disabled["geosite-ad1"] = true
		disabled["geosite-ad2"] = true
	}
	for _, raw := range dnsCfg.DisabledAdRuleSets {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if slices.Contains(managedAdRuleSetTags, tag) {
			disabled[tag] = true
		}
	}
	return disabled
}

func isManagedRewriteAnswer(ans string) bool {
	fields := strings.Fields(ans)
	if len(fields) != 5 {
		return false
	}
	if !strings.HasSuffix(fields[0], ".") || fields[1] != managedRewriteTTLStr || fields[2] != "IN" {
		return false
	}
	if fields[3] != "A" && fields[3] != "AAAA" {
		return false
	}
	_, err := netip.ParseAddr(fields[4])
	return err == nil
}

func isManagedRewriteDNSRule(r sboption.DNSRule) bool {
	if r.Action != "predefined" || !strings.EqualFold(r.Rcode, "NOERROR") || r.Answer.IsEmpty() {
		return false
	}
	if r.Type != "" || r.Mode != "" || len(r.Rules) > 0 || r.Server != "" || r.ClashMode != "" ||
		r.ClientSubnet != "" || r.Strategy != "" || r.Invert != nil || r.DisableCache != nil ||
		r.RewriteTTL != nil || !r.RuleSet.IsEmpty() || !r.DomainKeyword.IsEmpty() ||
		!r.DomainRegex.IsEmpty() || !r.SourceIPCIDR.IsEmpty() || !r.QueryType.IsEmpty() || len(r.Extra) > 0 {
		return false
	}
	hasDomain := !r.Domain.IsEmpty()
	hasSuffix := !r.DomainSuffix.IsEmpty()
	if hasDomain == hasSuffix {
		return false
	}
	for _, a := range r.Answer.Slice() {
		if !isManagedRewriteAnswer(a) {
			return false
		}
	}
	return true
}

func managedRewriteInsertIndex(rules []sboption.DNSRule) int {
	idx := 0
	for i, r := range rules {
		isSfx, isKw := sboption.IsManagedPrivatePTRDNSRule(r, privateReverseDNSSuffixes, DNSSDBrowseKeyword)
		if isSfx || isKw || strings.TrimSpace(r.ClashMode) != "" || strings.TrimSpace(r.Server) == "dns_tailscale" {
			idx = i + 1
		}
	}
	return idx
}

func reconcileManagedRewritesInDoc(doc *sboption.Document, rewrites []config.DNSRewriteRule) {
	kept := make([]sboption.DNSRule, 0, len(doc.DNS.Rules))
	for _, r := range doc.DNS.Rules {
		if isManagedRewriteDNSRule(r) {
			continue
		}
		kept = append(kept, r)
	}

	type rewriteKey struct {
		wildcard bool
		domain   string
	}
	var order []rewriteKey
	grouped := make(map[rewriteKey][]string)

	for _, rule := range rewrites {
		domain, isWildcard, rrType, ipStr, err := parseDNSRewriteRule(rule)
		if err != nil {
			log.Warn("忽略非法 DNS 重写规则 (%q -> %q): %v", rule.Domain, rule.Answer, err)
			continue
		}
		k := rewriteKey{wildcard: isWildcard, domain: domain}
		if _, exists := grouped[k]; !exists {
			order = append(order, k)
		}
		ans := fmt.Sprintf("%s. %s IN %s %s", domain, managedRewriteTTLStr, rrType, ipStr)
		if !slices.Contains(grouped[k], ans) {
			grouped[k] = append(grouped[k], ans)
		}
	}

	if len(order) == 0 {
		doc.DNS.Rules = kept
		return
	}

	compiled := make([]sboption.DNSRule, 0, len(order))
	for _, k := range order {
		rule := sboption.DNSRule{
			Action: "predefined",
			Rcode:  "NOERROR",
			Answer: sboption.ListOf(grouped[k]...),
		}
		if k.wildcard {
			rule.DomainSuffix = sboption.ListOf(k.domain)
		} else {
			rule.Domain = sboption.ListOf(k.domain)
		}
		compiled = append(compiled, rule)
	}

	insertAt := managedRewriteInsertIndex(kept)
	doc.DNS.Rules = slices.Insert(kept, insertAt, compiled...)
}

func containsAnyManagedAdTag(tags []string) bool {
	for _, t := range tags {
		if slices.Contains(managedAdRuleSetTags, t) {
			return true
		}
	}
	return false
}

func isPlainRuleSetOnlyDNSRule(r sboption.DNSRule) bool {
	if r.Type != "" || r.Mode != "" || len(r.Rules) > 0 || r.Server != "" || r.ClashMode != "" ||
		r.ClientSubnet != "" || r.Rcode != "" || !r.Answer.IsEmpty() || r.Strategy != "" ||
		r.Invert != nil || r.DisableCache != nil || r.RewriteTTL != nil ||
		!r.Domain.IsEmpty() || !r.DomainSuffix.IsEmpty() || !r.DomainKeyword.IsEmpty() ||
		!r.DomainRegex.IsEmpty() || !r.SourceIPCIDR.IsEmpty() || !r.QueryType.IsEmpty() || len(r.Extra) > 0 {
		return false
	}
	return !r.RuleSet.IsEmpty()
}

func isPureManagedAdRuleSetDNSRule(r sboption.DNSRule) bool {
	return strings.EqualFold(strings.TrimSpace(r.Action), "reject") &&
		isPlainRuleSetOnlyDNSRule(r) &&
		containsAnyManagedAdTag(r.RuleSet.Slice())
}

func isManagedInvertDomainSuffixDNSRule(r sboption.DNSRule) bool {
	if r.Invert == nil || !*r.Invert || r.DomainSuffix.IsEmpty() {
		return false
	}
	return r.Type == "" && r.Mode == "" && len(r.Rules) == 0 && r.Action == "" && r.Server == "" &&
		r.ClashMode == "" && r.ClientSubnet == "" && r.Rcode == "" && r.Answer.IsEmpty() &&
		r.Strategy == "" && r.DisableCache == nil && r.RewriteTTL == nil &&
		r.RuleSet.IsEmpty() && r.Domain.IsEmpty() && r.DomainKeyword.IsEmpty() &&
		r.DomainRegex.IsEmpty() && r.SourceIPCIDR.IsEmpty() && r.QueryType.IsEmpty() && len(r.Extra) == 0
}

func unwrapManagedAdDNSRule(r sboption.DNSRule) (sboption.DNSRule, bool) {
	if strings.EqualFold(r.Action, "reject") && r.Type == "logical" && r.Mode == "and" && len(r.Rules) == 2 && len(r.Extra) == 0 {
		sub0, sub1 := r.Rules[0], r.Rules[1]
		if sub0.Action == "" && isPlainRuleSetOnlyDNSRule(sub0) && containsAnyManagedAdTag(sub0.RuleSet.Slice()) && isManagedInvertDomainSuffixDNSRule(sub1) {
			return sboption.DNSRule{
				Action:  "reject",
				RuleSet: sub0.RuleSet.Clone(),
			}, true
		}
	}
	return r, false
}

func isPlainRuleSetOnlyRouteRule(r sboption.RouteRule) bool {
	if r.Type != "" || r.Mode != "" || len(r.Rules) > 0 || r.Outbound != "" || r.ClashMode != "" ||
		r.Invert != nil || r.IPIsPrivate != nil || !r.Network.IsEmpty() || !r.Protocol.IsEmpty() ||
		!r.Port.IsEmpty() || !r.PortRange.IsEmpty() || !r.Domain.IsEmpty() || !r.DomainSuffix.IsEmpty() ||
		!r.DomainKeyword.IsEmpty() || !r.DomainRegex.IsEmpty() || !r.IPCIDR.IsEmpty() ||
		!r.SourceIPCIDR.IsEmpty() || len(r.Extra) > 0 {
		return false
	}
	return !r.RuleSet.IsEmpty()
}

func isPureManagedAdRuleSetRouteRule(r sboption.RouteRule) bool {
	return strings.EqualFold(strings.TrimSpace(r.Action), "reject") &&
		isPlainRuleSetOnlyRouteRule(r) &&
		containsAnyManagedAdTag(r.RuleSet.Slice())
}

func isManagedInvertDomainSuffixRouteRule(r sboption.RouteRule) bool {
	if r.Invert == nil || !*r.Invert || r.DomainSuffix.IsEmpty() {
		return false
	}
	return r.Type == "" && r.Mode == "" && len(r.Rules) == 0 && r.Action == "" && r.Outbound == "" &&
		r.ClashMode == "" && r.IPIsPrivate == nil && r.Network.IsEmpty() && r.Protocol.IsEmpty() &&
		r.Port.IsEmpty() && r.PortRange.IsEmpty() && r.RuleSet.IsEmpty() && r.Domain.IsEmpty() &&
		r.DomainKeyword.IsEmpty() && r.DomainRegex.IsEmpty() && r.IPCIDR.IsEmpty() &&
		r.SourceIPCIDR.IsEmpty() && len(r.Extra) == 0
}

func unwrapManagedAdRouteRule(r sboption.RouteRule) (sboption.RouteRule, bool) {
	if strings.EqualFold(r.Action, "reject") && r.Type == "logical" && r.Mode == "and" && len(r.Rules) == 2 && len(r.Extra) == 0 {
		sub0, sub1 := r.Rules[0], r.Rules[1]
		if sub0.Action == "" && isPlainRuleSetOnlyRouteRule(sub0) && containsAnyManagedAdTag(sub0.RuleSet.Slice()) && isManagedInvertDomainSuffixRouteRule(sub1) {
			return sboption.RouteRule{
				Action:  "reject",
				RuleSet: sub0.RuleSet.Clone(),
			}, true
		}
	}
	return r, false
}

func managedAdDNSInsertIndex(rules []sboption.DNSRule) int {
	idx := 0
	for i, r := range rules {
		isSfx, isKw := sboption.IsManagedPrivatePTRDNSRule(r, privateReverseDNSSuffixes, DNSSDBrowseKeyword)
		if isSfx || isKw || strings.TrimSpace(r.ClashMode) != "" || strings.TrimSpace(r.Server) == "dns_tailscale" || isManagedRewriteDNSRule(r) {
			idx = i + 1
		}
	}
	return idx
}

func reconcileManagedAdDNSRulesInDoc(doc *sboption.Document, definedRuleSets, disabledTags map[string]bool, allowList []string) {
	if doc == nil || doc.DNS == nil {
		return
	}

	activeTags := make(map[string]bool)
	unwrapped := make([]sboption.DNSRule, 0, len(doc.DNS.Rules))
	for _, raw := range doc.DNS.Rules {
		r, _ := unwrapManagedAdDNSRule(raw)
		if isPureManagedAdRuleSetDNSRule(r) {
			filtered := make([]string, 0, r.RuleSet.Len())
			for _, tag := range r.RuleSet.Slice() {
				if disabledTags[tag] {
					continue
				}
				filtered = append(filtered, tag)
				activeTags[tag] = true
			}
			if len(filtered) == 0 {
				continue
			}
			r.RuleSet = sboption.Listable[string]{Items: filtered, Scalar: r.RuleSet.Scalar}
		}
		unwrapped = append(unwrapped, r)
	}

	var restoreRules []sboption.DNSRule
	var missingAd []string
	for _, tag := range []string{"geosite-ad1", "geosite-ad2"} {
		if definedRuleSets[tag] && !disabledTags[tag] && !activeTags[tag] {
			missingAd = append(missingAd, tag)
		}
	}
	if len(missingAd) > 0 {
		restoreRules = append(restoreRules, sboption.DNSRule{
			Action:  "reject",
			RuleSet: sboption.ListOf(missingAd...),
		})
	}
	if definedRuleSets[BuiltinPCDNRuleSetTag] && !disabledTags[BuiltinPCDNRuleSetTag] && !activeTags[BuiltinPCDNRuleSetTag] {
		restoreRules = append(restoreRules, sboption.DNSRule{
			Action:  "reject",
			RuleSet: sboption.ListOf(BuiltinPCDNRuleSetTag),
		})
	}
	if len(restoreRules) > 0 {
		insertAt := managedAdDNSInsertIndex(unwrapped)
		unwrapped = slices.Insert(unwrapped, insertAt, restoreRules...)
	}

	if len(allowList) > 0 {
		for i, r := range unwrapped {
			if isPureManagedAdRuleSetDNSRule(r) {
				unwrapped[i] = sboption.DNSRule{
					Type:   "logical",
					Mode:   "and",
					Action: "reject",
					Rules: []sboption.DNSRule{
						{RuleSet: r.RuleSet.Clone()},
						{DomainSuffix: sboption.ListOf(allowList...), Invert: new(true)},
					},
				}
			}
		}
	}
	doc.DNS.Rules = unwrapped
}

func reconcileManagedAdRouteRulesInDoc(doc *sboption.Document, definedRuleSets, disabledTags map[string]bool, allowList []string) {
	if doc == nil || doc.Route == nil {
		return
	}

	activeTags := make(map[string]bool)
	unwrapped := make([]sboption.RouteRule, 0, len(doc.Route.Rules))
	for _, raw := range doc.Route.Rules {
		r, _ := unwrapManagedAdRouteRule(raw)
		if isPureManagedAdRuleSetRouteRule(r) {
			filtered := make([]string, 0, r.RuleSet.Len())
			for _, tag := range r.RuleSet.Slice() {
				if disabledTags[tag] {
					continue
				}
				filtered = append(filtered, tag)
				activeTags[tag] = true
			}
			if len(filtered) == 0 {
				continue
			}
			r.RuleSet = sboption.Listable[string]{Items: filtered, Scalar: r.RuleSet.Scalar}
		}
		unwrapped = append(unwrapped, r)
	}

	var restoreRules []sboption.RouteRule
	if definedRuleSets[BuiltinPCDNRuleSetTag] && !disabledTags[BuiltinPCDNRuleSetTag] && !activeTags[BuiltinPCDNRuleSetTag] {
		restoreRules = append(restoreRules, sboption.RouteRule{
			Action:  "reject",
			RuleSet: sboption.ListOf(BuiltinPCDNRuleSetTag),
		})
	}
	var missingAd []string
	for _, tag := range []string{"geosite-ad1", "geosite-ad2"} {
		if definedRuleSets[tag] && !disabledTags[tag] && !activeTags[tag] {
			missingAd = append(missingAd, tag)
		}
	}
	if len(missingAd) > 0 {
		restoreRules = append(restoreRules, sboption.RouteRule{
			Action:  "reject",
			RuleSet: sboption.ListOf(missingAd...),
		})
	}
	if len(restoreRules) > 0 {
		insertAt := sboption.BlockRouteInsertIndex(unwrapped)
		unwrapped = slices.Insert(unwrapped, insertAt, restoreRules...)
	}

	if len(allowList) > 0 {
		for i, r := range unwrapped {
			if isPureManagedAdRuleSetRouteRule(r) {
				unwrapped[i] = sboption.RouteRule{
					Type:   "logical",
					Mode:   "and",
					Action: "reject",
					Rules: []sboption.RouteRule{
						{RuleSet: r.RuleSet.Clone()},
						{DomainSuffix: sboption.ListOf(allowList...), Invert: new(true)},
					},
				}
			}
		}
	}
	doc.Route.Rules = unwrapped
}

func isManagedBlockAAAADNSRule(r sboption.DNSRule) bool {
	if r.Action != "predefined" || !strings.EqualFold(r.Rcode, "NOERROR") || !r.Answer.IsEmpty() {
		return false
	}
	if r.Type != "" || r.Mode != "" || len(r.Rules) > 0 || r.Server != "" || r.ClashMode != "" ||
		r.ClientSubnet != "" || r.Strategy != "" || r.Invert != nil || r.DisableCache != nil ||
		r.RewriteTTL != nil || !r.RuleSet.IsEmpty() || !r.Domain.IsEmpty() || !r.DomainSuffix.IsEmpty() ||
		!r.DomainKeyword.IsEmpty() || !r.DomainRegex.IsEmpty() || !r.SourceIPCIDR.IsEmpty() || len(r.Extra) > 0 {
		return false
	}
	qts := r.QueryType.Slice()
	return len(qts) == 1 && strings.EqualFold(strings.TrimSpace(qts[0]), "AAAA")
}

func managedBlockAAAAInsertIndex(rules []sboption.DNSRule) int {
	idx := 0
	for i, r := range rules {
		isSfx, isKw := sboption.IsManagedPrivatePTRDNSRule(r, privateReverseDNSSuffixes, DNSSDBrowseKeyword)
		if isSfx || isKw ||
			strings.TrimSpace(r.ClashMode) != "" ||
			strings.TrimSpace(r.Server) == "dns_tailscale" ||
			isManagedRewriteDNSRule(r) ||
			strings.EqualFold(strings.TrimSpace(r.Action), "reject") {
			idx = i + 1
			continue
		}
		rs := r.RuleSet.Slice()
		if slices.Contains(rs, "geosite-cn") || slices.Contains(rs, "geosite-geolocation-!cn") {
			return idx
		}
	}
	return idx
}

func reconcileBlockAAAADNSRuleInDoc(doc *sboption.Document, blockAAAA bool) {
	if doc == nil || doc.DNS == nil {
		return
	}
	kept := make([]sboption.DNSRule, 0, len(doc.DNS.Rules))
	for _, r := range doc.DNS.Rules {
		if isManagedBlockAAAADNSRule(r) {
			continue
		}
		kept = append(kept, r)
	}
	if !blockAAAA {
		doc.DNS.Rules = kept
		return
	}
	insertAt := managedBlockAAAAInsertIndex(kept)
	rule := sboption.DNSRule{
		QueryType: sboption.ListOf("AAAA"),
		Action:    "predefined",
		Rcode:     "NOERROR",
	}
	doc.DNS.Rules = slices.Insert(kept, insertAt, rule)
}
