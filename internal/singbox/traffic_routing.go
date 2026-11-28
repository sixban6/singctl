// 文件职责：生成客户端智能分流诊断报告，并在 *sboption.Document 上精准注入或无损剥离托管分流/DNS 规则。
package singbox

import (
	"fmt"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

// BuildClientRoutingReport 结合 singctl.yaml 与当前 sing-box config.json 生成界面渲染所需的全景报告。
func BuildClientRoutingReport(cfg *config.Config, rawConfigJSON string) ClientRoutingReport {
	var tr config.TrafficRoutingConfig
	if cfg != nil {
		tr = cfg.TrafficRouting.Normalized()
	}

	groups, directTag := InspectClientRoutingOutbounds(rawConfigJSON)
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}

	items := make([]ClientRoutingPresetState, 0, len(clientRoutingPresets))
	enabledCount := 0
	customCount := 0
	for _, p := range clientRoutingPresets {
		defOutbound := ResolvePresetDefaultOutbound(p.PreferVPS, p.PreferAuto, groupTags)
		enabled, configuredGroup := tr.PresetState(p.ID, p.DefaultOn, defOutbound)
		selectedGroup := configuredGroup
		if !slices.Contains(groupTags, selectedGroup) {
			selectedGroup = defOutbound
		}
		effectiveDest := selectedGroup
		if !enabled {
			effectiveDest = directTag
		}
		if enabled {
			enabledCount++
		}
		customized := false
		if ov, ok := tr.Presets[p.ID]; ok {
			if ov.Enabled != nil && *ov.Enabled != p.DefaultOn {
				customized = true
			}
			if ov.Outbound != "" && ov.Outbound != defOutbound {
				customized = true
			}
		}
		if customized {
			customCount++
		}
		items = append(items, ClientRoutingPresetState{
			ID:              p.ID,
			Name:            p.Name,
			Category:        p.Category,
			CategoryLabel:   p.CategoryLabel,
			Description:     p.Description,
			DomainsSummary:  p.DomainsSummary,
			DefaultOn:       p.DefaultOn,
			DefaultOutbound: defOutbound,
			Enabled:         enabled,
			SelectedGroup:   selectedGroup,
			EffectiveDest:   effectiveDest,
			Customized:      customized,
		})
	}

	return ClientRoutingReport{
		Groups:       groups,
		DirectTag:    directTag,
		Categories:   resolveCategoriesForGroups(groupTags, directTag),
		Items:        items,
		CustomRules:  slices.Clone(tr.Rules),
		EnabledCount: enabledCount,
		CustomCount:  customCount + len(tr.Rules),
		TotalCount:   len(items),
		HasConfig:    strings.TrimSpace(rawConfigJSON) != "",
	}
}

func resolveCategoriesForGroups(groupTags []string, directTag string) []TrafficCategoryInfo {
	cats := ClientRoutingCategories()
	aiDest := ResolvePresetDefaultOutbound(true, false, groupTags)
	commonDest := ResolvePresetDefaultOutbound(false, false, groupTags)
	if directTag == "" {
		directTag = "#DC"
	}

	for i := range cats {
		switch cats[i].ID {
		case "ai":
			cats[i].DefaultDest = aiDest
			if aiDest != "#VPS" {
				cats[i].Description = fmt.Sprintf("OpenAI、Claude、Gemini 等 AI 服务，当前无 #VPS 自建组，默认自动走 %s 分组独立选线", aiDest)
			}
		case "streaming", "gaming", "social":
			cats[i].DefaultDest = commonDest
			if commonDest != "Proxy" {
				cats[i].Description = strings.ReplaceAll(cats[i].Description, "默认走 Proxy", "默认走 "+commonDest)
			}
		case "office":
			cats[i].DefaultDest = "直连 " + directTag
			if directTag != "#DC" {
				cats[i].Description = strings.ReplaceAll(cats[i].Description, "#DC", directTag)
			}
		}
	}
	return cats
}

// ApplyTrafficRoutingToConfigJSON 将客户端「智能分流开关中心」策略幂等地编译注入 sing-box config.json。
func ApplyTrafficRoutingToConfigJSON(rawJSON string, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig) (string, error) {
	return ApplyTrafficRoutingWithPrevRules(rawJSON, nil, tr, cr)
}

// ApplyTrafficRoutingWithPrevRules 将当前与历史审计自定义出口规则一同对齐编译，更新或删除时零残留剥离旧规则。
func ApplyTrafficRoutingWithPrevRules(rawJSON string, prevRules []config.TrafficCustomRule, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig) (string, error) {
	return applyTrafficRoutingWithPrevForPlatform(rawJSON, prevRules, tr, cr, "")
}

// ApplyTrafficRoutingForPlatform 与 ApplyTrafficRoutingToConfigJSON 逻辑一致，额外感知目标平台。
func ApplyTrafficRoutingForPlatform(rawJSON string, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig, platform string) (string, error) {
	return applyTrafficRoutingWithPrevForPlatform(rawJSON, nil, tr, cr, platform)
}

func applyTrafficRoutingWithPrevForPlatform(rawJSON string, prevRules []config.TrafficCustomRule, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig, platform string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("解析 sing-box config.json 失败: %w", err)
	}
	applyTrafficRoutingWithPrevToDoc(doc, prevRules, tr, cr, platform)
	return doc.MarshalPretty()
}

func applyTrafficRoutingToDoc(doc *sboption.Document, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig, platform string) {
	applyTrafficRoutingWithPrevToDoc(doc, nil, tr, cr, platform)
}

func applyTrafficRoutingWithPrevToDoc(doc *sboption.Document, prevRules []config.TrafficCustomRule, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig, platform string) {
	if doc == nil {
		return
	}
	if doc.Route == nil {
		doc.Route = &sboption.RouteOptions{}
	}

	groups, directTag := inspectOutboundsFromDoc(doc)
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}

	normTR := tr.Normalized()
	preserveNativeHoK := shouldPreserveNativeHoK(normTR, groupTags, doc.Route.Rules)

	definedRuleSets := collectDefinedRuleSetTags(doc.Route)
	managedSuffixes, managedRuleSets := collectManagedSignatures(preserveNativeHoK)
	customRouteSet := buildCustomRuleSignatures(cr)

	isIOS := strings.EqualFold(strings.TrimSpace(platform), PlatformIOS)
	var proxyDNS, directDNS string
	if doc.DNS != nil {
		proxyDNS, directDNS = resolveClientDNSTags(doc.DNS)
	}
	customTrafficSig := buildCustomTrafficRuleSignatures(prevRules, normTR.Rules, groupTags, directTag, proxyDNS, directDNS, isIOS)

	strippedRouteRules := stripManagedRouteRules(doc.Route.Rules, managedSuffixes, managedRuleSets, customRouteSet)
	strippedRouteRules = stripCustomTrafficRouteRules(strippedRouteRules, customTrafficSig.routeJSONs, customRouteSet)
	customTrafficRoutes := compileCustomTrafficRouteRules(normTR.Rules, groupTags, directTag, isIOS)
	managedRouteRules := compileManagedRouteRules(normTR, groupTags, directTag, definedRuleSets, preserveNativeHoK)
	allTrafficRoutes := append(customTrafficRoutes, managedRouteRules...)
	insertRouteIdx := sboption.TrafficRouteInsertIndex(strippedRouteRules)
	doc.Route.Rules = slices.Insert(strippedRouteRules, insertRouteIdx, allTrafficRoutes...)

	if doc.DNS != nil {
		if proxyDNS != "" || directDNS != "" {
			skipEnabledGeositeDNS := isIOS && proxyDNS != "" && strings.TrimSpace(doc.DNS.Final) == proxyDNS
			strippedDNSRules := stripManagedDNSRules(doc.DNS.Rules, managedSuffixes, managedRuleSets, customRouteSet)
			strippedDNSRules = stripCustomTrafficDNSRules(strippedDNSRules, customTrafficSig.dnsJSONs, customRouteSet)
			customTrafficDNS := compileCustomTrafficDNSRules(normTR.Rules, groupTags, directTag, proxyDNS, directDNS, isIOS)
			managedDNSRules := compileManagedDNSRules(normTR, proxyDNS, directDNS, definedRuleSets, preserveNativeHoK, skipEnabledGeositeDNS)
			allTrafficDNS := append(customTrafficDNS, managedDNSRules...)
			insertDNSIdx := sboption.TrafficDNSInsertIndex(strippedDNSRules)
			doc.DNS.Rules = slices.Insert(strippedDNSRules, insertDNSIdx, allTrafficDNS...)
		}
	}
}

func collectDefinedRuleSetTags(route *sboption.RouteOptions) map[string]bool {
	out := make(map[string]bool)
	if route == nil {
		return out
	}
	for _, rs := range route.RuleSet {
		if tag := strings.TrimSpace(rs.Tag); tag != "" {
			out[tag] = true
		}
	}
	return out
}

func shouldPreserveNativeHoK(tr config.TrafficRoutingConfig, groupTags []string, existingRouteRules []sboption.RouteRule) bool {
	defOut := ResolvePresetDefaultOutbound(false, true, groupTags)
	enabled, out := tr.PresetState("hok", true, defOut)
	if !enabled || (out != "" && out != defOut) {
		return false
	}
	for _, r := range existingRouteRules {
		if slices.Equal(r.RuleSet.Slice(), []string{"geosite-hok"}) && r.Outbound == defOut {
			return true
		}
	}
	return false
}

func collectManagedSignatures(preserveNativeHoK bool) (suffixes map[string]bool, ruleSets map[string]bool) {
	suffixes = make(map[string]bool)
	ruleSets = make(map[string]bool)
	for _, p := range clientRoutingPresets {
		if preserveNativeHoK && p.ID == "hok" {
			continue
		}
		for _, d := range p.DomainSuffixes {
			suffixes[strings.ToLower(strings.TrimSpace(d))] = true
		}
		for _, rs := range p.RuleSets {
			ruleSets[strings.ToLower(strings.TrimSpace(rs))] = true
		}
	}
	return suffixes, ruleSets
}

func isManagedSuffix(raw string, managed map[string]bool) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if managed[s] {
		return true
	}
	return managed["sgameglobal.com"] && (s == "sgameglobal.com" || strings.HasSuffix(s, ".sgameglobal.com"))
}

type customSignature struct {
	routeJSONs map[string]bool
	dnsJSONs   map[string]bool
}

func buildCustomRuleSignatures(cr config.CustomRulesConfig) customSignature {
	sig := customSignature{
		routeJSONs: make(map[string]bool, len(cr.Route)),
		dnsJSONs:   make(map[string]bool, len(cr.DNS)),
	}
	for _, r := range cr.Route {
		if c, err := sboption.CanonicalJSON(r); err == nil {
			sig.routeJSONs[c] = true
		}
	}
	for _, d := range cr.DNS {
		if c, err := sboption.CanonicalJSON(d); err == nil {
			sig.dnsJSONs[c] = true
		}
	}
	return sig
}

func isProtectedRule(rule any, known map[string]bool) bool {
	if len(known) == 0 {
		return false
	}
	c, err := sboption.CanonicalJSON(rule)
	return err == nil && known[c]
}

func isPureTrafficRouteRule(r sboption.RouteRule) bool {
	act := strings.ToLower(strings.TrimSpace(r.Action))
	if act != "" && act != "route" {
		return false
	}
	return len(r.Extra) == 0 && r.Type == "" && r.Mode == "" && len(r.Rules) == 0 &&
		r.ClashMode == "" && r.IPIsPrivate == nil && r.Network.IsEmpty() && r.Protocol.IsEmpty() &&
		r.Port.IsEmpty() && r.PortRange.IsEmpty() && r.Domain.IsEmpty() && r.DomainKeyword.IsEmpty() &&
		r.DomainRegex.IsEmpty() && r.IPCIDR.IsEmpty() && r.SourceIPCIDR.IsEmpty()
}

func isPureTrafficDNSRule(r sboption.DNSRule) bool {
	act := strings.ToLower(strings.TrimSpace(r.Action))
	if act != "" && act != "route" {
		return false
	}
	return len(r.Extra) == 0 && r.Type == "" && r.Mode == "" && len(r.Rules) == 0 &&
		r.ClashMode == "" && r.Rcode == "" && r.Strategy == "" && r.DisableCache == nil && r.RewriteTTL == nil &&
		r.Domain.IsEmpty() && r.DomainKeyword.IsEmpty() && r.DomainRegex.IsEmpty() &&
		r.SourceIPCIDR.IsEmpty() && r.QueryType.IsEmpty()
}

func stripManagedListables(
	dsIn, rsIn sboption.Listable[string],
	suffixes, ruleSets map[string]bool,
) (keep bool, changed bool, dsOut, rsOut sboption.Listable[string]) {
	hasManagedList := false
	hasRemaining := false

	if !dsIn.IsEmpty() {
		hasManagedList = true
		filtered := make([]string, 0, dsIn.Len())
		for _, item := range dsIn.Slice() {
			if !isManagedSuffix(item, suffixes) {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
		}
		if len(filtered) > 0 {
			dsOut = sboption.Listable[string]{Items: filtered, Scalar: dsIn.Scalar}
			hasRemaining = true
		}
	}
	if !rsIn.IsEmpty() {
		hasManagedList = true
		filtered := make([]string, 0, rsIn.Len())
		for _, item := range rsIn.Slice() {
			if !ruleSets[strings.ToLower(strings.TrimSpace(item))] {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
		}
		if len(filtered) > 0 {
			rsOut = sboption.Listable[string]{Items: filtered, Scalar: rsIn.Scalar}
			hasRemaining = true
		}
	}
	if !hasManagedList || !changed {
		return true, false, dsIn, rsIn
	}
	return hasRemaining, true, dsOut, rsOut
}

func stripManagedRouteRules(rules []sboption.RouteRule, suffixes, ruleSets map[string]bool, crSig customSignature) []sboption.RouteRule {
	out := make([]sboption.RouteRule, 0, len(rules))
	for _, r := range rules {
		if !isPureTrafficRouteRule(r) || isProtectedRule(r, crSig.routeJSONs) {
			out = append(out, r)
			continue
		}
		keep, changed, dsOut, rsOut := stripManagedListables(r.DomainSuffix, r.RuleSet, suffixes, ruleSets)
		if !keep {
			continue
		}
		if !changed {
			out = append(out, r)
			continue
		}
		cp := r.Clone()
		cp.DomainSuffix = dsOut
		cp.RuleSet = rsOut
		out = append(out, cp)
	}
	return out
}

func stripManagedDNSRules(rules []sboption.DNSRule, suffixes, ruleSets map[string]bool, crSig customSignature) []sboption.DNSRule {
	out := make([]sboption.DNSRule, 0, len(rules))
	for _, r := range rules {
		if !isPureTrafficDNSRule(r) || isProtectedRule(r, crSig.dnsJSONs) {
			out = append(out, r)
			continue
		}
		keep, changed, dsOut, rsOut := stripManagedListables(r.DomainSuffix, r.RuleSet, suffixes, ruleSets)
		if !keep {
			continue
		}
		if !changed {
			out = append(out, r)
			continue
		}
		cp := r.Clone()
		cp.DomainSuffix = dsOut
		cp.RuleSet = rsOut
		out = append(out, cp)
	}
	return out
}

type compiledMatcherRule struct {
	isRuleSet bool
	values    []string
	target    string
}

func appendStagedMatcher(staged []compiledMatcherRule, isRuleSet bool, values []string, target string) []compiledMatcherRule {
	if len(values) == 0 || target == "" {
		return staged
	}
	if n := len(staged); n > 0 && staged[n-1].isRuleSet == isRuleSet && staged[n-1].target == target {
		for _, v := range values {
			if !slices.Contains(staged[n-1].values, v) {
				staged[n-1].values = append(staged[n-1].values, v)
			}
		}
		return staged
	}
	return append(staged, compiledMatcherRule{
		isRuleSet: isRuleSet,
		values:    slices.Clone(values),
		target:    target,
	})
}

func compileManagedRouteRules(tr config.TrafficRoutingConfig, groupTags []string, directTag string, definedRuleSets map[string]bool, preserveNativeHoK bool) []sboption.RouteRule {
	var staged []compiledMatcherRule
	for _, p := range clientRoutingPresets {
		if preserveNativeHoK && p.ID == "hok" {
			continue
		}
		defOutbound := ResolvePresetDefaultOutbound(p.PreferVPS, p.PreferAuto, groupTags)
		enabled, selectedGroup := tr.PresetState(p.ID, p.DefaultOn, defOutbound)
		targetOutbound := selectedGroup
		if !slices.Contains(groupTags, targetOutbound) {
			targetOutbound = defOutbound
		}
		if !enabled {
			targetOutbound = directTag
		}
		if len(p.DomainSuffixes) > 0 {
			staged = appendStagedMatcher(staged, false, p.DomainSuffixes, targetOutbound)
		}
		if len(p.RuleSets) > 0 {
			staged = appendStagedMatcher(staged, true, filterExistingRuleSets(p.RuleSets, definedRuleSets, false), targetOutbound)
		}
	}

	out := make([]sboption.RouteRule, 0, len(staged))
	for _, s := range staged {
		rule := sboption.RouteRule{Action: "route", Outbound: s.target}
		if s.isRuleSet {
			rule.RuleSet = sboption.ListOf(s.values...)
		} else {
			rule.DomainSuffix = sboption.ListOf(s.values...)
		}
		out = append(out, rule)
	}
	return out
}

func compileManagedDNSRules(tr config.TrafficRoutingConfig, proxyDNS, directDNS string, definedRuleSets map[string]bool, preserveNativeHoK, skipEnabledGeosite bool) []sboption.DNSRule {
	var staged []compiledMatcherRule
	for _, p := range clientRoutingPresets {
		if preserveNativeHoK && p.ID == "hok" {
			continue
		}
		enabled, _ := tr.PresetState(p.ID, p.DefaultOn, "")
		targetDNS := proxyDNS
		if !enabled {
			targetDNS = directDNS
		}
		if targetDNS == "" {
			continue
		}
		if len(p.DomainSuffixes) > 0 {
			staged = appendStagedMatcher(staged, false, p.DomainSuffixes, targetDNS)
		}
		if len(p.RuleSets) > 0 && !(skipEnabledGeosite && enabled) {
			staged = appendStagedMatcher(staged, true, filterExistingRuleSets(p.RuleSets, definedRuleSets, true), targetDNS)
		}
	}

	out := make([]sboption.DNSRule, 0, len(staged))
	for _, s := range staged {
		rule := sboption.DNSRule{Server: s.target}
		if s.isRuleSet {
			rule.RuleSet = sboption.ListOf(s.values...)
		} else {
			rule.DomainSuffix = sboption.ListOf(s.values...)
		}
		out = append(out, rule)
	}
	return out
}

func filterExistingRuleSets(tags []string, defined map[string]bool, dnsDomainOnly bool) []string {
	if len(defined) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if dnsDomainOnly && strings.HasPrefix(strings.ToLower(tag), "geoip-") {
			continue
		}
		if defined[tag] {
			out = append(out, tag)
		}
	}
	return out
}

func resolveClientDNSTags(dns *sboption.DNSOptions) (proxyTag, directTag string) {
	if dns == nil {
		return "", ""
	}
	var allTags []string
	for _, srv := range dns.Servers {
		if tag := strings.TrimSpace(srv.Tag); tag != "" {
			allTags = append(allTags, tag)
		}
	}
	for _, candidate := range []string{"dns_local", "local", "direct"} {
		if slices.Contains(allTags, candidate) {
			directTag = candidate
			break
		}
	}
	for _, candidate := range []string{"dns_proxy", "remote", "dns_remote"} {
		if slices.Contains(allTags, candidate) {
			proxyTag = candidate
			break
		}
	}
	if proxyTag == "" {
		if f := strings.TrimSpace(dns.Final); f != "" && f != directTag {
			proxyTag = f
		}
	}
	return proxyTag, directTag
}
