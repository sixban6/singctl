// 文件职责：生成客户端智能分流诊断报告，并将托管分流/DNS 规则精准注入或无损剥离 sing-box config.json。
package singbox

import (
	"encoding/json"
	"fmt"
	"singctl/internal/config"
	"slices"
	"strings"
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
		// 若配置中的目标策略组在当前订阅生成的 config.json 中不存在，展示并生效时回退安全默认组
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
		EnabledCount: enabledCount,
		CustomCount:  customCount,
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
// 该函数同时清理 singgen 模板中同源规则集/域名条目的散落重复项，使开启选组或关闭直连（#DC）均 100% 精准生效，
// 并同时同步 dns.rules（开启走 dns_proxy，关闭走 dns_local）。
func ApplyTrafficRoutingToConfigJSON(rawJSON string, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig) (string, error) {
	return ApplyTrafficRoutingForPlatform(rawJSON, tr, cr, "")
}

// ApplyTrafficRoutingForPlatform 与 ApplyTrafficRoutingToConfigJSON 逻辑一致，额外感知目标平台：
// 在 iOS 平台且 dns.final 已指向 proxyDNS 时，跳过开启（proxyDNS）预设中的 geosite-* DNS 规则，
// 仅保留体积极小的 domain_suffix 及直连（directDNS）规则，以降低 SFI 沙盒规则匹配开销与内存峰值。
func ApplyTrafficRoutingForPlatform(rawJSON string, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig, platform string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return "", fmt.Errorf("解析 sing-box config.json 失败: %w", err)
	}

	routeMap, ok := doc["route"].(map[string]any)
	if !ok {
		routeMap = map[string]any{}
		doc["route"] = routeMap
	}

	groups, directTag := inspectOutboundsFromMap(doc)
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}

	existingRouteRules, _ := routeMap["rules"].([]any)
	normTR := tr.Normalized()
	preserveNativeHoK := shouldPreserveNativeHoK(normTR, groupTags, existingRouteRules)

	definedRuleSets := collectDefinedRuleSetTags(routeMap)
	managedSuffixes, managedRuleSets := collectManagedSignatures(preserveNativeHoK)
	customRouteSet := buildCustomRuleSignatures(cr)

	// 1. 剥离 route.rules 中由本模块接管的散落预设规则，并定位插入槽位（广告拦截 geosite-ad1/ad2 之后、cn/!cn 之前）
	strippedRouteRules := stripManagedRouteRules(existingRouteRules, managedSuffixes, managedRuleSets, customRouteSet)
	managedRouteRules := compileManagedRouteRules(normTR, groupTags, directTag, definedRuleSets, preserveNativeHoK)
	insertRouteIdx := findTrafficRouteInsertIndex(strippedRouteRules)

	finalRouteRules := make([]any, 0, len(strippedRouteRules)+len(managedRouteRules))
	finalRouteRules = append(finalRouteRules, strippedRouteRules[:insertRouteIdx]...)
	for _, mr := range managedRouteRules {
		finalRouteRules = append(finalRouteRules, mr)
	}
	finalRouteRules = append(finalRouteRules, strippedRouteRules[insertRouteIdx:]...)
	routeMap["rules"] = finalRouteRules

	// 2. 同步编译并注入 dns.rules（仅处理明确存在的 DNS server tag）
	isIOS := strings.EqualFold(strings.TrimSpace(platform), PlatformIOS)
	if dnsMap, ok := doc["dns"].(map[string]any); ok {
		proxyDNS, directDNS := resolveClientDNSTags(dnsMap)
		if proxyDNS != "" || directDNS != "" {
			skipEnabledGeositeDNS := isIOS && proxyDNS != "" && strings.TrimSpace(stringField(dnsMap, "final")) == proxyDNS
			existingDNSRules, _ := dnsMap["rules"].([]any)
			strippedDNSRules := stripManagedDNSRules(existingDNSRules, managedSuffixes, managedRuleSets, customRouteSet)
			managedDNSRules := compileManagedDNSRules(normTR, proxyDNS, directDNS, definedRuleSets, preserveNativeHoK, skipEnabledGeositeDNS)
			insertDNSIdx := findTrafficDNSInsertIndex(strippedDNSRules)

			finalDNSRules := make([]any, 0, len(strippedDNSRules)+len(managedDNSRules))
			finalDNSRules = append(finalDNSRules, strippedDNSRules[:insertDNSIdx]...)
			for _, dr := range managedDNSRules {
				finalDNSRules = append(finalDNSRules, dr)
			}
			finalDNSRules = append(finalDNSRules, strippedDNSRules[insertDNSIdx:]...)
			dnsMap["rules"] = finalDNSRules
		}
	}

	return PrettyJSON(mustMarshalRawJSON(doc))
}

func mustMarshalRawJSON(doc map[string]any) string {
	b, _ := json.Marshal(doc)
	return string(b)
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func collectDefinedRuleSetTags(routeMap map[string]any) map[string]bool {
	out := make(map[string]bool)
	rawRS, _ := routeMap["rule_set"].([]any)
	for _, item := range rawRS {
		if rm, ok := item.(map[string]any); ok {
			if tag := strings.TrimSpace(stringField(rm, "tag")); tag != "" {
				out[tag] = true
			}
		}
	}
	return out
}

func shouldPreserveNativeHoK(tr config.TrafficRoutingConfig, groupTags []string, existingRouteRules []any) bool {
	defOut := ResolvePresetDefaultOutbound(false, true, groupTags)
	enabled, out := tr.PresetState("hok", true, defOut)
	if !enabled || (out != "" && out != defOut) {
		return false
	}
	// 仅当现存配置仍保有原生单 string "geosite-hok" -> defOut (#Auto) 规则时原样保留（含 203.80.96.0/24 HK ECS）；
	// 若曾切换直连或其他组后恢复默认，则走受管重建流程将其写回 #Auto。
	for _, r := range existingRouteRules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if rs := extractStringOrSlice(rm["rule_set"]); slices.Equal(rs, []string{"geosite-hok"}) && stringField(rm, "outbound") == defOut {
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
	// singgen 模板包含 download.sgameglobal.com / res.sgameglobal.com 等子域，仅当 HoK 被接管时统一收敛至 sgameglobal.com
	return managed["sgameglobal.com"] && (s == "sgameglobal.com" || strings.HasSuffix(s, ".sgameglobal.com"))
}

func extractStringOrSlice(raw any) []string {
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if t := strings.TrimSpace(s); t != "" {
					out = append(out, t)
				}
			}
		}
		return out
	}
	return nil
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
		if b, err := json.Marshal(r); err == nil {
			sig.routeJSONs[string(b)] = true
		}
	}
	for _, d := range cr.DNS {
		if b, err := json.Marshal(d); err == nil {
			sig.dnsJSONs[string(b)] = true
		}
	}
	return sig
}

func isProtectedCustomRule(rm map[string]any, known map[string]bool) bool {
	if len(known) == 0 {
		return false
	}
	b, err := json.Marshal(rm)
	if err != nil {
		return false
	}
	return known[string(b)]
}

func hasOnlyAllowedKeys(rm map[string]any, allowed map[string]bool) bool {
	for k := range rm {
		if !allowed[k] {
			return false
		}
	}
	return true
}

var allowedPureRouteRuleKeys = map[string]bool{
	"action":        true,
	"outbound":      true,
	"domain_suffix": true,
	"rule_set":      true,
}

var allowedPureDNSRuleKeys = map[string]bool{
	"action":        true,
	"server":        true,
	"client_subnet": true,
	"domain_suffix": true,
	"rule_set":      true,
}

func stripManagedFromPureRule(rm map[string]any, suffixes, ruleSets map[string]bool) (keep bool, updated map[string]any) {
	clone := make(map[string]any, len(rm))
	for k, v := range rm {
		clone[k] = v
	}

	hasRemainingMatcher := false
	hasManagedList := false
	changed := false

	if rawDS, exists := clone["domain_suffix"]; exists {
		hasManagedList = true
		ds := extractStringOrSlice(rawDS)
		filtered := make([]string, 0, len(ds))
		for _, item := range ds {
			if !isManagedSuffix(item, suffixes) {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
		}
		if len(filtered) > 0 {
			clone["domain_suffix"] = filtered
			hasRemainingMatcher = true
		} else {
			delete(clone, "domain_suffix")
		}
	}

	if rawRS, exists := clone["rule_set"]; exists {
		hasManagedList = true
		rs := extractStringOrSlice(rawRS)
		filtered := make([]string, 0, len(rs))
		for _, item := range rs {
			if !ruleSets[strings.ToLower(strings.TrimSpace(item))] {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
		}
		if len(filtered) > 0 {
			clone["rule_set"] = filtered
			hasRemainingMatcher = true
		} else {
			delete(clone, "rule_set")
		}
	}

	if !hasManagedList || !changed {
		return true, rm
	}
	if !hasRemainingMatcher {
		return false, nil
	}
	return true, clone
}

func stripManagedRouteRules(rules []any, suffixes, ruleSets map[string]bool, crSig customSignature) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		action := strings.ToLower(strings.TrimSpace(stringField(rm, "action")))
		if (action != "" && action != "route") ||
			!hasOnlyAllowedKeys(rm, allowedPureRouteRuleKeys) ||
			isProtectedCustomRule(rm, crSig.routeJSONs) {
			out = append(out, r)
			continue
		}
		keep, updated := stripManagedFromPureRule(rm, suffixes, ruleSets)
		if keep {
			out = append(out, updated)
		}
	}
	return out
}

func stripManagedDNSRules(rules []any, suffixes, ruleSets map[string]bool, crSig customSignature) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		action := strings.ToLower(strings.TrimSpace(stringField(rm, "action")))
		if (action != "" && action != "route") ||
			!hasOnlyAllowedKeys(rm, allowedPureDNSRuleKeys) ||
			isProtectedCustomRule(rm, crSig.dnsJSONs) {
			out = append(out, r)
			continue
		}
		keep, updated := stripManagedFromPureRule(rm, suffixes, ruleSets)
		if keep {
			out = append(out, updated)
		}
	}
	return out
}

type compiledMatcherRule struct {
	isRuleSet bool
	values    []string
	target    string
}

func compileManagedRouteRules(tr config.TrafficRoutingConfig, groupTags []string, directTag string, definedRuleSets map[string]bool, preserveNativeHoK bool) []map[string]any {
	var staged []compiledMatcherRule
	appendStaged := func(isRuleSet bool, values []string, outbound string) {
		if len(values) == 0 || outbound == "" {
			return
		}
		if n := len(staged); n > 0 && staged[n-1].isRuleSet == isRuleSet && staged[n-1].target == outbound {
			for _, v := range values {
				if !slices.Contains(staged[n-1].values, v) {
					staged[n-1].values = append(staged[n-1].values, v)
				}
			}
			return
		}
		staged = append(staged, compiledMatcherRule{
			isRuleSet: isRuleSet,
			values:    slices.Clone(values),
			target:    outbound,
		})
	}

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

		// sing-box 单条规则同时填 domain_suffix 与 rule_set 表示 AND；因此拆分为独立规则，并仅对相邻同类型同出站合并
		if len(p.DomainSuffixes) > 0 {
			appendStaged(false, p.DomainSuffixes, targetOutbound)
		}
		if len(p.RuleSets) > 0 {
			filteredRS := filterExistingRuleSets(p.RuleSets, definedRuleSets, false)
			appendStaged(true, filteredRS, targetOutbound)
		}
	}

	out := make([]map[string]any, 0, len(staged))
	for _, s := range staged {
		key := "domain_suffix"
		if s.isRuleSet {
			key = "rule_set"
		}
		out = append(out, map[string]any{
			"action":   "route",
			key:        s.values,
			"outbound": s.target,
		})
	}
	return out
}

func compileManagedDNSRules(tr config.TrafficRoutingConfig, proxyDNS, directDNS string, definedRuleSets map[string]bool, preserveNativeHoK, skipEnabledGeosite bool) []map[string]any {
	var staged []compiledMatcherRule
	appendStaged := func(isRuleSet bool, values []string, server string) {
		if len(values) == 0 || server == "" {
			return
		}
		if n := len(staged); n > 0 && staged[n-1].isRuleSet == isRuleSet && staged[n-1].target == server {
			for _, v := range values {
				if !slices.Contains(staged[n-1].values, v) {
					staged[n-1].values = append(staged[n-1].values, v)
				}
			}
			return
		}
		staged = append(staged, compiledMatcherRule{
			isRuleSet: isRuleSet,
			values:    slices.Clone(values),
			target:    server,
		})
	}

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
			appendStaged(false, p.DomainSuffixes, targetDNS)
		}
		if len(p.RuleSets) > 0 && !(skipEnabledGeosite && enabled) {
			// DNS pre-match 仅匹配域名类 geosite-* 规则集，跳过纯 IP 类的 geoip-*
			filteredRS := filterExistingRuleSets(p.RuleSets, definedRuleSets, true)
			appendStaged(true, filteredRS, targetDNS)
		}
	}

	out := make([]map[string]any, 0, len(staged))
	for _, s := range staged {
		key := "domain_suffix"
		if s.isRuleSet {
			key = "rule_set"
		}
		out = append(out, map[string]any{
			key:      s.values,
			"server": s.target,
		})
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

func resolveClientDNSTags(dnsMap map[string]any) (proxyTag, directTag string) {
	rawServers, _ := dnsMap["servers"].([]any)
	var allTags []string
	for _, item := range rawServers {
		sm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := strings.TrimSpace(stringField(sm, "tag"))
		if tag != "" {
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
		if f := strings.TrimSpace(stringField(dnsMap, "final")); f != "" && f != directTag {
			proxyTag = f
		}
	}
	return proxyTag, directTag
}

func findTrafficRouteInsertIndex(rules []any) int {
	// 首选锚点：广告拦截 rule (geosite-ad1 / geosite-ad2) 之后（保留私网/custom_rules/去广告在最前）
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(stringField(rm, "action"), "reject") {
			for _, tag := range extractStringOrSlice(rm["rule_set"]) {
				if tag == "geosite-ad1" || tag == "geosite-ad2" {
					return i + 1
				}
			}
		}
	}
	// 次选锚点：通用国内/非国内兜底规则之前
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		for _, tag := range extractStringOrSlice(rm["rule_set"]) {
			if tag == "geosite-cn" || tag == "geosite-geolocation-!cn" || tag == "geoip-cn" {
				return i
			}
		}
	}
	// 保底锚点：跳过前序系统级规则 (sniff / hijack-dns / clash_mode / ip_is_private / reject)
	idx := 0
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(stringField(rm, "action")))
		_, hasClash := rm["clash_mode"]
		_, hasPrivate := rm["ip_is_private"]
		if action == "sniff" || action == "hijack-dns" || action == "reject" || hasClash || hasPrivate {
			idx = i + 1
		}
	}
	return idx
}

func findTrafficDNSInsertIndex(rules []any) int {
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		for _, tag := range extractStringOrSlice(rm["rule_set"]) {
			if tag == "geosite-cn" || tag == "geosite-geolocation-!cn" {
				return i
			}
		}
	}
	idx := 0
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if _, hasClash := rm["clash_mode"]; hasClash || strings.EqualFold(stringField(rm, "action"), "reject") {
			idx = i + 1
		}
	}
	return idx
}
