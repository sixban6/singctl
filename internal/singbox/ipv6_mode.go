package singbox

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"singctl/internal/config"
)

// cnExtraDirectRuleSets 列出 route.rules 已划为直连 (#DC) 但默认模板尚未单独写入 dns.rules 的国内规则集。
// 在启用 IPv6 双栈分流 (cn_only / full) 时，将其对齐注入 dns_local，避免中国大陆 IPv6 查询误落入海外 dns_proxy 或被 AAAA 抑制拦截。
var cnExtraDirectRuleSets = []string{
	"geosite-private",
	"geosite-bank-cn",
	"geosite-jd",
	"geosite-ali",
	"geosite-baidu",
	"geosite-bytedance",
	"geosite-pdd",
	"geosite-bili",
	"geosite-meituan",
	"geosite-ctrip",
	"geosite-tencent",
	"geosite-ctm_cn",
}

// ApplyIPv6ModeToConfigJSON 将客户端 gateway.ipv6_mode ("off" | "cn_only" | "full")
// 幂等地编译写入 sing-box JSON 配置的 dns.strategy 与 dns.rules：
//   - "off": dns.strategy = "ipv4_only"，清除自动注入的 AAAA predefined 规则与扩展直连规则，保持纯 IPv4 行为。
//   - "cn_only": dns.strategy = "prefer_ipv4"，对齐国内直连规则集至 dns_local（保留国内 A + AAAA 双栈），
//     并对所有指向 dns_proxy 的规则及兜底规则在本地 0ms 返回 NOERROR 空 AAAA（海外流量稳定走 IPv4，彻底零 DNS 泄漏）。
//   - "full": dns.strategy = "prefer_ipv4"，对齐国内直连规则集至 dns_local，允许海外 A + AAAA 经 dns_proxy 隧道双栈解析。
func ApplyIPv6ModeToConfigJSON(rawJSON, ipv6Mode string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	mode, ok := config.NormalizeGatewayIPv6Mode(ipv6Mode)
	if !ok {
		return "", fmt.Errorf("无效的 IPv6 模式 %q（仅支持 off / cn_only / full）", ipv6Mode)
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("ipv6 mode: parse config JSON: %w", err)
	}
	if root == nil {
		return rawJSON, nil
	}

	dnsMap, hasDNS := root["dns"].(map[string]any)
	if !hasDNS || dnsMap == nil {
		return rawJSON, nil
	}

	rawRules := asAnySlice(dnsMap["rules"])
	cleanedRules := make([]any, 0, len(rawRules))
	var cnClientSubnet any

	for _, item := range rawRules {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		if cnClientSubnet == nil && containsRuleSetTag(ruleMap["rule_set"], "geosite-cn") {
			if cs, exists := ruleMap["client_subnet"]; exists && cs != nil {
				cnClientSubnet = cs
			}
		}
		if isAutoInjectedAAAAPredefinedRule(ruleMap) || isAutoInjectedCNDirectDNSRule(ruleMap) {
			continue
		}
		cleanedRules = append(cleanedRules, ruleMap)
	}

	if mode == config.GatewayIPv6Off {
		dnsMap["strategy"] = "ipv4_only"
		dnsMap["rules"] = cleanedRules
		return marshalPrettySingBoxJSON(root)
	}

	dnsMap["strategy"] = "prefer_ipv4"

	declaredRuleSets := collectDeclaredRouteRuleSetTags(root)
	existingDNSTags := collectReferencedDNSRuleSetTags(cleanedRules)
	var missingCNTags []string
	for _, tag := range cnExtraDirectRuleSets {
		if _, declared := declaredRuleSets[tag]; !declared {
			continue
		}
		if _, already := existingDNSTags[tag]; already {
			continue
		}
		missingCNTags = append(missingCNTags, tag)
	}

	withDirectCN := cleanedRules
	if len(missingCNTags) > 0 {
		extraRule := map[string]any{
			"rule_set": missingCNTags,
			"server":   "dns_local",
		}
		if cnClientSubnet != nil {
			extraRule["client_subnet"] = cnClientSubnet
		}
		withDirectCN = insertRuleBeforeGeositeCN(cleanedRules, extraRule)
	}

	if mode == config.GatewayIPv6Full {
		dnsMap["rules"] = withDirectCN
		return marshalPrettySingBoxJSON(root)
	}

	// cn_only: 对每一条命中 dns_proxy 的规则，先插入一条同匹配条件但 query_type=["AAAA"] -> predefined NOERROR 的规则，
	// 并在末尾追加全局 AAAA predefined NOERROR 兜底（兜底未命中任何规则而落入 final: dns_proxy 的海外域名）。
	finalRules := make([]any, 0, len(withDirectCN)*2+1)
	for _, item := range withDirectCN {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		if srv, _ := ruleMap["server"].(string); srv == "dns_proxy" {
			if _, hasQT := ruleMap["query_type"]; !hasQT {
				if _, hasAct := ruleMap["action"]; !hasAct {
					twin := cloneRuleForAAAASuppress(ruleMap)
					finalRules = append(finalRules, twin)
				}
			}
		}
		finalRules = append(finalRules, ruleMap)
	}
	finalRules = append(finalRules, map[string]any{
		"query_type": []string{"AAAA"},
		"action":     "predefined",
		"rcode":      "NOERROR",
	})

	dnsMap["rules"] = finalRules
	return marshalPrettySingBoxJSON(root)
}

func cloneRuleForAAAASuppress(src map[string]any) map[string]any {
	twin := maps.Clone(src)
	delete(twin, "server")
	delete(twin, "client_subnet")
	delete(twin, "strategy")
	delete(twin, "disable_cache")
	delete(twin, "rewrite_ttl")
	twin["query_type"] = []string{"AAAA"}
	twin["action"] = "predefined"
	twin["rcode"] = "NOERROR"
	return twin
}

func isAutoInjectedAAAAPredefinedRule(rule map[string]any) bool {
	act, _ := rule["action"].(string)
	rcode, _ := rule["rcode"].(string)
	if act != "predefined" || !strings.EqualFold(rcode, "NOERROR") {
		return false
	}
	return isOnlyQueryTypeAAAA(rule["query_type"])
}

func isOnlyQueryTypeAAAA(val any) bool {
	switch qt := val.(type) {
	case string:
		return strings.EqualFold(strings.TrimSpace(qt), "AAAA")
	case []string:
		return len(qt) == 1 && strings.EqualFold(strings.TrimSpace(qt[0]), "AAAA")
	case []any:
		if len(qt) != 1 {
			return false
		}
		s, ok := qt[0].(string)
		return ok && strings.EqualFold(strings.TrimSpace(s), "AAAA")
	default:
		return false
	}
}

func isAutoInjectedCNDirectDNSRule(rule map[string]any) bool {
	if srv, _ := rule["server"].(string); srv != "dns_local" {
		return false
	}
	for k := range rule {
		switch k {
		case "rule_set", "server", "client_subnet":
		default:
			return false
		}
	}
	tags := extractStringOrSlice(rule["rule_set"])
	if len(tags) == 0 {
		return false
	}
	for _, tag := range tags {
		if !slices.Contains(cnExtraDirectRuleSets, tag) {
			return false
		}
	}
	return true
}

func containsRuleSetTag(raw any, target string) bool {
	return slices.Contains(extractStringOrSlice(raw), target)
}

func asAnySlice(raw any) []any {
	s, _ := raw.([]any)
	return s
}

func collectDeclaredRouteRuleSetTags(root map[string]any) map[string]struct{} {
	tags := make(map[string]struct{})
	routeMap, ok := root["route"].(map[string]any)
	if !ok || routeMap == nil {
		return tags
	}
	for _, item := range asAnySlice(routeMap["rule_set"]) {
		if rsMap, ok := item.(map[string]any); ok {
			if tag, _ := rsMap["tag"].(string); strings.TrimSpace(tag) != "" {
				tags[strings.TrimSpace(tag)] = struct{}{}
			}
		}
	}
	return tags
}

func collectReferencedDNSRuleSetTags(rules []any) map[string]struct{} {
	tags := make(map[string]struct{})
	for _, item := range rules {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		for _, t := range extractStringOrSlice(ruleMap["rule_set"]) {
			tags[t] = struct{}{}
		}
	}
	return tags
}

func insertRuleBeforeGeositeCN(rules []any, extraRule map[string]any) []any {
	insertAt := len(rules)
	for i, item := range rules {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		if containsRuleSetTag(ruleMap["rule_set"], "geosite-cn") || containsRuleSetTag(ruleMap["rule_set"], "geosite-geolocation-!cn") {
			insertAt = i
			break
		}
	}
	out := make([]any, 0, len(rules)+1)
	out = append(out, rules[:insertAt]...)
	out = append(out, extraRule)
	out = append(out, rules[insertAt:]...)
	return out
}

func marshalPrettySingBoxJSON(root map[string]any) (string, error) {
	outBytes, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", err
	}
	return string(outBytes), nil
}
