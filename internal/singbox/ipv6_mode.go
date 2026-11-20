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

// cnPublicDoHIPCIDRs 与 cnPublicDoHDomains 用于拦截局域网终端（iOS/Android/Chrome 等）绕过网关 :53、
// 直接通过 443/853 请求国内公共 DoH/DoT 导致的 DNS 泄漏。路由器本机 AdGuard Home 出站已在 nft output 链显式豁免。
var cnPublicDoHIPCIDRs = []string{
	"223.5.5.5/32",
	"223.6.6.6/32",
	"119.29.29.29/32",
	"119.28.28.28/32",
	"120.53.53.53/32",
	"1.12.12.12/32",
	"114.114.114.114/32",
	"114.114.115.115/32",
	"180.76.76.76/32",
	"2400:3200::1/128",
	"2400:3200:baba::1/128",
	"2402:4e00::/128",
	"2402:4e00:1::/128",
	"240c::6666/128",
	"240c::6644/128",
}

var cnPublicDoHDomains = []string{
	"dns.alidns.com",
	"doh.pub",
	"dns.pub",
	"sm2.doh.pub",
	"dot.pub",
	"doh.360.cn",
	"dns.360.cn",
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
	} else {
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
		} else {
			// cn_only: 对每一条命中 dns_proxy 的规则，先插入一条同匹配条件但 query_type=["AAAA","HTTPS"] -> predefined NOERROR 的规则，
			// 并在末尾追加全局 AAAA/HTTPS predefined NOERROR 兜底（兜底未命中任何规则而落入 final: dns_proxy 的海外域名）。
			finalRules := make([]any, 0, len(withDirectCN)*2+1)
			for _, item := range withDirectCN {
				ruleMap, ok := item.(map[string]any)
				if !ok || ruleMap == nil {
					continue
				}
				if srv, _ := ruleMap["server"].(string); srv == "dns_proxy" {
					if _, hasQT := ruleMap["query_type"]; !hasQT {
						if act, _ := ruleMap["action"].(string); act == "" || act == "route" {
							finalRules = append(finalRules, cloneRuleForAAAASuppress(ruleMap))
						}
					}
				}
				finalRules = append(finalRules, ruleMap)
			}
			finalRules = append(finalRules, map[string]any{
				"query_type": []string{"AAAA", "HTTPS"},
				"action":     "predefined",
				"rcode":      "NOERROR",
			})
			dnsMap["rules"] = finalRules
		}
	}

	applyIPv6ModeToRouteRules(root, mode)
	return marshalPrettySingBoxJSON(root)
}

func cloneRuleForAAAASuppress(src map[string]any) map[string]any {
	twin := maps.Clone(src)
	delete(twin, "server")
	delete(twin, "client_subnet")
	delete(twin, "strategy")
	delete(twin, "disable_cache")
	delete(twin, "rewrite_ttl")
	twin["query_type"] = []string{"AAAA", "HTTPS"}
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
	return isAutoIPv6SuppressQueryTypes(rule["query_type"])
}

// isAutoIPv6SuppressQueryTypes 同时识别历史 ["AAAA"] 与新版 ["AAAA", "HTTPS"]，确保平滑幂等升级。
func isAutoIPv6SuppressQueryTypes(val any) bool {
	qts := extractQueryTypeStrings(val)
	switch len(qts) {
	case 1:
		return qts[0] == "AAAA"
	case 2:
		return (qts[0] == "AAAA" && qts[1] == "HTTPS") || (qts[0] == "HTTPS" && qts[1] == "AAAA")
	default:
		return false
	}
}

func extractQueryTypeStrings(val any) []string {
	switch qt := val.(type) {
	case string:
		if s := strings.ToUpper(strings.TrimSpace(qt)); s != "" {
			return []string{s}
		}
	case []string:
		out := make([]string, 0, len(qt))
		for _, item := range qt {
			out = append(out, strings.ToUpper(strings.TrimSpace(item)))
		}
		return out
	case []any:
		out := make([]string, 0, len(qt))
		for _, item := range qt {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, strings.ToUpper(strings.TrimSpace(s)))
		}
		return out
	}
	return nil
}

func applyIPv6ModeToRouteRules(root map[string]any, mode string) {
	routeMap, ok := root["route"].(map[string]any)
	if !ok || routeMap == nil {
		return
	}
	rawRules := asAnySlice(routeMap["rules"])
	if len(rawRules) == 0 {
		return
	}

	cleaned := make([]any, 0, len(rawRules))
	for _, item := range rawRules {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		if isAutoInjectedDNSBypassRejectRule(ruleMap) || isAutoInjectedSTUNRejectRule(ruleMap) || isAutoInjectedIPv6RouteRejectRule(ruleMap) {
			continue
		}
		cleaned = append(cleaned, ruleMap)
	}

	if mode == config.GatewayIPv6Off {
		routeMap["rules"] = cleaned
		return
	}

	// 插入拦截规则至 sniff / hijack-dns / ip_is_private 之后，确保域名可被嗅探且私有/DNS 流量先命中。
	insertAt := 0
	for i, item := range cleaned {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		act, _ := ruleMap["action"].(string)
		isPriv, _ := ruleMap["ip_is_private"].(bool)
		if isPriv || act == "hijack-dns" || act == "sniff" {
			insertAt = i + 1
		}
	}

	dnsBypassRejectRules := []any{
		map[string]any{
			"action": "reject",
			"port":   853,
		},
		map[string]any{
			"action":  "reject",
			"ip_cidr": slices.Clone(cnPublicDoHIPCIDRs),
			"port":    []int{443, 853},
		},
		map[string]any{
			"action": "reject",
			"domain": slices.Clone(cnPublicDoHDomains),
			"port":   []int{443, 853},
		},
	}

	withDNSReject := make([]any, 0, len(cleaned)+len(dnsBypassRejectRules))
	withDNSReject = append(withDNSReject, cleaned[:insertAt]...)
	withDNSReject = append(withDNSReject, dnsBypassRejectRules...)
	withDNSReject = append(withDNSReject, cleaned[insertAt:]...)

	// 在 geoip-cn/#DC 之后、通用 udp 1024:65535 -> #DC 兜底规则之前拦截海外 WebRTC STUN，
	// 防止浏览器通过 STUN 穿透直连出口暴露家庭真实公网 IP；国内微信/QQ/游戏 STUN 已先命中 geoip-cn 直连不受影响。
	stunRejectRules := []any{
		map[string]any{
			"action":   "reject",
			"protocol": "stun",
		},
		map[string]any{
			"action":  "reject",
			"network": "udp",
			"port":    []int{3478, 3479, 5349},
		},
		map[string]any{
			"action":     "reject",
			"network":    "udp",
			"port_range": []string{"19302:19309"},
		},
	}
	stunInsertAt := findSTUNRejectInsertIndex(withDNSReject)
	withLeaksBlocked := make([]any, 0, len(withDNSReject)+len(stunRejectRules))
	withLeaksBlocked = append(withLeaksBlocked, withDNSReject[:stunInsertAt]...)
	withLeaksBlocked = append(withLeaksBlocked, stunRejectRules...)
	withLeaksBlocked = append(withLeaksBlocked, withDNSReject[stunInsertAt:]...)

	if mode == config.GatewayIPv6Full {
		routeMap["rules"] = withLeaksBlocked
		return
	}

	// cn_only: 在每条走向代理出站的 route 规则前秒拒 ::/0（避免代理节点无 IPv6 时浏览器 Happy Eyeballs 挂死），
	// 若 route.final 也是代理出站则在末尾追加全局 ::/0 reject 兜底；国内 #DC 规则与明确指定 ip_cidr 的规则不受影响。
	finalRules := make([]any, 0, len(withLeaksBlocked)*2+1)
	for _, item := range withLeaksBlocked {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		if isProxyRouteRule(ruleMap) {
			matcher := maps.Clone(ruleMap)
			delete(matcher, "action")
			delete(matcher, "outbound")
			finalRules = append(finalRules, map[string]any{
				"type":   "logical",
				"mode":   "and",
				"action": "reject",
				"rules": []any{
					matcher,
					map[string]any{
						"ip_cidr": []string{"::/0"},
					},
				},
			})
		}
		finalRules = append(finalRules, ruleMap)
	}
	if finalOut, _ := routeMap["final"].(string); strings.TrimSpace(finalOut) != "" && !isDirectOrLocalOutbound(finalOut) {
		finalRules = append(finalRules, map[string]any{
			"action":  "reject",
			"ip_cidr": []string{"::/0"},
		})
	}
	routeMap["rules"] = finalRules
}

func findSTUNRejectInsertIndex(rules []any) int {
	afterGeoIPCN := -1
	for i, item := range rules {
		ruleMap, ok := item.(map[string]any)
		if !ok || ruleMap == nil {
			continue
		}
		if isCatchAllUDPDirectRule(ruleMap) {
			return i
		}
		act, _ := ruleMap["action"].(string)
		out, _ := ruleMap["outbound"].(string)
		if (act == "" || act == "route") && isDirectOrLocalOutbound(out) {
			if containsRuleSetTag(ruleMap["rule_set"], "geoip-cn") || containsRuleSetTag(ruleMap["rule_set"], "geoip-private") {
				afterGeoIPCN = i + 1
			}
		}
	}
	if afterGeoIPCN >= 0 {
		return afterGeoIPCN
	}
	return len(rules)
}

func isCatchAllUDPDirectRule(rule map[string]any) bool {
	act, _ := rule["action"].(string)
	if act != "" && act != "route" {
		return false
	}
	netw, _ := rule["network"].(string)
	if !strings.EqualFold(strings.TrimSpace(netw), "udp") {
		return false
	}
	out, _ := rule["outbound"].(string)
	if !isDirectOrLocalOutbound(out) {
		return false
	}
	if !slices.Contains(extractStringOrSlice(rule["port_range"]), "1024:65535") {
		return false
	}
	for _, k := range []string{"domain", "domain_suffix", "rule_set", "ip_cidr"} {
		if _, exists := rule[k]; exists {
			return false
		}
	}
	return true
}

func isAutoInjectedSTUNRejectRule(rule map[string]any) bool {
	if act, _ := rule["action"].(string); act != "reject" {
		return false
	}
	if len(rule) == 2 {
		if proto, _ := rule["protocol"].(string); proto == "stun" {
			return true
		}
		return false
	}
	if len(rule) != 3 {
		return false
	}
	if netw, _ := rule["network"].(string); netw != "udp" {
		return false
	}
	if isExactPorts(rule["port"], []int{3478, 3479, 5349}) {
		return true
	}
	return slices.Equal(extractStringOrSlice(rule["port_range"]), []string{"19302:19309"})
}

func isAutoInjectedDNSBypassRejectRule(rule map[string]any) bool {
	if act, _ := rule["action"].(string); act != "reject" {
		return false
	}
	if len(rule) == 2 && isSinglePort(rule["port"], 853) {
		return true
	}
	if len(rule) == 3 && isPortPair(rule["port"], 443, 853) {
		if slices.Equal(extractStringOrSlice(rule["ip_cidr"]), cnPublicDoHIPCIDRs) {
			return true
		}
		if slices.Equal(extractStringOrSlice(rule["domain"]), cnPublicDoHDomains) {
			return true
		}
	}
	return false
}

func isAutoInjectedIPv6RouteRejectRule(rule map[string]any) bool {
	if act, _ := rule["action"].(string); act != "reject" {
		return false
	}
	// 匹配末尾 ::/0 兜底规则，或历史平铺写法遗留的 ::/0 reject 规则以便迁移清理。
	cidrs := extractStringOrSlice(rule["ip_cidr"])
	if len(cidrs) == 1 && cidrs[0] == "::/0" {
		return true
	}
	typ, _ := rule["type"].(string)
	mode, _ := rule["mode"].(string)
	if typ != "logical" || mode != "and" {
		return false
	}
	subRules := asAnySlice(rule["rules"])
	if len(subRules) != 2 {
		return false
	}
	lastSub, ok := subRules[1].(map[string]any)
	if !ok || lastSub == nil || len(lastSub) != 1 {
		return false
	}
	lastCIDRs := extractStringOrSlice(lastSub["ip_cidr"])
	return len(lastCIDRs) == 1 && lastCIDRs[0] == "::/0"
}

func isProxyRouteRule(rule map[string]any) bool {
	act, _ := rule["action"].(string)
	if act != "" && act != "route" {
		return false
	}
	out, _ := rule["outbound"].(string)
	if strings.TrimSpace(out) == "" || isDirectOrLocalOutbound(out) {
		return false
	}
	if _, hasIPCIDR := rule["ip_cidr"]; hasIPCIDR {
		return false
	}
	for k := range rule {
		if k != "action" && k != "outbound" {
			return true
		}
	}
	return false
}

func isDirectOrLocalOutbound(out string) bool {
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "#dc", "direct", "block", "dns-out":
		return true
	default:
		return false
	}
}

func isExactPorts(raw any, want []int) bool {
	ports, ok := extractPorts(raw)
	return ok && slices.Equal(ports, want)
}

func isSinglePort(raw any, want int) bool {
	ports, ok := extractPorts(raw)
	return ok && len(ports) == 1 && ports[0] == want
}

func isPortPair(raw any, a, b int) bool {
	ports, ok := extractPorts(raw)
	if !ok || len(ports) != 2 {
		return false
	}
	return (ports[0] == a && ports[1] == b) || (ports[0] == b && ports[1] == a)
}

func extractPorts(raw any) ([]int, bool) {
	switch v := raw.(type) {
	case int:
		return []int{v}, true
	case int64:
		return []int{int(v)}, true
	case float64:
		return []int{int(v)}, true
	case []int:
		return v, true
	case []any:
		out := make([]int, 0, len(v))
		for _, item := range v {
			p, ok := extractSinglePortNum(item)
			if !ok {
				return nil, false
			}
			out = append(out, p)
		}
		return out, true
	default:
		return nil, false
	}
}

func extractSinglePortNum(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
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
