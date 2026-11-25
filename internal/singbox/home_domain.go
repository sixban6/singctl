// 文件职责：负责在客户端 sing-box 配置中幂等置顶本地域名（如 .home）的 dns_local 解析规则与 direct 路由规则，防止内网域名泄漏至海外代理 DNS。
package singbox

import (
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

func isManagedHomeDomainDNSRule(r sboption.DNSRule, suffix string) bool {
	if r.Server != "dns_local" || r.Action != "" || (r.Invert != nil && *r.Invert) || r.DomainSuffix.Len() != 1 {
		return false
	}
	if !r.Domain.IsEmpty() || !r.DomainKeyword.IsEmpty() || !r.RuleSet.IsEmpty() || !r.QueryType.IsEmpty() {
		return false
	}
	return strings.EqualFold(strings.Trim(strings.TrimSpace(r.DomainSuffix.Items[0]), "."), suffix)
}

func resolveDirectOutboundTag(doc *sboption.Document) string {
	if doc != nil {
		for _, ob := range doc.Outbounds {
			if strings.EqualFold(strings.TrimSpace(ob.Type), "direct") && strings.TrimSpace(ob.Tag) != "" {
				return strings.TrimSpace(ob.Tag)
			}
		}
	}
	return "direct"
}

func isManagedHomeDomainRouteRule(r sboption.RouteRule, suffix, directTag string) bool {
	out := strings.TrimSpace(r.Outbound)
	if out != directTag && out != "direct" {
		return false
	}
	if (r.Invert != nil && *r.Invert) || r.DomainSuffix.Len() != 1 {
		return false
	}
	if r.Action != "" && r.Action != "route" {
		return false
	}
	if !r.Domain.IsEmpty() || !r.DomainKeyword.IsEmpty() || !r.RuleSet.IsEmpty() || !r.IPCIDR.IsEmpty() || !r.Protocol.IsEmpty() {
		return false
	}
	return strings.EqualFold(strings.Trim(strings.TrimSpace(r.DomainSuffix.Items[0]), "."), suffix)
}

func hasDNSServerTag(doc *sboption.Document, tag string) bool {
	if doc == nil || doc.DNS == nil {
		return false
	}
	for _, s := range doc.DNS.Servers {
		if s.Tag == tag {
			return true
		}
	}
	return false
}

// ensureHomeDomainRulesInDoc 在强类型 sing-box 文档上幂等维护本地域名后缀的置顶 dns_local 与 direct 路由规则；
// suffix 为空时清除旧受管后缀规则，prevSuffix 非空且变更时自动替换旧后缀规则。
func ensureHomeDomainRulesInDoc(doc *sboption.Document, suffix, prevSuffix string) bool {
	if doc == nil {
		return false
	}
	normSfx := ""
	if strings.TrimSpace(suffix) != "" {
		if n, err := config.NormalizeHomeDomainSuffix(suffix); err == nil {
			normSfx = n
		}
	}
	normPrev := strings.ToLower(strings.Trim(strings.TrimSpace(prevSuffix), "."))
	changed := false

	// 1. DNS rules：确保位于 RFC 6303 私网 PTR 拦截之后、任何海外/geosite 代理规则之前
	if doc.DNS != nil && hasDNSServerTag(doc, "dns_local") {
		rules := doc.DNS.Rules
		if normPrev != "" && normPrev != normSfx {
			filtered := slices.DeleteFunc(slices.Clone(rules), func(r sboption.DNSRule) bool {
				return isManagedHomeDomainDNSRule(r, normPrev)
			})
			if len(filtered) != len(rules) {
				rules = filtered
				changed = true
			}
		}
		if normSfx == "" {
			// 若关闭本地域名，也顺带移除残留的旧受管规则（当 prevSuffix 为空时忽略）
			if changed {
				doc.DNS.Rules = rules
			}
		} else {
			hasWant := slices.ContainsFunc(rules, func(r sboption.DNSRule) bool {
				return isManagedHomeDomainDNSRule(r, normSfx)
			})
			if !hasWant {
				insertAt := 0
				for i, r := range rules {
					isSfx, isKw := sboption.IsManagedPrivatePTRDNSRule(r, privateReverseDNSSuffixes, DNSSDBrowseKeyword)
					if isSfx || isKw {
						insertAt = i + 1
						continue
					}
					break
				}
				rule := sboption.DNSRule{
					DomainSuffix: sboption.ListOf(normSfx),
					Server:       "dns_local",
				}
				merged := make([]sboption.DNSRule, 0, len(rules)+1)
				merged = append(merged, rules[:insertAt]...)
				merged = append(merged, rule)
				merged = append(merged, rules[insertAt:]...)
				rules = merged
				changed = true
			}
			if changed {
				doc.DNS.Rules = rules
			}
		}
	}

	// 2. Route rules：确保紧随 hijack-dns/sniff 之后命中实际 direct 出站（如 #DC），并自动修复旧版硬编码 direct 规则
	if doc.Route != nil {
		directTag := resolveDirectOutboundTag(doc)
		rules := doc.Route.Rules
		routeChanged := false
		if normPrev != "" && normPrev != normSfx {
			filtered := slices.DeleteFunc(slices.Clone(rules), func(r sboption.RouteRule) bool {
				return isManagedHomeDomainRouteRule(r, normPrev, directTag)
			})
			if len(filtered) != len(rules) {
				rules = filtered
				routeChanged = true
			}
		}
		if normSfx != "" {
			// 清理同后缀但指向旧/错误 direct tag（如 "direct" != "#DC"）的陈旧托管规则
			healed := slices.DeleteFunc(slices.Clone(rules), func(r sboption.RouteRule) bool {
				return isManagedHomeDomainRouteRule(r, normSfx, directTag) && strings.TrimSpace(r.Outbound) != directTag
			})
			if len(healed) != len(rules) {
				rules = healed
				routeChanged = true
			}
			hasWant := slices.ContainsFunc(rules, func(r sboption.RouteRule) bool {
				return isManagedHomeDomainRouteRule(r, normSfx, directTag) && strings.TrimSpace(r.Outbound) == directTag
			})
			if !hasWant {
				insertAt := 0
				for i, r := range rules {
					if r.Action == "sniff" || r.Action == "hijack-dns" || slices.Contains(r.Protocol.Slice(), "dns") {
						insertAt = i + 1
						continue
					}
					break
				}
				rule := sboption.RouteRule{
					DomainSuffix: sboption.ListOf(normSfx),
					Outbound:     directTag,
				}
				merged := make([]sboption.RouteRule, 0, len(rules)+1)
				merged = append(merged, rules[:insertAt]...)
				merged = append(merged, rule)
				merged = append(merged, rules[insertAt:]...)
				rules = merged
				routeChanged = true
			}
		}
		if routeChanged {
			doc.Route.Rules = rules
			changed = true
		}
	}

	return changed
}

// PatchHomeDomainDNSJSON 在既有 sing-box 配置 JSON 上幂等注入/更新本地域名后缀（如 home）的本地解析与直连路由规则。
func PatchHomeDomainDNSJSON(rawJSON, suffix, prevSuffix string) (string, bool, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, false, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", false, err
	}
	if !ensureHomeDomainRulesInDoc(doc, suffix, prevSuffix) {
		return rawJSON, false, nil
	}
	formatted, err := doc.MarshalPretty()
	if err != nil {
		return "", false, err
	}
	return formatted + "\n", true, nil
}
