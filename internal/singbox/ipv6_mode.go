// 文件职责：将客户端网关 IPv6 分流模式（off / cn_only / full）幂等编译至 *sboption.Document 的 DNS 与路由防泄漏规则。
package singbox

import (
	"fmt"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
)

// cnExtraDirectRuleSets 列出 route.rules 已划为直连 (#DC) 但默认模板尚未单独写入 dns.rules 的国内规则集。
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

// cnPublicDoHIPCIDRs 与 cnPublicDoHDomains 用于拦截局域网终端绕过网关 :53 直接请求国内公共 DoH/DoT 导致的 DNS 泄漏。
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

// CNPublicDoHIPCIDRs 返回防绕过拦截的国内公共 DoH/DoT IP 网段副本。
func CNPublicDoHIPCIDRs() []string { return slices.Clone(cnPublicDoHIPCIDRs) }

// CNPublicDoHDomains 返回防绕过拦截的国内公共 DoH/DoT 域名副本。
func CNPublicDoHDomains() []string { return slices.Clone(cnPublicDoHDomains) }

// ApplyIPv6ModeToConfigJSON 将客户端 gateway.ipv6_mode ("off" | "cn_only" | "full")
// 幂等地编译写入 sing-box JSON 配置的 dns.strategy、dns.rules 与 route.rules。
func ApplyIPv6ModeToConfigJSON(rawJSON, ipv6Mode string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	if _, ok := config.NormalizeGatewayIPv6Mode(ipv6Mode); !ok {
		return "", fmt.Errorf("无效的 IPv6 模式 %q（仅支持 off / cn_only / full）", ipv6Mode)
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("ipv6 mode: parse config JSON: %w", err)
	}
	if doc.DNS == nil {
		return rawJSON, nil
	}
	if err := applyIPv6ModeToDoc(doc, ipv6Mode); err != nil {
		return "", err
	}
	return doc.MarshalPretty()
}

func applyIPv6ModeToDoc(doc *sboption.Document, ipv6Mode string) error {
	mode, ok := config.NormalizeGatewayIPv6Mode(ipv6Mode)
	if !ok {
		return fmt.Errorf("无效的 IPv6 模式 %q（仅支持 off / cn_only / full）", ipv6Mode)
	}
	if doc == nil || doc.DNS == nil {
		return nil
	}

	cleanedDNS := make([]sboption.DNSRule, 0, len(doc.DNS.Rules))
	cnClientSubnet := ""
	for _, r := range doc.DNS.Rules {
		if cnClientSubnet == "" && slices.Contains(r.RuleSet.Slice(), "geosite-cn") && r.ClientSubnet != "" {
			cnClientSubnet = r.ClientSubnet
		}
		if sboption.IsManagedAAAASuppressDNSRule(r) || sboption.IsManagedCNDirectDNSRule(r, cnExtraDirectRuleSets) {
			continue
		}
		cleanedDNS = append(cleanedDNS, r)
	}

	if mode == config.GatewayIPv6Off {
		doc.DNS.Strategy = "ipv4_only"
		doc.DNS.Rules = cleanedDNS
	} else {
		doc.DNS.Strategy = "prefer_ipv4"

		declaredRuleSets := collectDefinedRuleSetTags(doc.Route)
		referencedDNSTags := make(map[string]bool)
		collectReferencedDNSRuleSets(cleanedDNS, referencedDNSTags)

		var missingCNTags []string
		for _, tag := range cnExtraDirectRuleSets {
			if declaredRuleSets[tag] && !referencedDNSTags[tag] {
				missingCNTags = append(missingCNTags, tag)
			}
		}

		withDirectCN := cleanedDNS
		if len(missingCNTags) > 0 {
			extraRule := sboption.DNSRule{
				RuleSet:      sboption.ListOf(missingCNTags...),
				Server:       "dns_local",
				ClientSubnet: cnClientSubnet,
			}
			insertAt := sboption.BeforeGeositeCNDNSInsertIndex(cleanedDNS)
			withDirectCN = slices.Insert(slices.Clone(cleanedDNS), insertAt, extraRule)
		}

		if mode == config.GatewayIPv6Full {
			doc.DNS.Rules = withDirectCN
		} else {
			finalDNS := make([]sboption.DNSRule, 0, len(withDirectCN)*2+1)
			for _, r := range withDirectCN {
				if r.Server == "dns_proxy" && r.QueryType.IsEmpty() && (r.Action == "" || r.Action == "route") {
					finalDNS = append(finalDNS, cloneDNSRuleForAAAASuppress(r))
				}
				finalDNS = append(finalDNS, r)
			}
			finalDNS = append(finalDNS, sboption.DNSRule{
				QueryType: sboption.ListOf("AAAA", "HTTPS"),
				Action:    "predefined",
				Rcode:     "NOERROR",
			})
			doc.DNS.Rules = finalDNS
		}
	}

	applyIPv6ModeToRouteRulesInDoc(doc.Route, mode)
	return nil
}

func cloneDNSRuleForAAAASuppress(src sboption.DNSRule) sboption.DNSRule {
	twin := src.Clone()
	twin.Server = ""
	twin.ClientSubnet = ""
	twin.Strategy = ""
	twin.DisableCache = nil
	twin.RewriteTTL = nil
	twin.QueryType = sboption.ListOf("AAAA", "HTTPS")
	twin.Action = "predefined"
	twin.Rcode = "NOERROR"
	return twin
}

func applyIPv6ModeToRouteRulesInDoc(route *sboption.RouteOptions, mode string) {
	if route == nil || len(route.Rules) == 0 {
		return
	}

	cleaned := make([]sboption.RouteRule, 0, len(route.Rules))
	for _, r := range route.Rules {
		if sboption.IsManagedDNSBypassRejectRouteRule(r, cnPublicDoHIPCIDRs, cnPublicDoHDomains) ||
			sboption.IsManagedSTUNRejectRouteRule(r) ||
			sboption.IsManagedIPv6RejectRouteRule(r) {
			continue
		}
		cleaned = append(cleaned, r)
	}

	if mode == config.GatewayIPv6Off {
		route.Rules = cleaned
		return
	}

	dnsBypassRejectRules := []sboption.RouteRule{
		{
			Action: "reject",
			Port:   sboption.ScalarOf[uint16](853),
		},
		{
			Action: "reject",
			IPCIDR: sboption.ListOf(cnPublicDoHIPCIDRs...),
			Port:   sboption.ListOf[uint16](443, 853),
		},
		{
			Action: "reject",
			Domain: sboption.ListOf(cnPublicDoHDomains...),
			Port:   sboption.ListOf[uint16](443, 853),
		},
	}
	insertAt := sboption.DNSBypassRejectInsertIndex(cleaned)
	withDNSReject := slices.Insert(slices.Clone(cleaned), insertAt, dnsBypassRejectRules...)

	stunRejectRules := []sboption.RouteRule{
		{
			Action:   "reject",
			Protocol: sboption.ScalarOf("stun"),
		},
		{
			Action:  "reject",
			Network: sboption.ScalarOf("udp"),
			Port:    sboption.ListOf[uint16](3478, 3479, 5349),
		},
		{
			Action:    "reject",
			Network:   sboption.ScalarOf("udp"),
			PortRange: sboption.ListOf("19302:19309"),
		},
	}
	stunInsertAt := sboption.STUNRejectInsertIndex(withDNSReject, isDirectOrLocalOutbound)
	withLeaksBlocked := slices.Insert(withDNSReject, stunInsertAt, stunRejectRules...)

	if mode == config.GatewayIPv6Full {
		route.Rules = withLeaksBlocked
		return
	}

	finalRules := make([]sboption.RouteRule, 0, len(withLeaksBlocked)*2+1)
	for _, r := range withLeaksBlocked {
		if isProxyRouteRule(r) {
			matcher := r.Clone()
			matcher.Action = ""
			matcher.Outbound = ""
			finalRules = append(finalRules, sboption.RouteRule{
				Type:   "logical",
				Mode:   "and",
				Action: "reject",
				Rules: []sboption.RouteRule{
					matcher,
					{IPCIDR: sboption.ListOf("::/0")},
				},
			})
		}
		finalRules = append(finalRules, r)
	}
	if finalOut := strings.TrimSpace(route.Final); finalOut != "" && !isDirectOrLocalOutbound(finalOut) {
		finalRules = append(finalRules, sboption.RouteRule{
			Action: "reject",
			IPCIDR: sboption.ListOf("::/0"),
		})
	}
	route.Rules = finalRules
}

func isProxyRouteRule(r sboption.RouteRule) bool {
	if r.Action != "" && r.Action != "route" {
		return false
	}
	if strings.TrimSpace(r.Outbound) == "" || isDirectOrLocalOutbound(r.Outbound) {
		return false
	}
	if !r.IPCIDR.IsEmpty() {
		return false
	}
	return len(r.Extra) > 0 || len(r.Rules) > 0 || r.ClashMode != "" || r.IPIsPrivate != nil ||
		!r.Network.IsEmpty() || !r.Protocol.IsEmpty() || !r.Port.IsEmpty() || !r.PortRange.IsEmpty() ||
		!r.RuleSet.IsEmpty() || !r.Domain.IsEmpty() || !r.DomainSuffix.IsEmpty() ||
		!r.DomainKeyword.IsEmpty() || !r.DomainRegex.IsEmpty() || !r.SourceIPCIDR.IsEmpty()
}

func isDirectOrLocalOutbound(out string) bool {
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "#dc", "direct", "block", "dns-out":
		return true
	default:
		return false
	}
}
