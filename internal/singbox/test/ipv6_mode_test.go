// 文件职责：验证 IPv6 分流三模式（cn_only / full / off）切换、AAAA/HTTPS 孪生抑制、STUN/DoH 防泄漏与幂等性。
package singbox_test

import (
	"slices"
	"testing"

	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func sampleDNSRoutingConfigJSON() string {
	return `{
  "dns": {
    "final": "dns_proxy",
    "strategy": "ipv4_only",
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353},
      {"tag": "dns_proxy", "type": "https", "server": "8.8.8.8", "detour": "#VPS"}
    ],
    "rules": [
      {"clash_mode": "Direct", "client_subnet": "203.0.113.0/24", "server": "dns_local"},
      {"clash_mode": "Global", "server": "dns_proxy"},
      {"domain_suffix": ["openai.com"], "server": "dns_proxy"},
      {"rule_set": ["geosite-apple"], "server": "dns_local"},
      {"rule_set": "geosite-cn", "client_subnet": "203.0.113.0/24", "server": "dns_local"},
      {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"}
    ]
  },
  "route": {
    "final": "Proxy",
    "rules": [
      {"action": "sniff"},
      {"action": "hijack-dns", "port": 53},
      {"ip_is_private": true, "outbound": "#DC"},
      {"action": "route", "clash_mode": "global", "outbound": "Proxy"},
      {"action": "route", "domain_suffix": ["openai.com"], "outbound": "#VPS"},
      {"action": "route", "rule_set": ["geosite-cn"], "outbound": "#DC"},
      {"action": "route", "rule_set": "geosite-geolocation-!cn", "outbound": "Proxy"},
      {"action": "route", "rule_set": ["geoip-cn", "geoip-private"], "outbound": "#DC"},
      {"action": "route", "network": "udp", "port_range": ["1024:65535"], "outbound": "#DC"}
    ],
    "rule_set": [
      {"tag": "geosite-cn"},
      {"tag": "geosite-private"},
      {"tag": "geosite-bili"},
      {"tag": "geosite-tencent"},
      {"tag": "geosite-geolocation-!cn"},
      {"tag": "geosite-apple"}
    ]
  }
}`
}

func TestApplyIPv6ModeToConfigJSON_TransitionsAndIdempotency(t *testing.T) {
	base := sampleDNSRoutingConfigJSON()

	cnOnlyJSON, err := singbox.ApplyIPv6ModeToConfigJSON(base, "cn_only")
	if err != nil {
		t.Fatalf("ApplyIPv6ModeToConfigJSON(cn_only): %v", err)
	}
	doc, err := sboption.ParseDocument([]byte(cnOnlyJSON))
	if err != nil {
		t.Fatalf("parse cn_only: %v", err)
	}
	if doc.DNS.Strategy != "prefer_ipv4" {
		t.Fatalf("expected prefer_ipv4 in cn_only, got %v", doc.DNS.Strategy)
	}
	rules := doc.DNS.Rules

	foundGlobalTwin := false
	foundOpenAITwin := false
	foundExtraCN := false
	extraCNIdx := -1
	geositeCNIdx := -1
	for i, r := range rules {
		if r.ClashMode == "Global" && r.Action == "predefined" && r.Rcode == "NOERROR" {
			if !slices.Equal(r.QueryType.Slice(), []string{"AAAA", "HTTPS"}) {
				t.Fatalf("expected [AAAA HTTPS] query_type on Global twin, got %v", r.QueryType.Slice())
			}
			next := rules[i+1]
			if next.ClashMode == "Global" && next.Server == "dns_proxy" {
				foundGlobalTwin = true
			}
		}
		if slices.Contains(r.RuleSet.Slice(), "geosite-bili") && r.Server == "dns_local" {
			foundExtraCN = true
			extraCNIdx = i
		}
		if slices.Contains(r.RuleSet.Slice(), "geosite-cn") && r.Server == "dns_local" {
			geositeCNIdx = i
		}
		if slices.Equal(r.DomainSuffix.Slice(), []string{"openai.com"}) && r.Action == "predefined" {
			if !slices.Equal(r.QueryType.Slice(), []string{"AAAA", "HTTPS"}) {
				t.Fatalf("expected [AAAA HTTPS] query_type on openai twin, got %v", r.QueryType.Slice())
			}
			next := rules[i+1]
			if next.Server == "dns_proxy" {
				foundOpenAITwin = true
			}
		}
	}
	if !foundGlobalTwin || !foundOpenAITwin {
		t.Fatalf("expected predefined AAAA+HTTPS twins before Global and openai.com dns_proxy rules, got rules=%+v", rules)
	}
	if !foundExtraCN || extraCNIdx >= geositeCNIdx {
		t.Fatalf("expected missing CN direct rulesets injected before geosite-cn (extra=%d cn=%d)", extraCNIdx, geositeCNIdx)
	}
	lastRule := rules[len(rules)-1]
	if !sboption.IsManagedAAAASuppressDNSRule(lastRule) || lastRule.ClashMode != "" || !lastRule.DomainSuffix.IsEmpty() || !slices.Equal(lastRule.QueryType.Slice(), []string{"AAAA", "HTTPS"}) {
		t.Fatalf("expected final catch-all [AAAA HTTPS] predefined NOERROR rule, got %+v", lastRule)
	}

	routeRules := doc.Route.Rules
	privateIdx, dotIdx, dohIPIdx, dohDomIdx := -1, -1, -1, -1
	geoipCNIdx, stunProtoIdx, stunPortsIdx, stunRangeIdx, udpCatchAllIdx := -1, -1, -1, -1, -1
	foundVPSTwin, foundGeoNotCNTwin, foundDCRejectTwin := false, false, false
	for i, r := range routeRules {
		if slices.Equal(r.IPCIDR.Slice(), []string{"::/0"}) && (!r.DomainSuffix.IsEmpty() || !r.RuleSet.IsEmpty() || r.ClashMode != "") {
			t.Fatalf("unsafe flat OR rule combines ip_cidr=[::/0] with other matchers: %+v", r)
		}
		if r.IPIsPrivate != nil && *r.IPIsPrivate {
			privateIdx = i
		}
		if r.Action == "reject" && slices.Equal(r.Port.Slice(), []uint16{853}) {
			dotIdx = i
		}
		if r.Action == "reject" && slices.Equal(r.Port.Slice(), []uint16{443, 853}) {
			if !r.IPCIDR.IsEmpty() {
				dohIPIdx = i
			}
			if !r.Domain.IsEmpty() {
				dohDomIdx = i
			}
		}
		if slices.Contains(r.RuleSet.Slice(), "geoip-cn") && r.Outbound == "#DC" {
			geoipCNIdx = i
		}
		if sboption.IsManagedSTUNRejectRouteRule(r) {
			if slices.Equal(r.Protocol.Slice(), []string{"stun"}) {
				stunProtoIdx = i
			} else if slices.Equal(r.Port.Slice(), []uint16{3478, 3479, 5349}) {
				stunPortsIdx = i
			} else if slices.Equal(r.PortRange.Slice(), []string{"19302:19309"}) {
				stunRangeIdx = i
			}
		}
		if sboption.IsCatchAllUDPDirectRouteRule(r, func(tag string) bool { return tag == "#DC" }) {
			udpCatchAllIdx = i
		}
		if r.Type == "logical" && r.Mode == "and" && r.Action == "reject" && len(r.Rules) == 2 {
			sub0 := r.Rules[0]
			sub1 := r.Rules[1]
			if slices.Equal(sub1.IPCIDR.Slice(), []string{"::/0"}) {
				if sub0.Action != "" || sub0.Outbound != "" {
					t.Fatalf("logical AND matcher sub[0] must not keep action/outbound: %+v", sub0)
				}
				if slices.Equal(sub0.DomainSuffix.Slice(), []string{"openai.com"}) && routeRules[i+1].Outbound == "#VPS" {
					foundVPSTwin = true
				}
				if slices.Contains(sub0.RuleSet.Slice(), "geosite-geolocation-!cn") && routeRules[i+1].Outbound == "Proxy" {
					foundGeoNotCNTwin = true
				}
				if slices.Contains(sub0.RuleSet.Slice(), "geosite-cn") {
					foundDCRejectTwin = true
				}
			}
		}
	}
	if privateIdx < 0 || dotIdx != privateIdx+1 || dohIPIdx != privateIdx+2 || dohDomIdx != privateIdx+3 {
		t.Fatalf("expected DoT/CN-DoH reject rules right after ip_is_private (%d): dot=%d ip=%d dom=%d", privateIdx, dotIdx, dohIPIdx, dohDomIdx)
	}
	if geoipCNIdx < 0 || udpCatchAllIdx < 0 || stunProtoIdx <= geoipCNIdx || stunPortsIdx != stunProtoIdx+1 || stunRangeIdx != stunProtoIdx+2 || stunRangeIdx >= udpCatchAllIdx {
		t.Fatalf("expected 3 STUN reject rules after geoip-cn (%d) and before udp 1024:65535 (%d): proto=%d ports=%d range=%d", geoipCNIdx, udpCatchAllIdx, stunProtoIdx, stunPortsIdx, stunRangeIdx)
	}
	if !foundVPSTwin || !foundGeoNotCNTwin {
		t.Fatalf("expected logical-AND ::/0 reject twins before #VPS and Proxy route rules (vps=%v geo=%v)", foundVPSTwin, foundGeoNotCNTwin)
	}
	if foundDCRejectTwin {
		t.Fatal("must NOT inject ::/0 reject twin before #DC domestic rules")
	}
	lastRouteRule := routeRules[len(routeRules)-1]
	if !sboption.IsManagedIPv6RejectRouteRule(lastRouteRule) || lastRouteRule.Type != "" || !slices.Equal(lastRouteRule.IPCIDR.Slice(), []string{"::/0"}) {
		t.Fatalf("expected final catch-all ::/0 reject route rule, got %+v", lastRouteRule)
	}

	cnOnlyAgain, err := singbox.ApplyIPv6ModeToConfigJSON(cnOnlyJSON, "cn_only")
	if err != nil {
		t.Fatalf("re-apply cn_only: %v", err)
	}
	if cnOnlyAgain != cnOnlyJSON {
		t.Fatalf("expected idempotent cn_only output\nfirst:\n%s\nsecond:\n%s", cnOnlyJSON, cnOnlyAgain)
	}

	legacyJSON := `{
  "dns": {
    "final": "dns_proxy",
    "strategy": "prefer_ipv4",
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353},
      {"tag": "dns_proxy", "type": "https", "server": "8.8.8.8", "detour": "#VPS"}
    ],
    "rules": [
      {"clash_mode": "Direct", "client_subnet": "203.0.113.0/24", "server": "dns_local"},
      {"clash_mode": "Global", "query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"},
      {"clash_mode": "Global", "server": "dns_proxy"},
      {"domain_suffix": ["openai.com"], "query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"},
      {"domain_suffix": ["openai.com"], "server": "dns_proxy"},
      {"rule_set": ["geosite-apple"], "server": "dns_local"},
      {"rule_set": "geosite-cn", "client_subnet": "203.0.113.0/24", "server": "dns_local"},
      {"rule_set": "geosite-geolocation-!cn", "query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"},
      {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"},
      {"query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"}
    ]
  },
  "route": {
    "final": "Proxy",
    "rules": [
      {"action": "sniff"},
      {"action": "hijack-dns", "port": 53},
      {"ip_is_private": true, "outbound": "#DC"},
      {"action": "route", "clash_mode": "global", "outbound": "Proxy"},
      {"action": "reject", "domain_suffix": ["openai.com"], "ip_cidr": ["::/0"]},
      {"action": "route", "domain_suffix": ["openai.com"], "outbound": "#VPS"},
      {"action": "route", "rule_set": ["geosite-cn"], "outbound": "#DC"},
      {"action": "route", "rule_set": "geosite-geolocation-!cn", "outbound": "Proxy"},
      {"action": "route", "rule_set": ["geoip-cn", "geoip-private"], "outbound": "#DC"},
      {"action": "route", "network": "udp", "port_range": ["1024:65535"], "outbound": "#DC"},
      {"action": "reject", "ip_cidr": ["::/0"]}
    ],
    "rule_set": [
      {"tag": "geosite-cn"},
      {"tag": "geosite-private"},
      {"tag": "geosite-bili"},
      {"tag": "geosite-tencent"},
      {"tag": "geosite-geolocation-!cn"},
      {"tag": "geosite-apple"}
    ]
  }
}`
	upgradedJSON, err := singbox.ApplyIPv6ModeToConfigJSON(legacyJSON, "cn_only")
	if err != nil {
		t.Fatalf("upgrade legacy cn_only: %v", err)
	}
	if upgradedJSON != cnOnlyJSON {
		t.Fatalf("expected legacy AAAA config upgrade cleanly to cn_only output\nupgraded:\n%s\nwant:\n%s", upgradedJSON, cnOnlyJSON)
	}

	fullJSON, err := singbox.ApplyIPv6ModeToConfigJSON(cnOnlyJSON, "full")
	if err != nil {
		t.Fatalf("ApplyIPv6ModeToConfigJSON(full): %v", err)
	}
	fullDoc, err := sboption.ParseDocument([]byte(fullJSON))
	if err != nil {
		t.Fatalf("parse full: %v", err)
	}
	if fullDoc.DNS.Strategy != "prefer_ipv4" {
		t.Fatalf("expected prefer_ipv4 in full, got %v", fullDoc.DNS.Strategy)
	}
	hasExtraCNInFull := false
	for _, r := range fullDoc.DNS.Rules {
		if sboption.IsManagedAAAASuppressDNSRule(r) {
			t.Fatalf("expected zero AAAA/HTTPS suppression rules in full mode, found %+v", r)
		}
		if slices.Contains(r.RuleSet.Slice(), "geosite-tencent") && r.Server == "dns_local" {
			hasExtraCNInFull = true
		}
	}
	if !hasExtraCNInFull {
		t.Fatal("expected extra CN direct rulesets preserved in full mode")
	}
	dohCIDRs := singbox.CNPublicDoHIPCIDRs()
	dohDomains := singbox.CNPublicDoHDomains()
	fullBypassRejectCount := 0
	fullSTUNRejectCount := 0
	for _, r := range fullDoc.Route.Rules {
		if sboption.IsManagedIPv6RejectRouteRule(r) {
			t.Fatalf("expected zero ::/0 reject rules in full mode, found %+v", r)
		}
		if sboption.IsManagedDNSBypassRejectRouteRule(r, dohCIDRs, dohDomains) {
			fullBypassRejectCount++
		}
		if sboption.IsManagedSTUNRejectRouteRule(r) {
			fullSTUNRejectCount++
		}
	}
	if fullBypassRejectCount != 3 || fullSTUNRejectCount != 3 {
		t.Fatalf("expected 3 DoT/CN-DoH + 3 STUN reject rules preserved in full mode, got bypass=%d stun=%d", fullBypassRejectCount, fullSTUNRejectCount)
	}

	offJSON, err := singbox.ApplyIPv6ModeToConfigJSON(fullJSON, "off")
	if err != nil {
		t.Fatalf("ApplyIPv6ModeToConfigJSON(off): %v", err)
	}
	offDoc, err := sboption.ParseDocument([]byte(offJSON))
	if err != nil {
		t.Fatalf("parse off: %v", err)
	}
	if offDoc.DNS.Strategy != "ipv4_only" {
		t.Fatalf("expected ipv4_only in off mode, got %v", offDoc.DNS.Strategy)
	}
	if gotLen := len(offDoc.DNS.Rules); gotLen != 6 {
		t.Fatalf("expected original 6 DNS rules restored in off mode, got %d (%+v)", gotLen, offDoc.DNS.Rules)
	}
	if gotLen := len(offDoc.Route.Rules); gotLen != 9 {
		t.Fatalf("expected original 9 route rules restored in off mode, got %d (%+v)", gotLen, offDoc.Route.Rules)
	}
}
