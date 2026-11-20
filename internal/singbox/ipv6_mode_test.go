package singbox

import (
	"encoding/json"
	"slices"
	"testing"
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

	// 1. cn_only: sets prefer_ipv4, aligns domestic CN rulesets to dns_local before geosite-cn,
	//    prepends AAAA+HTTPS predefined NOERROR before each dns_proxy rule, appends fallback AAAA+HTTPS rule,
	//    injects DoT/CN-DoH reject rules after ip_is_private, and adds ::/0 reject before proxy route rules + final.
	cnOnlyJSON, err := ApplyIPv6ModeToConfigJSON(base, "cn_only")
	if err != nil {
		t.Fatalf("ApplyIPv6ModeToConfigJSON(cn_only): %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(cnOnlyJSON), &doc); err != nil {
		t.Fatalf("unmarshal cn_only: %v", err)
	}
	dnsMap := doc["dns"].(map[string]any)
	if dnsMap["strategy"] != "prefer_ipv4" {
		t.Fatalf("expected prefer_ipv4 in cn_only, got %v", dnsMap["strategy"])
	}
	rules := dnsMap["rules"].([]any)

	// Verify twin AAAA+HTTPS rules precede their matching dns_proxy rules.
	foundGlobalTwin := false
	foundOpenAITwin := false
	foundExtraCN := false
	extraCNIdx := -1
	geositeCNIdx := -1
	for i, raw := range rules {
		m := raw.(map[string]any)
		if m["clash_mode"] == "Global" && m["action"] == "predefined" && m["rcode"] == "NOERROR" {
			if !slices.Equal(extractQueryTypeStrings(m["query_type"]), []string{"AAAA", "HTTPS"}) {
				t.Fatalf("expected [AAAA HTTPS] query_type on Global twin, got %v", m["query_type"])
			}
			next := rules[i+1].(map[string]any)
			if next["clash_mode"] == "Global" && next["server"] == "dns_proxy" {
				foundGlobalTwin = true
			}
		}
		if containsRuleSetTag(m["rule_set"], "geosite-bili") && m["server"] == "dns_local" {
			foundExtraCN = true
			extraCNIdx = i
		}
		if containsRuleSetTag(m["rule_set"], "geosite-cn") && m["server"] == "dns_local" {
			geositeCNIdx = i
		}
		if ds := extractStringOrSlice(m["domain_suffix"]); len(ds) == 1 && ds[0] == "openai.com" && m["action"] == "predefined" {
			if !slices.Equal(extractQueryTypeStrings(m["query_type"]), []string{"AAAA", "HTTPS"}) {
				t.Fatalf("expected [AAAA HTTPS] query_type on openai twin, got %v", m["query_type"])
			}
			next := rules[i+1].(map[string]any)
			if next["server"] == "dns_proxy" {
				foundOpenAITwin = true
			}
		}
	}
	if !foundGlobalTwin || !foundOpenAITwin {
		t.Fatalf("expected predefined AAAA+HTTPS twins before Global and openai.com dns_proxy rules, got rules=%v", rules)
	}
	if !foundExtraCN || extraCNIdx >= geositeCNIdx {
		t.Fatalf("expected missing CN direct rulesets injected before geosite-cn (extra=%d cn=%d)", extraCNIdx, geositeCNIdx)
	}
	lastRule := rules[len(rules)-1].(map[string]any)
	if !isAutoInjectedAAAAPredefinedRule(lastRule) || len(lastRule) != 3 || !slices.Equal(extractQueryTypeStrings(lastRule["query_type"]), []string{"AAAA", "HTTPS"}) {
		t.Fatalf("expected final catch-all [AAAA HTTPS] predefined NOERROR rule, got %v", lastRule)
	}

	// Verify route.rules in cn_only: DoT 853 + CN DoH rules after ip_is_private, STUN reject after geoip-cn before udp 1024:65535, logical-AND ::/0 reject before #VPS/Proxy only, plus tail ::/0 reject.
	routeRules := doc["route"].(map[string]any)["rules"].([]any)
	privateIdx, dotIdx, dohIPIdx, dohDomIdx := -1, -1, -1, -1
	geoipCNIdx, stunProtoIdx, stunPortsIdx, stunRangeIdx, udpCatchAllIdx := -1, -1, -1, -1, -1
	foundVPSTwin, foundGeoNotCNTwin, foundDCRejectTwin := false, false, false
	for i, raw := range routeRules {
		m := raw.(map[string]any)
		// Regression guard: a flat rule must NEVER combine ip_cidr=["::/0"] with another matcher (OR semantics would reject IPv4!).
		if slices.Equal(extractStringOrSlice(m["ip_cidr"]), []string{"::/0"}) && len(m) > 2 {
			t.Fatalf("unsafe flat OR rule combines ip_cidr=[::/0] with other matchers: %v", m)
		}
		if priv, _ := m["ip_is_private"].(bool); priv {
			privateIdx = i
		}
		if m["action"] == "reject" && len(m) == 2 && isSinglePort(m["port"], 853) {
			dotIdx = i
		}
		if m["action"] == "reject" && len(m) == 3 && isPortPair(m["port"], 443, 853) {
			if len(extractStringOrSlice(m["ip_cidr"])) > 0 {
				dohIPIdx = i
			}
			if len(extractStringOrSlice(m["domain"])) > 0 {
				dohDomIdx = i
			}
		}
		if containsRuleSetTag(m["rule_set"], "geoip-cn") && m["outbound"] == "#DC" {
			geoipCNIdx = i
		}
		if isAutoInjectedSTUNRejectRule(m) {
			if m["protocol"] == "stun" {
				stunProtoIdx = i
			} else if isExactPorts(m["port"], []int{3478, 3479, 5349}) {
				stunPortsIdx = i
			} else if slices.Equal(extractStringOrSlice(m["port_range"]), []string{"19302:19309"}) {
				stunRangeIdx = i
			}
		}
		if isCatchAllUDPDirectRule(m) {
			udpCatchAllIdx = i
		}
		if m["type"] == "logical" && m["mode"] == "and" && m["action"] == "reject" {
			subs := asAnySlice(m["rules"])
			if len(subs) == 2 {
				sub0, ok0 := subs[0].(map[string]any)
				sub1, ok1 := subs[1].(map[string]any)
				if ok0 && ok1 && len(sub1) == 1 && slices.Equal(extractStringOrSlice(sub1["ip_cidr"]), []string{"::/0"}) {
					if _, hasAct := sub0["action"]; hasAct {
						t.Fatalf("logical AND matcher sub[0] must not keep action: %v", sub0)
					}
					if _, hasOut := sub0["outbound"]; hasOut {
						t.Fatalf("logical AND matcher sub[0] must not keep outbound: %v", sub0)
					}
					if ds := extractStringOrSlice(sub0["domain_suffix"]); len(ds) == 1 && ds[0] == "openai.com" {
						next := routeRules[i+1].(map[string]any)
						if next["outbound"] == "#VPS" {
							foundVPSTwin = true
						}
					}
					if containsRuleSetTag(sub0["rule_set"], "geosite-geolocation-!cn") {
						next := routeRules[i+1].(map[string]any)
						if next["outbound"] == "Proxy" {
							foundGeoNotCNTwin = true
						}
					}
					if containsRuleSetTag(sub0["rule_set"], "geosite-cn") {
						foundDCRejectTwin = true
					}
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
	lastRouteRule := routeRules[len(routeRules)-1].(map[string]any)
	if !isAutoInjectedIPv6RouteRejectRule(lastRouteRule) || len(lastRouteRule) != 2 {
		t.Fatalf("expected final catch-all ::/0 reject route rule, got %v", lastRouteRule)
	}

	// Re-applying cn_only must produce identical output (idempotency).
	cnOnlyAgain, err := ApplyIPv6ModeToConfigJSON(cnOnlyJSON, "cn_only")
	if err != nil {
		t.Fatalf("re-apply cn_only: %v", err)
	}
	if cnOnlyAgain != cnOnlyJSON {
		t.Fatalf("expected idempotent cn_only output\nfirst:\n%s\nsecond:\n%s", cnOnlyJSON, cnOnlyAgain)
	}

	// Upgrading legacy ["AAAA"] DNS rules + legacy broken flat ::/0 reject route rule produces clean identical cn_only output (no duplicates).
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
	upgradedJSON, err := ApplyIPv6ModeToConfigJSON(legacyJSON, "cn_only")
	if err != nil {
		t.Fatalf("upgrade legacy cn_only: %v", err)
	}
	if upgradedJSON != cnOnlyJSON {
		t.Fatalf("expected legacy AAAA config upgrade cleanly to cn_only output\nupgraded:\n%s\nwant:\n%s", upgradedJSON, cnOnlyJSON)
	}

	// 2. full: keeps prefer_ipv4, domestic direct CN rulesets, and DoT/CN-DoH route rejects; removes AAAA/HTTPS suppression & ::/0 route rejects.
	fullJSON, err := ApplyIPv6ModeToConfigJSON(cnOnlyJSON, "full")
	if err != nil {
		t.Fatalf("ApplyIPv6ModeToConfigJSON(full): %v", err)
	}
	var fullDoc map[string]any
	_ = json.Unmarshal([]byte(fullJSON), &fullDoc)
	fullDNS := fullDoc["dns"].(map[string]any)
	if fullDNS["strategy"] != "prefer_ipv4" {
		t.Fatalf("expected prefer_ipv4 in full, got %v", fullDNS["strategy"])
	}
	fullRules := fullDNS["rules"].([]any)
	hasExtraCNInFull := false
	for _, raw := range fullRules {
		m := raw.(map[string]any)
		if isAutoInjectedAAAAPredefinedRule(m) {
			t.Fatalf("expected zero AAAA/HTTPS suppression rules in full mode, found %v", m)
		}
		if containsRuleSetTag(m["rule_set"], "geosite-tencent") && m["server"] == "dns_local" {
			hasExtraCNInFull = true
		}
	}
	if !hasExtraCNInFull {
		t.Fatal("expected extra CN direct rulesets preserved in full mode")
	}
	fullRouteRules := fullDoc["route"].(map[string]any)["rules"].([]any)
	fullBypassRejectCount := 0
	fullSTUNRejectCount := 0
	for _, raw := range fullRouteRules {
		m := raw.(map[string]any)
		if isAutoInjectedIPv6RouteRejectRule(m) {
			t.Fatalf("expected zero ::/0 reject rules in full mode, found %v", m)
		}
		if isAutoInjectedDNSBypassRejectRule(m) {
			fullBypassRejectCount++
		}
		if isAutoInjectedSTUNRejectRule(m) {
			fullSTUNRejectCount++
		}
	}
	if fullBypassRejectCount != 3 || fullSTUNRejectCount != 3 {
		t.Fatalf("expected 3 DoT/CN-DoH + 3 STUN reject rules preserved in full mode, got bypass=%d stun=%d", fullBypassRejectCount, fullSTUNRejectCount)
	}

	// 3. off: restores ipv4_only and strips all auto-injected DNS and route rules.
	offJSON, err := ApplyIPv6ModeToConfigJSON(fullJSON, "off")
	if err != nil {
		t.Fatalf("ApplyIPv6ModeToConfigJSON(off): %v", err)
	}
	var offDoc map[string]any
	_ = json.Unmarshal([]byte(offJSON), &offDoc)
	offDNS := offDoc["dns"].(map[string]any)
	if offDNS["strategy"] != "ipv4_only" {
		t.Fatalf("expected ipv4_only in off mode, got %v", offDNS["strategy"])
	}
	if gotLen := len(offDNS["rules"].([]any)); gotLen != 6 {
		t.Fatalf("expected original 6 DNS rules restored in off mode, got %d (%v)", gotLen, offDNS["rules"])
	}
	offRouteRules := offDoc["route"].(map[string]any)["rules"].([]any)
	if gotLen := len(offRouteRules); gotLen != 9 {
		t.Fatalf("expected original 9 route rules restored in off mode, got %d (%v)", gotLen, offRouteRules)
	}
}
