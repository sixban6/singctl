package singbox

import (
	"encoding/json"
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
	//    prepends AAAA predefined NOERROR before each dns_proxy rule, and appends fallback AAAA rule.
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

	// Verify twin AAAA rules precede their matching dns_proxy rules.
	foundGlobalTwin := false
	foundOpenAITwin := false
	foundExtraCN := false
	extraCNIdx := -1
	geositeCNIdx := -1
	for i, raw := range rules {
		m := raw.(map[string]any)
		if m["clash_mode"] == "Global" && m["action"] == "predefined" && m["rcode"] == "NOERROR" {
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
			next := rules[i+1].(map[string]any)
			if next["server"] == "dns_proxy" {
				foundOpenAITwin = true
			}
		}
	}
	if !foundGlobalTwin || !foundOpenAITwin {
		t.Fatalf("expected predefined AAAA twins before Global and openai.com dns_proxy rules, got rules=%v", rules)
	}
	if !foundExtraCN || extraCNIdx >= geositeCNIdx {
		t.Fatalf("expected missing CN direct rulesets injected before geosite-cn (extra=%d cn=%d)", extraCNIdx, geositeCNIdx)
	}
	lastRule := rules[len(rules)-1].(map[string]any)
	if !isAutoInjectedAAAAPredefinedRule(lastRule) || len(lastRule) != 3 {
		t.Fatalf("expected final catch-all AAAA predefined NOERROR rule, got %v", lastRule)
	}

	// Re-applying cn_only must produce identical rule count (idempotency).
	cnOnlyAgain, err := ApplyIPv6ModeToConfigJSON(cnOnlyJSON, "cn_only")
	if err != nil {
		t.Fatalf("re-apply cn_only: %v", err)
	}
	if cnOnlyAgain != cnOnlyJSON {
		t.Fatalf("expected idempotent cn_only output\nfirst:\n%s\nsecond:\n%s", cnOnlyJSON, cnOnlyAgain)
	}

	// 2. full: keeps prefer_ipv4 and domestic direct CN rulesets, removes all AAAA suppression rules.
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
			t.Fatalf("expected zero AAAA suppression rules in full mode, found %v", m)
		}
		if containsRuleSetTag(m["rule_set"], "geosite-tencent") && m["server"] == "dns_local" {
			hasExtraCNInFull = true
		}
	}
	if !hasExtraCNInFull {
		t.Fatal("expected extra CN direct rulesets preserved in full mode")
	}

	// 3. off: restores ipv4_only and strips auto-injected AAAA and extra CN direct rules.
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
}
