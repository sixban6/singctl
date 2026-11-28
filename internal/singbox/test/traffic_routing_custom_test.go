// 文件职责：覆盖审计快捷定向出口规则向 sing-box Route/DNS 规则编译、优先级排序、幂等更新及删除剥离的单测。
package singbox_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

const customRoutingFixtureJSON = `{
  "dns": {
    "final": "dns_proxy",
    "servers": [
      {"tag": "dns_proxy", "address": "https://dns.google/dns-query"},
      {"tag": "dns_local", "address": "https://dns.alidns.com/dns-query"}
    ],
    "rules": [
      {"clash_mode": "direct", "server": "dns_local"},
      {"rule_set": "geosite-cn", "server": "dns_local"},
      {"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"}
    ]
  },
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["#Auto", "#VPS", "#DC"]},
    {"type": "selector", "tag": "#VPS", "outbounds": ["vps-1"]},
    {"type": "urltest", "tag": "#Auto", "outbounds": ["node-1"]},
    {"type": "direct", "tag": "#DC"}
  ],
  "route": {
    "rule_set": [
      {"tag": "geosite-ad1", "type": "remote", "url": "https://example.com/ad1.srs"},
      {"tag": "geosite-youtube", "type": "remote", "url": "https://example.com/yt.srs"},
      {"tag": "geosite-cn", "type": "remote", "url": "https://example.com/cn.srs"},
      {"tag": "geosite-geolocation-!cn", "type": "remote", "url": "https://example.com/notcn.srs"}
    ],
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "#DC"},
      {"rule_set": "geosite-ad1", "action": "reject"},
      {"rule_set": "geosite-cn", "outbound": "#DC"},
      {"rule_set": "geosite-geolocation-!cn", "outbound": "Proxy"}
    ]
  }
}`

func TestApplyTrafficRoutingWithPrevRules_CustomOutboundAndDNS(t *testing.T) {
	tr := config.TrafficRoutingConfig{
		Rules: []config.TrafficCustomRule{
			{
				Target:    "youtube.com",
				MatchType: config.TrafficMatchDomainSuffix,
				Outbound:  config.TrafficOutboundDirect,
			},
			{
				Target:    "api.example.com",
				MatchType: config.TrafficMatchDomain,
				Outbound:  "#VPS",
				SourceIP:  "192.168.1.50",
			},
			{
				Target:    "198.51.100.20/32",
				MatchType: config.TrafficMatchIPCIDR,
				Outbound:  "Proxy",
			},
			{
				Target:    "missing-group.example.com",
				MatchType: config.TrafficMatchDomain,
				Outbound:  "NonExistentGroup",
			},
		},
	}

	compiled1, err := singbox.ApplyTrafficRoutingWithPrevRules(customRoutingFixtureJSON, nil, tr, config.CustomRulesConfig{})
	if err != nil {
		t.Fatalf("ApplyTrafficRoutingWithPrevRules failed: %v", err)
	}

	// Idempotent second run with same rules
	compiled2, err := singbox.ApplyTrafficRoutingWithPrevRules(compiled1, tr.Rules, tr, config.CustomRulesConfig{})
	if err != nil {
		t.Fatalf("second ApplyTrafficRoutingWithPrevRules failed: %v", err)
	}

	doc1, err := sboption.ParseDocument([]byte(compiled1))
	if err != nil {
		t.Fatalf("parse compiled1: %v", err)
	}
	doc2, err := sboption.ParseDocument([]byte(compiled2))
	if err != nil {
		t.Fatalf("parse compiled2: %v", err)
	}
	if len(doc1.Route.Rules) != len(doc2.Route.Rules) || len(doc1.DNS.Rules) != len(doc2.DNS.Rules) {
		t.Fatalf("expected idempotent counts, got route %d vs %d, dns %d vs %d", len(doc1.Route.Rules), len(doc2.Route.Rules), len(doc1.DNS.Rules), len(doc2.DNS.Rules))
	}

	// Find youtube.com direct route & geosite-youtube preset route: custom rule must come BEFORE preset and after adblock.
	adIdx, customYTIdx, presetYTIdx, scopedAPIIdx, cidrIdx := -1, -1, -1, -1, -1
	for i, r := range doc1.Route.Rules {
		if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") {
			adIdx = i
		}
		if slices.Contains(r.DomainSuffix.Slice(), "youtube.com") && r.Outbound == "#DC" {
			customYTIdx = i
		}
		if slices.Contains(r.RuleSet.Slice(), "geosite-youtube") {
			presetYTIdx = i
		}
		if slices.Contains(r.Domain.Slice(), "api.example.com") && r.Outbound == "#VPS" && slices.Contains(r.SourceIPCIDR.Slice(), "192.168.1.50/32") {
			scopedAPIIdx = i
		}
		if slices.Contains(r.IPCIDR.Slice(), "198.51.100.20/32") && r.Outbound == "Proxy" {
			cidrIdx = i
		}
		if slices.Contains(r.Domain.Slice(), "missing-group.example.com") {
			t.Fatalf("unknown outbound rule should be skipped cleanly")
		}
	}
	if customYTIdx < 0 || scopedAPIIdx < 0 || cidrIdx < 0 {
		t.Fatalf("missing compiled custom route rules (yt=%d api=%d cidr=%d)\n%s", customYTIdx, scopedAPIIdx, cidrIdx, compiled1)
	}
	if adIdx >= 0 && customYTIdx <= adIdx {
		t.Fatalf("custom rule (%d) must stay AFTER adblock (%d)", customYTIdx, adIdx)
	}
	if presetYTIdx >= 0 && customYTIdx >= presetYTIdx {
		t.Fatalf("custom youtube direct rule (%d) must appear BEFORE youtube preset (%d)", customYTIdx, presetYTIdx)
	}
	if scopedAPIIdx >= customYTIdx {
		t.Fatalf("source_ip-scoped rule (%d) should have precedence BEFORE global custom rules (%d)", scopedAPIIdx, customYTIdx)
	}

	// DNS rules must mirror domain route overrides (youtube.com -> dns_local, api.example.com -> dns_proxy with source_ip_cidr).
	ytDNSIdx, presetYTDNSIdx, apiDNSIdx := -1, -1, -1
	for i, d := range doc1.DNS.Rules {
		if slices.Contains(d.DomainSuffix.Slice(), "youtube.com") && d.Server == "dns_local" {
			ytDNSIdx = i
		}
		if slices.Contains(d.RuleSet.Slice(), "geosite-youtube") {
			presetYTDNSIdx = i
		}
		if slices.Contains(d.Domain.Slice(), "api.example.com") && d.Server == "dns_proxy" && slices.Contains(d.SourceIPCIDR.Slice(), "192.168.1.50/32") {
			apiDNSIdx = i
		}
		if slices.Contains(d.Domain.Slice(), "198.51.100.20/32") {
			t.Fatalf("IP CIDR rule must not generate a DNS domain rule")
		}
	}
	if ytDNSIdx < 0 || apiDNSIdx < 0 {
		t.Fatalf("missing compiled custom DNS rules (ytDNS=%d apiDNS=%d)\n%s", ytDNSIdx, apiDNSIdx, compiled1)
	}
	if presetYTDNSIdx >= 0 && ytDNSIdx >= presetYTDNSIdx {
		t.Fatalf("custom youtube DNS rule (%d) must precede preset DNS rule (%d)", ytDNSIdx, presetYTDNSIdx)
	}

	// Update youtube.com -> #VPS and delete api.example.com: prev rules must be completely stripped!
	trUpdated := config.TrafficRoutingConfig{
		Rules: []config.TrafficCustomRule{
			{
				Target:    "youtube.com",
				MatchType: config.TrafficMatchDomainSuffix,
				Outbound:  "#VPS",
			},
		},
	}
	compiledUpdated, err := singbox.ApplyTrafficRoutingWithPrevRules(compiled1, tr.Rules, trUpdated, config.CustomRulesConfig{})
	if err != nil {
		t.Fatalf("update ApplyTrafficRoutingWithPrevRules failed: %v", err)
	}
	docUpdated, err := sboption.ParseDocument([]byte(compiledUpdated))
	if err != nil {
		t.Fatalf("parse compiledUpdated: %v", err)
	}
	foundNewYT := false
	for _, r := range docUpdated.Route.Rules {
		if slices.Contains(r.DomainSuffix.Slice(), "youtube.com") {
			if r.Outbound == "#DC" {
				t.Fatalf("stale youtube.com -> #DC rule remained after update")
			}
			if r.Outbound == "#VPS" {
				foundNewYT = true
			}
		}
		if slices.Contains(r.Domain.Slice(), "api.example.com") || slices.Contains(r.IPCIDR.Slice(), "198.51.100.20/32") {
			t.Fatalf("deleted custom route rule remained: %+v", r)
		}
	}
	if !foundNewYT {
		t.Fatalf("expected updated youtube.com -> #VPS rule")
	}
	for _, d := range docUpdated.DNS.Rules {
		if slices.Contains(d.DomainSuffix.Slice(), "youtube.com") && d.Server == "dns_local" {
			t.Fatalf("stale youtube.com -> dns_local rule remained after switching to #VPS")
		}
		if slices.Contains(d.Domain.Slice(), "api.example.com") {
			t.Fatalf("deleted api.example.com DNS rule remained")
		}
	}

	// iOS skips source_ip-scoped rules while keeping global rules.
	iosOut, err := singbox.ApplyTrafficRoutingForPlatform(customRoutingFixtureJSON, tr, config.CustomRulesConfig{}, singbox.PlatformIOS)
	if err != nil {
		t.Fatalf("ApplyTrafficRoutingForPlatform(ios) failed: %v", err)
	}
	if strings.Contains(iosOut, `"source_ip_cidr"`) {
		t.Fatalf("iOS compiled output must skip source_ip_cidr rule:\n%s", iosOut)
	}

	// BuildClientRoutingReport populates CustomRules and counts them in CustomCount.
	rep := singbox.BuildClientRoutingReport(&config.Config{TrafficRouting: tr}, customRoutingFixtureJSON)
	if len(rep.CustomRules) != len(tr.Rules) || rep.CustomCount < len(tr.Rules) {
		raw, _ := json.Marshal(rep)
		t.Fatalf("expected CustomRules (%d) and CustomCount >= %d in report: %s", len(rep.CustomRules), len(tr.Rules), string(raw))
	}
}
