package singbox_test

import (
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func TestAdBlockWhitelist_PlainWrapping_DNSAndRoute(t *testing.T) {
	raw := `{
		"dns": {
			"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
			"rules": [
				{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
				{"rule_set": "geosite-cn", "server": "dns_local"}
			]
		},
		"route": {
			"rules": [
				{"action": "sniff"},
				{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
				{"rule_set": "geosite-cn", "outbound": "#DC"}
			]
		}
	}`

	managed := []string{"wxaintpcos.wxqcloud.qq.com.cn", "dl.weshineapp.com"}
	updated, changed, err := singbox.SyncAdBlockWhitelistInConfigJSON(raw, nil, managed)
	if err != nil {
		t.Fatalf("SyncAdBlockWhitelistInConfigJSON failed: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when wrapping plain adblock rules")
	}

	doc, err := sboption.ParseDocument([]byte(updated))
	if err != nil {
		t.Fatalf("ParseDocument failed: %v", err)
	}

	// Verify DNS adblock rule wrapped
	dnsRule := doc.DNS.Rules[0]
	if dnsRule.Type != "logical" || dnsRule.Mode != "and" || dnsRule.Action != "reject" || len(dnsRule.Rules) != 2 {
		t.Fatalf("unexpected wrapped DNS rule: %+v", dnsRule)
	}
	if !slices.Equal(dnsRule.Rules[0].RuleSet.Slice(), []string{"geosite-ad1", "geosite-ad2"}) {
		t.Fatalf("unexpected DNS sub-rule 0: %+v", dnsRule.Rules[0])
	}
	if dnsRule.Rules[1].Invert == nil || !*dnsRule.Rules[1].Invert {
		t.Fatalf("expected DNS sub-rule 1 invert=true, got %+v", dnsRule.Rules[1])
	}
	gotDNSSuffix := dnsRule.Rules[1].DomainSuffix.Slice()
	for _, want := range managed {
		if !slices.Contains(gotDNSSuffix, want) {
			t.Fatalf("DNS invert domain_suffix missing %q: %v", want, gotDNSSuffix)
		}
	}

	// Verify Route adblock rule wrapped
	routeRule := doc.Route.Rules[1]
	if routeRule.Type != "logical" || routeRule.Mode != "and" || routeRule.Action != "reject" || len(routeRule.Rules) != 2 {
		t.Fatalf("unexpected wrapped Route rule: %+v", routeRule)
	}
	if routeRule.Rules[1].Invert == nil || !*routeRule.Rules[1].Invert {
		t.Fatalf("expected Route sub-rule 1 invert=true, got %+v", routeRule.Rules[1])
	}
	gotRouteSuffix := routeRule.Rules[1].DomainSuffix.Slice()
	for _, want := range managed {
		if !slices.Contains(gotRouteSuffix, want) {
			t.Fatalf("Route invert domain_suffix missing %q: %v", want, gotRouteSuffix)
		}
	}

	// Idempotent on second call
	updated2, changed2, err := singbox.SyncAdBlockWhitelistInConfigJSON(updated, managed, managed)
	if err != nil {
		t.Fatalf("second SyncAdBlockWhitelistInConfigJSON failed: %v", err)
	}
	if changed2 || updated2 != updated {
		t.Fatalf("expected idempotent second call (changed=false), got changed=%v", changed2)
	}
}

func TestAdBlockWhitelist_ExistingLogical_PreservesUnmanagedAndCleanRemoval(t *testing.T) {
	// Simulate live n4120 rule already wrapped with an unmanaged subscription domain
	raw := `{
		"dns": {
			"rules": [
				{
					"type": "logical",
					"mode": "and",
					"rules": [
						{"rule_set": ["geosite-ad1", "geosite-ad2"]},
						{"invert": true, "domain_suffix": ["unmanaged-sub.example.com"]}
					],
					"action": "reject"
				}
			]
		},
		"route": {
			"rules": [
				{
					"type": "logical",
					"mode": "and",
					"rules": [
						{"rule_set": ["geosite-ad1", "geosite-ad2"]},
						{"invert": true, "domain_suffix": ["unmanaged-sub.example.com"]}
					],
					"action": "reject"
				}
			]
		}
	}`

	oldSet := []string{"wxaintpcos.wxqcloud.qq.com.cn"}
	newSet := []string{"wxaintpcos.wxqcloud.qq.com.cn", "custom-allow.example.com"}

	step1, changed1, err := singbox.SyncAdBlockWhitelistInConfigJSON(raw, nil, newSet)
	if err != nil || !changed1 {
		t.Fatalf("step1 failed: changed=%v err=%v", changed1, err)
	}
	if !strings.Contains(step1, "unmanaged-sub.example.com") || !strings.Contains(step1, "custom-allow.example.com") {
		t.Fatalf("step1 lost unmanaged or new domain:\n%s", step1)
	}

	// Now remove custom-allow.example.com -> unmanaged-sub.example.com must remain, custom-allow must vanish
	step2, changed2, err := singbox.SyncAdBlockWhitelistInConfigJSON(step1, newSet, oldSet)
	if err != nil || !changed2 {
		t.Fatalf("step2 failed: changed=%v err=%v", changed2, err)
	}
	if !strings.Contains(step2, "unmanaged-sub.example.com") || !strings.Contains(step2, "wxaintpcos.wxqcloud.qq.com.cn") {
		t.Fatalf("step2 lost preserved domains:\n%s", step2)
	}
	if strings.Contains(step2, "custom-allow.example.com") {
		t.Fatalf("step2 failed to remove custom-allow.example.com:\n%s", step2)
	}

	// If an existing logical rule has ONLY managed domains and newManaged is empty, it unwraps cleanly back to plain rule
	plainOnlyRaw, _, err := singbox.SyncAdBlockWhitelistInConfigJSON(`{
		"dns": {"rules": [{"rule_set": ["geosite-ad1"], "action": "reject"}]},
		"route": {"rules": [{"rule_set": ["geosite-ad1"], "action": "reject"}]}
	}`, nil, oldSet)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, changed3, err := singbox.SyncAdBlockWhitelistInConfigJSON(plainOnlyRaw, oldSet, nil)
	if err != nil || !changed3 {
		t.Fatalf("unwrap failed: changed=%v err=%v", changed3, err)
	}
	doc, err := sboption.ParseDocument([]byte(unwrapped))
	if err != nil {
		t.Fatal(err)
	}
	if doc.DNS.Rules[0].Type != "" || doc.DNS.Rules[0].Action != "reject" || !slices.Equal(doc.DNS.Rules[0].RuleSet.Slice(), []string{"geosite-ad1"}) {
		t.Fatalf("expected clean unwrap to plain DNS rule, got %+v", doc.DNS.Rules[0])
	}
}

func TestAdBlockWhitelist_ExplicitBlockExcludesDefaultSafeDomain(t *testing.T) {
	cfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Whitelist: []string{"  Allow.Example.COM. ", "not a domain", "192.0.2.1"},
		},
		Audit: config.AuditConfig{
			Whitelist: []string{"audit-safe.example.com", "198.51.100.1/24", "203.0.113.9"},
		},
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{
				{Target: "dl.weshineapp.com"},
				{Target: "scoped.example.com", SourceIP: "192.168.1.50"},
			},
		},
		Subs: []config.Subscription{
			{Name: "s1", URL: "https://sub.example.com/feed"},
		},
	}

	got := singbox.EffectiveAdBlockWhitelist(cfg)
	if slices.Contains(got, "dl.weshineapp.com") {
		t.Fatalf("explicitly blocked domain dl.weshineapp.com must be excluded from defaults: %v", got)
	}
	for _, want := range []string{
		"wxaintpcos.wxqcloud.qq.com.cn",
		"pass1.soogif.com",
		"dns.weixin.qq.com.cn",
		"allow.example.com",
		"audit-safe.example.com",
		"sub.example.com",
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("EffectiveAdBlockWhitelist missing %q: %v", want, got)
		}
	}
	for _, forbid := range []string{"192.0.2.1", "198.51.100.1/24", "203.0.113.9"} {
		if slices.Contains(got, forbid) {
			t.Fatalf("IP/CIDR %q must not enter domain_suffix whitelist: %v", forbid, got)
		}
	}
}

func TestAdBlockWhitelist_CompilePipeline_NormalAndLowMemory(t *testing.T) {
	baseJSON := `{
		"log": {"level": "info"},
		"outbounds": [
			{"tag": "node-a", "type": "vless", "server": "198.51.100.10"},
			{"tag": "Proxy", "type": "selector", "outbounds": ["node-a"]},
			{"tag": "#DC", "type": "direct"}
		],
		"dns": {
			"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
			"rules": [
				{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
				{"rule_set": "geosite-cn", "server": "dns_local"}
			]
		},
		"route": {
			"rule_set": [
				{"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://example.com/ad1.srs"},
				{"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://example.com/ad2.srs"},
				{"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://example.com/cn.srs"}
			],
			"rules": [
				{"action": "sniff"},
				{"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
				{"rule_set": "geosite-cn", "outbound": "#DC"}
			]
		}
	}`

	cfg := &config.Config{
		LowMemory: config.LowMemoryOn,
		DNS:       config.ClientDNSConfig{Whitelist: []string{"extra.example.com"}},
	}
	g := singbox.NewOfflineConfigGenerator(cfg)
	out, err := g.RunCompilePipeline(baseJSON, "linux")
	if err != nil {
		t.Fatalf("RunCompilePipeline(lowmem) failed: %v", err)
	}
	if strings.Contains(out, "geosite-ad2") {
		t.Fatalf("expected geosite-ad2 pruned in low-memory mode:\n%s", out)
	}
	for _, want := range append(slices.Clone(constant.DefaultAdBlockSafeDomains), "extra.example.com") {
		if !strings.Contains(out, want) {
			t.Fatalf("expected low-memory compiled config to still exempt %q on geosite-ad1:\n%s", want, out)
		}
	}
}
