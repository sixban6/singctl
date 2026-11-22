// 文件职责：覆盖 sing-box 加强版加密 DNS 编译、重写、白名单逻辑反选、去广告暂停/单规则集启停、屏蔽 AAAA、缓存清理、配置预览与三引擎注入测试。
package singbox_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func runSingBoxCheckIfAvailable(t *testing.T, label, jsonContent string) {
	t.Helper()
	sbBin, err := exec.LookPath("sing-box")
	if err != nil || sbBin == "" {
		return
	}
	cfgFile := filepath.Join(t.TempDir(), label+".json")
	if err := os.WriteFile(cfgFile, []byte(jsonContent), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgFile).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed for %s: %v\noutput: %s\nconfig:\n%s", label, err, string(out), jsonContent)
	}
}

const enhancedDNSBaseJSON = `{
  "log": {"level": "warn"},
  "dns": {
    "servers": [
      {"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"},
      {"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}
    ],
    "rules": [
      {"clash_mode": "Direct", "server": "dns_local"},
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": ["block-builtin-pcdn"], "action": "reject"},
      {"rule_set": "geosite-cn", "server": "dns_local"}
    ],
    "final": "dns_proxy"
  },
  "outbounds": [
    {"tag": "Proxy", "type": "direct"},
    {"tag": "#DC", "type": "direct"}
  ],
  "route": {
    "default_domain_resolver": "dns_local",
    "rule_set": [
      {"tag": "geosite-ad1", "type": "inline", "rules": [{"domain_suffix": ["ads1.example.com"]}]},
      {"tag": "geosite-ad2", "type": "inline", "rules": [{"domain_suffix": ["ads2.example.com"]}]},
      {"tag": "block-builtin-pcdn", "type": "inline", "rules": [{"domain_suffix": ["pcdn.example.com"]}]},
      {"tag": "geosite-cn", "type": "inline", "rules": [{"domain_suffix": ["cn.example.com"]}]}
    ],
    "rules": [
      {"action": "sniff"},
      {"action": "hijack-dns", "port": 53},
      {"ip_is_private": true, "outbound": "#DC"},
      {"rule_set": ["block-builtin-pcdn"], "action": "reject"},
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "geosite-cn", "outbound": "#DC"}
    ],
    "final": "Proxy"
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "top-secret-token-value"
    },
    "cache_file": {
      "enabled": true,
      "store_dns": false
    }
  }
}`

func TestParseEncryptedDNSServer_TableDriven(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantType string
		wantHost string
		wantPort int
		wantPath string
		wantErr  bool
	}{
		{
			name:     "doh_ip_default_port_and_path",
			raw:      "https://223.5.5.5",
			wantType: "https",
			wantHost: "223.5.5.5",
			wantPort: 443,
			wantPath: "/dns-query",
		},
		{
			name:     "doh_ip_explicit_port_and_custom_path",
			raw:      "https://1.12.12.12:8443/resolve",
			wantType: "https",
			wantHost: "1.12.12.12",
			wantPort: 8443,
			wantPath: "/resolve",
		},
		{
			name:     "doh_ipv6_brackets",
			raw:      "https://[2001:db8::53]/dns-query",
			wantType: "https",
			wantHost: "2001:db8::53",
			wantPort: 443,
			wantPath: "/dns-query",
		},
		{
			name:     "dot_default_port",
			raw:      "tls://223.6.6.6",
			wantType: "tls",
			wantHost: "223.6.6.6",
			wantPort: 853,
		},
		{
			name:     "dot_explicit_port",
			raw:      "tls://120.53.53.53:853",
			wantType: "tls",
			wantHost: "120.53.53.53",
			wantPort: 853,
		},
		{
			name:     "doq_default_port",
			raw:      "quic://223.5.5.5",
			wantType: "quic",
			wantHost: "223.5.5.5",
			wantPort: 853,
		},
		{
			name:     "h3_default_port_and_path",
			raw:      "h3://223.5.5.5/dns-query",
			wantType: "h3",
			wantHost: "223.5.5.5",
			wantPort: 443,
			wantPath: "/dns-query",
		},
		{
			name:     "domain_doh_accepted",
			raw:      "https://dns.example.com/dns-query",
			wantType: "https",
			wantHost: "dns.example.com",
			wantPort: 443,
			wantPath: "/dns-query",
		},
		{name: "reject_empty", raw: "", wantErr: true},
		{name: "reject_plaintext_udp", raw: "udp://223.5.5.5:53", wantErr: true},
		{name: "reject_plaintext_tcp", raw: "tcp://223.5.5.5:53", wantErr: true},
		{name: "reject_plaintext_http", raw: "http://223.5.5.5/dns-query", wantErr: true},
		{name: "reject_bare_ip", raw: "223.5.5.5", wantErr: true},
		{name: "reject_invalid_port_zero", raw: "https://223.5.5.5:0/dns-query", wantErr: true},
		{name: "reject_invalid_port_overflow", raw: "tls://223.6.6.6:70000", wantErr: true},
		{name: "reject_newline_injection", raw: "https://223.5.5.5/dns-query\nmalicious", wantErr: true},
		{name: "reject_space_injection", raw: "https://223.5.5.5/dns query", wantErr: true},
		{name: "reject_userinfo", raw: "https://user:pass@223.5.5.5/dns-query", wantErr: true},
		{name: "reject_missing_host", raw: "https:///dns-query", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := singbox.ParseEncryptedDNSServer(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %+v", tc.raw, srv)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.raw, err)
			}
			if srv.Tag != "dns_local" || srv.Type != tc.wantType || srv.Server != tc.wantHost || srv.ServerPort != tc.wantPort || srv.Path != tc.wantPath {
				t.Fatalf("got %+v, want type=%q host=%q port=%d path=%q", srv, tc.wantType, tc.wantHost, tc.wantPort, tc.wantPath)
			}
		})
	}
}

func TestValidateDNSRewriteRule_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		rule    config.DNSRewriteRule
		wantErr bool
	}{
		{"valid_ipv4_exact", config.DNSRewriteRule{Domain: "nas.example.com", Answer: "192.0.2.10"}, false},
		{"valid_ipv6_wildcard", config.DNSRewriteRule{Domain: "*.lab.example.com", Answer: "2001:db8::10"}, false},
		{"valid_uppercase_trailing_dot", config.DNSRewriteRule{Domain: "NAS.Example.COM.", Answer: "198.51.100.20"}, false},
		{"reject_empty_domain", config.DNSRewriteRule{Domain: "", Answer: "192.0.2.10"}, true},
		{"reject_empty_answer", config.DNSRewriteRule{Domain: "nas.example.com", Answer: ""}, true},
		{"reject_invalid_ip", config.DNSRewriteRule{Domain: "nas.example.com", Answer: "not-an-ip"}, true},
		{"reject_ipv6_zone", config.DNSRewriteRule{Domain: "nas.example.com", Answer: "fe80::1%eth0"}, true},
		{"reject_domain_newline_injection", config.DNSRewriteRule{Domain: "nas.example.com\n60 IN A 192.0.2.9", Answer: "192.0.2.10"}, true},
		{"reject_answer_injection", config.DNSRewriteRule{Domain: "nas.example.com", Answer: "192.0.2.10; rm -rf /"}, true},
		{"reject_double_wildcard", config.DNSRewriteRule{Domain: "*.*.example.com", Answer: "192.0.2.10"}, true},
		{"reject_bare_wildcard", config.DNSRewriteRule{Domain: "*", Answer: "192.0.2.10"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := singbox.ValidateDNSRewriteRule(tc.rule)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %+v", tc.rule)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %+v: %v", tc.rule, err)
			}
		})
	}
}

func TestApplyEnhancedSingBoxDNS_FullLifecycleAndSingBoxCheck(t *testing.T) {
	now := time.Unix(1700000000, 0)

	t.Run("default_upgrades_plaintext_udp_to_encrypted_doh_with_cache", func(t *testing.T) {
		out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(enhancedDNSBaseJSON, config.ClientDNSConfig{}, nil, now)
		if err != nil {
			t.Fatalf("ApplyEnhancedSingBoxDNSJSON failed: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true when upgrading plaintext UDP dns_local")
		}

		doc, err := sboption.ParseDocument([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		var localSrv *sboption.DNSServer
		for i := range doc.DNS.Servers {
			if doc.DNS.Servers[i].Tag == "dns_local" {
				localSrv = &doc.DNS.Servers[i]
				break
			}
		}
		if localSrv == nil || localSrv.Type != "https" || localSrv.Server != "223.5.5.5" || localSrv.ServerPort != 443 || localSrv.Path != "/dns-query" {
			t.Fatalf("expected dns_local upgraded to default DoH, got %+v", localSrv)
		}
		if doc.DNS.DisableCache == nil || *doc.DNS.DisableCache {
			t.Fatalf("expected disable_cache=false, got %v", doc.DNS.DisableCache)
		}
		if doc.DNS.Optimistic == nil || !*doc.DNS.Optimistic {
			t.Fatalf("expected optimistic=true, got %v", doc.DNS.Optimistic)
		}
		if doc.Experimental.CacheFile.StoreDNS == nil || !*doc.Experimental.CacheFile.StoreDNS {
			t.Fatalf("expected store_dns=true, got %v", doc.Experimental.CacheFile.StoreDNS)
		}

		// Idempotency
		out2, changed2, err := singbox.ApplyEnhancedSingBoxDNSJSON(out, config.ClientDNSConfig{}, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		if changed2 || out2 != out {
			t.Fatalf("expected idempotent second apply (changed=%v)", changed2)
		}
		runSingBoxCheckIfAvailable(t, "default_doh", out)
	})

	t.Run("custom_upstreams_rewrites_whitelist_subdomains_block_aaaa_and_malicious_payloads", func(t *testing.T) {
		dnsCfg := config.ClientDNSConfig{
			Upstreams: []string{
				"udp://114.114.114.114:53",   // invalid plaintext, must be skipped
				"tls://223.6.6.6:853",        // first valid encrypted upstream
				"https://1.12.12.12/dns-query",
			},
			Whitelist: []string{"*.allow.example.com", "bad\ninjection.example.com", "ok.example.com"},
			Rewrites: []config.DNSRewriteRule{
				{Domain: "nas.example.com", Answer: "192.0.2.10"},
				{Domain: "nas.example.com", Answer: "2001:db8::10"},
				{Domain: "*.home.example.com", Answer: "198.51.100.20"},
				{Domain: "evil.example.com\nIN A 1.1.1.1", Answer: "192.0.2.99"}, // injection must never enter output
			},
			BlockAAAA: true,
		}
		subDomains := []string{"sub.overseas.example.com"}

		out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(enhancedDNSBaseJSON, dnsCfg, subDomains, now)
		if err != nil {
			t.Fatalf("ApplyEnhancedSingBoxDNSJSON failed: %v", err)
		}
		if !changed {
			t.Fatal("expected changed=true")
		}
		if strings.Contains(out, "evil.example.com") || strings.Contains(out, "injection.example.com") {
			t.Fatalf("malicious injection leaked into output:\n%s", out)
		}

		doc, err := sboption.ParseDocument([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		// Verify first valid TLS upstream used
		foundTLS := false
		for _, s := range doc.DNS.Servers {
			if s.Tag == "dns_local" && s.Type == "tls" && s.Server == "223.6.6.6" && s.ServerPort == 853 {
				foundTLS = true
			}
		}
		if !foundTLS {
			t.Fatalf("expected dns_local upgraded to tls://223.6.6.6:853, got %+v", doc.DNS.Servers)
		}

		// Verify Rewrites (exact merged dual-stack + wildcard)
		foundExact := false
		foundWildcard := false
		foundBlockAAAA := false
		wrappedDNSRejects := 0
		for _, r := range doc.DNS.Rules {
			if r.Action == "predefined" && r.Rcode == "NOERROR" {
				if slices.Equal(r.Domain.Slice(), []string{"nas.example.com"}) &&
					slices.Equal(r.Answer.Slice(), []string{
						"nas.example.com. 60 IN A 192.0.2.10",
						"nas.example.com. 60 IN AAAA 2001:db8::10",
					}) {
					foundExact = true
				}
				if slices.Equal(r.DomainSuffix.Slice(), []string{"home.example.com"}) &&
					slices.Equal(r.Answer.Slice(), []string{"home.example.com. 60 IN A 198.51.100.20"}) {
					foundWildcard = true
				}
				if slices.Equal(r.QueryType.Slice(), []string{"AAAA"}) && r.Answer.IsEmpty() {
					foundBlockAAAA = true
				}
			}
			if r.Action == "reject" && r.Type == "logical" && r.Mode == "and" && len(r.Rules) == 2 {
				inv := r.Rules[1]
				if inv.Invert != nil && *inv.Invert &&
					slices.Equal(inv.DomainSuffix.Slice(), []string{"allow.example.com", "ok.example.com", "sub.overseas.example.com"}) {
					wrappedDNSRejects++
				}
			}
		}
		if !foundExact || !foundWildcard || !foundBlockAAAA {
			t.Fatalf("missing expected DNS rules: exact=%v wildcard=%v blockAAAA=%v\nrules=%+v",
				foundExact, foundWildcard, foundBlockAAAA, doc.DNS.Rules)
		}
		if wrappedDNSRejects != 2 {
			t.Fatalf("expected 2 wrapped logical reject DNS rules (ad + pcdn), got %d", wrappedDNSRejects)
		}

		// Verify Route rules also wrap ad + pcdn rejects with invert=true and do NOT force subDomains direct
		wrappedRouteRejects := 0
		for _, r := range doc.Route.Rules {
			if r.Outbound == "#DC" && slices.Contains(r.DomainSuffix.Slice(), "sub.overseas.example.com") {
				t.Fatal("must NOT force overseas subscription domain direct in route.rules")
			}
			if r.Action == "reject" && r.Type == "logical" && r.Mode == "and" && len(r.Rules) == 2 {
				inv := r.Rules[1]
				if inv.Invert != nil && *inv.Invert &&
					slices.Equal(inv.DomainSuffix.Slice(), []string{"allow.example.com", "ok.example.com", "sub.overseas.example.com"}) {
					wrappedRouteRejects++
				}
			}
		}
		if wrappedRouteRejects != 2 {
			t.Fatalf("expected 2 wrapped logical reject Route rules (ad + pcdn), got %d", wrappedRouteRejects)
		}
		runSingBoxCheckIfAvailable(t, "full_enhanced_tls", out)

		// Verify clearing BlockAAAA / Rewrites / Whitelist removes them cleanly & idempotently
		cleared, changedClear, err := singbox.ApplyEnhancedSingBoxDNSJSON(out, config.ClientDNSConfig{}, nil, now)
		if err != nil || !changedClear {
			t.Fatalf("clear apply failed: changed=%v err=%v", changedClear, err)
		}
		if strings.Contains(cleared, "nas.example.com") || strings.Contains(cleared, `"AAAA"`) || strings.Contains(cleared, `"invert"`) {
			t.Fatalf("cleared rules lingered in config:\n%s", cleared)
		}
		runSingBoxCheckIfAvailable(t, "cleared_enhanced", cleared)
	})

	t.Run("domain_based_doh_adds_encrypted_bootstrap_and_passes_singbox_check", func(t *testing.T) {
		dnsCfg := config.ClientDNSConfig{
			Upstreams: []string{"https://dns.example.com/dns-query"},
		}
		out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(enhancedDNSBaseJSON, dnsCfg, nil, now)
		if err != nil || !changed {
			t.Fatalf("domain DoH apply failed: changed=%v err=%v", changed, err)
		}
		runSingBoxCheckIfAvailable(t, "domain_doh_bootstrap", out)
	})

	t.Run("adblock_pause_resume_and_per_ruleset_toggle_preserve_ruleset_defs", func(t *testing.T) {
		// 1. Temporary pause (AdblockDisabledUntil > now) pauses geosite-ad1 & geosite-ad2, keeps PCDN & keeps rule_set defs
		pausedCfg := config.ClientDNSConfig{AdblockDisabledUntil: now.Unix() + 600}
		pausedJSON, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON(enhancedDNSBaseJSON, pausedCfg, nil, now)
		if err != nil || !changed {
			t.Fatalf("pause failed: changed=%v err=%v", changed, err)
		}
		docPaused, err := sboption.ParseDocument([]byte(pausedJSON))
		if err != nil {
			t.Fatal(err)
		}
		// RuleSet definitions MUST still be preserved!
		rsTags := make([]string, 0, len(docPaused.Route.RuleSet))
		for _, rs := range docPaused.Route.RuleSet {
			rsTags = append(rsTags, rs.Tag)
		}
		if !slices.Contains(rsTags, "geosite-ad1") || !slices.Contains(rsTags, "geosite-ad2") || !slices.Contains(rsTags, singbox.BuiltinPCDNRuleSetTag) {
			t.Fatalf("rule_set definitions must be preserved while paused, got %v", rsTags)
		}
		for _, r := range docPaused.DNS.Rules {
			if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") || slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
				t.Fatalf("geosite-ad1/ad2 should be paused in dns.rules, got %+v", r)
			}
		}
		for _, r := range docPaused.Route.Rules {
			if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") || slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
				t.Fatalf("geosite-ad1/ad2 should be paused in route.rules, got %+v", r)
			}
		}
		// PCDN must stay active during adblock pause
		hasPCDN := false
		for _, r := range docPaused.DNS.Rules {
			if slices.Contains(r.RuleSet.Slice(), singbox.BuiltinPCDNRuleSetTag) && r.Action == "reject" {
				hasPCDN = true
			}
		}
		if !hasPCDN {
			t.Fatal("expected block-builtin-pcdn to stay active when adblock is paused")
		}
		runSingBoxCheckIfAvailable(t, "adblock_paused", pausedJSON)

		// 2. Manual indefinite pause (< 0) stays paused even far in future
		manualPausedCfg := config.ClientDNSConfig{AdblockDisabledUntil: -1}
		manualJSON, _, err := singbox.ApplyEnhancedSingBoxDNSJSON(pausedJSON, manualPausedCfg, nil, now.Add(365*24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(manualJSON, `"action": "reject"`) && strings.Contains(manualJSON, `"geosite-ad1"`) {
			docM, _ := sboption.ParseDocument([]byte(manualJSON))
			for _, r := range docM.DNS.Rules {
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") {
					t.Fatal("manual pause (-1) must keep geosite-ad1 disabled")
				}
			}
		}

		// 3. Auto-resume once now >= AdblockDisabledUntil restores geosite-ad1 & geosite-ad2!
		resumedJSON, changedResume, err := singbox.ApplyEnhancedSingBoxDNSJSON(pausedJSON, pausedCfg, nil, now.Add(601*time.Second))
		if err != nil || !changedResume {
			t.Fatalf("auto-resume failed: changed=%v err=%v", changedResume, err)
		}
		docResumed, err := sboption.ParseDocument([]byte(resumedJSON))
		if err != nil {
			t.Fatal(err)
		}
		hasAd1DNS, hasAd2DNS := false, false
		for _, r := range docResumed.DNS.Rules {
			if r.Action == "reject" {
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") {
					hasAd1DNS = true
				}
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
					hasAd2DNS = true
				}
			}
		}
		hasAd1Route, hasAd2Route := false, false
		for _, r := range docResumed.Route.Rules {
			if r.Action == "reject" {
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") {
					hasAd1Route = true
				}
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
					hasAd2Route = true
				}
			}
		}
		if !hasAd1DNS || !hasAd2DNS || !hasAd1Route || !hasAd2Route {
			t.Fatalf("expected geosite-ad1 & geosite-ad2 restored on resume: dns=(%v,%v) route=(%v,%v)",
				hasAd1DNS, hasAd2DNS, hasAd1Route, hasAd2Route)
		}
		runSingBoxCheckIfAvailable(t, "adblock_resumed", resumedJSON)

		// 4. Per-ruleset toggle: disable geosite-ad2 and block-builtin-pcdn, keep geosite-ad1 active
		partialCfg := config.ClientDNSConfig{
			DisabledAdRuleSets: []string{"geosite-ad2", singbox.BuiltinPCDNRuleSetTag},
		}
		partialJSON, _, err := singbox.ApplyEnhancedSingBoxDNSJSON(resumedJSON, partialCfg, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		docPartial, err := sboption.ParseDocument([]byte(partialJSON))
		if err != nil {
			t.Fatal(err)
		}
		ad1Active, ad2Active, pcdnActive := false, false, false
		for _, r := range docPartial.DNS.Rules {
			if r.Action == "reject" {
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") {
					ad1Active = true
				}
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
					ad2Active = true
				}
				if slices.Contains(r.RuleSet.Slice(), singbox.BuiltinPCDNRuleSetTag) {
					pcdnActive = true
				}
			}
		}
		if !ad1Active || ad2Active || pcdnActive {
			t.Fatalf("unexpected partial toggle state: ad1=%v ad2=%v pcdn=%v", ad1Active, ad2Active, pcdnActive)
		}
		runSingBoxCheckIfAvailable(t, "adblock_partial", partialJSON)

		// 5. Re-enable all rulesets restores geosite-ad2 & block-builtin-pcdn cleanly
		restoredAll, _, err := singbox.ApplyEnhancedSingBoxDNSJSON(partialJSON, config.ClientDNSConfig{}, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		docAll, _ := sboption.ParseDocument([]byte(restoredAll))
		ad1Active, ad2Active, pcdnActive = false, false, false
		for _, r := range docAll.DNS.Rules {
			if r.Action == "reject" {
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad1") {
					ad1Active = true
				}
				if slices.Contains(r.RuleSet.Slice(), "geosite-ad2") {
					ad2Active = true
				}
				if slices.Contains(r.RuleSet.Slice(), singbox.BuiltinPCDNRuleSetTag) {
					pcdnActive = true
				}
			}
		}
		if !ad1Active || !ad2Active || !pcdnActive {
			t.Fatalf("expected all 3 rulesets re-enabled: ad1=%v ad2=%v pcdn=%v", ad1Active, ad2Active, pcdnActive)
		}
		runSingBoxCheckIfAvailable(t, "adblock_restored_all", restoredAll)
	})

	t.Run("block_aaaa_toggle_preserves_ipv6_cn_only_overseas_rules", func(t *testing.T) {
		cnOnlyJSON, err := singbox.ApplyIPv6ModeToConfigJSON(enhancedDNSBaseJSON, config.GatewayIPv6CNOnly)
		if err != nil {
			t.Fatalf("ApplyIPv6ModeToConfigJSON failed: %v", err)
		}
		withBlock, _, err := singbox.ApplyEnhancedSingBoxDNSJSON(cnOnlyJSON, config.ClientDNSConfig{BlockAAAA: true}, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		withoutBlock, _, err := singbox.ApplyEnhancedSingBoxDNSJSON(withBlock, config.ClientDNSConfig{BlockAAAA: false}, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := sboption.ParseDocument([]byte(withoutBlock))
		if err != nil {
			t.Fatal(err)
		}
		foundCNOnlySuppress := false
		for _, r := range doc.DNS.Rules {
			if r.Action == "predefined" && r.Rcode == "NOERROR" {
				qts := r.QueryType.Slice()
				if slices.Equal(qts, []string{"AAAA"}) {
					t.Fatal("managed BlockAAAA rule should have been removed")
				}
				if slices.Equal(qts, []string{"AAAA", "HTTPS"}) {
					foundCNOnlySuppress = true
				}
			}
		}
		if !foundCNOnlySuppress {
			t.Fatal("toggling BlockAAAA off accidentally removed ipv6 cn_only AAAA+HTTPS suppress rules")
		}
		runSingBoxCheckIfAvailable(t, "block_aaaa_cn_only_preserved", withoutBlock)
	})

	t.Run("invalid_json_and_concurrent_race_safe", func(t *testing.T) {
		if _, _, err := singbox.ApplyEnhancedSingBoxDNSJSON("{broken", config.ClientDNSConfig{}, nil, now); err == nil {
			t.Fatal("expected error on broken JSON")
		}
		if out, changed, err := singbox.ApplyEnhancedSingBoxDNSJSON("   ", config.ClientDNSConfig{}, nil, now); err != nil || changed || out != "   " {
			t.Fatalf("expected empty JSON no-op, got out=%q changed=%v err=%v", out, changed, err)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				res, _, err := singbox.ApplyEnhancedSingBoxDNSJSON(enhancedDNSBaseJSON, config.ClientDNSConfig{
					Upstreams: []string{"https://223.5.5.5/dns-query"},
					Whitelist: []string{"ok.example.com"},
					Rewrites:  []config.DNSRewriteRule{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
					BlockAAAA: true,
				}, []string{"sub.example.com"}, now)
				if err != nil || !strings.Contains(res, "192.0.2.10") {
					t.Errorf("concurrent ApplyEnhancedSingBoxDNSJSON failed: %v", err)
				}
			})
		}
		wg.Wait()
	})
}

func TestInjectLocalDNS_ThreeEngineAndPlaintextUDPFallbackFix(t *testing.T) {
	t.Cleanup(func() { adguard.SetInstalledCheckForTest(nil) })

	t.Run("linux_without_external_engine_upgrades_plaintext_udp_to_encrypted_doh", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return false })
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/feed"}},
			DNS: config.ClientDNSConfig{
				Engine:    constant.DNSEngineAuto,
				Upstreams: []string{"https://1.12.12.12/dns-query"},
				Rewrites:  []config.DNSRewriteRule{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
				BlockAAAA: true,
			},
		}
		gen := singbox.NewOfflineConfigGenerator(cfg)
		gen.SetLocalDNSProbe(func(_ string, _ int) bool { return false })

		out, err := gen.RunCompilePipeline(enhancedDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline failed: %v", err)
		}
		doc, err := sboption.ParseDocument([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		var localSrv *sboption.DNSServer
		for i := range doc.DNS.Servers {
			if doc.DNS.Servers[i].Tag == "dns_local" {
				localSrv = &doc.DNS.Servers[i]
			}
		}
		if localSrv == nil || localSrv.Type != "https" || localSrv.Server != "1.12.12.12" {
			t.Fatalf("expected encrypted DoH dns_local (no plaintext UDP 53 fallback), got %+v", localSrv)
		}
		if doc.DNS.DisableCache == nil || *doc.DNS.DisableCache || doc.DNS.Optimistic == nil || !*doc.DNS.Optimistic {
			t.Fatalf("expected cache enabled + optimistic=true, got disable=%v opt=%v", doc.DNS.DisableCache, doc.DNS.Optimistic)
		}
		if !strings.Contains(out, "nas.example.com. 60 IN A 192.0.2.10") || !strings.Contains(out, "sub.example.com") {
			t.Fatalf("expected rewrites & subscription domain whitelist injected:\n%s", out)
		}
		// BlockAAAA must survive apply_ipv6_mode stage in full compile pipeline
		hasBlockAAAA := false
		for _, r := range doc.DNS.Rules {
			if r.Action == "predefined" && slices.Equal(r.QueryType.Slice(), []string{"AAAA"}) {
				hasBlockAAAA = true
			}
		}
		if !hasBlockAAAA {
			t.Fatal("expected BlockAAAA rule to survive full compile pipeline")
		}
	})

	t.Run("linux_explicit_smartdns_ready_routes_to_loopback_and_unready_falls_back_to_doh", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return false })
		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine:  constant.DNSEngineSmartDNS,
				DNSPort: 5354,
			},
		}
		genReady := singbox.NewOfflineConfigGenerator(cfg)
		genReady.SetLocalDNSProbe(func(engine string, port int) bool {
			return engine == constant.DNSEngineSmartDNS && port == 5354
		})
		outReady, err := genReady.InjectLocalDNS(enhancedDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("InjectLocalDNS(smartdns ready) failed: %v", err)
		}
		docReady, _ := sboption.ParseDocument([]byte(outReady))
		if docReady.DNS.Servers[1].Type != "udp" || docReady.DNS.Servers[1].Server != "127.0.0.1" || docReady.DNS.Servers[1].ServerPort != 5354 {
			t.Fatalf("expected smartdns loopback 127.0.0.1:5354, got %+v", docReady.DNS.Servers[1])
		}
		if docReady.DNS.DisableCache == nil || !*docReady.DNS.DisableCache || docReady.DNS.Optimistic == nil || *docReady.DNS.Optimistic {
			t.Fatalf("expected disable_cache=true optimistic=false for external smartdns")
		}

		// When SmartDNS is NOT ready, must fall back to encrypted DoH instead of dead loopback or plaintext UDP!
		genDown := singbox.NewOfflineConfigGenerator(cfg)
		genDown.SetLocalDNSProbe(func(_ string, _ int) bool { return false })
		outDown, err := genDown.InjectLocalDNS(enhancedDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("InjectLocalDNS(smartdns down) failed: %v", err)
		}
		docDown, _ := sboption.ParseDocument([]byte(outDown))
		if docDown.DNS.Servers[1].Type != "https" || docDown.DNS.Servers[1].Server != "223.5.5.5" {
			t.Fatalf("expected fallback to encrypted DoH when smartdns unready, got %+v", docDown.DNS.Servers[1])
		}
	})

	t.Run("linux_explicit_singbox_ignores_installed_adguard_and_ios_never_modified", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine: constant.DNSEngineSingBox,
			},
		}
		gen := singbox.NewOfflineConfigGenerator(cfg)
		outLinux, err := gen.InjectLocalDNS(enhancedDNSBaseJSON, "linux")
		if err != nil {
			t.Fatal(err)
		}
		docLinux, _ := sboption.ParseDocument([]byte(outLinux))
		if docLinux.DNS.Servers[1].Type != "https" || docLinux.DNS.Servers[1].Server == "127.0.0.1" {
			t.Fatalf("explicit singbox engine must use encrypted DoH, not AdGuard loopback: %+v", docLinux.DNS.Servers[1])
		}

		outIOS, err := gen.InjectLocalDNS(enhancedDNSBaseJSON, singbox.PlatformIOS)
		if err != nil {
			t.Fatal(err)
		}
		if outIOS != enhancedDNSBaseJSON {
			t.Fatal("InjectLocalDNS must be a no-op on iOS")
		}
	})
}

func TestSyncLiveEnhancedDNS_ClearCache_AndPreview(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	workDir := filepath.Join(tmpDir, "work")
	if err := os.MkdirAll(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(workDir, "config.json")

	if err := os.WriteFile(cfgPath, []byte(enhancedDNSBaseJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workPath, []byte(enhancedDNSBaseJSON), 0600); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1700000000, 0)
	dnsCfg := config.ClientDNSConfig{
		Upstreams: []string{"https://223.5.5.5/dns-query"},
		Whitelist: []string{"ok.example.com"},
		Rewrites:  []config.DNSRewriteRule{{Domain: "nas.example.com", Answer: "192.0.2.10"}},
		BlockAAAA: true,
	}

	changed, err := singbox.SyncLiveSingBoxEnhancedDNS(t.Context(), cfgPath, workPath, dnsCfg, []string{"sub.example.com"}, now)
	if err != nil {
		t.Fatalf("SyncLiveSingBoxEnhancedDNS failed: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on initial sync")
	}
	fi, err := os.Stat(cfgPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permission on synced config.json, got %v err=%v", fi.Mode().Perm(), err)
	}

	// Idempotent second call
	changedAgain, err := singbox.SyncLiveSingBoxEnhancedDNS(t.Context(), cfgPath, workPath, dnsCfg, []string{"sub.example.com"}, now)
	if err != nil || changedAgain {
		t.Fatalf("expected changed=false on idempotent sync, got changed=%v err=%v", changedAgain, err)
	}

	// Verify sandbox work config also updated
	workRaw, err := os.ReadFile(workPath)
	if err != nil || !strings.Contains(string(workRaw), "nas.example.com. 60 IN A 192.0.2.10") {
		t.Fatalf("expected workPath updated with enhanced DNS rules")
	}

	// Verify pause -> resume recovers ad rule_set even if rule_set was previously stripped in live config
	pausedCfg := dnsCfg
	pausedCfg.AdblockDisabledUntil = -1
	if changedPause, err := singbox.SyncLiveSingBoxEnhancedDNS(t.Context(), cfgPath, workPath, pausedCfg, []string{"sub.example.com"}, now); err != nil || !changedPause {
		t.Fatalf("pause sync failed: changed=%v err=%v", changedPause, err)
	}
	// Simulate legacy config that dropped geosite-ad1 from route.rule_set while base snapshot still holds it
	pausedRaw, _ := os.ReadFile(cfgPath)
	pausedDoc, _ := sboption.ParseDocument(pausedRaw)
	filteredRS := make([]sboption.RuleSet, 0, len(pausedDoc.Route.RuleSet))
	for _, rs := range pausedDoc.Route.RuleSet {
		if rs.Tag != "geosite-ad1" {
			filteredRS = append(filteredRS, rs)
		}
	}
	pausedDoc.Route.RuleSet = filteredRS
	strippedPretty, _ := pausedDoc.MarshalPretty()
	if err := os.WriteFile(cfgPath, []byte(strippedPretty+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resumedCfg := dnsCfg
	resumedCfg.AdblockDisabledUntil = 0
	if changedResume, err := singbox.SyncLiveSingBoxEnhancedDNS(t.Context(), cfgPath, workPath, resumedCfg, []string{"sub.example.com"}, now); err != nil || !changedResume {
		t.Fatalf("resume sync from base snapshot failed: changed=%v err=%v", changedResume, err)
	}
	resumedRaw, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(resumedRaw), `"geosite-ad1"`) {
		t.Fatalf("expected geosite-ad1 restored from base snapshot:\n%s", string(resumedRaw))
	}

	// Verify ClearSingBoxDNSCache removes cache.db in both config & work dirs and respects canceled ctx
	cacheMain := filepath.Join(tmpDir, "cache.db")
	cacheWork := filepath.Join(workDir, "cache.db")
	if err := os.WriteFile(cacheMain, []byte("cached-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cacheWork, []byte("cached-work"), 0600); err != nil {
		t.Fatal(err)
	}

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := singbox.ClearSingBoxDNSCache(canceledCtx, cfgPath, workPath); err == nil {
		t.Fatal("expected error on canceled context")
	}

	if err := singbox.ClearSingBoxDNSCache(t.Context(), cfgPath, workPath); err != nil {
		t.Fatalf("ClearSingBoxDNSCache failed: %v", err)
	}
	if _, err := os.Stat(cacheMain); !os.IsNotExist(err) {
		t.Fatalf("expected %s deleted, stat err=%v", cacheMain, err)
	}
	if _, err := os.Stat(cacheWork); !os.IsNotExist(err) {
		t.Fatalf("expected %s deleted, stat err=%v", cacheWork, err)
	}
	// Idempotent when cache.db already absent
	if err := singbox.ClearSingBoxDNSCache(t.Context(), cfgPath, workPath); err != nil {
		t.Fatalf("second ClearSingBoxDNSCache failed: %v", err)
	}

	// Verify ExtractSingBoxDNSSectionPretty masks sensitive headers/tokens and excludes secrets/outbounds
	secretCfg := `{
  "dns": {
    "servers": [
      {
        "tag": "dns_local",
        "type": "https",
        "server": "223.5.5.5",
        "server_port": 443,
        "path": "/dns-query?token=super-secret-query",
        "headers": {"Authorization": "Bearer real-secret-header"}
      }
    ],
    "final": "dns_local"
  },
  "outbounds": [{"tag": "node", "type": "vless", "uuid": "11111111-1111-1111-1111-111111111111"}],
  "experimental": {"clash_api": {"secret": "clash-top-secret"}}
}`
	secretPath := filepath.Join(tmpDir, "secret-config.json")
	if err := os.WriteFile(secretPath, []byte(secretCfg), 0600); err != nil {
		t.Fatal(err)
	}
	preview, err := singbox.ExtractSingBoxDNSSectionPretty(secretPath)
	if err != nil {
		t.Fatalf("ExtractSingBoxDNSSectionPretty failed: %v", err)
	}
	if strings.Contains(preview, "super-secret-query") ||
		strings.Contains(preview, "real-secret-header") ||
		strings.Contains(preview, "clash-top-secret") ||
		strings.Contains(preview, "11111111-1111-1111-1111-111111111111") {
		t.Fatalf("preview leaked sensitive data:\n%s", preview)
	}
	var previewObj map[string]any
	if err := json.Unmarshal([]byte(preview), &previewObj); err != nil {
		t.Fatalf("preview is not valid JSON: %v\n%s", err, preview)
	}
	if _, ok := previewObj["dns"]; !ok {
		t.Fatalf("expected top-level dns key in preview:\n%s", preview)
	}
	if _, err := singbox.ExtractSingBoxDNSSectionPretty(filepath.Join(tmpDir, "nonexistent.json")); err == nil {
		t.Fatal("expected error for nonexistent file")
	}

	// Verify ExtractSubscriptionDomains
	subDomains := singbox.ExtractSubscriptionDomains(&config.Config{
		Subs: []config.Subscription{
			{URL: "https://Sub1.Example.COM/path?token=abc"},
			{URL: "https://192.0.2.5/sub"}, // IP ignored
			{URL: "http://localhost:3001/sub"},
			{URL: "https://sub1.example.com/dup"},
			{URL: "https://sub2.example.com:8443/feed"},
		},
	})
	if !slices.Equal(subDomains, []string{"sub1.example.com", "sub2.example.com"}) {
		t.Fatalf("ExtractSubscriptionDomains = %v, want [sub1.example.com sub2.example.com]", subDomains)
	}

	// Verify ManagedAdRuleSetTags
	tags := singbox.ManagedAdRuleSetTags()
	if !slices.Equal(tags, []string{"geosite-ad1", "geosite-ad2", singbox.BuiltinPCDNRuleSetTag}) {
		t.Fatalf("ManagedAdRuleSetTags = %v", tags)
	}
}
