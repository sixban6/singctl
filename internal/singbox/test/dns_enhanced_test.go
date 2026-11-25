// 文件职责：覆盖双引擎（AdGuard Home / SmartDNS）本地 DNS 注入、应急纯 IP DoH 兜底（强制关闭 optimistic 缓存）、订阅域名提取与 DNS 重写防注入校验。
package singbox_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

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

const dualEngineDNSBaseJSON = `{
  "log": {"level": "warn"},
  "dns": {
    "servers": [
      {"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"},
      {"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}
    ],
    "rules": [
      {"clash_mode": "Direct", "server": "dns_local"},
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
      {"tag": "geosite-cn", "type": "inline", "rules": [{"domain_suffix": ["cn.example.com"]}]}
    ],
    "rules": [
      {"action": "sniff"},
      {"action": "hijack-dns", "port": 53},
      {"ip_is_private": true, "outbound": "#DC"},
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
      "store_dns": true,
      "store_fakeip": true
    }
  }
}`

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

func TestExtractSubscriptionDomains(t *testing.T) {
	if got := singbox.ExtractSubscriptionDomains(nil); len(got) != 0 {
		t.Fatalf("nil config should return empty slice, got %v", got)
	}
	subDomains := singbox.ExtractSubscriptionDomains(&config.Config{
		Subs: []config.Subscription{
			{URL: "https://sub1.example.com/api?token=abc"},
			{URL: "https://SUB1.example.com/dup"},
			{URL: "https://192.0.2.1/ip-only"},
			{URL: "http://localhost:8080/local"},
			{URL: "https://sub2.example.com:8443/feed"},
			{URL: "   "},
		},
	})
	if !slices.Equal(subDomains, []string{"sub1.example.com", "sub2.example.com"}) {
		t.Fatalf("ExtractSubscriptionDomains = %v, want [sub1.example.com sub2.example.com]", subDomains)
	}
}

func TestInjectLocalDNS_DualEngineAndNoOptimisticFallbackDoH(t *testing.T) {
	t.Cleanup(func() { adguard.SetInstalledCheckForTest(nil) })

	findLocal := func(t *testing.T, doc *sboption.Document) *sboption.DNSServer {
		t.Helper()
		for i := range doc.DNS.Servers {
			if doc.DNS.Servers[i].Tag == "dns_local" {
				return &doc.DNS.Servers[i]
			}
		}
		t.Fatal("dns_local not found")
		return nil
	}

	t.Run("linux_without_external_engine_uses_safe_wan_udp_with_optimistic_false", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return false })
		tmpResolvDir := t.TempDir()
		ispResolv := filepath.Join(tmpResolvDir, "resolv.auto")
		if err := os.WriteFile(ispResolv, []byte("nameserver 192.168.1.1\nnameserver 203.0.113.53\n"), 0600); err != nil {
			t.Fatal(err)
		}
		lanOnlyResolv := filepath.Join(tmpResolvDir, "resolv.lan")
		if err := os.WriteFile(lanOnlyResolv, []byte("nameserver 127.0.0.1\nnameserver 192.168.1.1\n"), 0600); err != nil {
			t.Fatal(err)
		}

		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine: constant.DNSEngineAuto,
			},
		}
		gen := singbox.NewOfflineConfigGenerator(cfg)
		gen.SetLocalDNSProbe(func(_ string, _ int) bool { return false })
		gen.SetFallbackDNSResolvForTest([]string{ispResolv}, []string{})

		out, err := gen.RunCompilePipeline(dualEngineDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline failed: %v", err)
		}
		doc, err := sboption.ParseDocument([]byte(out))
		if err != nil {
			t.Fatal(err)
		}
		localSrv := findLocal(t, doc)
		if localSrv.Type != "udp" || localSrv.Server != "203.0.113.53" || localSrv.ServerPort != 53 {
			t.Fatalf("expected safe WAN ISP UDP 53 fallback (203.0.113.53), got %+v", localSrv)
		}
		if doc.DNS.DisableCache == nil || !*doc.DNS.DisableCache {
			t.Fatalf("expected disable_cache=true in WAN UDP fallback, got %v", doc.DNS.DisableCache)
		}
		if doc.DNS.Optimistic == nil || *doc.DNS.Optimistic {
			t.Fatalf("expected optimistic=false in WAN UDP fallback, got %v", doc.DNS.Optimistic)
		}
		if doc.Experimental.CacheFile.StoreDNS == nil || *doc.Experimental.CacheFile.StoreDNS {
			t.Fatalf("expected store_dns=false in WAN UDP fallback, got %v", doc.Experimental.CacheFile.StoreDNS)
		}
		runSingBoxCheckIfAvailable(t, "fallback_wan_udp_no_optimistic", out)

		// When resolv files only contain private/loopback DNS, skip private IPs and fall back to 114.114.114.114:53
		genLAN := singbox.NewOfflineConfigGenerator(cfg)
		genLAN.SetLocalDNSProbe(func(_ string, _ int) bool { return false })
		genLAN.SetFallbackDNSResolvForTest([]string{lanOnlyResolv}, []string{})

		outLAN, err := genLAN.RunCompilePipeline(dualEngineDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline(lan-only) failed: %v", err)
		}
		docLAN, err := sboption.ParseDocument([]byte(outLAN))
		if err != nil {
			t.Fatal(err)
		}
		localLAN := findLocal(t, docLAN)
		if localLAN.Type != "udp" || localLAN.Server != singbox.DefaultFallbackPlainUDPDNS || localLAN.ServerPort != 53 {
			t.Fatalf("expected lan-only resolv to skip private IPs and use %s:53, got %+v", singbox.DefaultFallbackPlainUDPDNS, localLAN)
		}
	})

	t.Run("linux_explicit_smartdns_ready_routes_to_loopback_and_unready_falls_back_to_wan_udp_no_optimistic", func(t *testing.T) {
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
		outReady, err := genReady.InjectLocalDNS(dualEngineDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("InjectLocalDNS(smartdns ready) failed: %v", err)
		}
		docReady, _ := sboption.ParseDocument([]byte(outReady))
		srvReady := findLocal(t, docReady)
		if srvReady.Type != "udp" || srvReady.Server != "127.0.0.1" || srvReady.ServerPort != 5354 {
			t.Fatalf("expected smartdns loopback 127.0.0.1:5354, got %+v", srvReady)
		}
		if docReady.DNS.DisableCache == nil || !*docReady.DNS.DisableCache ||
			docReady.DNS.Optimistic == nil || *docReady.DNS.Optimistic ||
			docReady.Experimental.CacheFile.StoreDNS == nil || *docReady.Experimental.CacheFile.StoreDNS ||
			docReady.Experimental.CacheFile.StoreFakeIP == nil || *docReady.Experimental.CacheFile.StoreFakeIP {
			t.Fatalf("expected disable_cache=true optimistic=false store_dns=false store_fakeip=false for external smartdns")
		}

		// When SmartDNS is NOT ready, must fall back to safe public WAN UDP DNS with optimistic=false!
		lanResolv := filepath.Join(t.TempDir(), "resolv.auto")
		if err := os.WriteFile(lanResolv, []byte("nameserver 192.168.1.1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		genDown := singbox.NewOfflineConfigGenerator(cfg)
		genDown.SetLocalDNSProbe(func(_ string, _ int) bool { return false })
		genDown.SetFallbackDNSResolvForTest([]string{lanResolv}, []string{})
		outDown, err := genDown.InjectLocalDNS(dualEngineDNSBaseJSON, "linux")
		if err != nil {
			t.Fatalf("InjectLocalDNS(smartdns down) failed: %v", err)
		}
		docDown, _ := sboption.ParseDocument([]byte(outDown))
		srvDown := findLocal(t, docDown)
		if srvDown.Type != "udp" || srvDown.Server != singbox.DefaultFallbackPlainUDPDNS || srvDown.ServerPort != 53 {
			t.Fatalf("expected fallback to public UDP 53 (%s) when smartdns unready, got %+v", singbox.DefaultFallbackPlainUDPDNS, srvDown)
		}
		if docDown.DNS.DisableCache == nil || !*docDown.DNS.DisableCache ||
			docDown.DNS.Optimistic == nil || *docDown.DNS.Optimistic ||
			docDown.Experimental.CacheFile.StoreDNS == nil || *docDown.Experimental.CacheFile.StoreDNS {
			t.Fatalf("expected disable_cache=true optimistic=false store_dns=false on fallback")
		}
	})

	t.Run("linux_legacy_singbox_engine_normalizes_to_auto_and_ios_untouched", func(t *testing.T) {
		adguard.SetInstalledCheckForTest(func() bool { return true })
		cfg := &config.Config{
			DNS: config.ClientDNSConfig{
				Engine: "singbox", // legacy value must normalize to auto
			},
		}
		gen := singbox.NewOfflineConfigGenerator(cfg)
		gen.SetLocalDNSProbe(func(engine string, port int) bool {
			return engine == constant.DNSEngineAdGuard && port == 5353
		})
		outLinux, err := gen.InjectLocalDNS(dualEngineDNSBaseJSON, "linux")
		if err != nil {
			t.Fatal(err)
		}
		docLinux, _ := sboption.ParseDocument([]byte(outLinux))
		srvLinux := findLocal(t, docLinux)
		if srvLinux.Type != "udp" || srvLinux.Server != "127.0.0.1" || srvLinux.ServerPort != 5353 {
			t.Fatalf("legacy singbox config should normalize to auto and link ready AdGuard, got %+v", srvLinux)
		}

		outIOS, err := gen.InjectLocalDNS(dualEngineDNSBaseJSON, singbox.PlatformIOS)
		if err != nil {
			t.Fatal(err)
		}
		if outIOS != dualEngineDNSBaseJSON {
			t.Fatal("InjectLocalDNS must be a no-op on iOS")
		}
	})
}
