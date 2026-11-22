// 文件职责：覆盖 iOS SFI 沙盒兼容适配、镜像前缀剥离、50MB 规则集精简及静态/真机二进制校验测试。
package singbox_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func TestAdaptIOSConfig_StripsSandboxMirrorAndHeavyRulesets(t *testing.T) {
	input := `{
  "services": [{"type": "api", "listen": "127.0.0.1"}],
  "http_clients": [{"detour": "Proxy"}],
  "dns": {
    "final": "dns_proxy",
    "disable_cache": true,
    "optimistic": true,
    "independent_cache": true,
    "rules": [
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "geosite-ad2", "action": "reject"},
      {"rule_set": "geosite-cn", "server": "dns_local"}
    ]
  },
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["#Auto"]},
    {"type": "urltest", "tag": "#Auto", "outbounds": ["node-1"]},
    {"type": "direct", "tag": "#DC"}
  ],
  "route": {
    "default_domain_resolver": "dns_local",
    "default_mark": 255,
    "rules": [
      {"action": "sniff"},
      {"rule_set": "geosite-ad2", "action": "reject"},
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "geosite-cn", "outbound": "#DC"}
    ],
    "rule_set": [
      {"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://mirror.example.com/https://raw.githubusercontent.com/org/repo/main/ad1.srs", "download_detour": "#DC"},
      {"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://mirror.example.com/https://raw.githubusercontent.com/org/repo/main/ad2.srs", "download_detour": "#DC"},
      {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://proxy.example.net/prefix/https://raw.githubusercontent.com/org/repo/main/cn.srs", "download_detour": "#DC"},
      {"tag": "geosite-unused", "type": "remote", "format": "binary", "url": "https://mirror.example.com/https://raw.githubusercontent.com/org/repo/main/unused.srs", "download_detour": "#DC"}
    ]
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9095",
      "external_ui": "/etc/sing-box/ui",
      "external_ui_download_url": "https://example.com/ui.zip",
      "external_ui_download_detour": "#DC"
    },
    "cache_file": {
      "enabled": true,
      "path": "/etc/sing-box/cache.db",
      "store_dns": true,
      "store_fakeip": true
    }
  }
}`

	out, err := singbox.AdaptIOSConfig(input, "https://mirror.example.com")
	if err != nil {
		t.Fatalf("AdaptIOSConfig failed: %v", err)
	}

	if err := singbox.CheckIOSCompatibility(out); err != nil {
		t.Fatalf("adapted output failed CheckIOSCompatibility: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("unmarshal adapted JSON: %v", err)
	}

	if _, exists := doc["services"]; exists {
		t.Fatalf("services should be stripped on iOS")
	}
	httpClients, ok := doc["http_clients"].([]any)
	if !ok || len(httpClients) != 1 {
		t.Fatalf("expected 1 top-level http_clients entry on iOS v1.14+, got %v", doc["http_clients"])
	}
	hc0, _ := httpClients[0].(map[string]any)
	if hc0["tag"] != "hc-proxy" || hc0["detour"] != "Proxy" {
		t.Fatalf("expected http_clients[0]={tag:hc-proxy, detour:Proxy}, got %v", hc0)
	}

	dnsMap := doc["dns"].(map[string]any)
	if _, exists := dnsMap["optimistic"]; exists {
		t.Fatalf("dns.optimistic should be removed")
	}
	if _, exists := dnsMap["independent_cache"]; exists {
		t.Fatalf("dns.independent_cache should be removed when disable_cache=true")
	}
	parsedAdapted, err := sboption.ParseDocument([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	dnsRules := parsedAdapted.DNS.Rules
	if len(dnsRules) != 2 {
		t.Fatalf("expected 2 dns rules after dropping pure geosite-ad2 rule, got %d: %+v", len(dnsRules), dnsRules)
	}
	if tags := dnsRules[0].RuleSet.Slice(); !slices.Equal(tags, []string{"geosite-ad1"}) {
		t.Fatalf("expected geosite-ad2 stripped from multi-tag dns rule, got %v", tags)
	}

	routeMap := doc["route"].(map[string]any)
	if _, exists := routeMap["default_mark"]; exists {
		t.Fatalf("route.default_mark should be removed on iOS")
	}
	if routeMap["default_http_client"] != "hc-proxy" {
		t.Fatalf("expected route.default_http_client=hc-proxy, got %v", routeMap["default_http_client"])
	}
	routeRules := routeMap["rules"].([]any)
	if len(routeRules) != 3 {
		t.Fatalf("expected 3 route rules after dropping pure geosite-ad2 rule, got %d", len(routeRules))
	}

	rsList := routeMap["rule_set"].([]any)
	if len(rsList) != 2 {
		t.Fatalf("expected geosite-ad2 & geosite-unused pruned leaving 2 rule_sets, got %d: %v", len(rsList), rsList)
	}
	for _, item := range rsList {
		rm := item.(map[string]any)
		tag := rm["tag"].(string)
		u := rm["url"].(string)
		if tag == "geosite-ad2" || tag == "geosite-unused" {
			t.Fatalf("unexpected rule_set remaining: %s", tag)
		}
		if !strings.HasPrefix(u, "https://raw.githubusercontent.com/") {
			t.Fatalf("expected mirror stripped from %s url, got %q", tag, u)
		}
		if _, hasLegacy := rm["download_detour"]; hasLegacy {
			t.Fatalf("expected legacy download_detour removed on v1.14+ for %s, got %v", tag, rm["download_detour"])
		}
	}

	exp := doc["experimental"].(map[string]any)
	cf := exp["cache_file"].(map[string]any)
	if len(cf) != 1 || cf["enabled"] != true {
		t.Fatalf("expected cache_file normalized to {enabled:true}, got %v", cf)
	}
	ca := exp["clash_api"].(map[string]any)
	if ca["external_controller"] != "127.0.0.1:9095" {
		t.Fatalf("expected external_controller preserved, got %v", ca["external_controller"])
	}
	if _, exists := ca["external_ui"]; exists {
		t.Fatalf("expected external_ui deleted")
	}
}

func TestAdaptIOSConfig_DetourFallbackPriority(t *testing.T) {
	base := `{"outbounds":[{"type":"urltest","tag":"#Auto"},{"type":"direct","tag":"#DC"}],"route":{"rules":[{"rule_set":"geosite-cn","outbound":"#DC"}],"rule_set":[{"tag":"geosite-cn","type":"remote","url":"https://example.com/cn.srs","download_detour":"#DC"}]}}`
	out, err := singbox.AdaptIOSConfig(base, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, `"download_detour"`) {
		t.Fatalf("v1.14+ output must not contain legacy download_detour, got %s", out)
	}
	if !strings.Contains(out, `"detour":"#Auto"`) || !strings.Contains(out, `"default_http_client":"hc-proxy"`) {
		t.Fatalf("expected #Auto http_client detour fallback when Proxy absent, got %s", out)
	}

	onlyDirect := `{"outbounds":[{"type":"direct","tag":"#DC"}],"route":{"rules":[{"rule_set":"geosite-cn","outbound":"#DC"}],"rule_set":[{"tag":"geosite-cn","type":"remote","url":"https://example.com/cn.srs","download_detour":"#DC"}]}}`
	outDirect, err := singbox.AdaptIOSConfig(onlyDirect, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(outDirect, `"download_detour"`) || strings.Contains(outDirect, `"detour"`) {
		t.Fatalf("empty direct fallback must omit both download_detour and empty-direct detour, got %s", outDirect)
	}
	if !strings.Contains(outDirect, `"default_http_client":"hc-direct"`) {
		t.Fatalf("expected default_http_client=hc-direct on direct fallback, got %s", outDirect)
	}

	outLegacy, err := singbox.AdaptIOSConfigForVersion(base, "", "v1.12")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outLegacy, `"download_detour":"#Auto"`) {
		t.Fatalf("v1.12 legacy output expected download_detour=#Auto, got %s", outLegacy)
	}
	if strings.Contains(outLegacy, `"http_clients"`) || strings.Contains(outLegacy, `"default_http_client"`) {
		t.Fatalf("v1.12 legacy output must not contain 1.14 http_clients fields, got %s", outLegacy)
	}
}

func TestApplyTrafficRoutingForPlatform_IOSSkipsEnabledGeositeDNS(t *testing.T) {
	base := `{
  "dns": {
    "final": "dns_proxy",
    "servers": [
      {"tag": "dns_proxy", "type": "https"},
      {"tag": "dns_local", "type": "udp"}
    ],
    "rules": []
  },
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["#Auto"]},
    {"type": "selector", "tag": "#VPS", "outbounds": ["#Auto"]},
    {"type": "direct", "tag": "#DC"}
  ],
  "route": {
    "rules": [],
    "rule_set": [
      {"tag": "geosite-disney", "type": "remote", "url": "https://example.com/disney.srs"},
      {"tag": "geosite-apple", "type": "remote", "url": "https://example.com/apple.srs"}
    ]
  }
}`
	tr := config.TrafficRoutingConfig{
		Presets: map[string]config.TrafficRuleOverride{
			"openai": {Enabled: new(true), Outbound: "#VPS"},
			"disney": {Enabled: new(true), Outbound: "Proxy"},
			"apple":  {Enabled: new(false), Outbound: "#DC"},
		},
	}

	out, err := singbox.ApplyTrafficRoutingForPlatform(base, tr, config.CustomRulesConfig{}, singbox.PlatformIOS)
	if err != nil {
		t.Fatalf("ApplyTrafficRoutingForPlatform failed: %v", err)
	}

	doc, err := sboption.ParseDocument([]byte(out))
	if err != nil {
		t.Fatal(err)
	}

	var foundProxyDisneyRS, foundLocalAppleRS, foundProxyDomainSuffix bool
	for _, r := range doc.DNS.Rules {
		rs := r.RuleSet.Slice()
		ds := r.DomainSuffix.Slice()
		if r.Server == "dns_proxy" {
			if slices.Contains(rs, "geosite-disney") {
				foundProxyDisneyRS = true
			}
			for _, d := range ds {
				if d == "openai.com" || d == "chatgpt.com" {
					foundProxyDomainSuffix = true
				}
			}
		}
		if r.Server == "dns_local" && slices.Contains(rs, "geosite-apple") {
			foundLocalAppleRS = true
		}
	}
	if foundProxyDisneyRS {
		t.Fatalf("iOS dns.rules should skip enabled geosite-disney when dns.final==dns_proxy")
	}
	if !foundProxyDomainSuffix {
		t.Fatalf("iOS dns.rules should keep domain_suffix for enabled presets")
	}
	if !foundLocalAppleRS {
		t.Fatalf("iOS dns.rules should keep disabled direct geosite-apple rule")
	}

	var foundRouteDisney bool
	for _, r := range doc.Route.Rules {
		if slices.Contains(r.RuleSet.Slice(), "geosite-disney") {
			foundRouteDisney = true
		}
	}
	if !foundRouteDisney {
		t.Fatalf("route.rules should still contain geosite-disney")
	}
}

func TestInjectCustomRulesForPlatform_IOSExcludesSourceIPAndLocalSRS(t *testing.T) {
	cacheDir := t.TempDir()
	t.Setenv("SINGCTL_RULESET_CACHE_DIR", cacheDir)
	if err := os.WriteFile(filepath.Join(cacheDir, "block-ads.srs"), make([]byte, 32), 0600); err != nil {
		t.Fatal(err)
	}

	g := singbox.NewOfflineConfigGenerator(&config.Config{
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{
				{Target: "lan-only.example.com", SourceIP: "192.0.2.10"},
				{Target: "ruleset:block-ads", RuleSetURL: "https://example.com/block-ads.srs"},
				{Target: "global-bad.example.com"},
			},
		},
	})
	base := `{"dns":{"rules":[],"servers":[{"tag":"dns_local","type":"udp"}]},"route":{"rules":[],"rule_set":[]}}`
	out, err := g.InjectCustomRulesForPlatform(base, singbox.PlatformIOS)
	if err != nil {
		t.Fatalf("InjectCustomRulesForPlatform(ios) failed: %v", err)
	}
	if strings.Contains(out, "lan-only.example.com") || strings.Contains(out, "192.0.2.10") {
		t.Fatalf("iOS output must skip LAN device SourceIP block rule, got %s", out)
	}
	if !strings.Contains(out, "global-bad.example.com") {
		t.Fatalf("iOS output should keep global block rule, got %s", out)
	}
	if strings.Contains(out, `"type":"local"`) {
		t.Fatalf("iOS output must not inject local rule_set, got %s", out)
	}
	if !strings.Contains(out, `"type":"remote"`) || !strings.Contains(out, "https://example.com/block-ads.srs") {
		t.Fatalf("iOS output should keep remote block rule_set URL, got %s", out)
	}
	if err := singbox.CheckIOSCompatibility(out); err != nil {
		t.Fatalf("CheckIOSCompatibility failed: %v", err)
	}
}

func TestCheckIOSCompatibility_RejectsSandboxIncompatibleFields(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			name: "default_mark",
			json: `{"route":{"default_mark":1}}`,
			want: "default_mark",
		},
		{
			name: "external_ui",
			json: `{"experimental":{"clash_api":{"external_ui":"/etc/sing-box/ui"}}}`,
			want: "external_ui",
		},
		{
			name: "cache_file_path",
			json: `{"experimental":{"cache_file":{"path":"/etc/sing-box/cache.db"}}}`,
			want: "cache_file.path",
		},
		{
			name: "services",
			json: `{"services":[{"type":"api"}]}`,
			want: "services",
		},
		{
			name: "local_path_only_ruleset",
			json: `{"route":{"rule_set":[{"tag":"custom-rs","path":"/etc/sing-box/c.srs"}]}}`,
			want: "custom-rs",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := singbox.CheckIOSCompatibility(tc.json)
			if err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAdaptIOSConfig_SingBoxCheckRealBinary(t *testing.T) {
	sbBin, err := exec.LookPath("sing-box")
	if err != nil || sbBin == "" {
		t.Skip("sing-box binary not available in PATH")
	}

	fullCfg := `{
  "log": {"level": "warn"},
  "dns": {
    "final": "dns_proxy",
    "servers": [
      {"tag": "dns_local", "type": "local"},
      {"tag": "dns_proxy", "type": "https", "server": "8.8.8.8"}
    ],
    "rules": [
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "geosite-cn", "server": "dns_local"}
    ]
  },
  "inbounds": [{"type": "tun", "tag": "tun-in", "address": ["198.18.0.1/30"], "auto_route": true}],
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["#Auto", "node-1"]},
    {"type": "urltest", "tag": "#Auto", "outbounds": ["node-1"]},
    {"type": "direct", "tag": "#DC"},
    {"type": "socks", "tag": "node-1", "server": "192.0.2.10", "server_port": 1080}
  ],
  "route": {
    "default_domain_resolver": "dns_local",
    "default_mark": 255,
    "final": "Proxy",
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"rule_set": ["geosite-ad1", "geosite-ad2"], "action": "reject"},
      {"rule_set": "geosite-cn", "outbound": "#DC"}
    ],
    "rule_set": [
      {"tag": "geosite-ad1", "type": "remote", "format": "binary", "url": "https://mirror.example.com/https://raw.githubusercontent.com/org/repo/main/ad1.srs", "download_detour": "#DC"},
      {"tag": "geosite-ad2", "type": "remote", "format": "binary", "url": "https://mirror.example.com/https://raw.githubusercontent.com/org/repo/main/ad2.srs", "download_detour": "#DC"},
      {"tag": "geosite-cn", "type": "remote", "format": "binary", "url": "https://mirror.example.com/https://raw.githubusercontent.com/org/repo/main/cn.srs", "download_detour": "#DC"}
    ]
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9095",
      "external_ui": "/etc/sing-box/ui"
    },
    "cache_file": {"enabled": true, "path": "/etc/sing-box/cache.db", "store_dns": true}
  }
}`
	adapted, err := singbox.AdaptIOSConfig(fullCfg, "https://mirror.example.com")
	if err != nil {
		t.Fatalf("AdaptIOSConfig failed: %v", err)
	}
	pretty, err := singbox.PrettyJSON(adapted)
	if err != nil {
		t.Fatalf("PrettyJSON failed: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "ios-config.json")
	if err := os.WriteFile(cfgPath, []byte(pretty), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), sbBin, "check", "-c", cfgPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed: %v\n%s", err, string(out))
	}
}
