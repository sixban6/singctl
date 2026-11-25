// 文件职责：测试客户端本地域名与设备名册（HomeDomainConfig）校验、通配重写生成、昵称反查、YAML 宽容解析与深拷贝隔离。
package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestHomeDomain_SuffixAndAliasNormalization(t *testing.T) {
	suffixCases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{"", "home", false},
		{"  .HOME. ", "home", false},
		{"home.arpa", "home.arpa", false},
		{"lan", "lan", false},
		{"internal", "internal", false},
		{"home.lan", "home.lan", false},
		{"local", "", true},
		{"my.local", "", true},
		{"localhost", "", true},
		{"com", "", true},
		{"cn", "", true},
		{"net", "", true},
		{"org", "", true},
		{"bad space", "", true},
		{"bad;rm", "", true},
		{"-bad", "", true},
		{"a.b.c", "", true},
	}
	for _, tc := range suffixCases {
		got, err := config.NormalizeHomeDomainSuffix(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeHomeDomainSuffix(%q) = %q, want error", tc.raw, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeHomeDomainSuffix(%q) = (%q, %v), want (%q, nil)", tc.raw, got, err, tc.want)
		}
	}

	aliasCases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{"ax3000t", "ax3000t", false},
		{" N60-Pro ", "n60-pro", false},
		{"nas", "nas", false},
		{"a", "a", false},
		{"", "", true},
		{"localhost", "", true},
		{"wpad", "", true},
		{"bad.dot", "", true},
		{"-leading", "", true},
		{"trailing-", "", true},
		{"bad_under", "", true},
		{"中文", "", true},
		{strings.Repeat("a", 64), "", true},
	}
	for _, tc := range aliasCases {
		got, err := config.NormalizeDeviceAlias(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("NormalizeDeviceAlias(%q) = %q, want error", tc.raw, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeDeviceAlias(%q) = (%q, %v), want (%q, nil)", tc.raw, got, err, tc.want)
		}
	}

	suggestCases := []struct {
		raw  string
		want string
	}{
		{"Xiaomi_AX3000T", "xiaomi-ax3000t"},
		{"  My--NAS.local  ", "my-nas"},
		{"iPhone (15 Pro)", "iphone-15-pro"},
		{"中文设备", ""},
		{"localhost", ""},
	}
	for _, tc := range suggestCases {
		if got := config.SanitizeSuggestedAlias(tc.raw); got != tc.want {
			t.Fatalf("SanitizeSuggestedAlias(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestHomeDomain_RewritesLookupValidateYAMLAndClone(t *testing.T) {
	hd := config.HomeDomainConfig{
		Suffix: "home",
		Devices: []config.HomeDomainDevice{
			{
				Alias:       "nas",
				DisplayName: "家庭NAS",
				IP:          "192.0.2.10",
				MAC:         "AA:BB:CC:DD:EE:01",
				Source:      "lan",
				Wildcard:    true,
				Services:    []config.HomeDomainService{{Label: "DSM", Scheme: "http", Port: 5000}},
			},
			{
				Alias:       "ax3000t",
				DisplayName: "书房路由",
				IP:          "100.64.0.22",
				Source:      "tailscale",
				Services:    []config.HomeDomainService{{Label: "WebUI", Scheme: "http", Port: 8090}},
			},
		},
	}

	if err := hd.Validate(); err != nil {
		t.Fatalf("expected valid HomeDomainConfig, got %v", err)
	}
	if !hd.IsEnabled() || !hd.IsTailscaleDNSEnabled() || !hd.IsFollowDHCPEnabled() {
		t.Fatalf("expected default booleans true")
	}

	gotRewrites := hd.BuildManagedRewrites()
	wantRewrites := []config.DNSRewriteRule{
		{Domain: "ax3000t.home", Answer: "100.64.0.22"},
		{Domain: "nas.home", Answer: "192.0.2.10"},
		{Domain: "*.nas.home", Answer: "192.0.2.10"},
	}
	if !reflect.DeepEqual(gotRewrites, wantRewrites) {
		t.Fatalf("BuildManagedRewrites() = %+v, want %+v", gotRewrites, wantRewrites)
	}

	// LookupFriendlyName prefers MAC (survives DHCP/IPv6 IP changes) and falls back to IP
	label, fqdn, ok := hd.LookupFriendlyName("198.51.100.99", "aa:bb:cc:dd:ee:01")
	if !ok || label != "家庭NAS" || fqdn != "nas.home" {
		t.Fatalf("LookupFriendlyName by MAC = (%q, %q, %v), want (家庭NAS, nas.home, true)", label, fqdn, ok)
	}
	label2, fqdn2, ok2 := hd.LookupFriendlyName("100.64.0.22", "")
	if !ok2 || label2 != "书房路由" || fqdn2 != "ax3000t.home" {
		t.Fatalf("LookupFriendlyName by IP = (%q, %q, %v), want (书房路由, ax3000t.home, true)", label2, fqdn2, ok2)
	}

	// Explicit disabled yields zero rewrites
	disabled := hd.Clone()
	disabled.SetEnabled(false)
	if len(disabled.BuildManagedRewrites()) != 0 {
		t.Fatalf("disabled HomeDomainConfig must yield 0 managed rewrites")
	}

	// Duplicate alias rejected
	dup := hd.Clone()
	dup.Devices = append(dup.Devices, config.HomeDomainDevice{Alias: "NAS", IP: "192.0.2.11"})
	if err := dup.Validate(); err == nil {
		t.Fatalf("expected duplicate alias error")
	}

	// Invalid IP rejected
	badIP := hd.Clone()
	badIP.Devices[0].IP = "not-an-ip"
	if err := badIP.Validate(); err == nil {
		t.Fatalf("expected invalid IP error")
	}

	// YAML load with missing spaces after colons (knownYAMLKeys) + deep Clone isolation
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	rawYAML := `home_domain:
  suffix:"home"
  tailscale_dns:true
  follow_dhcp:true
  devices:
    - alias:"nas"
      display_name:"家庭NAS"
      ip:"192.0.2.10"
      mac:"aa:bb:cc:dd:ee:01"
      wildcard:true
      services:
        - label:"DSM"
          scheme:"http"
          port:5000
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if loaded.HomeDomain.EffectiveSuffix() != "home" || len(loaded.HomeDomain.Devices) != 1 || loaded.HomeDomain.Devices[0].Services[0].Port != 5000 {
		t.Fatalf("unexpected loaded HomeDomain: %+v", loaded.HomeDomain)
	}

	cloned := loaded.Clone()
	cloned.HomeDomain.Devices[0].Alias = "mutated"
	cloned.HomeDomain.Devices[0].Services[0].Port = 9999
	if loaded.HomeDomain.Devices[0].Alias != "nas" || loaded.HomeDomain.Devices[0].Services[0].Port != 5000 {
		t.Fatalf("Clone() did not deep-copy HomeDomain slices")
	}
}
