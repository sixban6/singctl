// 文件职责：测试 DNS 防绕过分层配置模型（L1~L4 默认值、App 分组开关、源 IP 豁免校验、YAML 持久化与 Clone 深拷贝隔离）。
package config_test

import (
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/config"
)

func TestDNSBypassGuardConfig_DefaultsAndValidation(t *testing.T) {
	var zero config.DNSBypassGuardConfig
	if !zero.IsEnabled() {
		t.Fatal("zero-value DNSBypassGuardConfig must default to enabled")
	}
	if !zero.LayerDoTDoQ() || !zero.LayerPublicDoH() || !zero.LayerSDKHTTPDNS() || !zero.LayerAppHTTPDNS() {
		t.Fatal("all four layers L1~L4 must default to enabled")
	}
	for _, id := range []string{"bilibili", "bytedance", "jd", "netease", "meituan", "ctrip", "oem"} {
		if !zero.IsAppGroupEnabled(id) {
			t.Fatalf("expected app group %q default enabled", id)
		}
	}
	if zero.IsAppGroupEnabled("wechat") {
		t.Fatal("expected high-risk app group wechat default disabled")
	}

	// Explicit override toggles
	off := false
	on := true
	custom := config.DNSBypassGuardConfig{
		Enabled: &on,
		Layers: config.DNSBypassGuardLayers{
			DoTDoQ:     &off,
			PublicDoH:  &on,
			SDKHTTPDNS: &off,
			AppHTTPDNS: &on,
		},
		AppGroups: map[string]bool{
			"bilibili": false,
			"wechat":   true,
		},
		ExemptSourceIPs: []string{"192.0.2.10", "198.51.100.0/24"},
	}
	if custom.LayerDoTDoQ() || !custom.LayerPublicDoH() || custom.LayerSDKHTTPDNS() || !custom.LayerAppHTTPDNS() {
		t.Fatalf("unexpected custom layer flags: %+v", custom.Layers)
	}
	if custom.IsAppGroupEnabled("bilibili") {
		t.Fatal("expected bilibili explicitly disabled")
	}
	if !custom.IsAppGroupEnabled("wechat") {
		t.Fatal("expected wechat explicitly enabled")
	}
	if !custom.IsAppGroupEnabled("jd") {
		t.Fatal("expected unspecified jd to keep default enabled")
	}

	// ExemptSourceIP normalization & malicious input rejection
	validCases := []struct {
		in   []string
		want []string
	}{
		{[]string{"192.0.2.10", "192.0.2.10/32", "198.51.100.0/24", "2001:db8::5"}, []string{"192.0.2.10/32", "198.51.100.0/24", "2001:db8::5/128"}},
		{nil, nil},
	}
	for _, tc := range validCases {
		got, err := config.NormalizeExemptSourceIPs(tc.in)
		if err != nil {
			t.Fatalf("NormalizeExemptSourceIPs(%v) unexpected err: %v", tc.in, err)
		}
		if !slices.Equal(got, tc.want) {
			t.Fatalf("NormalizeExemptSourceIPs(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}

	badInputs := [][]string{
		{"127.0.0.1"},
		{"::1"},
		{"0.0.0.0/0"},
		{"::/0"},
		{"not-an-ip"},
		{"192.0.2.1; rm -rf /"},
		{"192.0.2.1\n192.0.2.2"},
		{"192.0.2.1/33"},
	}
	for _, bad := range badInputs {
		if _, err := config.NormalizeExemptSourceIPs(bad); err == nil {
			t.Fatalf("expected error for invalid exempt_source_ips=%v", bad)
		}
	}
}

func TestDNSBypassGuardConfig_YAMLRoundTripAndCloneIsolation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")

	off := false
	on := true
	orig := &config.Config{
		DNS: config.ClientDNSConfig{
			BypassGuard: config.DNSBypassGuardConfig{
				Enabled: &on,
				Layers: config.DNSBypassGuardLayers{
					DoTDoQ:     &off,
					PublicDoH:  &on,
					SDKHTTPDNS: &on,
					AppHTTPDNS: &on,
				},
				AppGroups: map[string]bool{
					"wechat":   true,
					"bilibili": false,
				},
				ExemptSourceIPs: []string{"192.0.2.50/32"},
			},
		},
	}

	if err := config.Save(cfgPath, orig); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if !reloaded.DNS.BypassGuard.IsEnabled() || reloaded.DNS.BypassGuard.LayerDoTDoQ() || !reloaded.DNS.BypassGuard.IsAppGroupEnabled("wechat") || reloaded.DNS.BypassGuard.IsAppGroupEnabled("bilibili") {
		t.Fatalf("reloaded BypassGuard mismatch: %+v", reloaded.DNS.BypassGuard)
	}
	if !slices.Equal(reloaded.DNS.BypassGuard.ExemptSourceIPs, []string{"192.0.2.50/32"}) {
		t.Fatalf("reloaded ExemptSourceIPs mismatch: %v", reloaded.DNS.BypassGuard.ExemptSourceIPs)
	}

	// Verify Clone() deep-copy isolation
	cloned := reloaded.Clone()
	*cloned.DNS.BypassGuard.Layers.DoTDoQ = true
	cloned.DNS.BypassGuard.AppGroups["wechat"] = false
	cloned.DNS.BypassGuard.ExemptSourceIPs[0] = "198.51.100.99/32"

	if reloaded.DNS.BypassGuard.LayerDoTDoQ() {
		t.Fatal("Clone leaked Layers.DoTDoQ pointer mutation")
	}
	if !reloaded.DNS.BypassGuard.IsAppGroupEnabled("wechat") {
		t.Fatal("Clone leaked AppGroups map mutation")
	}
	if reloaded.DNS.BypassGuard.ExemptSourceIPs[0] != "192.0.2.50/32" {
		t.Fatal("Clone leaked ExemptSourceIPs slice mutation")
	}
}
