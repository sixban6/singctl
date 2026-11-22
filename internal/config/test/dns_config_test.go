// 文件职责：验证三引擎防劫持 ClientDNSConfig 扩展字段、引擎校验、YAML 宽容反序列化、深拷贝隔离、AST 清理落盘与并发安全。
package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
)

func TestClientDNSConfig_EngineValidationAndDefaults(t *testing.T) {
	validCases := []struct {
		raw  string
		want bool
	}{
		{"", true},
		{"   ", true},
		{constant.DNSEngineAuto, true},
		{constant.DNSEngineSmartDNS, true},
		{constant.DNSEngineAdGuard, true},
		{"SmartDNS", true},
		{"  ADGUARD ", true},
		{"singbox", false},
		{"  SINGBOX ", false},
		{"bind9", false},
		{"dnsmasq", false},
		{"singbox;rm -rf /", false},
	}
	for _, tc := range validCases {
		if got := config.IsValidDNSEngine(tc.raw); got != tc.want {
			t.Errorf("IsValidDNSEngine(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}

	var nilCfg *config.ClientDNSConfig
	if got := nilCfg.GetEngine(); got != constant.DNSEngineAuto {
		t.Fatalf("nil GetEngine() = %q, want %q", got, constant.DNSEngineAuto)
	}
	if got := nilCfg.GetUpstreamMode(); got != config.DNSUpstreamModeFastestIP {
		t.Fatalf("nil GetUpstreamMode() = %q, want %q", got, config.DNSUpstreamModeFastestIP)
	}
	if nilCfg.IsAdblockPaused(time.Now()) {
		t.Fatal("nil IsAdblockPaused should be false")
	}
	nilCfg.SetEngine(constant.DNSEngineSmartDNS) // must not panic

	var d config.ClientDNSConfig
	if got := d.GetEngine(); got != constant.DNSEngineAuto {
		t.Fatalf("zero GetEngine() = %q, want %q", got, constant.DNSEngineAuto)
	}
	d.SetEngine("  SmartDNS ")
	if got := d.GetEngine(); got != constant.DNSEngineSmartDNS {
		t.Fatalf("after SetEngine(SmartDNS), GetEngine() = %q", got)
	}
	d.SetEngine("invalid-engine")
	if got := d.GetEngine(); got != constant.DNSEngineAuto {
		t.Fatalf("invalid SetEngine should normalize to auto, got %q", got)
	}
	d.SetEngine("singbox")
	if got := d.GetEngine(); got != constant.DNSEngineAuto {
		t.Fatalf("legacy singbox SetEngine should normalize to auto, got %q", got)
	}
	d.Engine = "singbox"
	if got := d.GetEngine(); got != constant.DNSEngineAuto {
		t.Fatalf("legacy singbox Engine field should normalize to auto, got %q", got)
	}
	d.Engine = "bogus"
	if got := d.GetEngine(); got != constant.DNSEngineAuto {
		t.Fatalf("bogus Engine field should normalize to auto, got %q", got)
	}

	modeCases := []struct {
		raw  string
		want string
	}{
		{"", config.DNSUpstreamModeFastestIP},
		{"fastest_ip", config.DNSUpstreamModeFastestIP},
		{" PARALLEL ", config.DNSUpstreamModeParallel},
		{"load_balance", config.DNSUpstreamModeLoadBalance},
		{"unknown", config.DNSUpstreamModeFastestIP},
	}
	for _, tc := range modeCases {
		d.UpstreamMode = tc.raw
		if got := d.GetUpstreamMode(); got != tc.want {
			t.Errorf("GetUpstreamMode(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}

	now := time.Unix(1700000000, 0)
	pauseCases := []struct {
		until int64
		want  bool
	}{
		{0, false},
		{-1, true},
		{-999, true},
		{now.Unix() - 1, false},
		{now.Unix(), false},
		{now.Unix() + 60, true},
	}
	for _, tc := range pauseCases {
		d.AdblockDisabledUntil = tc.until
		if got := d.IsAdblockPaused(now); got != tc.want {
			t.Errorf("IsAdblockPaused(until=%d) = %v, want %v", tc.until, got, tc.want)
		}
	}
}

func TestClientDNSConfig_YAMLUnmarshalKnownKeysCloneAndASTSave(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")

	// Intentionally include missing space after colon on new knownYAMLKeys and string-encoded int64 timestamp.
	rawYAML := `subs:
  - name: "main"
    url: "https://sub.example.com/1"
dns:
  enabled: true
  engine:"singbox"
  dns_port: "5353"
  web_port: 3000
  username: "root"
  password: "TestPassword1234"
  upstreams:
    - "https://223.5.5.5/dns-query"
    - "tls://223.6.6.6:853"
    - "https://223.5.5.5/dns-query"
  upstream_mode:"parallel"
  whitelist:
    - "ok.example.com"
    - "  sub.example.com "
  rewrites:
    - domain:"nas.example.com"
      answer:"192.0.2.10"
    - domain: "*.lab.example.com"
      answer: "2001:db8::10"
  block_aaaa:true
  adblock_disabled_until:"1893456000"
  disabled_ad_rule_sets:
    - "geosite-ad2"
    - "block-builtin-pcdn"
  smartdns_filters:
    - "https://example.com/anti-ad.conf"
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.DNS.GetEngine() != constant.DNSEngineAuto {
		t.Fatalf("legacy YAML engine:singbox should normalize to auto, got %q", cfg.DNS.GetEngine())
	}
	if cfg.DNS.GetUpstreamMode() != config.DNSUpstreamModeParallel {
		t.Fatalf("UpstreamMode = %q, want parallel", cfg.DNS.GetUpstreamMode())
	}
	if !slices.Equal(cfg.DNS.Upstreams, []string{"https://223.5.5.5/dns-query", "tls://223.6.6.6:853"}) {
		t.Fatalf("Upstreams = %v", cfg.DNS.Upstreams)
	}
	if !slices.Equal(cfg.DNS.Whitelist, []string{"ok.example.com", "sub.example.com"}) {
		t.Fatalf("Whitelist = %v", cfg.DNS.Whitelist)
	}
	wantRewrites := []config.DNSRewriteRule{
		{Domain: "nas.example.com", Answer: "192.0.2.10"},
		{Domain: "*.lab.example.com", Answer: "2001:db8::10"},
	}
	if !slices.Equal(cfg.DNS.Rewrites, wantRewrites) {
		t.Fatalf("Rewrites = %+v, want %+v", cfg.DNS.Rewrites, wantRewrites)
	}
	if !cfg.DNS.BlockAAAA {
		t.Fatal("expected BlockAAAA = true")
	}
	if cfg.DNS.AdblockDisabledUntil != 1893456000 {
		t.Fatalf("AdblockDisabledUntil = %d, want 1893456000", cfg.DNS.AdblockDisabledUntil)
	}
	if !slices.Equal(cfg.DNS.DisabledAdRuleSets, []string{"geosite-ad2", "block-builtin-pcdn"}) {
		t.Fatalf("DisabledAdRuleSets = %v", cfg.DNS.DisabledAdRuleSets)
	}
	if !slices.Equal(cfg.DNS.SmartDNSFilters, []string{"https://example.com/anti-ad.conf"}) {
		t.Fatalf("SmartDNSFilters = %v", cfg.DNS.SmartDNSFilters)
	}

	// Verify Clone deep isolation on all new DNS slices
	cloned := cfg.Clone()
	cloned.DNS.Upstreams[0] = "https://1.12.12.12/dns-query"
	cloned.DNS.Whitelist[0] = "mutated.example.com"
	cloned.DNS.Rewrites[0].Answer = "198.51.100.99"
	cloned.DNS.DisabledAdRuleSets[0] = "geosite-ad1"
	cloned.DNS.SmartDNSFilters[0] = "https://mutated.example.com/f.conf"

	if cfg.DNS.Upstreams[0] != "https://223.5.5.5/dns-query" ||
		cfg.DNS.Whitelist[0] != "ok.example.com" ||
		cfg.DNS.Rewrites[0].Answer != "192.0.2.10" ||
		cfg.DNS.DisabledAdRuleSets[0] != "geosite-ad2" ||
		cfg.DNS.SmartDNSFilters[0] != "https://example.com/anti-ad.conf" {
		t.Fatalf("Clone mutated original DNS slices: %+v", cfg.DNS)
	}

	// Verify Save removes cleared optional DNS fields from YAML AST and keeps 0600 mode
	cfg.DNS.Upstreams = nil
	cfg.DNS.Whitelist = nil
	cfg.DNS.Rewrites = nil
	cfg.DNS.BlockAAAA = false
	cfg.DNS.AdblockDisabledUntil = 0
	cfg.DNS.DisabledAdRuleSets = nil
	cfg.DNS.SmartDNSFilters = nil
	cfg.DNS.Engine = ""
	cfg.DNS.UpstreamMode = ""

	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("config.Save failed: %v", err)
	}
	fi, err := os.Stat(cfgPath)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 mode after Save, got %v err=%v", fi.Mode().Perm(), err)
	}

	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("reload after Save failed: %v", err)
	}
	if reloaded.DNS.GetEngine() != constant.DNSEngineAuto ||
		reloaded.DNS.GetUpstreamMode() != config.DNSUpstreamModeFastestIP ||
		len(reloaded.DNS.Upstreams) != 0 ||
		len(reloaded.DNS.Whitelist) != 0 ||
		len(reloaded.DNS.Rewrites) != 0 ||
		reloaded.DNS.BlockAAAA ||
		reloaded.DNS.AdblockDisabledUntil != 0 ||
		len(reloaded.DNS.DisabledAdRuleSets) != 0 ||
		len(reloaded.DNS.SmartDNSFilters) != 0 {
		t.Fatalf("cleared DNS fields survived Save AST merge: %+v", reloaded.DNS)
	}

	// Verify idempotency and race safety of Clone + read helpers
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			cp := reloaded.Clone()
			cp.DNS.SetEngine(constant.DNSEngineSmartDNS)
			_ = cp.DNS.GetEngine()
			_ = cp.DNS.GetUpstreamMode()
			_ = cp.DNS.IsAdblockPaused(time.Now())
		})
	}
	wg.Wait()
}
