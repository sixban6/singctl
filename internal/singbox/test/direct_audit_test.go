// 文件职责：测试零订阅「审计模式」(WorkModeAudit) 的极简 sing-box 直连透明审计配置编译、边界校验与并发安全。
package singbox_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestConfigGenerator_DirectAuditMode_ZeroSubs(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			Mode:     "main",
			WorkMode: config.WorkModeAudit,
			IPv6Mode: config.GatewayIPv6Off,
		},
		DNS: config.ClientDNSConfig{
			Engine:  "smartdns",
			DNSPort: 5353,
		},
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{
				{Target: "tracker.example.com", Reason: "privacy"},
				{Target: "203.0.113.99", SourceIP: "192.168.1.50", Reason: "iot block"},
			},
		},
	}

	gen := singbox.NewOfflineConfigGenerator(cfg)
	gen.SetLocalDNSProbe(func(_ string, _ int) bool { return true })

	raw, err := gen.GenerateForPlatform("linux")
	if err != nil {
		t.Fatalf("GenerateForPlatform(linux) in direct-audit mode failed: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("generated direct-audit config is not valid JSON: %v\n%s", err, raw)
	}

	// Must have tproxy inbound on :7895 and loopback Clash API.
	if !strings.Contains(raw, `"type": "tproxy"`) || !strings.Contains(raw, `"listen_port": 7895`) {
		t.Fatalf("expected tproxy inbound :7895 in direct-audit config:\n%s", raw)
	}
	if !strings.Contains(raw, `"127.0.0.1:9090"`) {
		t.Fatalf("expected hardened loopback Clash API 127.0.0.1:9090:\n%s", raw)
	}
	if !strings.Contains(raw, `"action": "sniff"`) || !strings.Contains(raw, `"action": "hijack-dns"`) {
		t.Fatalf("expected sniff + hijack-dns rules in direct-audit config:\n%s", raw)
	}
	// Local DNS wired to SmartDNS 127.0.0.1:5353.
	if !strings.Contains(raw, `"127.0.0.1"`) || !strings.Contains(raw, `5353`) {
		t.Fatalf("expected dns_local wired to 127.0.0.1:5353:\n%s", raw)
	}
	// Custom block rules must be compiled even without subscriptions.
	if !strings.Contains(raw, `"tracker.example.com"`) || !strings.Contains(raw, `"203.0.113.99/32"`) {
		t.Fatalf("expected custom block rules injected in direct-audit mode:\n%s", raw)
	}
	// Must contain ONLY direct outbound (no proxy/selector/urltest outbounds).
	outbounds, _ := doc["outbounds"].([]any)
	if len(outbounds) != 1 {
		t.Fatalf("expected exactly 1 direct outbound in direct-audit mode, got %d: %v", len(outbounds), outbounds)
	}

	t.Run("ios_still_requires_subscriptions", func(t *testing.T) {
		if _, err := gen.GenerateForPlatform(singbox.PlatformIOS); err == nil {
			t.Fatal("expected GenerateForPlatform(ios) to fail when subs is empty")
		}
	})

	t.Run("legacy_proxy_mode_without_subs_auto_falls_back_to_audit", func(t *testing.T) {
		proxyCfg := &config.Config{
			Gateway: config.GatewayConfig{WorkMode: config.WorkModeProxy},
		}
		g := singbox.NewOfflineConfigGenerator(proxyCfg)
		g.SetLocalDNSProbe(func(_ string, _ int) bool { return false })
		rawOut, gErr := g.GenerateForPlatform("linux")
		if gErr != nil {
			t.Fatalf("expected legacy work_mode=proxy without subs to auto-fall back to direct-audit, got err: %v", gErr)
		}
		var outDoc map[string]any
		if uErr := json.Unmarshal([]byte(rawOut), &outDoc); uErr != nil {
			t.Fatalf("invalid generated JSON: %v", uErr)
		}
		outs, _ := outDoc["outbounds"].([]any)
		if len(outs) != 1 {
			t.Fatalf("expected 1 direct outbound in auto audit fallback, got %d: %v", len(outs), outs)
		}
	})

	t.Run("delegated_mode_without_subs_rejected", func(t *testing.T) {
		delegatedCfg := &config.Config{
			Gateway: config.GatewayConfig{
				Mode:         "main",
				SideRouterIP: "192.168.55.88",
			},
		}
		if _, gErr := singbox.NewOfflineConfigGenerator(delegatedCfg).GenerateForPlatform("linux"); gErr == nil {
			t.Fatal("expected delegated main router without subs to skip/reject sing-box config generation")
		}
	})

	t.Run("concurrent_generation_race_free", func(t *testing.T) {
		var wg sync.WaitGroup
		for range 6 {
			wg.Go(func() {
				g := singbox.NewOfflineConfigGenerator(cfg.Clone())
				g.SetLocalDNSProbe(func(_ string, _ int) bool { return false })
				if out, gErr := g.GenerateForPlatform("linux"); gErr != nil || out == "" {
					t.Errorf("concurrent direct-audit generate failed: %v", gErr)
				}
			})
		}
		wg.Wait()
	})
}
