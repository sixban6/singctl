// 文件职责：验证局域网指定设备强制 Direct (#DC + dns_local) 双层规则在 sing-box 编译流水线与原地热同步中的锚点位置与幂等替换。
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

func TestDirectDevices_SyncAndCompilePipeline(t *testing.T) {
	baseJSON := `{
		"outbounds": [
			{"tag": "Proxy", "type": "selector", "outbounds": ["node-a"]},
			{"tag": "node-a", "type": "vless", "server": "198.51.100.10"},
			{"tag": "#DC", "type": "direct"}
		],
		"dns": {
			"servers": [
				{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"},
				{"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8"}
			],
			"rules": [
				{"clash_mode": "Direct", "server": "dns_local"},
				{"domain_suffix": ["tracker.example.com"], "action": "reject"},
				{"rule_set": ["geosite-cn"], "server": "dns_local"},
				{"rule_set": ["geosite-geolocation-!cn"], "server": "dns_proxy"}
			]
		},
		"route": {
			"rules": [
				{"action": "sniff"},
				{"protocol": "dns", "action": "hijack-dns"},
				{"ip_is_private": true, "outbound": "#DC"},
				{"domain_suffix": ["tracker.example.com"], "action": "reject"},
				{"rule_set": ["geosite-ad1"], "action": "reject"},
				{"rule_set": ["geosite-cn"], "outbound": "#DC"},
				{"rule_set": ["geosite-geolocation-!cn"], "outbound": "Proxy"}
			]
		}
	}`

	t.Run("sync_direct_devices_anchors_and_idempotent_update_and_clear", func(t *testing.T) {
		out1, err := singbox.SyncDirectDevicesInConfigJSON(baseJSON, []string{"192.168.1.50", "192.168.1.60", "192.168.1.50/32"})
		if err != nil {
			t.Fatalf("SyncDirectDevicesInConfigJSON add failed: %v", err)
		}
		doc1, err := sboption.ParseDocument([]byte(out1))
		if err != nil {
			t.Fatal(err)
		}

		// Verify route rule inserted after reject rules and before geosite-cn
		routeIdx := slices.IndexFunc(doc1.Route.Rules, func(r sboption.RouteRule) bool {
			return r.Outbound == "#DC" && len(r.SourceIPCIDR.Slice()) == 2
		})
		if routeIdx < 0 {
			t.Fatalf("expected managed direct device route rule in:\n%s", out1)
		}
		adIdx := slices.IndexFunc(doc1.Route.Rules, func(r sboption.RouteRule) bool {
			return r.Action == "reject" && slices.Contains(r.RuleSet.Slice(), "geosite-ad1")
		})
		cnIdx := slices.IndexFunc(doc1.Route.Rules, func(r sboption.RouteRule) bool {
			return slices.Contains(r.RuleSet.Slice(), "geosite-cn")
		})
		if !(adIdx >= 0 && routeIdx > adIdx && routeIdx < cnIdx) {
			t.Fatalf("expected direct device route rule strictly after adblock (%d) and before geosite-cn (%d), got %d", adIdx, cnIdx, routeIdx)
		}
		if gotCIDRs := doc1.Route.Rules[routeIdx].SourceIPCIDR.Slice(); !slices.Equal(gotCIDRs, []string{"192.168.1.50/32", "192.168.1.60/32"}) {
			t.Fatalf("unexpected route source_ip_cidr: %v", gotCIDRs)
		}

		// Verify DNS rule inserted after reject and before geosite-cn/dns_proxy
		dnsIdx := slices.IndexFunc(doc1.DNS.Rules, func(r sboption.DNSRule) bool {
			return r.Server == "dns_local" && len(r.SourceIPCIDR.Slice()) == 2
		})
		dnsCNIdx := slices.IndexFunc(doc1.DNS.Rules, func(r sboption.DNSRule) bool {
			return slices.Contains(r.RuleSet.Slice(), "geosite-cn")
		})
		if dnsIdx < 0 || !(dnsIdx < dnsCNIdx) {
			t.Fatalf("expected direct device DNS rule before geosite-cn (%d), got %d\n%s", dnsCNIdx, dnsIdx, out1)
		}

		// Update list -> replace cleanly with 1 rule
		out2, err := singbox.SyncDirectDevicesInConfigJSON(out1, []string{"192.168.1.60"})
		if err != nil {
			t.Fatalf("SyncDirectDevicesInConfigJSON update failed: %v", err)
		}
		doc2, err := sboption.ParseDocument([]byte(out2))
		if err != nil {
			t.Fatal(err)
		}
		countRoute := 0
		for _, r := range doc2.Route.Rules {
			if len(r.SourceIPCIDR.Slice()) > 0 && r.Outbound == "#DC" {
				countRoute++
				if !slices.Equal(r.SourceIPCIDR.Slice(), []string{"192.168.1.60/32"}) {
					t.Fatalf("expected updated source_ip_cidr [192.168.1.60/32], got %v", r.SourceIPCIDR.Slice())
				}
			}
		}
		if countRoute != 1 {
			t.Fatalf("expected exactly 1 managed route rule after update, got %d", countRoute)
		}

		// Clear list -> remove completely
		out3, err := singbox.SyncDirectDevicesInConfigJSON(out2, nil)
		if err != nil {
			t.Fatalf("SyncDirectDevicesInConfigJSON clear failed: %v", err)
		}
		if strings.Contains(out3, "192.168.1.") {
			t.Fatalf("expected direct device rules completely removed, got:\n%s", out3)
		}
	})

	t.Run("detects_direct_tag_fallback_when_hash_dc_absent", func(t *testing.T) {
		auditJSON := `{
			"outbounds": [{"tag": "direct", "type": "direct"}],
			"dns": {"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}], "rules": []},
			"route": {"rules": [{"action": "sniff"}]}
		}`
		out, err := singbox.SyncDirectDevicesInConfigJSON(auditJSON, []string{"192.168.1.77"})
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatal(err)
		}
		rules := parsed["route"].(map[string]any)["rules"].([]any)
		foundDirect := false
		for _, item := range rules {
			m := item.(map[string]any)
			if m["outbound"] == "direct" {
				foundDirect = true
			}
		}
		if !foundDirect {
			t.Fatalf("expected outbound tag fallback to 'direct', got:\n%s", out)
		}
	})

	t.Run("compile_pipeline_applies_on_linux_and_skips_ios", func(t *testing.T) {
		cfg := &config.Config{
			Subs: []config.Subscription{{Name: "main", URL: "https://sub.example.com/1"}},
			Audit: config.AuditConfig{
				DirectDevices: []string{"192.168.1.50"},
			},
		}
		gen := singbox.NewOfflineConfigGenerator(cfg)
		linuxOut, err := gen.RunCompilePipeline(baseJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline(linux) failed: %v", err)
		}
		if !strings.Contains(linuxOut, "192.168.1.50/32") {
			t.Fatalf("expected 192.168.1.50/32 injected in linux pipeline output")
		}

		iosOut, err := gen.RunCompilePipeline(baseJSON, singbox.PlatformIOS)
		if err != nil {
			t.Fatalf("RunCompilePipeline(ios) failed: %v", err)
		}
		if strings.Contains(iosOut, "192.168.1.50") {
			t.Fatalf("expected iOS pipeline not to inject LAN router source_ip_cidr")
		}
	})
}
