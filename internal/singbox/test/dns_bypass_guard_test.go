// 文件职责：测试四层防 DNS 绕过引擎（L1~L4、App 细粒度子项、横向源 IP 豁免、白名单优先、微信互斥、旧规则迁移与并发安全）。
package singbox_test

import (
	"slices"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/sboption"
)

func baseBypassTestConfigJSON() string {
	return `{
  "dns": {
    "final": "dns_local",
    "strategy": "ipv4_only",
    "servers": [
      {"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}
    ],
    "rules": []
  },
  "route": {
    "final": "direct",
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"},
      {"action": "reject", "port": 853, "source_ip_cidr": ["192.0.2.99/32"]},
      {"action": "route", "domain_suffix": ["example.com"], "outbound": "direct"}
    ]
  }
}`
}

func TestDNSBypassGuard_DefaultFourLayersAndIPv4Decoupling(t *testing.T) {
	cfg := &config.Config{
		Gateway: config.GatewayConfig{
			WorkMode: config.WorkModeAudit,
			IPv6Mode: config.GatewayIPv6Off, // 纯 IPv4 下也必须注入 L1~L4
		},
	}

	out, changed, err := singbox.ApplyDNSBypassGuardToConfigJSON(baseBypassTestConfigJSON(), cfg)
	if err != nil {
		t.Fatalf("ApplyDNSBypassGuardToConfigJSON failed: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on first injection")
	}

	doc, err := sboption.ParseDocument([]byte(out))
	if err != nil {
		t.Fatalf("parse output failed: %v", err)
	}

	var hasL1DoT, hasL2DoHIP, hasL2DoHDom, hasL3SDKIP, hasL3SDKDom, hasL4AppDom, hasL4AppIP, keptUserRule bool
	for _, r := range doc.Route.Rules {
		if r.Action == "reject" && slices.Equal(r.Port.Slice(), []uint16{853}) && slices.Equal(r.SourceIPCIDR.Slice(), []string{"192.0.2.99/32"}) {
			keptUserRule = true
		}
		if r.Action != "reject" || r.Type != "" || !r.SourceIPCIDR.IsEmpty() {
			continue
		}
		ports := r.Port.Slice()
		if slices.Equal(ports, []uint16{853}) && r.IPCIDR.IsEmpty() && r.Domain.IsEmpty() {
			hasL1DoT = true
		}
		if slices.Equal(ports, []uint16{443, 853}) {
			if slices.Contains(r.IPCIDR.Slice(), "223.5.5.5/32") && slices.Contains(r.IPCIDR.Slice(), "1.1.1.1/32") && slices.Contains(r.IPCIDR.Slice(), "8.8.8.8/32") {
				hasL2DoHIP = true
			}
			if slices.Contains(r.Domain.Slice(), "dns.alidns.com") && slices.Contains(r.Domain.Slice(), "dns.google") && slices.Contains(r.Domain.Slice(), "cloudflare-dns.com") {
				hasL2DoHDom = true
			}
		}
		if slices.Equal(ports, []uint16{80, 443}) {
			if slices.Contains(r.IPCIDR.Slice(), "203.107.1.0/24") && slices.Contains(r.IPCIDR.Slice(), "119.29.29.29/32") && slices.Contains(r.IPCIDR.Slice(), "180.76.76.112/32") {
				hasL3SDKIP = true
			}
			if slices.Contains(r.Domain.Slice(), "httpdns.alicdn.com") &&
				slices.Contains(r.Domain.Slice(), "resolvers-cn.httpdns.aliyuncs.com") &&
				slices.Contains(r.Domain.Slice(), "httpsdns.baidu.com") &&
				slices.Contains(r.Domain.Slice(), "dig.bdurl.net") {
				hasL3SDKDom = true
			}
			if slices.Contains(r.IPCIDR.Slice(), "103.37.155.60/32") &&
				slices.Contains(r.IPCIDR.Slice(), "103.37.152.97/32") &&
				slices.Contains(r.IPCIDR.Slice(), "103.37.152.224/32") &&
				slices.Contains(r.IPCIDR.Slice(), "203.76.217.49/32") &&
				slices.Contains(r.IPCIDR.Slice(), "2405:1480:2000:3::5/128") {
				hasL4AppIP = true
				if slices.Contains(r.IPCIDR.Slice(), "101.236.69.43/32") || slices.Contains(r.IPCIDR.Slice(), "103.37.152.92/32") {
					t.Fatalf("shared Meituan business API VIPs must NOT be IP-blocked: %v", r.IPCIDR.Slice())
				}
			}
			if slices.Contains(r.Domain.Slice(), "httpdns.bilivideo.com") &&
				slices.Contains(r.Domain.Slice(), "dns.jd.com") &&
				slices.Contains(r.Domain.Slice(), "httpdns.meituan.com") &&
				slices.Contains(r.Domain.Slice(), "httpdnsvip.meituan.com") &&
				slices.Contains(r.Domain.Slice(), "httpdnsmultiapi.meituan.com") &&
				slices.Contains(r.Domain.Slice(), "httpdnsmultiapivip.meituan.com") {
				hasL4AppDom = true
				if slices.Contains(r.Domain.Slice(), "dns.weixin.qq.com") ||
					slices.Contains(r.Domain.Slice(), "dns.weixin.qq.com.cn") ||
					slices.Contains(r.Domain.Slice(), "aedns.weixin.qq.com") {
					t.Fatalf("high-risk wechat HTTPDNS must NOT be blocked by default: %v", r.Domain.Slice())
				}
			}
		}
	}

	if !hasL1DoT || !hasL2DoHIP || !hasL2DoHDom || !hasL3SDKIP || !hasL3SDKDom || !hasL4AppDom || !hasL4AppIP {
		t.Fatalf("missing default bypass guard layers: L1=%v L2IP=%v L2Dom=%v L3IP=%v L3Dom=%v L4Dom=%v L4IP=%v",
			hasL1DoT, hasL2DoHIP, hasL2DoHDom, hasL3SDKIP, hasL3SDKDom, hasL4AppDom, hasL4AppIP)
	}
	if !keptUserRule {
		t.Fatal("user-scoped port 853 rule must be preserved untouched")
	}

	// Idempotency
	out2, changed2, err := singbox.ApplyDNSBypassGuardToConfigJSON(out, cfg)
	if err != nil {
		t.Fatalf("second apply failed: %v", err)
	}
	if changed2 || out2 != out {
		t.Fatalf("expected idempotent re-apply (changed=%v)", changed2)
	}
}

func TestDNSBypassGuard_GranularLayersWeChatWhitelistAndExemptSourceIPs(t *testing.T) {
	off := false
	on := true
	cfg := &config.Config{
		DNS: config.ClientDNSConfig{
			Whitelist: []string{"httpdns.n.netease.com"},
			BypassGuard: config.DNSBypassGuardConfig{
				Enabled: &on,
				Layers: config.DNSBypassGuardLayers{
					DoTDoQ:     &on,
					PublicDoH:  &off, // L2 off
					SDKHTTPDNS: &on,
					AppHTTPDNS: &on,
				},
				AppGroups: map[string]bool{
					"bilibili": false, // disable bilibili
					"meituan":  false, // disable meituan (must drop both domains & dedicated VIP IPs)
					"wechat":   true,  // explicitly opt in to wechat
				},
				ExemptSourceIPs: []string{"192.0.2.151"},
			},
		},
	}

	out, changed, err := singbox.ApplyDNSBypassGuardToConfigJSON(baseBypassTestConfigJSON(), cfg)
	if err != nil || !changed {
		t.Fatalf("apply granular config failed: changed=%v err=%v", changed, err)
	}
	doc, err := sboption.ParseDocument([]byte(out))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	foundExemptWrappedWeChat := false
	foundL2 := false
	for _, r := range doc.Route.Rules {
		if r.Type == "logical" && r.Mode == "and" && r.Action == "reject" && len(r.Rules) == 2 {
			invSub := r.Rules[1]
			if invSub.Invert == nil || !*invSub.Invert || !slices.Equal(invSub.SourceIPCIDR.Slice(), []string{"192.0.2.151/32"}) {
				t.Fatalf("unexpected exempt logical rule tail: %+v", invSub)
			}
			head := r.Rules[0]
			if slices.Equal(head.Port.Slice(), []uint16{443, 853}) {
				foundL2 = true
			}
			if slices.Contains(head.Domain.Slice(), "httpdns.bilivideo.com") {
				t.Fatal("disabled bilibili group must not be injected")
			}
			if slices.Contains(head.Domain.Slice(), "httpdnsmultiapivip.meituan.com") || slices.Contains(head.IPCIDR.Slice(), "103.37.152.97/32") {
				t.Fatal("disabled meituan group must not inject domains or VIP IPs")
			}
			if slices.Contains(head.Domain.Slice(), "httpdns.n.netease.com") {
				t.Fatal("explicitly whitelisted domain httpdns.n.netease.com must be subtracted from reject rule")
			}
			if slices.Contains(head.Domain.Slice(), "dns.weixin.qq.com") &&
				slices.Contains(head.Domain.Slice(), "dns.weixin.qq.com.cn") &&
				slices.Contains(head.Domain.Slice(), "aedns.weixin.qq.com") {
				foundExemptWrappedWeChat = true
			}
		}
	}
	if foundL2 {
		t.Fatal("L2 public_doh was disabled and must not be injected")
	}
	if !foundExemptWrappedWeChat {
		t.Fatal("expected exempt-wrapped L4 rule containing wechat domains")
	}

	// Verify WeChat mutual exclusion with DefaultAdBlockSafeDomains
	wl := singbox.EffectiveAdBlockWhitelist(cfg)
	if slices.Contains(wl, "dns.weixin.qq.com") || slices.Contains(wl, "dns.weixin.qq.com.cn") || slices.Contains(wl, "aedns.weixin.qq.com") {
		t.Fatalf("when wechat bypass reject is explicitly enabled, EffectiveAdBlockWhitelist must exclude wechat HTTPDNS domains: %v", wl)
	}
	if !slices.Contains(wl, "wxaintpcos.wxqcloud.qq.com.cn") {
		t.Fatalf("WeChat sticker CDN domain must remain whitelisted: %v", wl)
	}

	// Disabling guard completely strips all managed bypass rules while keeping user-scoped rule
	cfgDisabled := cfg.Clone()
	cfgDisabled.DNS.BypassGuard.Enabled = &off
	stripped, changedStrip, err := singbox.ApplyDNSBypassGuardToConfigJSON(out, cfgDisabled)
	if err != nil || !changedStrip {
		t.Fatalf("disable guard failed: changed=%v err=%v", changedStrip, err)
	}
	strippedDoc, err := sboption.ParseDocument([]byte(stripped))
	if err != nil {
		t.Fatalf("parse stripped failed: %v", err)
	}
	if len(strippedDoc.Route.Rules) != 5 {
		t.Fatalf("expected original 5 route rules restored when guard disabled, got %d: %+v", len(strippedDoc.Route.Rules), strippedDoc.Route.Rules)
	}
}

func TestDNSBypassGuard_LegacyRuleCleanupAndConcurrentRace(t *testing.T) {
	// Legacy v1.14.182 config containing old 3 bypass rules from ipv6_mode.go
	legacy := `{
  "dns": {"final": "dns_local", "servers": [{"tag": "dns_local", "type": "udp", "server": "127.0.0.1", "server_port": 5353}]},
  "route": {
    "final": "direct",
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"ip_is_private": true, "outbound": "direct"},
      {"action": "reject", "port": 853},
      {"action": "reject", "ip_cidr": ["223.5.5.5/32","223.6.6.6/32","119.29.29.29/32","119.28.28.28/32","120.53.53.53/32","1.12.12.12/32","114.114.114.114/32","114.114.115.115/32","180.76.76.76/32","2400:3200::1/128","2400:3200:baba::1/128","2402:4e00::/128","2402:4e00:1::/128","240c::6666/128","240c::6644/128"], "port": [443,853]},
      {"action": "reject", "domain": ["dns.alidns.com","doh.pub","dns.pub","sm2.doh.pub","dot.pub","doh.360.cn","dns.360.cn"], "port": [443,853]},
      {"action": "route", "domain_suffix": ["example.com"], "outbound": "direct"}
    ]
  }
}`
	cfg := &config.Config{}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			out, _, err := singbox.ApplyDNSBypassGuardToConfigJSON(legacy, cfg)
			if err != nil {
				t.Errorf("concurrent apply error: %v", err)
				return
			}
			doc, err := sboption.ParseDocument([]byte(out))
			if err != nil {
				t.Errorf("parse error: %v", err)
				return
			}
			dotCount := 0
			for _, r := range doc.Route.Rules {
				if r.Action == "reject" && slices.Equal(r.Port.Slice(), []uint16{853}) {
					dotCount++
				}
			}
			if dotCount != 1 {
				t.Errorf("expected exactly 1 deduplicated port-853 rule after legacy cleanup, got %d", dotCount)
			}
		})
	}
	wg.Wait()
}
