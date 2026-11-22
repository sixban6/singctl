// 文件职责：覆盖 sboption 子包的 Listable 双态编解码、未知字段无损 Round-Trip、空值/畸形输入防御与规则锚点定位测试。
package sboption_test

import (
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/singbox/sboption"
)

func TestListable_DualModeRoundTripAndBoundaries(t *testing.T) {
	type sampleRule struct {
		RuleSet sboption.Listable[string] `json:"rule_set,omitzero"`
		Port    sboption.Listable[uint16] `json:"port,omitzero"`
	}

	cases := []struct {
		name      string
		input     string
		wantItems []string
		wantPorts []uint16
		wantJSON  string
		wantErr   bool
	}{
		{
			name:      "scalar_string_and_scalar_port_preserved",
			input:     `{"rule_set":"geosite-hok","port":853}`,
			wantItems: []string{"geosite-hok"},
			wantPorts: []uint16{853},
			wantJSON:  `{"rule_set":"geosite-hok","port":853}`,
		},
		{
			name:      "single_element_array_stays_array",
			input:     `{"rule_set":["geosite-apple"],"port":[443]}`,
			wantItems: []string{"geosite-apple"},
			wantPorts: []uint16{443},
			wantJSON:  `{"rule_set":["geosite-apple"],"port":[443]}`,
		},
		{
			name:      "multi_element_array",
			input:     `{"rule_set":["geosite-ad1","geosite-ad2"],"port":[443,853]}`,
			wantItems: []string{"geosite-ad1", "geosite-ad2"},
			wantPorts: []uint16{443, 853},
			wantJSON:  `{"rule_set":["geosite-ad1","geosite-ad2"],"port":[443,853]}`,
		},
		{
			name:     "empty_object_omits_zero_listables",
			input:    `{}`,
			wantJSON: `{}`,
		},
		{
			name:     "null_fields_treated_as_zero",
			input:    `{"rule_set":null,"port":null}`,
			wantJSON: `{}`,
		},
		{
			name:    "invalid_port_overflow_rejected",
			input:   `{"port":70000}`,
			wantErr: true,
		},
		{
			name:    "invalid_type_rejected",
			input:   `{"rule_set":{"bad":true}}`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r sampleRule
			err := json.Unmarshal([]byte(tc.input), &r)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			if !slices.Equal(r.RuleSet.Slice(), tc.wantItems) {
				t.Fatalf("RuleSet = %v, want %v", r.RuleSet.Slice(), tc.wantItems)
			}
			if !slices.Equal(r.Port.Slice(), tc.wantPorts) {
				t.Fatalf("Port = %v, want %v", r.Port.Slice(), tc.wantPorts)
			}
			if r.RuleSet.Len() != len(tc.wantItems) || r.RuleSet.IsEmpty() != (len(tc.wantItems) == 0) {
				t.Fatalf("unexpected Len/IsEmpty on RuleSet")
			}
			cloned := r.RuleSet.Clone()
			if !slices.Equal(cloned.Slice(), r.RuleSet.Slice()) || cloned.Scalar != r.RuleSet.Scalar {
				t.Fatalf("Clone mismatch: %+v vs %+v", cloned, r.RuleSet)
			}

			out, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if string(out) != tc.wantJSON {
				t.Fatalf("marshaled JSON = %s, want %s", string(out), tc.wantJSON)
			}
		})
	}

	// Verify ListOf and ScalarOf constructors
	s := sboption.ScalarOf("stun")
	if b, err := json.Marshal(s); err != nil || string(b) != `"stun"` {
		t.Fatalf("ScalarOf marshal = %s, err=%v", string(b), err)
	}
	l := sboption.ListOf("a")
	if b, err := json.Marshal(l); err != nil || string(b) != `["a"]` {
		t.Fatalf("ListOf(single) marshal = %s, err=%v", string(b), err)
	}
	empty := sboption.ListOf[string]()
	if !empty.IsZero() {
		t.Fatal("expected empty ListOf to report IsZero() == true")
	}
}

func TestDocument_ZeroByteLossRoundTripWithUnknownFields(t *testing.T) {
	complexJSON := `{
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123
  },
  "certificate": {
    "store": "mozilla"
  },
  "log": {
    "disabled": false,
    "level": "warn",
    "timestamp": true,
    "custom_log_field": "keep-me"
  },
  "dns": {
    "final": "dns_proxy",
    "strategy": "prefer_ipv4",
    "disable_cache": false,
    "reverse_mapping": true,
    "servers": [
      {
        "tag": "dns_proxy",
        "type": "https",
        "server": "1.1.1.1",
        "detour": "#VPS",
        "headers": {"X-Custom": "1"}
      }
    ],
    "rules": [
      {
        "rule_set": "geosite-hok",
        "client_subnet": "203.0.113.0/24",
        "server": "dns_proxy",
        "custom_dns_rule_flag": 42
      }
    ]
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["198.18.0.1/30"],
      "auto_route": true
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "Proxy",
      "outbounds": ["node-vr", "#DC"],
      "interrupt_exist_connections": true
    },
    {
      "type": "vless",
      "tag": "node-vr",
      "server": "198.51.100.10",
      "server_port": 443,
      "uuid": "11111111-1111-1111-1111-111111111111",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "tls": {
        "enabled": true,
        "server_name": "example.com",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": "pub123", "short_id": "a1b2"}
      }
    },
    {
      "type": "direct",
      "tag": "#DC"
    }
  ],
  "endpoints": [
    {
      "type": "tailscale",
      "tag": "ts-ep",
      "auth_key": "test-ep-key",
      "accept_routes": true
    }
  ],
  "http_clients": [
    {
      "tag": "hc-proxy",
      "detour": "Proxy",
      "connect_timeout": "5s"
    }
  ],
  "services": [
    {
      "type": "api",
      "listen": "127.0.0.1",
      "secret": "test-sec",
      "extra_svc": true
    }
  ],
  "route": {
    "final": "Proxy",
    "auto_detect_interface": true,
    "default_domain_resolver": {"server": "dns_proxy"},
    "custom_route_attr": "preserved",
    "rule_set": [
      {
        "tag": "geosite-hok",
        "type": "remote",
        "format": "binary",
        "url": "https://example.com/hok.srs",
        "custom_rs_field": "rs-ok"
      }
    ],
    "rules": [
      {"action": "sniff", "timeout": "1s"},
      {"type": "logical", "mode": "or", "action": "hijack-dns", "rules": [{"port": 53}, {"protocol": "dns"}]},
      {"action": "route", "rule_set": "geosite-hok", "outbound": "Proxy", "inbound": ["tun-in"]}
    ]
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "test-sec",
      "access_control_allow_private_network": true
    },
    "cache_file": {
      "enabled": true,
      "store_dns": true
    },
    "v2ray_api": {"listen": "127.0.0.1:10085"}
  }
}`

	doc, err := sboption.ParseDocument([]byte(complexJSON))
	if err != nil {
		t.Fatalf("ParseDocument failed: %v", err)
	}

	doc.Log.Level = "error"
	outPretty, err := doc.MarshalPretty()
	if err != nil {
		t.Fatalf("MarshalPretty failed: %v", err)
	}

	var wantMap, gotMap map[string]any
	if err := json.Unmarshal([]byte(complexJSON), &wantMap); err != nil {
		t.Fatal(err)
	}
	wantMap["log"].(map[string]any)["level"] = "error"
	if err := json.Unmarshal([]byte(outPretty), &gotMap); err != nil {
		t.Fatalf("output invalid JSON: %v", err)
	}

	wantCanonical, _ := json.Marshal(wantMap)
	gotCanonical, _ := json.Marshal(gotMap)
	if string(wantCanonical) != string(gotCanonical) {
		t.Fatalf("lossless round-trip mismatch!\nwant: %s\ngot:  %s", string(wantCanonical), string(gotCanonical))
	}

	emptyOutDoc, err := sboption.ParseDocument([]byte(`{"outbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	compactEmptyOut, err := emptyOutDoc.MarshalCompact()
	if err != nil || compactEmptyOut != `{"outbounds":[]}` {
		t.Fatalf("expected {\"outbounds\":[]} preserved, got %q (err=%v)", compactEmptyOut, err)
	}

	noOutDoc, err := sboption.ParseDocument([]byte(`{"inbounds":[{"type":"mixed"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	compactNoOut, err := noOutDoc.MarshalCompact()
	if err != nil || strings.Contains(compactNoOut, "outbounds") {
		t.Fatalf("expected absent outbounds omitted, got %q (err=%v)", compactNoOut, err)
	}

	if _, err := sboption.ParseDocument([]byte(`{broken`)); err == nil {
		t.Fatal("expected error on broken JSON")
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			d, pErr := sboption.ParseDocument([]byte(complexJSON))
			if pErr != nil {
				t.Errorf("concurrent ParseDocument: %v", pErr)
				return
			}
			if _, mErr := d.MarshalPretty(); mErr != nil {
				t.Errorf("concurrent MarshalPretty: %v", mErr)
			}
		})
	}
	wg.Wait()
}

func TestRuleAnchors_DeterministicPredicatesAndNoLenGuessing(t *testing.T) {
	privTrue := true
	routeRules := []sboption.RouteRule{
		{Action: "sniff"},
		{Action: "hijack-dns", Port: sboption.ScalarOf[uint16](53)},
		{IPIsPrivate: &privTrue, Outbound: "#DC"},
		{Action: "route", ClashMode: "global", Outbound: "Proxy"},
		{Action: "route", RuleSet: sboption.ScalarOf("geosite-hok"), Outbound: "#Auto"},
		{Action: "reject", RuleSet: sboption.ListOf("geosite-ad1", "geosite-ad2")},
		{Action: "route", RuleSet: sboption.ListOf("geosite-cn"), Outbound: "#DC"},
		{Action: "route", RuleSet: sboption.ListOf("geoip-cn", "geoip-private"), Outbound: "#DC"},
		{Action: "route", Network: sboption.ScalarOf("udp"), PortRange: sboption.ListOf("1024:65535"), Outbound: "#DC"},
	}

	if !sboption.IsSniffRouteRule(routeRules[0]) || !sboption.IsHijackDNSRouteRule(routeRules[1]) || !sboption.IsPrivateIPRouteRule(routeRules[2]) {
		t.Fatal("bootstrap predicates failed")
	}
	if !sboption.IsAdBlockRouteRule(routeRules[5]) || !sboption.IsRegionSplitRouteRule(routeRules[6]) {
		t.Fatal("adblock / region split predicates failed")
	}

	if got := sboption.DNSBypassRejectInsertIndex(routeRules); got != 3 {
		t.Fatalf("DNSBypassRejectInsertIndex = %d, want 3 (right after ip_is_private)", got)
	}
	if got := sboption.BlockRouteInsertIndex(routeRules); got != 4 {
		t.Fatalf("BlockRouteInsertIndex = %d, want 4 (right after clash_mode)", got)
	}
	if got := sboption.CustomRouteInsertIndex(routeRules); got != 5 {
		t.Fatalf("CustomRouteInsertIndex = %d, want 5 (right before geosite-ad1)", got)
	}
	if got := sboption.TrafficRouteInsertIndex(routeRules); got != 6 {
		t.Fatalf("TrafficRouteInsertIndex = %d, want 6 (right after geosite-ad1/ad2)", got)
	}
	isDirect := func(out string) bool { return out == "#DC" || out == "direct" }
	if got := sboption.STUNRejectInsertIndex(routeRules, isDirect); got != 8 {
		t.Fatalf("STUNRejectInsertIndex = %d, want 8 (right before catch-all UDP 1024:65535)", got)
	}

	managedSTUN := sboption.RouteRule{Action: "reject", Protocol: sboption.ScalarOf("stun")}
	userScopedSTUN := sboption.RouteRule{Action: "reject", Protocol: sboption.ScalarOf("stun"), SourceIPCIDR: sboption.ListOf("192.0.2.10/32")}
	if !sboption.IsManagedSTUNRejectRouteRule(managedSTUN) {
		t.Fatal("expected pure stun reject to be recognized as managed")
	}
	if sboption.IsManagedSTUNRejectRouteRule(userScopedSTUN) {
		t.Fatal("must NOT strip user-scoped stun reject with source_ip_cidr")
	}

	dohCIDRs := []string{"223.5.5.5/32"}
	dohDomains := []string{"dns.alidns.com"}
	managedDoT := sboption.RouteRule{Action: "reject", Port: sboption.ScalarOf[uint16](853)}
	userScopedDoT := sboption.RouteRule{Action: "reject", Port: sboption.ScalarOf[uint16](853), SourceIPCIDR: sboption.ListOf("192.0.2.10/32")}
	managedDoHIP := sboption.RouteRule{Action: "reject", IPCIDR: sboption.ListOf("223.5.5.5/32"), Port: sboption.ListOf[uint16](443, 853)}
	if !sboption.IsManagedDNSBypassRejectRouteRule(managedDoT, dohCIDRs, dohDomains) || !sboption.IsManagedDNSBypassRejectRouteRule(managedDoHIP, dohCIDRs, dohDomains) {
		t.Fatal("expected managed DoT/DoH rules recognized")
	}
	if sboption.IsManagedDNSBypassRejectRouteRule(userScopedDoT, dohCIDRs, dohDomains) {
		t.Fatal("must NOT strip user-scoped port 853 rule with source_ip_cidr")
	}

	logicalIPv6 := sboption.RouteRule{
		Type:   "logical",
		Mode:   "and",
		Action: "reject",
		Rules: []sboption.RouteRule{
			{DomainSuffix: sboption.ListOf("openai.com")},
			{IPCIDR: sboption.ListOf("::/0")},
		},
	}
	if !sboption.IsManagedIPv6RejectRouteRule(logicalIPv6) {
		t.Fatal("expected logical AND ::/0 reject rule recognized")
	}

	dnsRules := []sboption.DNSRule{
		{ClashMode: "Direct", Server: "dns_local"},
		{Server: "dns_tailscale", DomainSuffix: sboption.ListOf("ts.net")},
		{DomainSuffix: sboption.ListOf("openai.com"), Server: "dns_proxy"},
		{RuleSet: sboption.ScalarOf("geosite-cn"), Server: "dns_local"},
	}
	if got := sboption.CustomDNSInsertIndex(dnsRules); got != 2 {
		t.Fatalf("CustomDNSInsertIndex = %d, want 2", got)
	}
	if got := sboption.TrafficDNSInsertIndex(dnsRules); got != 3 {
		t.Fatalf("TrafficDNSInsertIndex = %d, want 3", got)
	}
	if got := sboption.BeforeGeositeCNDNSInsertIndex(dnsRules); got != 3 {
		t.Fatalf("BeforeGeositeCNDNSInsertIndex = %d, want 3", got)
	}
}

func TestDNSAndRouteRule_AnswerAndInvertRoundTripClone(t *testing.T) {
	rawDNS := `{"domain":["nas.example.com"],"action":"predefined","rcode":"NOERROR","answer":["nas.example.com. 60 IN A 192.0.2.10"],"invert":true}`
	var dr sboption.DNSRule
	if err := json.Unmarshal([]byte(rawDNS), &dr); err != nil {
		t.Fatalf("unmarshal DNSRule: %v", err)
	}
	if !slices.Equal(dr.Answer.Slice(), []string{"nas.example.com. 60 IN A 192.0.2.10"}) {
		t.Fatalf("DNSRule.Answer = %v", dr.Answer.Slice())
	}
	if dr.Invert == nil || !*dr.Invert {
		t.Fatalf("DNSRule.Invert = %v, want true", dr.Invert)
	}
	if len(dr.Extra) != 0 {
		t.Fatalf("expected answer and invert to be known keys, got Extra=%v", dr.Extra)
	}

	drClone := dr.Clone()
	drClone.Answer.Items[0] = "mutated"
	*drClone.Invert = false
	if dr.Answer.Items[0] != "nas.example.com. 60 IN A 192.0.2.10" || !*dr.Invert {
		t.Fatalf("DNSRule.Clone mutated original: %+v", dr)
	}

	outDNS, err := json.Marshal(dr)
	if err != nil {
		t.Fatalf("marshal DNSRule: %v", err)
	}
	if !strings.Contains(string(outDNS), `"answer":["nas.example.com. 60 IN A 192.0.2.10"]`) ||
		!strings.Contains(string(outDNS), `"invert":true`) {
		t.Fatalf("unexpected marshaled DNSRule: %s", string(outDNS))
	}

	// Scalar answer round-trip
	var scalarDR sboption.DNSRule
	if err := json.Unmarshal([]byte(`{"action":"predefined","rcode":"NOERROR","answer":"nas.example.com. 60 IN A 192.0.2.10"}`), &scalarDR); err != nil {
		t.Fatalf("unmarshal scalar answer: %v", err)
	}
	if b, err := json.Marshal(scalarDR); err != nil || !strings.Contains(string(b), `"answer":"nas.example.com. 60 IN A 192.0.2.10"`) {
		t.Fatalf("expected scalar answer preserved, got %s err=%v", string(b), err)
	}

	// RouteRule.Invert round-trip and Clone isolation
	rawRoute := `{"type":"logical","mode":"and","rules":[{"rule_set":["geosite-ad1"]},{"domain_suffix":["ok.example.com"],"invert":true}],"action":"reject"}`
	var rr sboption.RouteRule
	if err := json.Unmarshal([]byte(rawRoute), &rr); err != nil {
		t.Fatalf("unmarshal RouteRule: %v", err)
	}
	if len(rr.Rules) != 2 || rr.Rules[1].Invert == nil || !*rr.Rules[1].Invert || len(rr.Rules[1].Extra) != 0 {
		t.Fatalf("unexpected logical RouteRule with invert: %+v", rr)
	}
	rrClone := rr.Clone()
	*rrClone.Rules[1].Invert = false
	if !*rr.Rules[1].Invert {
		t.Fatal("RouteRule.Clone mutated original Invert pointer")
	}
	if !sboption.IsAdBlockRouteRule(rr) {
		t.Fatal("expected wrapped logical AND geosite-ad1 reject rule recognized by IsAdBlockRouteRule")
	}
}
