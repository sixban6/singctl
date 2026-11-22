// 文件职责：针对三路合并执行畸形规则过滤、旧协议迁移与 Fuzz 模糊测试，确保任意输入不 panic。
package singbox_test

import (
	"encoding/json"
	"strings"
	"testing"

	"singctl/internal/singbox"
)

func TestMergeManualConfig_DropsMalformedRulesAndInvalidDNSRuleSet(t *testing.T) {
	baseJSON := `{
		"dns": {
			"servers": [{"tag": "dns-local", "address": "223.5.5.5"}],
			"rules": [{"clash_mode": "Direct", "server": "dns-local"}]
		},
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rule_set": [{"tag": "rs-keep", "type": "remote", "url": "https://example.com/a.srs"}],
			"rules": [{"action": "sniff"}]
		}
	}`
	curJSON := `{
		"dns": {
			"servers": [{"tag": "dns-local", "address": "223.5.5.5"}],
			"rules": [
				{"clash_mode": "Direct", "server": "dns-local"},
				"corrupted-string-rule",
				{"rule_set": "rs-gone", "server": "dns-local"},
				{"rule_set": "rs-keep", "server": "dns-local"}
			]
		},
		"outbounds": [{"type": "direct", "tag": "direct"}],
		"route": {
			"rule_set": [{"tag": "rs-keep", "type": "remote", "url": "https://example.com/a.srs"}],
			"rules": [
				{"action": "sniff"},
				12345,
				null,
				{"domain_suffix": ["example.com"], "outbound": "direct"}
			]
		}
	}`
	freshJSON := baseJSON

	merged, changes, err := singbox.MergeManualConfig(baseJSON, curJSON, freshJSON)
	if err != nil {
		t.Fatalf("MergeManualConfig returned error: %v", err)
	}
	if changes == 0 {
		t.Fatalf("expected valid manual additions to be merged")
	}
	if strings.Contains(merged, "corrupted-string-rule") || strings.Contains(merged, "12345") {
		t.Fatalf("merged config leaked non-object scalar rules:\n%s", merged)
	}
	if strings.Contains(merged, "rs-gone") {
		t.Fatalf("merged dns.rules leaked dangling rule_set reference 'rs-gone':\n%s", merged)
	}
	if !strings.Contains(merged, `"domain_suffix"`) || !strings.Contains(merged, `"rs-keep"`) {
		t.Fatalf("expected valid route.rule and dns.rule to be preserved:\n%s", merged)
	}
}

func TestMergeManualConfig_MigratesLegacyProtocolUDPToNetworkUDP(t *testing.T) {
	oldCfg := `{"outbounds":[{"type":"direct","tag":"#DC"}],"route":{"rules":[{"action":"reject","port":443,"protocol":"udp"},{"action":"sniff"}]}}`
	freshCfg := `{"outbounds":[{"type":"direct","tag":"#DC"}],"route":{"rules":[{"action":"reject","port":443,"network":"udp"},{"action":"sniff"}]}}`

	merged, _, err := singbox.MergeManualConfig(oldCfg, oldCfg, freshCfg)
	if err != nil {
		t.Fatalf("MergeManualConfig failed: %v", err)
	}
	if strings.Contains(merged, `"protocol": "udp"`) || strings.Contains(merged, `"protocol":"udp"`) {
		t.Fatalf("legacy protocol=udp should be migrated/stripped during merge, got:\n%s", merged)
	}
	if !strings.Contains(merged, `"network": "udp"`) {
		t.Fatalf("expected network=udp in merged config, got:\n%s", merged)
	}

	norm, err := singbox.NormalizeClientLogLevel(oldCfg)
	if err != nil {
		t.Fatalf("NormalizeClientLogLevel failed: %v", err)
	}
	if strings.Contains(norm, `"protocol":"udp"`) || !strings.Contains(norm, `"network":"udp"`) {
		t.Fatalf("expected NormalizeClientLogLevel to rewrite protocol=udp to network=udp, got:\n%s", norm)
	}
}

func FuzzMergeManualConfig(f *testing.F) {
	f.Add(
		`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"action":"sniff"}]}}`,
		`{"log":{"level":"debug"},"outbounds":[{"type":"direct","tag":"direct"},{"type":"socks","tag":"my-socks","server":"127.0.0.1","server_port":1080}],"route":{"rules":[{"action":"sniff"},{"domain":["example.com"],"outbound":"my-socks"}]}}`,
		`{"outbounds":[{"type":"direct","tag":"direct"},{"type":"selector","tag":"Proxy","outbounds":["direct"]}],"route":{"rules":[{"action":"sniff"}]}}`,
	)
	f.Add(`{}`, `{"inbounds":"not-a-slice","outbounds":[null,123,{"tag":""}]}`, `{"inbounds":[],"outbounds":[]}`)

	f.Fuzz(func(t *testing.T, baseJSON, curJSON, freshJSON string) {
		out, _, err := singbox.MergeManualConfig(baseJSON, curJSON, freshJSON)
		if err != nil {
			return
		}
		var freshObj map[string]any
		if json.Unmarshal([]byte(freshJSON), &freshObj) == nil && freshObj != nil && strings.TrimSpace(out) != "" {
			var outObj map[string]any
			if uErr := json.Unmarshal([]byte(out), &outObj); uErr != nil {
				t.Fatalf("MergeManualConfig produced invalid JSON %q: %v", out, uErr)
			}
		}
	})
}
