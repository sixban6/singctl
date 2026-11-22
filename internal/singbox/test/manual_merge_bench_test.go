// 文件职责：压测三路结构化合并（100 节点 + 60 条规则）的内存分配与吞吐基准。
package singbox_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"singctl/internal/singbox"
)

func buildLargeBenchConfigJSON(nodeCount, ruleCount int, withManualEdit bool) string {
	outbounds := make([]map[string]any, 0, nodeCount+3)
	nodeTags := make([]string, 0, nodeCount)
	for i := range nodeCount {
		tag := fmt.Sprintf("node-%03d", i)
		nodeTags = append(nodeTags, tag)
		outbounds = append(outbounds, map[string]any{
			"type":        "vless",
			"tag":         tag,
			"server":      fmt.Sprintf("edge%d.example.com", i),
			"server_port": 443,
			"uuid":        "11111111-1111-1111-1111-111111111111",
		})
	}
	outbounds = append(outbounds,
		map[string]any{"type": "selector", "tag": "Proxy", "outbounds": nodeTags, "default": nodeTags[0]},
		map[string]any{"type": "direct", "tag": "direct"},
	)
	if withManualEdit {
		outbounds = append(outbounds, map[string]any{
			"type": "socks", "tag": "custom-socks", "server": "127.0.0.1", "server_port": 1080,
		})
	}

	rules := make([]map[string]any, 0, ruleCount+2)
	rules = append(rules, map[string]any{"action": "sniff"})
	for i := range ruleCount {
		rules = append(rules, map[string]any{
			"domain_suffix": []string{fmt.Sprintf("app-%d.example.com", i)},
			"outbound":      "Proxy",
		})
	}
	if withManualEdit {
		rules = append(rules, map[string]any{
			"domain_suffix": []string{"nas.lan"},
			"outbound":      "custom-socks",
		})
	}

	doc := map[string]any{
		"dns": map[string]any{
			"servers": []map[string]any{{"tag": "dns-local", "address": "223.5.5.5"}},
			"rules":   []map[string]any{{"clash_mode": "Direct", "server": "dns-local"}},
		},
		"inbounds":  []map[string]any{{"type": "tun", "tag": "tun-in"}},
		"outbounds": outbounds,
		"route": map[string]any{
			"rule_set": []map[string]any{{"tag": "rs-cn", "type": "remote", "url": "https://example.com/cn.srs"}},
			"rules":    rules,
			"final":    "Proxy",
		},
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func BenchmarkMergeManualConfig_100Nodes60Rules(b *testing.B) {
	base := buildLargeBenchConfigJSON(100, 60, false)
	cur := buildLargeBenchConfigJSON(100, 60, true)
	fresh := buildLargeBenchConfigJSON(105, 60, false)

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, _, err := singbox.MergeManualConfig(base, cur, fresh)
		if err != nil {
			b.Fatal(err)
		}
	}
}
