package singbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
)

func sampleConfigWithLeafNodes() string {
	doc := map[string]any{
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"},
				map[string]any{"tag": "dns_proxy", "type": "https", "server": "8.8.8.8", "detour": "#VPS"},
			},
			"rules": []any{},
			"final": "dns_proxy",
		},
		"outbounds": []any{
			map[string]any{"tag": "Proxy", "type": "selector", "outbounds": []any{"#VPS", "#Auto", "#Nodes", "#DC"}, "interrupt_exist_connections": true},
			map[string]any{"tag": "AI", "type": "selector", "outbounds": []any{"#VPS", "#Nodes", "#Auto"}, "interrupt_exist_connections": true},
			map[string]any{"tag": "#VPS", "type": "selector", "outbounds": []any{"sec_los_hy2", "sec_sg_vless"}},
			map[string]any{"tag": "#Auto", "type": "urltest", "outbounds": []any{"sec_los_hy2", "sec_sg_vless", "香港-IEPL-01", "日本-家宽-01"}, "url": defaultURLTestURL, "interval": "3m", "tolerance": 80},
			map[string]any{"tag": "#Nodes", "type": "selector", "outbounds": []any{"sec_los_hy2", "sec_sg_vless", "香港-IEPL-01", "日本-家宽-01", "香港-3x倍率"}},
			map[string]any{"tag": "sec_los_hy2", "type": "hysteria2", "server": "198.51.100.10", "server_port": 443},
			map[string]any{"tag": "sec_sg_vless", "type": "vless", "server": "198.51.100.20", "server_port": 443},
			map[string]any{"tag": "香港-IEPL-01", "type": "shadowsocks", "server": "203.0.113.10", "server_port": 8388},
			map[string]any{"tag": "日本-家宽-01", "type": "trojan", "server": "203.0.113.20", "server_port": 443},
			map[string]any{"tag": "香港-3x倍率", "type": "vmess", "server": "203.0.113.30", "server_port": 443},
			map[string]any{"tag": "剩余流量: 500GB", "type": "vmess", "server": "203.0.113.31", "server_port": 443},
			map[string]any{"tag": "#DC", "type": "direct"},
		},
		"route": map[string]any{
			"final": "Proxy",
			"rules": []any{
				map[string]any{"action": "reject", "network": "udp", "port": 443},
				map[string]any{"action": "route", "rule_set": "geosite-chat", "outbound": "AI"},
			},
		},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	return string(b)
}

func TestGroupsCompiler_MacrosForwardRefFallbackAndLiveCleanup(t *testing.T) {
	yamlText := `
version: 1
mode: merge
groups:
  # 故意把 Streaming 放在 #HK / #JP 之前，验证前向引用支持 + attach_to: [] 独立不注入 Proxy
  - name: "Streaming"
    type: selector
    use: ["#JP", "#HK", "#VPS"]
    default: "#JP"
    attach_to: []
    failover: true

  - name: "#HK"
    type: urltest
    match: "@hk"
    exclude: ["@high_rate"]
    tolerance: 45

  - name: "#JP"
    type: selector
    match: ["@jp", "@home"]

  # 按订阅源 + 协议过滤
  - name: "#Self-Hy2"
    type: selector
    from_sub: ["self"]
    protocol: ["hy2"]

  # 零节点命中防断网自动兜底测试（当前没有韩国节点）
  - name: "#KR"
    type: urltest
    match: ["@kr"]
`
	gc, err := config.ParseGroupsYAML([]byte(yamlText))
	if err != nil {
		t.Fatalf("ParseGroupsYAML failed: %v", err)
	}

	subOrigins := map[string][]string{
		"sec_los_hy2":  {"self"},
		"sec_sg_vless": {"self"},
		"香港-IEPL-01":   {"airport"},
		"日本-家宽-01":     {"airport"},
		"香港-3x倍率":      {"airport"},
	}

	compiled, report, err := CompileGroupsIntoConfigJSON(
		sampleConfigWithLeafNodes(),
		gc,
		subOrigins,
		[]string{"self", "airport"},
	)
	if err != nil {
		t.Fatalf("CompileGroupsIntoConfigJSON failed: %v", err)
	}

	findGroup := func(rep *GroupsPreviewReport, name string) *CompiledGroupPreview {
		for i := range rep.Groups {
			if rep.Groups[i].Name == name {
				return &rep.Groups[i]
			}
		}
		return nil
	}

	hk := findGroup(report, "#HK")
	if hk == nil || !slices.Equal(hk.Members, []string{"香港-IEPL-01"}) {
		t.Fatalf("expected #HK to keep 香港-IEPL-01 and exclude 香港-3x倍率, got %+v", hk)
	}

	selfHy2 := findGroup(report, "#Self-Hy2")
	if selfHy2 == nil || !slices.Equal(selfHy2.Members, []string{"sec_los_hy2"}) {
		t.Fatalf("expected #Self-Hy2 to match only sec_los_hy2, got %+v", selfHy2)
	}

	kr := findGroup(report, "#KR")
	if kr == nil || !kr.FallbackUsed || kr.FallbackTag != "#Auto" || !slices.Equal(kr.Members, []string{"#Auto"}) {
		t.Fatalf("expected #KR zero-match group to fallback safely to #Auto, got %+v", kr)
	}

	streaming := findGroup(report, "Streaming")
	if streaming == nil || streaming.Default != "#JP" || !streaming.Failover {
		t.Fatalf("expected Streaming forward-ref group with default=#JP and failover=true, got %+v", streaming)
	}

	proxy := findGroup(report, "Proxy")
	if proxy == nil {
		t.Fatal("missing Proxy group")
	}
	if slices.Contains(proxy.Members, "Streaming") {
		t.Fatalf("Streaming has attach_to: [], must NOT be injected into Proxy: %v", proxy.Members)
	}
	for _, mustHave := range []string{"#HK", "#JP", "#Self-Hy2", "#KR"} {
		if !slices.Contains(proxy.Members, mustHave) {
			t.Fatalf("expected Proxy to auto-attach %s, got %v", mustHave, proxy.Members)
		}
	}

	// 验证与智能分流开关中心联动：Streaming 和 #JP 自动出现在可选策略组中
	routingGroups, _ := InspectClientRoutingOutbounds(compiled)
	var rgTags []string
	for _, g := range routingGroups {
		rgTags = append(rgTags, g.Tag)
	}
	if !slices.Contains(rgTags, "Streaming") || !slices.Contains(rgTags, "#HK") {
		t.Fatalf("expected TrafficRouting to discover new groups, got %v", rgTags)
	}

	// 验证热更新删除分组时不残留旧自定义分组
	smallerGC, err := config.ParseGroupsYAML([]byte("version: 1\nmode: merge\ngroups:\n  - name: \"#JP\"\n    match: \"@jp\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	recompiled, rep2, err := RecompileLiveConfigWithGroups(compiled, &config.Config{}, smallerGC, "")
	if err != nil {
		t.Fatalf("RecompileLiveConfigWithGroups failed: %v", err)
	}
	if findGroup(rep2, "#HK") != nil || findGroup(rep2, "Streaming") != nil {
		t.Fatalf("expected removed groups #HK and Streaming to be cleaned up on recompile")
	}
	proxy2 := findGroup(rep2, "Proxy")
	if slices.Contains(proxy2.Members, "#HK") || !slices.Contains(proxy2.Members, "#JP") {
		t.Fatalf("expected Proxy to drop #HK and retain #JP, got %v", proxy2.Members)
	}
	if strings.Contains(recompiled, `"#HK"`) {
		t.Fatalf("expected recompiled JSON to have zero #HK remnants")
	}
}

func TestGroupsCompiler_CycleDetectionAndReplaceMode(t *testing.T) {
	cycleGC, err := config.ParseGroupsYAML([]byte(`
version: 1
mode: merge
groups:
  - name: "GroupA"
    use: ["GroupB"]
  - name: "GroupB"
    use: ["GroupA"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CompileGroupsIntoConfigJSON(sampleConfigWithLeafNodes(), cycleGC, nil, nil); err == nil || !strings.Contains(err.Error(), "循环依赖") {
		t.Fatalf("expected cycle detection error, got %v", err)
	}

	// Replace 模式删除了内置 AI 与 #VPS，编译器应自动修复悬空的 route / dns detour 引用
	replaceGC, err := config.ParseGroupsYAML([]byte(`
version: 1
mode: replace
groups:
  - name: "MainPool"
    type: urltest
    match: ["@self", "@hk", "@jp"]
`))
	if err != nil {
		t.Fatal(err)
	}
	replacedJSON, rep, err := CompileGroupsIntoConfigJSON(sampleConfigWithLeafNodes(), replaceGC, nil, nil)
	if err != nil {
		t.Fatalf("replace mode failed: %v", err)
	}
	if len(rep.Groups) != 1 || rep.Groups[0].Name != "MainPool" {
		t.Fatalf("expected exactly 1 group MainPool in replace mode, got %+v", rep.Groups)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(replacedJSON), &root); err != nil {
		t.Fatal(err)
	}
	routeMap := root["route"].(map[string]any)
	if routeMap["final"] != "MainPool" {
		t.Fatalf("expected route.final healed to MainPool, got %v", routeMap["final"])
	}
}

func TestGroupsFile_PermissionsAndEffectiveFailover(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: main\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	gPath := cfg.GroupsPath()
	if _, err := config.SaveGroupsFile(gPath, []byte("version: 1\ngroups:\n  - name: \"Streaming\"\n    type: selector\n    match: \"@jp\"\n    failover: true\n")); err != nil {
		t.Fatalf("SaveGroupsFile failed: %v", err)
	}
	st, err := os.Stat(gPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 on groups.yaml, got %v (err=%v)", st, err)
	}
	fo := cfg.EffectiveFailoverConfig()
	if !slices.Contains(fo.Groups, "Streaming") {
		t.Fatalf("expected EffectiveFailoverConfig to include Streaming, got %v", fo.Groups)
	}

	// 验证紧凑带数字/下划线代号 (HK01 / sec_sg1_hy2 / sec_jp1_vw) 精准匹配且不误伤 Plus-Node
	usRe, err := config.CompileGroupMatcher([]string{"@us"})
	if err != nil {
		t.Fatal(err)
	}
	if !usRe.MatchString("sec_los_hy2") || !usRe.MatchString("US01-West") || usRe.MatchString("HK-Plus-Node") {
		t.Fatalf("unexpected @us macro boundary behavior")
	}
	sgRe, _ := config.CompileGroupMatcher([]string{"@sg"})
	if !sgRe.MatchString("sec_sg1_hy2") || !sgRe.MatchString("SG02") {
		t.Fatalf("expected @sg to match sec_sg1_hy2 and SG02")
	}
}
