// 文件职责：全覆盖验证策略组编译器（CompileGroupsIntoConfigJSON）的前向引用、兜底自愈、环路检测、悬空引用修复与并发安全。
package singbox_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
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
			map[string]any{"tag": "#Auto", "type": "urltest", "outbounds": []any{"sec_los_hy2", "sec_sg_vless", "香港-IEPL-01", "日本-家宽-01"}, "url": singbox.DefaultURLTestURL, "interval": "3m", "tolerance": 80},
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

  - name: "#Self-Hy2"
    type: selector
    from_sub: ["self"]
    protocol: ["hy2"]

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

	compiled, report, err := singbox.CompileGroupsIntoConfigJSON(
		sampleConfigWithLeafNodes(),
		gc,
		subOrigins,
		[]string{"self", "airport"},
	)
	if err != nil {
		t.Fatalf("CompileGroupsIntoConfigJSON failed: %v", err)
	}

	findGroup := func(rep *singbox.GroupsPreviewReport, name string) *singbox.CompiledGroupPreview {
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

	routingGroups, _ := singbox.InspectClientRoutingOutbounds(compiled)
	var rgTags []string
	for _, g := range routingGroups {
		rgTags = append(rgTags, g.Tag)
	}
	if !slices.Contains(rgTags, "Streaming") || !slices.Contains(rgTags, "#HK") {
		t.Fatalf("expected TrafficRouting to discover new groups, got %v", rgTags)
	}

	smallerGC, err := config.ParseGroupsYAML([]byte("version: 1\nmode: merge\ngroups:\n  - name: \"#JP\"\n    match: \"@jp\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	recompiled, rep2, err := singbox.RecompileLiveConfigWithGroups(compiled, &config.Config{}, smallerGC, "")
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

func TestGroupsCompiler_CycleDetectionReplaceAndEdgeCases(t *testing.T) {
	if _, _, err := singbox.CompileGroupsIntoConfigJSON("{broken", nil, nil, nil); err == nil {
		t.Fatal("expected error on malformed JSON")
	}

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
	if _, _, err := singbox.CompileGroupsIntoConfigJSON(sampleConfigWithLeafNodes(), cycleGC, nil, nil); err == nil || !strings.Contains(err.Error(), "循环依赖") {
		t.Fatalf("expected cycle detection error, got %v", err)
	}

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
	replacedJSON, rep, err := singbox.CompileGroupsIntoConfigJSON(sampleConfigWithLeafNodes(), replaceGC, nil, nil)
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
	if rep.DefaultOutbound != "MainPool" || rep.DNSDetour != "MainPool" {
		t.Fatalf("expected DefaultOutbound=MainPool and DNSDetour=MainPool, got %+v", rep)
	}

	orderedReplaceGC, err := config.ParseGroupsYAML([]byte(`
version: 1
mode: replace
groups:
  - name: "#Main"
    type: urltest
    match: ["@self", "@hk"]
  - name: "Streaming"
    type: selector
    match: ["@jp"]
`))
	if err != nil {
		t.Fatal(err)
	}
	_, ordRep, err := singbox.CompileGroupsIntoConfigJSON(sampleConfigWithLeafNodes(), orderedReplaceGC, nil, nil)
	if err != nil {
		t.Fatalf("ordered replace mode failed: %v", err)
	}
	if len(ordRep.Groups) != 2 || ordRep.Groups[0].Name != "#Main" {
		t.Fatalf("expected replace mode to preserve #Main first order, got %+v", ordRep.Groups)
	}
	if ordRep.DefaultOutbound != "#Main" || ordRep.DNSDetour != "#Main" {
		t.Fatalf("expected DefaultOutbound=#Main and DNSDetour=#Main, got %+v", ordRep)
	}

	// Nil / empty GroupsConfig heals dangling refs when present and preserves untouched JSON when clean
	cleanRaw := sampleConfigWithLeafNodes()
	unchangedJSON, emptyRep, err := singbox.CompileGroupsIntoConfigJSON(cleanRaw, &config.GroupsConfig{Version: 1, Mode: config.GroupsModeMerge}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unchangedJSON != cleanRaw {
		t.Fatal("expected clean empty GroupsConfig to return exact input rawJSON untouched")
	}
	if emptyRep.DefaultOutbound != "Proxy" || emptyRep.DNSDetour != "#VPS" {
		t.Fatalf("expected empty merge conventions Proxy/#VPS, got %+v", emptyRep)
	}

	// Empty GroupsConfig with dangling route.final heals in-place
	danglingRaw := strings.Replace(cleanRaw, `"final": "Proxy"`, `"final": "MissingGroup"`, 1)
	healedEmptyJSON, healedRep, err := singbox.CompileGroupsIntoConfigJSON(danglingRaw, nil, nil, nil)
	if err != nil || healedRep.DefaultOutbound != "Proxy" || !strings.Contains(healedEmptyJSON, `"final": "Proxy"`) {
		t.Fatalf("expected nil GroupsConfig to heal dangling route.final to Proxy, err=%v rep=%+v", err, healedRep)
	}

	// {all} placeholder + missing target warning + invalid default warning + concurrent race safety
	edgeGC, err := config.ParseGroupsYAML([]byte(`
version: 1
mode: merge
groups:
  - name: "AllWithWarnings"
    type: selector
    use: ["{all}", "NonExistentGroup"]
    default: "MissingDefault"
`))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			out, r, cErr := singbox.CompileGroupsIntoConfigJSON(cleanRaw, edgeGC, nil, nil)
			if cErr != nil || !strings.Contains(out, `"AllWithWarnings"`) || len(r.Warnings) < 2 {
				t.Errorf("concurrent edge CompileGroupsIntoConfigJSON failed: err=%v warnings=%v", cErr, r.Warnings)
			}
		})
	}
	wg.Wait()
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
