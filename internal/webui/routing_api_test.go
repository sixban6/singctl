package webui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func buildValidTestSingBoxJSON(t *testing.T, cacheDir string) string {
	t.Helper()
	// 提供一份符合 modern sing-box 规范且包含典型策略组/DNS/规则集的客户端测试配置；
	// 宿主机若安装了 sing-box 二进制，PUT 接口会触发真实 `sing-box check` 全量校验。
	ruleSetTags := []struct {
		tag string
		fmt string
	}{
		{"geosite-ad1", "binary"},
		{"geosite-chat", "binary"},
		{"geosite-youtube", "binary"},
		{"geosite-netflix", "binary"},
		{"geoip-netflix", "binary"},
		{"geosite-disney", "binary"},
		{"geosite-hbo", "binary"},
		{"geosite-primevideo", "binary"},
		{"geosite-tiktok", "binary"},
		{"geosite-spotify", "binary"},
		{"geosite-porn", "binary"},
		{"geosite-steam", "binary"},
		{"geosite-epic", "binary"},
		{"geosite-playstation", "binary"},
		{"geosite-xbox", "binary"},
		{"geosite-hok", "binary"},
		{"geosite-google", "binary"},
		{"geoip-google", "binary"},
		{"geosite-telegram", "binary"},
		{"geoip-telegram", "binary"},
		{"geosite-x", "binary"},
		{"geosite-github", "binary"},
		{"geosite-sourcehut", "binary"},
		{"geosite-paypal", "binary"},
		{"geosite-cryptocurrency", "binary"},
		{"geosite-apple", "binary"},
		{"geoip-apple", "binary"},
		{"geosite-microsoft", "binary"},
		{"geosite-onedrive", "binary"},
		{"geosite-cn", "binary"},
		{"geosite-geolocation-!cn", "binary"},
		{"geoip-cn", "binary"},
	}
	ruleSetObjs := make([]map[string]any, 0, len(ruleSetTags))
	for _, rs := range ruleSetTags {
		ruleSetObjs = append(ruleSetObjs, map[string]any{
			"tag":    rs.tag,
			"type":   "remote",
			"format": rs.fmt,
			"url":    "https://example.com/rules/" + rs.tag + ".srs",
		})
	}

	doc := map[string]any{
		"log": map[string]any{
			"disabled": false,
			"level":    "warn",
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"},
				{"tag": "dns_proxy", "type": "udp", "server": "8.8.8.8", "detour": "#VPS"},
			},
			"rules": []map[string]any{
				{"clash_mode": "Direct", "server": "dns_local"},
				{"clash_mode": "Global", "server": "dns_proxy"},
				{"client_subnet": "203.0.113.0/24", "rule_set": "geosite-hok", "server": "dns_proxy"},
				{"rule_set": "geosite-cn", "server": "dns_local"},
				{"rule_set": "geosite-geolocation-!cn", "server": "dns_proxy"},
			},
			"final": "dns_proxy",
		},
		"inbounds": []map[string]any{
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
		},
		"outbounds": []map[string]any{
			{"type": "selector", "tag": "Proxy", "outbounds": []string{"#VPS", "#Auto", "#Nodes", "#DC"}, "default": "#VPS"},
			{"type": "selector", "tag": "AI", "outbounds": []string{"#VPS", "Proxy"}, "default": "#VPS"},
			{"type": "selector", "tag": "#VPS", "outbounds": []string{"node-us"}},
			{"type": "urltest", "tag": "#Auto", "outbounds": []string{"node-us"}},
			{"type": "selector", "tag": "#Nodes", "outbounds": []string{"node-us"}},
			{"type": "direct", "tag": "#DC"},
			{"type": "socks", "tag": "node-us", "server": "198.51.100.10", "server_port": 1080},
		},
		"route": map[string]any{
			"default_domain_resolver": "dns_local",
			"rule_set":                ruleSetObjs,
			"rules": []map[string]any{
				{"action": "sniff"},
				{"action": "reject", "rule_set": []string{"geosite-ad1"}},
				{"action": "route", "rule_set": "geosite-hok", "outbound": "#Auto"},
				{"action": "route", "rule_set": "geosite-chat", "outbound": "AI"},
				{"action": "route", "rule_set": []string{"geosite-netflix", "geosite-youtube", "geosite-steam"}, "outbound": "Proxy"},
				{"action": "route", "rule_set": []string{"geosite-apple", "geosite-cn"}, "outbound": "#DC"},
				{"action": "route", "rule_set": "geosite-geolocation-!cn", "outbound": "Proxy"},
				{"action": "route", "rule_set": []string{"geoip-cn"}, "outbound": "#DC"},
			},
			"final": "Proxy",
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{
				"enabled": true,
				"path":    filepath.Join(cacheDir, "cache.db"),
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHandleTrafficRouting_GetPutHotReloadAndValidation(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "singctl.yaml")
	sbPath := filepath.Join(dir, "config.json")
	workDir := filepath.Join(dir, "work")
	if err := os.MkdirAll(workDir, 0700); err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(workDir, "config.json")

	initialYAML := "# keep my top comment\nsubs:\n  - name: main\n    url: https://example.com/sub\n"
	if err := os.WriteFile(cfgPath, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}
	rawSB := buildValidTestSingBoxJSON(t, dir)
	if err := os.WriteFile(sbPath, []byte(rawSB), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workPath, []byte(rawSB), 0600); err != nil {
		t.Fatal(err)
	}

	srv := New(Options{
		ConfigPath:            cfgPath,
		SingBoxConfigPath:     sbPath,
		SingBoxWorkConfigPath: workPath,
	})

	doReq := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. GET /api/traffic-routing 返回 25 项预设与 5 大分类及推荐默认组
	rec := doReq(http.MethodGet, "/api/traffic-routing", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/traffic-routing status = %d: %s", rec.Code, rec.Body.String())
	}
	var gotReport singbox.ClientRoutingReport
	if err := json.Unmarshal(rec.Body.Bytes(), &gotReport); err != nil {
		t.Fatal(err)
	}
	if gotReport.TotalCount != 25 || len(gotReport.Categories) != 5 {
		t.Fatalf("unexpected total/categories: %d/%d", gotReport.TotalCount, len(gotReport.Categories))
	}
	findItem := func(rep singbox.ClientRoutingReport, id string) singbox.ClientRoutingPresetState {
		for _, it := range rep.Items {
			if it.ID == id {
				return it
			}
		}
		t.Fatalf("preset %q not found", id)
		return singbox.ClientRoutingPresetState{}
	}
	if oa := findItem(gotReport, "openai"); !oa.Enabled || oa.SelectedGroup != "#VPS" {
		t.Fatalf("openai default want enabled=#VPS, got %+v", oa)
	}
	if ap := findItem(gotReport, "apple"); ap.Enabled || ap.EffectiveDest != "#DC" {
		t.Fatalf("apple default want disabled (#DC), got %+v", ap)
	}
	if hok := findItem(gotReport, "hok"); !hok.Enabled || hok.SelectedGroup != "#Auto" {
		t.Fatalf("hok default want enabled=#Auto, got %+v", hok)
	}

	// 2. PUT: 修改 netflix -> #Nodes、开启 apple -> #VPS、关闭 steam -> #DC
	payload := `{"presets":{"netflix":{"enabled":true,"outbound":"#Nodes"},"apple":{"enabled":true,"outbound":"#VPS"},"steam":{"enabled":false}}}`
	rec = doReq(http.MethodPut, "/api/traffic-routing", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/traffic-routing status = %d: %s", rec.Code, rec.Body.String())
	}
	var putResp struct {
		OK      bool                        `json:"ok"`
		Applied bool                        `json:"applied"`
		Report  singbox.ClientRoutingReport `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &putResp); err != nil {
		t.Fatal(err)
	}
	if !putResp.OK || !putResp.Applied {
		t.Fatalf("expected ok & applied, got %+v", putResp)
	}

	// 校验 singctl.yaml 0600 落盘、保留原注释、可反序列化还原
	cfgInfo, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfgInfo.Mode().Perm() != 0600 {
		t.Fatalf("singctl.yaml perm = %o, want 0600", cfgInfo.Mode().Perm())
	}
	yamlBytes, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(yamlBytes), "# keep my top comment") {
		t.Fatalf("expected singctl.yaml comment to be preserved:\n%s", string(yamlBytes))
	}
	loadedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedCfg.TrafficRouting.Presets["netflix"].Outbound != "#Nodes" {
		t.Fatalf("expected netflix=#Nodes persisted, got %+v", loadedCfg.TrafficRouting.Presets)
	}

	// 校验主配置与沙盒配置均已更新且权限为 0600
	for _, p := range []string{sbPath, workPath} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("%s perm = %o, want 0600", p, fi.Mode().Perm())
		}
	}
	liveSBBytes, _ := os.ReadFile(sbPath)
	var liveDoc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
	}
	if err := json.Unmarshal(liveSBBytes, &liveDoc); err != nil {
		t.Fatal(err)
	}
	findRuleForTag := func(tag string) (outbound string, found bool) {
		for _, r := range liveDoc.Route.Rules {
			if rs, ok := r["rule_set"].([]any); ok {
				for _, item := range rs {
					if item == tag {
						ob, _ := r["outbound"].(string)
						return ob, true
					}
				}
			}
			if rsStr, ok := r["rule_set"].(string); ok && rsStr == tag {
				ob, _ := r["outbound"].(string)
				return ob, true
			}
		}
		return "", false
	}
	if ob, ok := findRuleForTag("geosite-netflix"); !ok || ob != "#Nodes" {
		t.Fatalf("expected geosite-netflix -> #Nodes, got %q (ok=%v)", ob, ok)
	}
	if ob, ok := findRuleForTag("geosite-apple"); !ok || ob != "#VPS" {
		t.Fatalf("expected geosite-apple -> #VPS, got %q (ok=%v)", ob, ok)
	}
	if ob, ok := findRuleForTag("geosite-steam"); !ok || ob != "#DC" {
		t.Fatalf("expected geosite-steam -> #DC, got %q (ok=%v)", ob, ok)
	}
	// DNS 中 steam 应走 dns_local，apple 应走 dns_proxy，且禁止出现 geoip-apple
	var appleDNS, steamDNS string
	for _, dr := range liveDoc.DNS.Rules {
		rs, _ := dr["rule_set"].([]any)
		srvTag, _ := dr["server"].(string)
		for _, item := range rs {
			switch item {
			case "geoip-apple":
				t.Fatalf("geoip-* must not be emitted in dns.rules: %+v", dr)
			case "geosite-apple":
				appleDNS = srvTag
			case "geosite-steam":
				steamDNS = srvTag
			}
		}
	}
	if appleDNS != "dns_proxy" || steamDNS != "dns_local" {
		t.Fatalf("unexpected DNS rules: apple=%q (want dns_proxy), steam=%q (want dns_local)", appleDNS, steamDNS)
	}

	// 3. 非法策略组或未知预设返回 400 且不破坏磁盘配置
	rec = doReq(http.MethodPut, "/api/traffic-routing", `{"presets":{"netflix":{"outbound":"NonExistentGroup"}}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid group, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(http.MethodPut, "/api/traffic-routing", `{"presets":{"not_a_preset":{"enabled":true}}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown preset, got %d: %s", rec.Code, rec.Body.String())
	}

	// 4. 一键恢复推荐默认：清空 singctl.yaml traffic_routing，并将 Apple 恢复直连、Steam/Netflix 恢复 Proxy
	rec = doReq(http.MethodPut, "/api/traffic-routing", `{"reset":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("reset PUT status = %d: %s", rec.Code, rec.Body.String())
	}
	reloadedCfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reloadedCfg.TrafficRouting.IsEmpty() {
		t.Fatalf("expected traffic_routing to be cleared after reset, got %+v", reloadedCfg.TrafficRouting)
	}
	// 原模板受保护规则（如 geosite-ad1 拒绝规则与 geosite-cn）必须始终完整保留
	liveAfterReset, _ := os.ReadFile(sbPath)
	if !strings.Contains(string(liveAfterReset), "geosite-ad1") || !strings.Contains(string(liveAfterReset), "geosite-cn") {
		t.Fatal("expected adblock and cn baseline rules to remain intact after reset")
	}
	if !slices.Contains([]string{""}, "") {
		t.Fatal("unreachable")
	}
}
