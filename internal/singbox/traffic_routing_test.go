package singbox

import (
	"slices"
	"strings"
	"testing"

	"singctl/internal/config"
)

func TestBuildClientRoutingReport_WithoutVPSGroupFallsBackToAI(t *testing.T) {
	rawNoVPS := `{
  "outbounds": [
    {"type": "selector", "tag": "Proxy", "outbounds": ["#Auto", "#Nodes", "#DC"]},
    {"type": "selector", "tag": "AI", "outbounds": ["#Nodes", "#Auto"]},
    {"type": "urltest", "tag": "#Auto", "outbounds": ["node-1"]},
    {"type": "selector", "tag": "#Nodes", "outbounds": ["node-1"]},
    {"type": "direct", "tag": "#DC"}
  ],
  "route": {
    "rule_set": [
      {"tag": "geosite-chat", "type": "remote", "url": "https://example.com/chat.srs"}
    ],
    "rules": []
  }
}`

	cfg := &config.Config{
		TrafficRouting: config.TrafficRoutingConfig{
			Presets: map[string]config.TrafficRuleOverride{
				// 即使历史配置曾指定 #VPS，缺失 #VPS 时也应安全回退至 AI
				"openai": {Enabled: new(true), Outbound: "#VPS"},
			},
		},
	}

	report := BuildClientRoutingReport(cfg, rawNoVPS)
	groupTags := make([]string, len(report.Groups))
	for i, g := range report.Groups {
		groupTags[i] = g.Tag
	}
	if slices.Contains(groupTags, "#VPS") {
		t.Fatalf("unexpected #VPS group in report.Groups: %v", groupTags)
	}

	var aiCat *TrafficCategoryInfo
	for i := range report.Categories {
		if report.Categories[i].ID == "ai" {
			aiCat = &report.Categories[i]
			break
		}
	}
	if aiCat == nil {
		t.Fatal("missing ai category")
	}
	if aiCat.DefaultDest != "AI" {
		t.Fatalf("expected ai category DefaultDest=AI, got %q", aiCat.DefaultDest)
	}
	if !strings.Contains(aiCat.Description, "自动走 AI 分组") {
		t.Fatalf("expected ai category description to mention AI fallback, got %q", aiCat.Description)
	}

	for _, item := range report.Items {
		if item.Category != "ai" {
			continue
		}
		if item.DefaultOutbound != "AI" {
			t.Fatalf("preset %s expected DefaultOutbound=AI, got %q", item.ID, item.DefaultOutbound)
		}
		if item.SelectedGroup != "AI" || item.EffectiveDest != "AI" {
			t.Fatalf("preset %s expected fallback to AI, got selected=%q effective=%q", item.ID, item.SelectedGroup, item.EffectiveDest)
		}
	}

	compiled, err := ApplyTrafficRoutingToConfigJSON(rawNoVPS, cfg.TrafficRouting, cfg.CustomRules)
	if err != nil {
		t.Fatalf("ApplyTrafficRoutingToConfigJSON failed: %v", err)
	}
	if strings.Contains(compiled, `"#VPS"`) {
		t.Fatalf("compiled config must not reference missing #VPS outbound:\n%s", compiled)
	}
	if !strings.Contains(compiled, `"outbound": "AI"`) {
		t.Fatalf("compiled config should route AI rules to AI outbound:\n%s", compiled)
	}
}
