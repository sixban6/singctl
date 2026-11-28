// 文件职责：验证自定义与第三方规则集 URL 规范化迁移、编译流水线重写、缓存清源及仓库内置规则集源文件/离线快照完整性。
package singbox_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	rssnapshot "singctl/internal/singbox/ruleset_snapshot"
	"singctl/internal/singbox/sboption"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestCanonicalizeRuleSetURL_TableDriven(t *testing.T) {
	const wantDouyin = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/douyin.srs"

	cases := []struct {
		name        string
		rawURL      string
		wantURL     string
		wantChanged bool
	}{
		{
			name:        "legacy_github_raw_refs_direct_cn",
			rawURL:      "https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/direct_cn.srs",
			wantURL:     constant.RuleSetReleaseBaseURL + "/direct_cn.srs",
			wantChanged: true,
		},
		{
			name:        "legacy_githubusercontent_hok",
			rawURL:      "https://raw.githubusercontent.com/sixban6/rulesets/main/rule/hok.srs",
			wantURL:     constant.RuleSetReleaseBaseURL + "/hok.srs",
			wantChanged: true,
		},
		{
			name:        "legacy_wx_shortvideo_renamed_to_wx_video",
			rawURL:      "https://raw.githubusercontent.com/sixban6/rulesets/main/rule/wx_shortvideo.srs",
			wantURL:     constant.RuleSetReleaseBaseURL + "/wx_video.srs",
			wantChanged: true,
		},
		{
			name:        "legacy_douyin_migrated_to_metacubex",
			rawURL:      "https://raw.githubusercontent.com/sixban6/rulesets/main/rule/douyin.srs",
			wantURL:     wantDouyin,
			wantChanged: true,
		},
		{
			name:        "mirror_prefixed_legacy_url_preserves_mirror",
			rawURL:      "https://gh-proxy.com/https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/direct_cn.srs",
			wantURL:     "https://gh-proxy.com/" + constant.RuleSetReleaseBaseURL + "/direct_cn.srs",
			wantChanged: true,
		},
		{
			name:        "already_canonical_rulesets_latest_unchanged",
			rawURL:      constant.RuleSetReleaseBaseURL + "/hok.srs",
			wantURL:     constant.RuleSetReleaseBaseURL + "/hok.srs",
			wantChanged: false,
		},
		{
			name:        "metacubex_unchanged",
			rawURL:      "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs",
			wantURL:     "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs",
			wantChanged: false,
		},
		{
			name:        "custom_third_party_unchanged",
			rawURL:      "https://example.com/custom.srs",
			wantURL:     "https://example.com/custom.srs",
			wantChanged: false,
		},
		{
			name:        "empty_string_unchanged",
			rawURL:      "",
			wantURL:     "",
			wantChanged: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotURL, gotChanged := singbox.CanonicalizeRuleSetURL(tc.rawURL)
			if gotChanged != tc.wantChanged || gotURL != tc.wantURL {
				t.Fatalf("CanonicalizeRuleSetURL(%q) = (%q, %v), want (%q, %v)",
					tc.rawURL, gotURL, gotChanged, tc.wantURL, tc.wantChanged)
			}
		})
	}
}

func TestCompilePipeline_RewritesLegacyCustomRuleSetURLs(t *testing.T) {
	inputJSON := `{
		"log": {"level": "info"},
		"outbounds": [
			{"tag": "Proxy", "type": "direct"},
			{"tag": "#DC", "type": "direct"}
		],
		"dns": {
			"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
			"rules": []
		},
		"route": {
			"rule_set": [
				{
					"tag": "geosite-ctm_cn",
					"type": "remote",
					"format": "binary",
					"url": "https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/direct_cn.srs"
				},
				{
					"tag": "geosite-hok",
					"type": "remote",
					"format": "binary",
					"url": "https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/hok.srs"
				},
				{
					"tag": "geosite-cn",
					"type": "remote",
					"format": "binary",
					"url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs"
				}
			],
			"rules": [
				{"action": "sniff"},
				{"action": "route", "rule_set": ["geosite-ctm_cn", "geosite-hok", "geosite-cn"], "outbound": "#DC"}
			]
		}
	}`

	for _, platform := range []string{"linux", singbox.PlatformIOS} {
		t.Run(platform, func(t *testing.T) {
			g := singbox.NewConfigGenerator(&config.Config{})
			out, err := g.RunCompilePipeline(inputJSON, platform)
			if err != nil {
				t.Fatalf("RunCompilePipeline(%s) failed: %v", platform, err)
			}
			doc, err := sboption.ParseDocument([]byte(out))
			if err != nil {
				t.Fatalf("parse compiled JSON: %v", err)
			}
			if doc.Route == nil {
				t.Fatal("expected non-nil route")
			}
			urls := make(map[string]string, len(doc.Route.RuleSet))
			for _, rs := range doc.Route.RuleSet {
				urls[rs.Tag] = rs.URL
			}
			if want := constant.RuleSetReleaseBaseURL + "/direct_cn.srs"; urls["geosite-ctm_cn"] != want {
				t.Fatalf("geosite-ctm_cn url = %q, want %q", urls["geosite-ctm_cn"], want)
			}
			if want := constant.RuleSetReleaseBaseURL + "/hok.srs"; urls["geosite-hok"] != want {
				t.Fatalf("geosite-hok url = %q, want %q", urls["geosite-hok"], want)
			}
			if strings.Contains(out, "sixban6/rulesets") {
				t.Fatalf("compiled config must not retain legacy sixban6/rulesets URL:\n%s", out)
			}
		})
	}
}

func TestRefreshConfigCache_MigratesLegacyManifestURL(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "rule_sets")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}

	srsPath := filepath.Join(cacheDir, "geosite-ctm_cn.srs")
	oldPayload := []byte("SRS\x02legacy-cached-payload")
	if err := os.WriteFile(srsPath, oldPayload, 0644); err != nil {
		t.Fatal(err)
	}

	legacyURL := "https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/direct_cn.srs"
	manifestJSON := `{
		"geosite-ctm_cn": {
			"url": "` + legacyURL + `",
			"format": "binary",
			"updated_at": "` + time.Now().UTC().Format(time.RFC3339) + `",
			"original": {
				"tag": "geosite-ctm_cn",
				"type": "remote",
				"format": "binary",
				"url": "` + legacyURL + `"
			}
		}
	}`
	if err := os.WriteFile(filepath.Join(cacheDir, "manifest.json"), []byte(manifestJSON), 0644); err != nil {
		t.Fatal(err)
	}

	cfgPath := filepath.Join(tmpDir, "config.json")
	cfgJSON := `{
		"route": {
			"rule_set": [
				{
					"tag": "geosite-ctm_cn",
					"type": "local",
					"format": "binary",
					"path": "` + filepath.ToSlash(srsPath) + `"
				}
			]
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	wantPayload := []byte("SRS\x02fresh-rulesets-latest")
	wantURL := constant.RuleSetReleaseBaseURL + "/direct_cn.srs"

	var mu sync.Mutex
	var requestedURLs []string
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			mu.Lock()
			requestedURLs = append(requestedURLs, req.URL.String())
			mu.Unlock()
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(wantPayload)),
				Header:     make(http.Header),
			}, nil
		}),
	}

	_, stats, err := singbox.RefreshConfigCache(cfgPath, singbox.LocalizeOptions{
		CacheDir: cacheDir,
		Client:   client,
		CacheTTL: 24 * time.Hour,
		Silent:   true,
	})
	if err != nil {
		t.Fatalf("RefreshConfigCache failed: %v", err)
	}
	if stats.Refreshed != 1 {
		t.Fatalf("expected stats.Refreshed = 1 even within 24h TTL when migrating legacy URL, got %+v", stats)
	}

	mu.Lock()
	gotReqURLs := slices.Clone(requestedURLs)
	mu.Unlock()
	if !slices.Contains(gotReqURLs, wantURL) {
		t.Fatalf("expected HTTP request to canonical URL %q, got %v", wantURL, gotReqURLs)
	}
	for _, u := range gotReqURLs {
		if strings.Contains(u, "sixban6/rulesets") {
			t.Fatalf("RefreshConfigCache must not fetch legacy URL %q", u)
		}
	}

	diskData, err := os.ReadFile(srsPath)
	if err != nil || !bytes.Equal(diskData, wantPayload) {
		t.Fatalf("expected cached .srs updated to fresh payload, err=%v got=%q", err, diskData)
	}

	rawMan, err := os.ReadFile(filepath.Join(cacheDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man map[string]struct {
		URL      string         `json:"url"`
		Original map[string]any `json:"original"`
	}
	if err := json.Unmarshal(rawMan, &man); err != nil {
		t.Fatal(err)
	}
	meta := man["geosite-ctm_cn"]
	if meta.URL != wantURL {
		t.Fatalf("manifest.url = %q, want %q", meta.URL, wantURL)
	}
	if origURL, _ := meta.Original["url"].(string); origURL != wantURL {
		t.Fatalf("manifest.original.url = %q, want %q", origURL, wantURL)
	}
}

func TestRepoCustomRuleSets_SourceJSONAndSnapshotIntegrity(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	type sourceRuleSet struct {
		Version int              `json:"version"`
		Rules   []map[string]any `json:"rules"`
	}

	loadRuleSet := func(name string) (string, sourceRuleSet) {
		t.Helper()
		p := filepath.Join(repoRoot, "rules", name)
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var parsed sourceRuleSet
		if err := json.Unmarshal(raw, &parsed); err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		if parsed.Version != 2 || len(parsed.Rules) == 0 {
			t.Fatalf("invalid source ruleset %s: version=%d rules=%d", name, parsed.Version, len(parsed.Rules))
		}
		return string(raw), parsed
	}

	directRaw, directParsed := loadRuleSet("direct_cn.json")
	if strings.Contains(directRaw, "tailscale.com") {
		t.Fatalf("rules/direct_cn.json must NOT contain tailscale.com:\n%s", directRaw)
	}
	suffixesRaw, _ := directParsed.Rules[0]["domain_suffix"].([]any)
	if len(suffixesRaw) != 11 {
		t.Fatalf("expected 11 domain_suffix entries in rules/direct_cn.json, got %d (%v)", len(suffixesRaw), suffixesRaw)
	}
	for _, must := range []string{"ghfast.top", "gh-proxy.com", "anti-ad.net", "tdos.vip", "ax1x.com"} {
		if !strings.Contains(directRaw, must) {
			t.Fatalf("expected rules/direct_cn.json to include %q:\n%s", must, directRaw)
		}
	}

	_, hokParsed := loadRuleSet("hok.json")
	if hokSuffixes, _ := hokParsed.Rules[0]["domain_suffix"].([]any); len(hokSuffixes) != 22 {
		t.Fatalf("expected 22 domain_suffix entries in rules/hok.json, got %d", len(hokSuffixes))
	}

	wxRaw, wxParsed := loadRuleSet("wx_video.json")
	for _, r := range wxParsed.Rules {
		if _, hasCIDR := r["ip_cidr"]; hasCIDR {
			t.Fatalf("rules/wx_video.json must not contain ip_cidr rules:\n%s", wxRaw)
		}
		if _, hasKW := r["domain_keyword"]; hasKW {
			t.Fatalf("rules/wx_video.json must not contain broad domain_keyword rules:\n%s", wxRaw)
		}
	}
	for _, forbidden := range []string{"wxapp.tc.qq.com", "wxsnsdy"} {
		if strings.Contains(wxRaw, forbidden) {
			t.Fatalf("rules/wx_video.json must not contain unrelated WeChat domain %q:\n%s", forbidden, wxRaw)
		}
	}

	if !rssnapshot.IsLite {
		snap := rssnapshot.Load()
		checks := map[string]string{
			"geosite-ctm_cn": constant.RuleSetReleaseBaseURL + "/direct_cn.srs",
			"geosite-hok":    constant.RuleSetReleaseBaseURL + "/hok.srs",
		}
		for tag, wantURL := range checks {
			matched, gotURL, format, ok := snap.Lookup(tag, "")
			if !ok || matched != tag || format != "binary" || gotURL != wantURL {
				t.Fatalf("snapshot Lookup(%q) = (%q, %q, %q, %v), want (%q, %q, binary, true)",
					tag, matched, gotURL, format, ok, tag, wantURL)
			}
			rawSRS, err := snap.Extract(tag)
			if err != nil || (!bytes.HasPrefix(rawSRS, []byte("SRS")) && !bytes.HasPrefix(rawSRS, []byte("RULE"))) {
				t.Fatalf("snapshot Extract(%q) invalid: err=%v prefix=%q", tag, err, rawSRS[:min(4, len(rawSRS))])
			}
		}
	}
}

func TestTrafficRouting_AIDevIncludesMagpieExaModels(t *testing.T) {
	preset, ok := singbox.LookupClientRoutingPreset("ai_dev")
	if !ok {
		t.Fatal("expected ai_dev routing preset present")
	}
	for _, domain := range []string{"usemagpie.ai", "exa.ai", "models.dev"} {
		if !slices.Contains(preset.DomainSuffixes, domain) {
			t.Fatalf("expected ai_dev preset DomainSuffixes to include %q, got %v", domain, preset.DomainSuffixes)
		}
	}
}
