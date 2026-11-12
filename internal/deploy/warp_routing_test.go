package deploy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"singctl/internal/config"
)

func loadEmbeddedServerTemplate(t *testing.T) []byte {
	t.Helper()
	raw, err := TemplateFiles.ReadFile("templates/server_config.json")
	if err != nil {
		t.Fatalf("read server_config.json: %v", err)
	}
	return raw
}

type parsedSingBoxRoute struct {
	Route struct {
		Final   string `json:"final"`
		RuleSet []struct {
			Tag string `json:"tag"`
			URL string `json:"url"`
		} `json:"rule_set"`
		Rules []struct {
			Action        string   `json:"action"`
			IPIsPrivate   bool     `json:"ip_is_private"`
			Outbound      string   `json:"outbound"`
			RuleSet       []string `json:"rule_set"`
			DomainSuffix  []string `json:"domain_suffix"`
			Domain        []string `json:"domain"`
			DomainKeyword []string `json:"domain_keyword"`
			IPCIDR        []string `json:"ip_cidr"`
		} `json:"rules"`
	} `json:"route"`
}

func TestNormalizeAndCleanWarpRules(t *testing.T) {
	cleaned, err := config.CleanWarpDomainRule("https://missav.ws/dm13/cn/test?foo=1#bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleaned != "missav.ws" {
		t.Fatalf("expected 'missav.ws', got %q", cleaned)
	}

	cleanedWildcard, err := config.CleanWarpDomainRule("*.Sub.Example.COM:443")
	if err != nil || cleanedWildcard != "sub.example.com" {
		t.Fatalf("expected 'sub.example.com', got %q (err=%v)", cleanedWildcard, err)
	}

	if _, err := config.CleanWarpDomainRule("example.com; rm -rf /"); err == nil {
		t.Fatal("expected shell metacharacter injection to fail")
	}

	cidr, err := config.CleanWarpCIDRRule("198.51.100.10")
	if err != nil || cidr != "198.51.100.10/32" {
		t.Fatalf("expected 198.51.100.10/32, got %q (err=%v)", cidr, err)
	}
}

func TestApplyWarpRouting_DefaultMissavDisableRedditGlobalAndBypass(t *testing.T) {
	tpl := loadEmbeddedServerTemplate(t)

	// 1. 默认未配置状态：仅 rule-reddit -> WARP，final=DC，ip_is_private=reject 保留
	outDefault, err := ApplyWarpRoutingToServerConfigJSON(tpl, config.WarpRoutingConfig{})
	if err != nil {
		t.Fatalf("default apply failed: %v", err)
	}
	var pDefault parsedSingBoxRoute
	if err := json.Unmarshal(outDefault, &pDefault); err != nil {
		t.Fatal(err)
	}
	if pDefault.Route.Final != "DC" {
		t.Fatalf("expected default final=DC, got %s", pDefault.Route.Final)
	}
	foundPrivateReject := false
	foundRedditWarp := false
	for _, r := range pDefault.Route.Rules {
		if r.IPIsPrivate && r.Action == "reject" {
			foundPrivateReject = true
		}
		if r.Outbound == "WARP" && slices.Contains(r.RuleSet, "rule-reddit") {
			foundRedditWarp = true
		}
	}
	if !foundPrivateReject || !foundRedditWarp {
		t.Fatalf("default route missing reject or reddit->WARP: reject=%v reddit=%v", foundPrivateReject, foundRedditWarp)
	}

	// 2. 开启 missav 预设：missav.ws / missav.ai / missav.com / missav.live / surrit.com / nineyu.com 全部编译至 WARP
	outMissav, err := ApplyWarpRoutingToServerConfigJSON(tpl, config.WarpRoutingConfig{
		Presets: map[string]bool{"missav": true},
	})
	if err != nil {
		t.Fatalf("missav apply failed: %v", err)
	}
	var pMissav parsedSingBoxRoute
	if err := json.Unmarshal(outMissav, &pMissav); err != nil {
		t.Fatal(err)
	}
	var warpSuffixes []string
	for _, r := range pMissav.Route.Rules {
		if r.Outbound == "WARP" && len(r.DomainSuffix) > 0 {
			warpSuffixes = append(warpSuffixes, r.DomainSuffix...)
		}
	}
	for _, want := range []string{"missav.ws", "missav.ai", "missav.com", "missav.live", "surrit.com", "nineyu.com"} {
		if !slices.Contains(warpSuffixes, want) {
			t.Fatalf("expected missav suffix %q in WARP rules, got %v", want, warpSuffixes)
		}
	}

	// 3. 显式关闭 reddit 默认预设后，rule-reddit 必须回到 DC
	outNoReddit, err := ApplyWarpRoutingToServerConfigJSON(tpl, config.WarpRoutingConfig{
		Presets: map[string]bool{"reddit": false},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pNoReddit parsedSingBoxRoute
	if err := json.Unmarshal(outNoReddit, &pNoReddit); err != nil {
		t.Fatal(err)
	}
	redditBackToDC := false
	for _, r := range pNoReddit.Route.Rules {
		if r.Outbound == "WARP" && slices.Contains(r.RuleSet, "rule-reddit") {
			t.Fatal("expected rule-reddit NOT to route via WARP when explicitly disabled")
		}
		if r.Outbound == "DC" && slices.Contains(r.RuleSet, "rule-reddit") {
			redditBackToDC = true
		}
	}
	if !redditBackToDC {
		t.Fatal("expected rule-reddit to fall back to DC")
	}

	// 4. 开启 netflix 等按需 .srs 预设会注入 rule_set；关闭后自动清理不留冗余
	outNetflix, err := ApplyWarpRoutingToServerConfigJSON(tpl, config.WarpRoutingConfig{
		Presets: map[string]bool{"netflix": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pNetflix parsedSingBoxRoute
	_ = json.Unmarshal(outNetflix, &pNetflix)
	hasNetflixRS := false
	for _, rs := range pNetflix.Route.RuleSet {
		if rs.Tag == "rule-netflix" {
			hasNetflixRS = true
		}
	}
	if !hasNetflixRS {
		t.Fatal("expected optional rule-netflix to be injected into route.rule_set")
	}

	// 5. global_warp 模式：DirectDomains / DirectCIDRs 白名单必须排在最前面 (DC) 且 final=WARP
	outGlobal, err := ApplyWarpRoutingToServerConfigJSON(tpl, config.WarpRoutingConfig{
		Mode:          config.WarpModeGlobalWarp,
		DirectDomains: []string{"direct.example.com", "full:exact.example.com"},
		DirectCIDRs:   []string{"198.51.100.0/24"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pGlobal parsedSingBoxRoute
	_ = json.Unmarshal(outGlobal, &pGlobal)
	if pGlobal.Route.Final != "WARP" {
		t.Fatalf("expected global_warp final=WARP, got %s", pGlobal.Route.Final)
	}
	directDomainIdx, directCIDRIdx := -1, -1
	for idx, r := range pGlobal.Route.Rules {
		if r.Outbound == "DC" && slices.Contains(r.DomainSuffix, "direct.example.com") && slices.Contains(r.Domain, "exact.example.com") {
			directDomainIdx = idx
		}
		if r.Outbound == "DC" && slices.Contains(r.IPCIDR, "198.51.100.0/24") {
			directCIDRIdx = idx
		}
	}
	if directDomainIdx < 0 || directCIDRIdx < 0 || directDomainIdx >= directCIDRIdx {
		t.Fatalf("expected Direct whitelist rules at top priority, got indices %d, %d", directDomainIdx, directCIDRIdx)
	}

	// 6. bypass 模式：全部 WARP 规则挂起，final=DC
	outBypass, err := ApplyWarpRoutingToServerConfigJSON(tpl, config.WarpRoutingConfig{
		Mode:        config.WarpModeBypass,
		Presets:     map[string]bool{"missav": true, "openai": true},
		WarpDomains: []string{"example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var pBypass parsedSingBoxRoute
	_ = json.Unmarshal(outBypass, &pBypass)
	if pBypass.Route.Final != "DC" {
		t.Fatalf("expected bypass final=DC, got %s", pBypass.Route.Final)
	}
	for _, r := range pBypass.Route.Rules {
		if r.Outbound == "WARP" {
			t.Fatalf("expected zero WARP rules in bypass mode, found %+v", r)
		}
	}
}

func TestApplyLiveWarpRouting_GuardsAndRollback(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	tpl := loadEmbeddedServerTemplate(t)
	if err := os.WriteFile(cfgPath, tpl, 0600); err != nil {
		t.Fatal(err)
	}

	// 1. 40000 端口不可用时，阻断切换并返回 ErrWarpTunnelUnavailable
	_, err := ApplyLiveWarpRouting(cfgPath, config.WarpRoutingConfig{
		Presets: map[string]bool{"missav": true},
	}, &LiveWarpApplyDeps{
		CheckWarpPort: func() bool { return false },
	})
	if !errors.Is(err, ErrWarpTunnelUnavailable) {
		t.Fatalf("expected ErrWarpTunnelUnavailable, got %v", err)
	}

	// 2. 重载失败时必须原子回滚旧 config.json 并保持 0600 权限
	restoreCalled := false
	_, err = ApplyLiveWarpRouting(cfgPath, config.WarpRoutingConfig{
		Presets: map[string]bool{"missav": true},
	}, &LiveWarpApplyDeps{
		CheckWarpPort:   func() bool { return true },
		ValidateConfig:  func(string) error { return nil },
		IsServiceActive: func() bool { return true },
		ReloadService:   func(bool) error { return errors.New("simulated sighup failure") },
		RestoreService:  func(wasActive bool) error { restoreCalled = wasActive; return nil },
	})
	if err == nil || !restoreCalled {
		t.Fatalf("expected reload failure with restore called, err=%v restoreCalled=%v", err, restoreCalled)
	}
	restored, _ := os.ReadFile(cfgPath)
	if string(restored) != string(tpl) {
		t.Fatal("expected config.json to be atomically rolled back to original content")
	}
	fi, _ := os.Stat(cfgPath)
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected rolled-back config.json mode 0600, got %o", fi.Mode().Perm())
	}
}
