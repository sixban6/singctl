// 文件职责：覆盖内置防 PCDN 域名后缀精确匹配、默认开关生效与 iOS inline 规则集同步测试。
package singbox_test

import (
	"encoding/json"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestMatchBuiltinPCDNDomain(t *testing.T) {
	positives := []string{
		"xy115x238x200x208xy240eyf7y7c00y103y8000yy16xy.mcdn.bilivideo.cn",
		"v1d.szbdyd.com",
		"txl3.nexitech.cn",
		"zz10.yirujs.com",
		"node1.xycdn.com.",
		"p2p.huya.com",
	}
	for _, host := range positives {
		if ok, suffix := singbox.MatchBuiltinPCDNDomain(host); !ok || suffix == "" {
			t.Fatalf("expected %q to match BuiltinPCDNDomainSuffixes", host)
		}
	}

	negatives := []string{
		"ipcdn.apple.com",
		"pcdn.brave.com",
		"static1.dmcdn.net",
		"upos-sz-mirrorcos.bilivideo.com",
		"api.github.com",
		"sub.example.com",
	}
	for _, host := range negatives {
		if ok, suffix := singbox.MatchBuiltinPCDNDomain(host); ok {
			t.Fatalf("expected %q NOT to match BuiltinPCDNDomainSuffixes, got %q", host, suffix)
		}
	}
}

func TestEffectiveBlockRules_DefaultAndToggle(t *testing.T) {
	cfgDefault := &config.Config{
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{{Target: "tracker.example.com"}},
		},
	}
	eff := singbox.EffectiveBlockRules(cfgDefault)
	if len(eff) != 2 || eff[0].Target != singbox.BuiltinPCDNRuleSetTarget || eff[1].Target != "tracker.example.com" {
		t.Fatalf("unexpected default EffectiveBlockRules: %+v", eff)
	}

	cfgDisabled := &config.Config{
		CustomRules: config.CustomRulesConfig{
			Block: []config.BlockRule{
				{Target: singbox.BuiltinPCDNRuleSetTarget},
				{Target: "tracker.example.com"},
			},
		},
	}
	cfgDisabled.Audit.SetPCDNBlock(false)
	effOff := singbox.EffectiveBlockRules(cfgDisabled)
	if len(effOff) != 1 || effOff[0].Target != "tracker.example.com" {
		t.Fatalf("expected builtin PCDN excluded when disabled, got %+v", effOff)
	}
}

func TestBuiltinPCDN_IOSCompatibility_And_SyncRoundTrip(t *testing.T) {
	base := `{"dns":{"rules":[{"rule_set":"geosite-cn","server":"dns_local"}]},"route":{"rules":[{"action":"sniff"},{"ip_is_private":true,"outbound":"#DC"}],"rule_set":[]}}`

	g := singbox.NewOfflineConfigGenerator(&config.Config{})
	iosJSON, err := g.InjectCustomRulesForPlatform(base, singbox.PlatformIOS)
	if err != nil {
		t.Fatalf("InjectCustomRulesForPlatform(ios) failed: %v", err)
	}
	if !strings.Contains(iosJSON, singbox.BuiltinPCDNRuleSetTag) || !strings.Contains(iosJSON, `"type":"inline"`) {
		t.Fatalf("expected inline %s in iOS config, got:\n%s", singbox.BuiltinPCDNRuleSetTag, iosJSON)
	}
	if err := singbox.CheckIOSCompatibility(iosJSON); err != nil {
		t.Fatalf("CheckIOSCompatibility failed: %v", err)
	}

	withBuiltin := singbox.EffectiveBlockRules(&config.Config{})
	removed, err := singbox.SyncBlockRulesInConfigJSON(iosJSON, withBuiltin, nil)
	if err != nil {
		t.Fatalf("SyncBlockRulesInConfigJSON remove failed: %v", err)
	}
	if strings.Contains(removed, singbox.BuiltinPCDNRuleSetTag) {
		t.Fatalf("expected %s to be stripped cleanly after disable, got:\n%s", singbox.BuiltinPCDNRuleSetTag, removed)
	}

	restored1, err := singbox.SyncBlockRulesInConfigJSON(removed, nil, withBuiltin)
	if err != nil {
		t.Fatalf("SyncBlockRulesInConfigJSON re-enable failed: %v", err)
	}
	restored2, err := singbox.SyncBlockRulesInConfigJSON(restored1, withBuiltin, withBuiltin)
	if err != nil {
		t.Fatalf("SyncBlockRulesInConfigJSON idempotent sync failed: %v", err)
	}
	var doc struct {
		Route struct {
			RuleSet []map[string]any `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(restored2), &doc); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rs := range doc.Route.RuleSet {
		if rs["tag"] == singbox.BuiltinPCDNRuleSetTag {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 %s definition after idempotent sync, got %d", singbox.BuiltinPCDNRuleSetTag, count)
	}
}
