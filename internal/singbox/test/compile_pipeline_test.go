// 文件职责：验证 sing-box 10 阶段强类型编译流水线（CompileStage）、单树零中间态序列化与 iOS/Linux 加固边界。
package singbox_test

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

func TestCompilePipeline_TableDrivenBoundaries(t *testing.T) {
	baseJSON := `{
		"log": {"level": "info"},
		"outbounds": [
			{"tag": "node-a", "type": "vless", "server": "198.51.100.10"},
			{"tag": "node-a", "type": "vless", "server": "198.51.100.10"},
			{"tag": "Proxy", "type": "selector", "outbounds": ["node-a"]},
			{"tag": "#DC", "type": "direct"}
		],
		"dns": {
			"servers": [{"tag": "dns_local", "type": "udp", "server": "223.5.5.5"}],
			"rules": []
		},
		"route": {
			"default_mark": 255,
			"rules": [
				{"action": "sniff"},
				{"protocol": "udp", "port": 443, "action": "reject"}
			]
		},
		"experimental": {
			"clash_api": {
				"external_controller": "0.0.0.0:9090",
				"external_ui": "ui"
			}
		}
	}`

	t.Run("linux_pipeline_hardening_and_ocp_custom_stage", func(t *testing.T) {
		g := singbox.NewOfflineConfigGenerator(&config.Config{})
		customRan := false
		extraStage := singbox.CompileStage{
			Name: "custom_marker",
			AppliesTo: func(_ *singbox.ConfigGenerator, doc *singbox.CompileDoc) bool {
				return !doc.IsIOS()
			},
			Apply: func(_ *singbox.ConfigGenerator, doc *singbox.CompileDoc) error {
				customRan = true
				d, err := doc.EnsureDoc()
				if err != nil || d == nil {
					return err
				}
				if d.Extra == nil {
					d.Extra = make(map[string]json.RawMessage)
				}
				d.Extra["_ocp_tested"] = json.RawMessage(`true`)
				doc.MarkDirty()
				return nil
			},
		}

		out, err := g.RunCompilePipeline(baseJSON, "linux", extraStage)
		if err != nil {
			t.Fatalf("RunCompilePipeline(linux) failed: %v", err)
		}
		if !customRan {
			t.Fatalf("expected custom OCP stage to execute on linux")
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("output invalid JSON: %v", err)
		}
		if parsed["log"].(map[string]any)["level"] != "warn" {
			t.Fatalf("expected log.level normalized to warn, got %v", parsed["log"])
		}
		clash := parsed["experimental"].(map[string]any)["clash_api"].(map[string]any)
		if clash["external_controller"] != "127.0.0.1:9090" {
			t.Fatalf("expected clash_api bound to loopback, got %v", clash["external_controller"])
		}
		if sec, _ := clash["secret"].(string); sec == "" {
			t.Fatalf("expected generated non-empty clash secret")
		}
		if parsed["_ocp_tested"] != true {
			t.Fatalf("expected custom OCP marker in output")
		}
	})

	t.Run("ios_pipeline_preserves_sandbox_and_nil_config_safe", func(t *testing.T) {
		var nilGen *singbox.ConfigGenerator
		out, err := nilGen.RunCompilePipeline(baseJSON, singbox.PlatformIOS)
		if err != nil {
			t.Fatalf("RunCompilePipeline(ios) with nil generator failed: %v", err)
		}
		if strings.Contains(out, `"default_mark"`) {
			t.Fatalf("expected default_mark removed for iOS SFI compatibility")
		}
		if strings.Contains(out, `"external_ui"`) {
			t.Fatalf("expected external_ui removed for iOS SFI compatibility")
		}
		if !strings.Contains(out, `"level": "warn"`) {
			t.Fatalf("expected log level normalized to warn on iOS too")
		}
	})

	t.Run("invalid_json_unsupported_platform_and_legacy_protocol_sanitized", func(t *testing.T) {
		g := singbox.NewOfflineConfigGenerator(nil)
		if _, err := g.RunCompilePipeline("{broken", "linux"); err == nil {
			t.Fatalf("expected error on invalid JSON")
		}
		if _, err := g.RunCompilePipeline(baseJSON, "freebsd"); err == nil {
			t.Fatalf("expected error on unsupported platform")
		}
		out, err := g.RunCompilePipeline(baseJSON, "linux")
		if err != nil {
			t.Fatalf("RunCompilePipeline failed: %v", err)
		}
		if strings.Contains(out, `"protocol": "udp"`) {
			t.Fatalf("expected legacy protocol=udp sanitized to network=udp:\n%s", out)
		}
		if !strings.Contains(out, `"network": "udp"`) {
			t.Fatalf("expected network=udp present after sanitization:\n%s", out)
		}
	})

	t.Run("single_tree_reuse_minimizes_json_roundtrips", func(t *testing.T) {
		doc := singbox.NewCompileDoc(`{"log":{"level":"info"},"route":{"rules":[{"protocol":"udp"}]}}`, "linux")
		g := singbox.NewOfflineConfigGenerator(nil)
		rootStages := []singbox.CompileStage{
			{
				Name: "normalize_log",
				Apply: func(_ *singbox.ConfigGenerator, d *singbox.CompileDoc) error {
					docTree, err := d.EnsureDoc()
					if err != nil {
						return err
					}
					if singbox.NormalizeClientLogLevelInDoc(docTree) {
						d.MarkDirty()
					}
					return nil
				},
			},
			{
				Name: "harden_clash",
				Apply: func(_ *singbox.ConfigGenerator, d *singbox.CompileDoc) error {
					docTree, err := d.EnsureDoc()
					if err != nil {
						return err
					}
					changed, err := singbox.HardenClientClashAPIInDoc(docTree)
					if changed {
						d.MarkDirty()
					}
					return err
				},
			},
		}
		if err := singbox.RunCompileStages(g, doc, rootStages); err != nil {
			t.Fatalf("RunCompileStages failed: %v", err)
		}
		if doc.UnmarshalCount() != 1 {
			t.Fatalf("expected exactly 1 JSON unmarshal across consecutive tree stages, got %d", doc.UnmarshalCount())
		}
		if doc.MarshalCount() != 0 {
			t.Fatalf("expected 0 intermediate JSON marshals during tree stages, got %d", doc.MarshalCount())
		}

		fullGen := singbox.NewOfflineConfigGenerator(&config.Config{
			Gateway: config.GatewayConfig{IPv6Mode: config.GatewayIPv6CNOnly},
			CustomRules: config.CustomRulesConfig{
				Block: []config.BlockRule{{Target: "bad.example.com"}},
			},
		})
		fullDoc := singbox.NewCompileDoc(baseJSON, "linux")
		if err := singbox.RunCompileStages(fullGen, fullDoc, singbox.DefaultCompileStages()); err != nil {
			t.Fatalf("full DefaultCompileStages failed: %v", err)
		}
		if fullDoc.UnmarshalCount() != 1 || fullDoc.MarshalCount() != 0 {
			t.Fatalf("expected 1 unmarshal and 0 intermediate marshals across full 10-stage pipeline, got unmarshal=%d marshal=%d",
				fullDoc.UnmarshalCount(), fullDoc.MarshalCount())
		}
	})

	t.Run("concurrent_pipeline_race_safe", func(t *testing.T) {
		g := singbox.NewOfflineConfigGenerator(&config.Config{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := g.RunCompilePipeline(baseJSON, "linux")
				if err != nil || !strings.Contains(res, `"network": "udp"`) {
					t.Errorf("concurrent RunCompilePipeline failed: %v", err)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("HardenClientClashAPI_contract_and_ios_bypass", func(t *testing.T) {
		raw := `{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090","external_ui":"ui"}}}`
		iosOut, err := singbox.HardenClientClashAPI(raw, singbox.PlatformIOS)
		if err != nil || iosOut != raw {
			t.Fatalf("expected iOS HardenClientClashAPI to return raw untouched, got %q err=%v", iosOut, err)
		}
		linuxOut, err := singbox.HardenClientClashAPI(raw, "linux")
		if err != nil || !strings.Contains(linuxOut, "127.0.0.1:9090") || strings.Contains(linuxOut, `"external_ui"`) {
			t.Fatalf("expected linux HardenClientClashAPI to harden controller & strip UI, got %q err=%v", linuxOut, err)
		}
		if _, err := singbox.HardenClientClashAPI("{broken", "linux"); err == nil {
			t.Fatal("expected error on invalid JSON")
		}
	})

	t.Run("exported_stage_wrappers_backward_compatible", func(t *testing.T) {
		g := singbox.NewOfflineConfigGenerator(&config.Config{})
		grouped, err := g.InjectGroupsForPlatform(baseJSON, "linux")
		if err != nil || !strings.Contains(grouped, `"Proxy"`) {
			t.Fatalf("InjectGroupsForPlatform failed: err=%v out=%s", err, grouped)
		}
		routed, err := g.InjectTrafficRoutingForPlatform(grouped, "linux")
		if err != nil || !strings.Contains(routed, `"route"`) {
			t.Fatalf("InjectTrafficRoutingForPlatform failed: err=%v out=%s", err, routed)
		}
	})
}
