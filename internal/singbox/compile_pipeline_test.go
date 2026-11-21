package singbox

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"singctl/internal/config"
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
		g := &ConfigGenerator{
			config: &config.Config{},
			silent: true,
		}
		customRan := false
		extraStage := configCompileStage{
			Name: "custom_marker",
			AppliesTo: func(_ *ConfigGenerator, doc *compileDoc) bool {
				return !doc.isIOS
			},
			Apply: func(_ *ConfigGenerator, doc *compileDoc) error {
				customRan = true
				root := doc.root
				if root == nil {
					return nil
				}
				root["_ocp_tested"] = true
				doc.dirty = true
				return nil
			},
		}

		out, err := g.runCompilePipeline(baseJSON, "linux", extraStage)
		if err != nil {
			t.Fatalf("runCompilePipeline(linux) failed: %v", err)
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
		var nilGen *ConfigGenerator
		out, err := nilGen.runCompilePipeline(baseJSON, PlatformIOS)
		if err != nil {
			t.Fatalf("runCompilePipeline(ios) with nil generator failed: %v", err)
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
		g := &ConfigGenerator{silent: true}
		if _, err := g.runCompilePipeline("{broken", "linux"); err == nil {
			t.Fatalf("expected error on invalid JSON")
		}
		if _, err := g.runCompilePipeline(baseJSON, "freebsd"); err == nil {
			t.Fatalf("expected error on unsupported platform")
		}
		out, err := g.runCompilePipeline(baseJSON, "linux")
		if err != nil {
			t.Fatalf("runCompilePipeline failed: %v", err)
		}
		if strings.Contains(out, `"protocol": "udp"`) {
			t.Fatalf("expected legacy protocol=udp sanitized to network=udp:\n%s", out)
		}
		if !strings.Contains(out, `"network": "udp"`) {
			t.Fatalf("expected network=udp present after sanitization:\n%s", out)
		}
	})

	t.Run("single_tree_reuse_minimizes_json_roundtrips", func(t *testing.T) {
		doc := newCompileDoc(`{"log":{"level":"info"},"route":{"rules":[{"protocol":"udp"}]}}`, "linux")
		g := &ConfigGenerator{silent: true}
		rootStages := []configCompileStage{
			{
				Name: "normalize_log",
				Apply: func(_ *ConfigGenerator, d *compileDoc) error {
					_, err := normalizeClientLogLevelInRoot(d.root)
					d.dirty = true
					return err
				},
			},
			{
				Name: "harden_clash",
				Apply: func(_ *ConfigGenerator, d *compileDoc) error {
					_, err := hardenClientClashAPIInRoot(d.root)
					d.dirty = true
					return err
				},
			},
		}
		// Seed initial tree parse + run consecutive in-memory stages.
		if err := runCompileStages(g, doc, rootStages); err != nil {
			t.Fatalf("runCompileStages failed: %v", err)
		}
		if doc.unmarshalCount != 1 {
			t.Fatalf("expected exactly 1 JSON unmarshal across consecutive tree stages, got %d", doc.unmarshalCount)
		}
		if doc.marshalCount != 0 {
			t.Fatalf("expected 0 intermediate JSON marshals during tree stages, got %d", doc.marshalCount)
		}
	})

	t.Run("concurrent_pipeline_race_safe", func(t *testing.T) {
		g := &ConfigGenerator{config: &config.Config{}, silent: true}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, err := g.runCompilePipeline(baseJSON, "linux")
				if err != nil || !strings.Contains(res, `"network": "udp"`) {
					t.Errorf("concurrent runCompilePipeline failed: %v", err)
				}
			}()
		}
		wg.Wait()
	})

	t.Run("HardenClientClashAPI_contract_and_ios_bypass", func(t *testing.T) {
		raw := `{"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090","external_ui":"ui"}}}`
		iosOut, err := HardenClientClashAPI(raw, PlatformIOS)
		if err != nil || iosOut != raw {
			t.Fatalf("expected iOS HardenClientClashAPI to return raw untouched, got %q err=%v", iosOut, err)
		}
		linuxOut, err := HardenClientClashAPI(raw, "linux")
		if err != nil || !strings.Contains(linuxOut, "127.0.0.1:9090") || strings.Contains(linuxOut, `"external_ui"`) {
			t.Fatalf("expected linux HardenClientClashAPI to harden controller & strip UI, got %q err=%v", linuxOut, err)
		}
		if _, err := HardenClientClashAPI("{broken", "linux"); err == nil {
			t.Fatal("expected error on invalid JSON")
		}
	})
}
