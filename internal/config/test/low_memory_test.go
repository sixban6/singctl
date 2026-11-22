// 文件职责：验证客户端自适应低内存模式（low_memory: auto/on/off 与布尔宽容解析）、EffectiveLowMemory 阈值边界、AST 无损保存与迁移幂等性。
package config_test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
	"singctl/configs"
	"singctl/internal/config"
)

func TestLowMemoryConfig_TableDrivenParsingAndBoundaries(t *testing.T) {
	const (
		mib      uint64 = 1024 * 1024
		n60ProKB uint64 = 491040 * 1024 // ~479.5 MiB ImmortalWrt N60 Pro
	)

	t.Run("normalize_low_memory_mode", func(t *testing.T) {
		cases := []struct {
			raw    string
			want   string
			wantOK bool
		}{
			{"", config.LowMemoryAuto, true},
			{"auto", config.LowMemoryAuto, true},
			{"  AUTO  ", config.LowMemoryAuto, true},
			{"on", config.LowMemoryOn, true},
			{"ON", config.LowMemoryOn, true},
			{"true", config.LowMemoryOn, true},
			{"TRUE", config.LowMemoryOn, true},
			{"1", config.LowMemoryOn, true},
			{"yes", config.LowMemoryOn, true},
			{"enabled", config.LowMemoryOn, true},
			{"off", config.LowMemoryOff, true},
			{"OFF", config.LowMemoryOff, true},
			{"false", config.LowMemoryOff, true},
			{"FALSE", config.LowMemoryOff, true},
			{"0", config.LowMemoryOff, true},
			{"no", config.LowMemoryOff, true},
			{"disabled", config.LowMemoryOff, true},
			{"invalid", "", false},
			{"on;rm -rf /", "", false},
			{strings.Repeat("x", 1024), "", false},
		}
		for _, tc := range cases {
			got, ok := config.NormalizeLowMemoryMode(tc.raw)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("NormalizeLowMemoryMode(%q) = (%q, %v), want (%q, %v)", tc.raw, got, ok, tc.want, tc.wantOK)
			}
		}
	})

	t.Run("effective_low_memory_ram_boundaries", func(t *testing.T) {
		var nilCfg *config.Config
		if nilCfg.EffectiveLowMemory(0) {
			t.Fatal("nil config with 0 RAM should be false")
		}
		if !nilCfg.EffectiveLowMemory(224 * mib) {
			t.Fatal("nil config with 224 MiB should auto-enable low_memory")
		}
		if !nilCfg.EffectiveLowMemory(n60ProKB) {
			t.Fatal("nil config with N60 Pro 479.5 MiB should auto-enable low_memory")
		}
		if !nilCfg.EffectiveLowMemory(512 * mib) {
			t.Fatal("nil config at exact 512 MiB boundary should auto-enable low_memory")
		}
		if nilCfg.EffectiveLowMemory(512*mib + 1) {
			t.Fatal("nil config at 512 MiB + 1 byte should be false")
		}

		cases := []struct {
			name     string
			mode     config.LowMemoryMode
			totalRAM uint64
			want     bool
		}{
			{"empty_0_ram", "", 0, false},
			{"empty_1_byte", "", 1, true},
			{"empty_224m", "", 224 * mib, true},
			{"empty_256m", "", 256 * mib, true},
			{"empty_384m", "", 384 * mib, true},
			{"empty_n60pro_479m", "", n60ProKB, true},
			{"empty_512m_exact", "", 512 * mib, true},
			{"empty_512m_plus_1", "", 512*mib + 1, false},
			{"empty_4g", "", 4096 * mib, false},
			{"empty_max_uint64", "", math.MaxUint64, false},
			{"auto_256m", config.LowMemoryAuto, 256 * mib, true},
			{"auto_512m", config.LowMemoryAuto, 512 * mib, true},
			{"auto_1g", config.LowMemoryAuto, 1024 * mib, false},
			{"on_0_ram", config.LowMemoryOn, 0, true},
			{"on_8g_ram", config.LowMemoryOn, 8192 * mib, true},
			{"off_0_ram", config.LowMemoryOff, 0, false},
			{"off_224m_ram", config.LowMemoryOff, 224 * mib, false},
			{"off_512m_ram", config.LowMemoryOff, 512 * mib, false},
		}
		for _, tc := range cases {
			cfg := &config.Config{LowMemory: tc.mode}
			if got := cfg.EffectiveLowMemory(tc.totalRAM); got != tc.want {
				t.Fatalf("%s: EffectiveLowMemory(mode=%q, ram=%d) = %v, want %v", tc.name, tc.mode, tc.totalRAM, got, tc.want)
			}
		}
	})

	t.Run("yaml_and_json_lenient_bool_and_colon_fix_and_malformed_rejection", func(t *testing.T) {
		dir := t.TempDir()
		yamlInputs := []struct {
			name     string
			yamlBody string
			wantLow  bool
			ram      uint64
			wantErr  bool
		}{
			{"bool_true_no_space", "low_memory:true\nsubs:\n  - name: a\n    url: https://example.com/s\n", true, 4096 * mib, false},
			{"bool_false_no_space", "low_memory:false\nsubs:\n  - name: a\n    url: https://example.com/s\n", false, 224 * mib, false},
			{"string_on_no_space", "low_memory:\"on\"\nsubs:\n  - name: a\n    url: https://example.com/s\n", true, 0, false},
			{"string_off", "low_memory: \"off\"\n", false, 256 * mib, false},
			{"string_auto", "low_memory: auto\n", true, n60ProKB, false},
			{"invalid_string_injection", "low_memory: \"on; rm -rf /\"\n", false, 0, true},
			{"invalid_sequence", "low_memory:\n  - on\n", false, 0, true},
			{"invalid_mapping", "low_memory:\n  nested: true\n", false, 0, true},
		}
		for _, tc := range yamlInputs {
			p := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.yamlBody), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(p)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("%s: expected Load error for malformed low_memory, got nil (cfg.LowMemory=%q)", tc.name, cfg.LowMemory)
				}
				continue
			}
			if err != nil {
				t.Fatalf("%s: unexpected Load error: %v", tc.name, err)
			}
			if got := cfg.EffectiveLowMemory(tc.ram); got != tc.wantLow {
				t.Fatalf("%s: EffectiveLowMemory(%d) = %v, want %v (mode=%q)", tc.name, tc.ram, got, tc.wantLow, cfg.LowMemory)
			}
		}

		// JSON bool & string tolerance
		var cfgTrue, cfgFalse, cfgBad config.Config
		if err := json.Unmarshal([]byte(`{"low_memory": true}`), &cfgTrue); err != nil || !cfgTrue.EffectiveLowMemory(0) {
			t.Fatalf("JSON true unmarshal failed: err=%v mode=%q", err, cfgTrue.LowMemory)
		}
		if err := json.Unmarshal([]byte(`{"low_memory": false}`), &cfgFalse); err != nil || cfgFalse.EffectiveLowMemory(224*mib) {
			t.Fatalf("JSON false unmarshal failed: err=%v mode=%q", err, cfgFalse.LowMemory)
		}
		if err := json.Unmarshal([]byte(`{"low_memory": "bad_val"}`), &cfgBad); err == nil {
			t.Fatal("expected JSON unmarshal error on invalid low_memory string")
		}
	})

	t.Run("save_ast_cleanup_migrate_clone_and_race_safety", func(t *testing.T) {
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "singctl.yaml")
		cfg := &config.Config{
			LowMemory: config.LowMemoryOn,
			Subs:      []config.Subscription{{Name: "main", URL: "https://example.com/sub"}},
		}
		if err := config.Save(cfgPath, cfg); err != nil {
			t.Fatalf("Save(on) failed: %v", err)
		}
		reloaded, err := config.Load(cfgPath)
		if err != nil {
			t.Fatalf("Load after Save(on) failed: %v", err)
		}
		if !reloaded.EffectiveLowMemory(8192 * mib) {
			t.Fatalf("expected EffectiveLowMemory=true after Save(on), got mode=%q", reloaded.LowMemory)
		}

		// Migrate preserves low_memory on client config without injecting server block
		rawOn, _ := os.ReadFile(cfgPath)
		migratedBytes, err := config.MigrateConfigBytes(rawOn, configs.DefaultConfigYAML)
		if err != nil {
			t.Fatalf("MigrateConfigBytes failed: %v", err)
		}
		if strings.Contains(string(migratedBytes), "\nserver:") {
			t.Fatalf("client migration with low_memory injected server block:\n%s", string(migratedBytes))
		}
		var migratedCfg config.Config
		if err := yaml.Unmarshal(migratedBytes, &migratedCfg); err != nil || !migratedCfg.EffectiveLowMemory(8192*mib) {
			t.Fatalf("migrated config lost low_memory=on: err=%v mode=%q", err, migratedCfg.LowMemory)
		}

		// Clearing LowMemory to "" removes stale key from AST on Save
		reloaded.LowMemory = ""
		if err := config.Save(cfgPath, reloaded); err != nil {
			t.Fatalf("Save(clear) failed: %v", err)
		}
		clearedBytes, _ := os.ReadFile(cfgPath)
		if strings.Contains(string(clearedBytes), "low_memory:") {
			t.Fatalf("expected cleared low_memory removed from YAML AST, got:\n%s", string(clearedBytes))
		}

		// Concurrent race check
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				cp := cfg.Clone()
				if !cp.EffectiveLowMemory(0) {
					t.Errorf("cloned config lost LowMemory")
				}
				cp.LowMemory = config.LowMemoryOff
				if !cfg.EffectiveLowMemory(0) {
					t.Errorf("mutating clone affected original")
				}
				_, _ = config.SaveConfigBytesAST(configs.ClientConfigYAML, cp)
			})
		}
		wg.Wait()
	})
}
