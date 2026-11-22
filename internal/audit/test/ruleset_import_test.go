// 文件职责：覆盖规则集整包导入（ImportAndBlockRuleSet）的输入规范解析、防自锁校验、本地缓存回退与并发安全测试。
package audit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestRuleSetImport_TableDrivenBoundaries(t *testing.T) {
	baseCfg := func() *config.Config {
		return &config.Config{
			Subs: []config.Subscription{
				{Name: "main", URL: "https://sub.example.com/api/v1?token=sub-test"},
			},
			Gateway: config.GatewayConfig{
				MainRouterIP: "192.168.1.1",
			},
		}
	}

	t.Run("spec_parsing_happy_path_and_end_to_end_mock_import", func(t *testing.T) {
		spec, err := audit.ParseRuleSetImportSpec("https://example.com/rules/game.json", "", "192.0.2.15")
		if err != nil {
			t.Fatalf("ParseRuleSetImportSpec failed: %v", err)
		}
		if spec.Tag != "block-game" || spec.NormSource != "192.0.2.15/32" || spec.DisplaySource != "192.0.2.15" {
			t.Fatalf("unexpected parsed spec: %+v", spec)
		}

		rsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"version":2,"rules":[{"domain_suffix":["telemetry.bad.example.org"]}]}`))
		}))
		defer rsSrv.Close()

		var deletedCount atomic.Int32
		clashSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/connections" {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"connections": []any{
						map[string]any{
							"id": "conn-bad-1",
							"metadata": map[string]any{
								"sourceIP":      "192.0.2.15",
								"host":          "app.telemetry.bad.example.org",
								"destinationIP": "198.51.100.99",
							},
						},
						map[string]any{
							"id": "conn-safe-2",
							"metadata": map[string]any{
								"sourceIP":      "192.0.2.15",
								"host":          "ok.example.org",
								"destinationIP": "203.0.113.5",
							},
						},
					},
				})
				return
			}
			if r.Method == http.MethodDelete && r.URL.Path == "/connections/conn-bad-1" {
				deletedCount.Add(1)
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer clashSrv.Close()

		tmpDir := t.TempDir()
		yamlPath := filepath.Join(tmpDir, "singctl.yaml")
		if err := os.WriteFile(yamlPath, []byte("subs:\n  - name: main\n    url: https://sub.example.com/sub\n"), 0600); err != nil {
			t.Fatal(err)
		}
		sbPath := filepath.Join(tmpDir, "singbox.json")
		if err := os.WriteFile(sbPath, []byte(`{"dns":{"rules":[]},"route":{"rules":[{"action":"sniff"}]}}`), 0600); err != nil {
			t.Fatal(err)
		}

		cfg := baseCfg()
		enf := audit.NewEnforcer(cfg, yamlPath)
		enf.SetPathsForTest(sbPath, "", []string{clashSrv.URL}, "")
		enf.SetDeps(rsSrv.Client(), func() string { return "" })

		res, err := enf.ImportAndBlockRuleSet(t.Context(), rsSrv.URL+"/telemetry-block.json", "", "192.0.2.15", "PCDN/遥测测试")
		if err != nil {
			t.Fatalf("ImportAndBlockRuleSet failed: %v", err)
		}
		if res.Target != "ruleset:block-telemetry-block" || !res.ConfigSaved || deletedCount.Load() != 1 {
			t.Fatalf("unexpected import result: %+v deleted=%d", res, deletedCount.Load())
		}
	})

	t.Run("invalid_inputs_and_schemes", func(t *testing.T) {
		if _, err := audit.ParseRuleSetImportSpec("   ", "", ""); err == nil {
			t.Fatalf("expected error on blank input")
		}
		if _, err := audit.ParseRuleSetImportSpec("ftp://example.com/bad.srs", "", ""); err == nil {
			t.Fatalf("expected error on non-http scheme")
		}
		if _, err := audit.ParseRuleSetImportSpec("https://example.com/ok.srs", "", "not-an-ip"); err == nil {
			t.Fatalf("expected error on invalid source IP")
		}
	})

	t.Run("anti_self_lock_rejects_protected_targets_before_write", func(t *testing.T) {
		cfg := baseCfg()
		for _, tc := range []struct {
			name   string
			parsed audit.DecompiledSRS
		}{
			{
				name: "user_subscription_domain",
				parsed: audit.DecompiledSRS{
					Rules: []audit.DecompiledSRSRule{
						{DomainSuffix: audit.SRSStringList{"sub.example.com"}},
					},
				},
			},
			{
				name: "protected_bootstrap_ip",
				parsed: audit.DecompiledSRS{
					Rules: []audit.DecompiledSRSRule{
						{IPCIDR: audit.SRSStringList{"1.1.1.1/32"}},
					},
				},
			},
			{
				name: "gateway_lan_ip",
				parsed: audit.DecompiledSRS{
					Rules: []audit.DecompiledSRSRule{
						{IPCIDR: audit.SRSStringList{"192.168.1.1/32"}},
					},
				},
			},
		} {
			if _, _, err := audit.ValidateDecompiledRuleSetSafety(cfg, "block-evil", &tc.parsed); err == nil {
				t.Fatalf("case %s: expected anti-self-lock error, got nil", tc.name)
			}
		}
	})

	t.Run("upstream_failure_falls_back_to_local_srs_cache", func(t *testing.T) {
		failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
		defer failSrv.Close()

		tmpDir := t.TempDir()
		dstPath := filepath.Join(tmpDir, "block-cached.srs")
		cachedContent := []byte("SRS\x02cached-binary-payload-more-than-16-bytes")
		if err := os.WriteFile(dstPath, cachedContent, 0600); err != nil {
			t.Fatal(err)
		}

		enf := audit.NewEnforcer(nil, "")
		enf.SetDeps(failSrv.Client(), nil)
		spec := audit.RuleSetImportSpec{Tag: "block-cached", SourceURL: failSrv.URL + "/cached.srs"}
		got, err := enf.FetchRuleSetPayload(t.Context(), spec, dstPath)
		if err != nil || string(got) != string(cachedContent) {
			t.Fatalf("expected cache fallback (%q, %v), got (%q, %v)", string(cachedContent), nil, string(got), err)
		}
		if _, err := enf.FetchRuleSetPayload(t.Context(), spec, filepath.Join(tmpDir, "missing.srs")); err == nil {
			t.Fatalf("expected error when both upstream and cache fail")
		}
	})

	t.Run("idempotent_reimport_and_concurrent_safety_checks", func(t *testing.T) {
		parsed := audit.DecompiledSRS{
			Rules: []audit.DecompiledSRSRule{
				{DomainSuffix: audit.SRSStringList{"tracker.example.org", "ads.example.org"}},
			},
		}

		cfg := baseCfg()
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cnt, samples, err := audit.ValidateDecompiledRuleSetSafety(cfg, "block-ads", &parsed)
				if err != nil || cnt != 2 || len(samples) != 2 {
					t.Errorf("concurrent ValidateDecompiledRuleSetSafety = (%d, %v, %v)", cnt, samples, err)
				}
			}()
		}
		wg.Wait()
	})
}
