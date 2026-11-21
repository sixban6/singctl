package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

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
		spec, err := parseRuleSetImportSpec("https://example.com/rules/game.json", "", "192.0.2.15")
		if err != nil {
			t.Fatalf("parseRuleSetImportSpec failed: %v", err)
		}
		if spec.tag != "block-game" || spec.normSource != "192.0.2.15/32" || spec.displaySource != "192.0.2.15" {
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
		enf := NewEnforcer(cfg, yamlPath)
		enf.SetPathsForTest(sbPath, "", []string{clashSrv.URL}, "")
		enf.httpClient = rsSrv.Client()
		enf.resolveSingBoxBin = func() string { return "" }

		res, err := enf.ImportAndBlockRuleSet(t.Context(), rsSrv.URL+"/telemetry-block.json", "", "192.0.2.15", "PCDN/遥测测试")
		if err != nil {
			t.Fatalf("ImportAndBlockRuleSet failed: %v", err)
		}
		if res.Target != "ruleset:block-telemetry-block" || !res.ConfigSaved || deletedCount.Load() != 1 {
			t.Fatalf("unexpected import result: %+v deleted=%d", res, deletedCount.Load())
		}
	})

	t.Run("invalid_inputs_and_schemes", func(t *testing.T) {
		if _, err := parseRuleSetImportSpec("   ", "", ""); err == nil {
			t.Fatalf("expected error on blank input")
		}
		if _, err := parseRuleSetImportSpec("ftp://example.com/bad.srs", "", ""); err == nil {
			t.Fatalf("expected error on non-http scheme")
		}
		if _, err := parseRuleSetImportSpec("https://example.com/ok.srs", "", "not-an-ip"); err == nil {
			t.Fatalf("expected error on invalid source IP")
		}
	})

	t.Run("anti_self_lock_rejects_protected_targets_before_write", func(t *testing.T) {
		cfg := baseCfg()
		for _, tc := range []struct {
			name   string
			parsed decompiledSRS
		}{
			{
				name: "user_subscription_domain",
				parsed: func() decompiledSRS {
					var s decompiledSRS
					s.Rules = append(s.Rules, struct {
						Domain        srsStringList `json:"domain"`
						DomainSuffix  srsStringList `json:"domain_suffix"`
						DomainKeyword srsStringList `json:"domain_keyword"`
						IPCIDR        srsStringList `json:"ip_cidr"`
					}{DomainSuffix: srsStringList{"sub.example.com"}})
					return s
				}(),
			},
			{
				name: "protected_bootstrap_ip",
				parsed: func() decompiledSRS {
					var s decompiledSRS
					s.Rules = append(s.Rules, struct {
						Domain        srsStringList `json:"domain"`
						DomainSuffix  srsStringList `json:"domain_suffix"`
						DomainKeyword srsStringList `json:"domain_keyword"`
						IPCIDR        srsStringList `json:"ip_cidr"`
					}{IPCIDR: srsStringList{"1.1.1.1/32"}})
					return s
				}(),
			},
			{
				name: "gateway_lan_ip",
				parsed: func() decompiledSRS {
					var s decompiledSRS
					s.Rules = append(s.Rules, struct {
						Domain        srsStringList `json:"domain"`
						DomainSuffix  srsStringList `json:"domain_suffix"`
						DomainKeyword srsStringList `json:"domain_keyword"`
						IPCIDR        srsStringList `json:"ip_cidr"`
					}{IPCIDR: srsStringList{"192.168.1.1/32"}})
					return s
				}(),
			},
		} {
			if _, _, err := validateDecompiledRuleSetSafety(cfg, "block-evil", &tc.parsed); err == nil {
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

		enf := &Enforcer{httpClient: failSrv.Client()}
		spec := ruleSetImportSpec{tag: "block-cached", sourceURL: failSrv.URL + "/cached.srs"}
		got, err := enf.fetchRuleSetPayload(t.Context(), spec, dstPath)
		if err != nil || string(got) != string(cachedContent) {
			t.Fatalf("expected cache fallback (%q, %v), got (%q, %v)", string(cachedContent), nil, string(got), err)
		}
		if _, err := enf.fetchRuleSetPayload(t.Context(), spec, filepath.Join(tmpDir, "missing.srs")); err == nil {
			t.Fatalf("expected error when both upstream and cache fail")
		}
	})

	t.Run("idempotent_reimport_and_concurrent_safety_checks", func(t *testing.T) {
		var parsed decompiledSRS
		parsed.Rules = append(parsed.Rules, struct {
			Domain        srsStringList `json:"domain"`
			DomainSuffix  srsStringList `json:"domain_suffix"`
			DomainKeyword srsStringList `json:"domain_keyword"`
			IPCIDR        srsStringList `json:"ip_cidr"`
		}{DomainSuffix: srsStringList{"tracker.example.org", "ads.example.org"}})

		cfg := baseCfg()
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cnt, samples, err := validateDecompiledRuleSetSafety(cfg, "block-ads", &parsed)
				if err != nil || cnt != 2 || len(samples) != 2 {
					t.Errorf("concurrent validateDecompiledRuleSetSafety = (%d, %v, %v)", cnt, samples, err)
				}
			}()
		}
		wg.Wait()
	})
}
