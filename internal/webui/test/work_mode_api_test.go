// 文件职责：测试客户端 WebUI 零订阅工作模式（基础模式/审计模式/代理模式）查询、切换校验与 /api/status 暴露契约。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
	"singctl/internal/gateway"
	"singctl/internal/webui"
)

func TestGatewayWorkModeAPI_ZeroSubsBasicAuditAndProxyGuard(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}

	var appliedModes []string
	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{LANIP: "192.168.1.1", LANIface: "br-lan"}
		},
		WorkModeApplyForTest: func(_ context.Context, cfg *config.Config, targetMode string) (bool, string, error) {
			appliedModes = append(appliedModes, targetMode)
			return true, "mock applied " + targetMode, nil
		},
	})

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Default without subs: configured=auto, effective=audit, hasSubs=false
	rec := doJSON(http.MethodGet, "/api/gateway", nil)
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"workMode":"auto"`) ||
		!strings.Contains(rec.Body.String(), `"effectiveWorkMode":"audit"`) ||
		!strings.Contains(rec.Body.String(), `"hasSubs":false`) {
		t.Fatalf("unexpected default GET /api/gateway: code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2. Switching to proxy without subs must return 400 with clear Chinese message
	rec = doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":     "main",
		"workMode": "proxy",
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "订阅") {
		t.Fatalf("expected 400 when switching to proxy without subs, got code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 3. Explicit audit without subs succeeds and triggers WorkModeApplyForTest
	rec = doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":     "main",
		"workMode": "audit",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"effectiveWorkMode":"audit"`) {
		t.Fatalf("switching to audit failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(appliedModes) != 1 || appliedModes[0] != config.WorkModeAudit {
		t.Fatalf("expected WorkModeApplyForTest called with audit, got %v", appliedModes)
	}

	// 4. GET /api/status exposes workMode & effectiveWorkMode under gateway
	rec = doJSON(http.MethodGet, "/api/status", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"effectiveWorkMode":"audit"`) {
		t.Fatalf("expected effectiveWorkMode=audit in /api/status, got code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 5. Legacy "basic" request smoothly normalizes to "audit" for backward compatibility
	rec = doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":     "main",
		"workMode": "basic",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"effectiveWorkMode":"audit"`) {
		t.Fatalf("legacy basic workMode should normalize to audit, got code=%d body=%s", rec.Code, rec.Body.String())
	}

	// 6. Switching from basic -> audit WITH ipv6Mode="off" (exact frontend payload) MUST succeed
	// even when a stale/broken sing-box config.json exists on disk (e.g. unsupported tailscale DNS server).
	t.Run("switch_to_audit_with_ipv6_param_ignores_stale_singbox_config", func(t *testing.T) {
		dir2 := t.TempDir()
		cfg2 := filepath.Join(dir2, "singctl.yaml")
		sb2 := filepath.Join(dir2, "config.json")
		if err := config.Save(cfg2, &config.Config{}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sb2, []byte(`{invalid-json-stale-config`), 0600); err != nil {
			t.Fatal(err)
		}
		var called []string
		srv2 := webui.New(webui.Options{
			ConfigPath:        cfg2,
			SingBoxConfigPath: sb2,
			GatewayProberForTest: func() gateway.TopologyInfo {
				return gateway.TopologyInfo{LANIP: "192.168.1.1", LANIface: "br-lan"}
			},
			WorkModeApplyForTest: func(_ context.Context, _ *config.Config, targetMode string) (bool, string, error) {
				called = append(called, targetMode)
				return true, "switched to " + targetMode, nil
			},
		})
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(map[string]any{
			"mode":     "main",
			"workMode": "audit",
			"ipv6Mode": "off",
		})
		req := httptest.NewRequest(http.MethodPut, "/api/gateway", &buf)
		req.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		srv2.Mux.ServeHTTP(rec2, req)
		if rec2.Code != http.StatusOK {
			t.Fatalf("expected 200 switching basic->audit with stale config.json, got code=%d body=%s", rec2.Code, rec2.Body.String())
		}
		if len(called) != 1 || called[0] != config.WorkModeAudit {
			t.Fatalf("expected WorkModeApplyForTest called with audit, got %v", called)
		}
	})

	// 7. Re-applying same effective workMode:
	//    - when sing-box is STOPPED (e.g. upgraded from legacy basic mode), MUST invoke WorkModeApplyForTest to start audit kernel
	//    - when sing-box is ALREADY RUNNING, MUST skip redundant restart
	t.Run("same_workmode_applies_only_when_singbox_stopped", func(t *testing.T) {
		for _, tc := range []struct {
			name        string
			sbRunning   bool
			wantApplied int
		}{
			{name: "stopped_starts_audit_kernel", sbRunning: false, wantApplied: 1},
			{name: "running_skips_redundant_restart", sbRunning: true, wantApplied: 0},
		} {
			t.Run(tc.name, func(t *testing.T) {
				d := t.TempDir()
				cPath := filepath.Join(d, "singctl.yaml")
				if err := config.Save(cPath, &config.Config{
					Gateway: config.GatewayConfig{WorkMode: config.WorkModeAudit},
				}); err != nil {
					t.Fatal(err)
				}
				var called []string
				s := webui.New(webui.Options{
					ConfigPath: cPath,
					GatewayProberForTest: func() gateway.TopologyInfo {
						return gateway.TopologyInfo{LANIP: "192.168.1.1", LANIface: "br-lan"}
					},
					SingBoxRunningForTest: func() bool { return tc.sbRunning },
					WorkModeApplyForTest: func(_ context.Context, _ *config.Config, targetMode string) (bool, string, error) {
						called = append(called, targetMode)
						return true, "applied " + targetMode, nil
					},
				})
				var buf bytes.Buffer
				_ = json.NewEncoder(&buf).Encode(map[string]any{
					"mode":     "main",
					"workMode": "audit",
				})
				req := httptest.NewRequest(http.MethodPut, "/api/gateway", &buf)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				s.Mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Fatalf("expected 200, got code=%d body=%s", rec.Code, rec.Body.String())
				}
				if len(called) != tc.wantApplied {
					t.Fatalf("sbRunning=%v: applied count=%d (%v), want %d", tc.sbRunning, len(called), called, tc.wantApplied)
				}
			})
		}
	})
}

func TestGatewayPutDelegatedModeAndSideRouter(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{
		Gateway: config.GatewayConfig{Mode: "main", WorkMode: config.WorkModeAudit},
	}); err != nil {
		t.Fatal(err)
	}

	var appliedModes []string
	sbRunning := true
	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{LANIP: "192.168.55.1", LANIface: "br-lan"}
		},
		SingBoxRunningForTest: func() bool { return sbRunning },
		WorkModeApplyForTest: func(_ context.Context, cfg *config.Config, targetMode string) (bool, string, error) {
			appliedModes = append(appliedModes, targetMode)
			if targetMode == config.WorkModeDelegated {
				sbRunning = false
			}
			return true, "mock applied " + targetMode, nil
		},
	})

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Side router role rejects workMode="delegated".
	recSide := doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":         "side",
		"mainRouterIP": "192.168.55.1",
		"workMode":     "delegated",
	})
	if recSide.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when side router selects delegated mode, got code=%d body=%s", recSide.Code, recSide.Body.String())
	}

	// 2. Reject invalid / self-looped sideRouterIP.
	for _, badIP := range []string{"127.0.0.1", "192.168.55.1", "8.8.8.8", "192.168.55.88;id"} {
		recBad := doJSON(http.MethodPut, "/api/gateway", map[string]any{
			"mode":         "main",
			"workMode":     "delegated",
			"sideRouterIP": badIP,
		})
		if recBad.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid sideRouterIP %q, got code=%d body=%s", badIP, recBad.Code, recBad.Body.String())
		}
	}

	// 3. Valid switch to delegated mode with sideRouterIP saves 0600, applies live stop, and exposes via GET /api/gateway & /api/status.
	failoverFalse := false
	recOK := doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":               "main",
		"workMode":           "delegated",
		"sideRouterIP":       "192.168.55.88",
		"sideRouterFailover": failoverFalse,
	})
	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 switching to delegated mode, got code=%d body=%s", recOK.Code, recOK.Body.String())
	}
	if len(appliedModes) != 1 || appliedModes[0] != config.WorkModeDelegated {
		t.Fatalf("expected WorkModeApplyForTest called with delegated, got %v", appliedModes)
	}
	if !strings.Contains(recOK.Body.String(), `"effectiveWorkMode":"delegated"`) ||
		!strings.Contains(recOK.Body.String(), `"sideRouterIP":"192.168.55.88"`) ||
		!strings.Contains(recOK.Body.String(), `"sideRouterFailover":false`) {
		t.Fatalf("unexpected delegated response body: %s", recOK.Body.String())
	}

	recGet := doJSON(http.MethodGet, "/api/gateway", nil)
	if recGet.Code != http.StatusOK || !strings.Contains(recGet.Body.String(), `"sideRouterStatus"`) || !strings.Contains(recGet.Body.String(), `"sideRouterIP":"192.168.55.88"`) {
		t.Fatalf("expected sideRouterStatus & sideRouterIP in GET /api/gateway: %s", recGet.Body.String())
	}

	recStatus := doJSON(http.MethodGet, "/api/status", nil)
	if recStatus.Code != http.StatusOK || !strings.Contains(recStatus.Body.String(), `"effectiveWorkMode":"delegated"`) || !strings.Contains(recStatus.Body.String(), `"sideRouterIP":"192.168.55.88"`) {
		t.Fatalf("expected delegated status in GET /api/status: %s", recStatus.Body.String())
	}
}

func TestGatewayAutoDerivation_BindUnbindSideRouterAndSubsTransition(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	// 故意预置历史 work_mode: audit，验证自动推导不再被旧配置锁死
	if err := config.Save(cfgPath, &config.Config{
		Gateway: config.GatewayConfig{Mode: "main", WorkMode: config.WorkModeAudit},
	}); err != nil {
		t.Fatal(err)
	}

	var appliedModes []string
	sbRunning := true
	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		GatewayProberForTest: func() gateway.TopologyInfo {
			return gateway.TopologyInfo{LANIP: "192.168.55.1", LANIface: "br-lan"}
		},
		SingBoxRunningForTest: func() bool { return sbRunning },
		WorkModeApplyForTest: func(_ context.Context, _ *config.Config, targetMode string) (bool, string, error) {
			appliedModes = append(appliedModes, targetMode)
			sbRunning = targetMode != config.WorkModeDelegated
			return true, "mock auto " + targetMode, nil
		},
	})

	doJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. 主路由仅绑定 sideRouterIP（不传 workMode）-> 自动切入 delegated 并停用本机 sing-box
	recBind := doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":               "main",
		"sideRouterIP":       "192.168.55.88",
		"sideRouterFailover": true,
	})
	if recBind.Code != http.StatusOK || !strings.Contains(recBind.Body.String(), `"effectiveWorkMode":"delegated"`) {
		t.Fatalf("expected auto delegated on binding sideRouterIP, got code=%d body=%s", recBind.Code, recBind.Body.String())
	}
	if len(appliedModes) != 1 || appliedModes[0] != config.WorkModeDelegated || sbRunning {
		t.Fatalf("expected WorkModeApplyForTest(delegated) and sbRunning=false, applied=%v sbRunning=%v", appliedModes, sbRunning)
	}

	// 2. 主路由解绑 sideRouterIP（不传 workMode）-> 清除残留 work_mode 并自动恢复 audit
	recUnbind := doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":         "main",
		"sideRouterIP": "",
	})
	if recUnbind.Code != http.StatusOK || !strings.Contains(recUnbind.Body.String(), `"effectiveWorkMode":"audit"`) {
		t.Fatalf("expected auto audit on unbinding sideRouterIP, got code=%d body=%s", recUnbind.Code, recUnbind.Body.String())
	}
	if len(appliedModes) != 2 || appliedModes[1] != config.WorkModeAudit || !sbRunning {
		t.Fatalf("expected WorkModeApplyForTest(audit) and sbRunning=true, applied=%v sbRunning=%v", appliedModes, sbRunning)
	}
	loadedAfterUnbind, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if loadedAfterUnbind.Gateway.SideRouterIP != "" || loadedAfterUnbind.Gateway.WorkMode != "" {
		t.Fatalf("expected sideRouterIP and work_mode cleared after unbind, got %+v", loadedAfterUnbind.Gateway)
	}

	// 3. 重新绑定为旁路由托管后，直接切换角色为 side（不传 workMode）-> 自动清 sideRouterIP 并恢复 audit
	_ = doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":         "main",
		"sideRouterIP": "192.168.55.88",
	})
	recSide := doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":         "side",
		"mainRouterIP": "192.168.55.254",
	})
	if recSide.Code != http.StatusOK || !strings.Contains(recSide.Body.String(), `"effectiveWorkMode":"audit"`) {
		t.Fatalf("expected switch to side router auto-deriving audit, got code=%d body=%s", recSide.Code, recSide.Body.String())
	}
	if last := appliedModes[len(appliedModes)-1]; last != config.WorkModeAudit || !sbRunning {
		t.Fatalf("expected side router switch to trigger audit kernel, applied=%v sbRunning=%v", appliedModes, sbRunning)
	}

	// 4. 添加有效订阅后 GET /api/gateway & GET /api/status 自动变为 proxy（不被历史 work_mode 锁死），清空订阅后自动回切 audit
	recSubAdd := doJSON(http.MethodPut, "/api/sb/subs", map[string]any{
		"subs": []map[string]any{{"name": "main", "url": "https://example.com/sub"}},
		"hy2":  map[string]any{"up": 0, "down": 0},
	})
	if recSubAdd.Code != http.StatusOK {
		t.Fatalf("PUT /api/sb/subs add failed: code=%d body=%s", recSubAdd.Code, recSubAdd.Body.String())
	}
	if g := doJSON(http.MethodGet, "/api/gateway", nil); !strings.Contains(g.Body.String(), `"effectiveWorkMode":"proxy"`) {
		t.Fatalf("expected GET /api/gateway effectiveWorkMode=proxy after adding sub: %s", g.Body.String())
	}
	if st := doJSON(http.MethodGet, "/api/status", nil); !strings.Contains(st.Body.String(), `"effectiveWorkMode":"proxy"`) {
		t.Fatalf("expected GET /api/status effectiveWorkMode=proxy after adding sub: %s", st.Body.String())
	}

	countBeforeClear := len(appliedModes)
	recSubClear := doJSON(http.MethodPut, "/api/sb/subs", map[string]any{
		"subs": []any{},
		"hy2":  map[string]any{"up": 0, "down": 0},
	})
	if recSubClear.Code != http.StatusOK {
		t.Fatalf("PUT /api/sb/subs clear failed: code=%d body=%s", recSubClear.Code, recSubClear.Body.String())
	}
	if g := doJSON(http.MethodGet, "/api/gateway", nil); !strings.Contains(g.Body.String(), `"effectiveWorkMode":"audit"`) {
		t.Fatalf("expected GET /api/gateway effectiveWorkMode=audit after clearing subs: %s", g.Body.String())
	}
	if len(appliedModes) != countBeforeClear+1 || appliedModes[len(appliedModes)-1] != config.WorkModeAudit {
		t.Fatalf("expected clearing all subs to hot-apply audit mode, appliedModes=%v", appliedModes)
	}
}
