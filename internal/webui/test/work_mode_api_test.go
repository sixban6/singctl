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
}
