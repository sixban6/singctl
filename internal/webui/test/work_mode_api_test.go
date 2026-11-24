// 文件职责：测试客户端 WebUI 零订阅工作模式（基础模式/审计模式/代理模式）查询、切换校验与 /api/status 暴露契约。
package webui_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

	// 1. Default without subs: configured=auto, effective=basic, hasSubs=false
	rec := doJSON(http.MethodGet, "/api/gateway", nil)
	if rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"workMode":"auto"`) ||
		!strings.Contains(rec.Body.String(), `"effectiveWorkMode":"basic"`) ||
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

	// 3. Switching to audit without subs succeeds and triggers WorkModeApplyForTest
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

	// 5. Switching back to basic without subs succeeds
	rec = doJSON(http.MethodPut, "/api/gateway", map[string]any{
		"mode":     "main",
		"workMode": "basic",
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"effectiveWorkMode":"basic"`) {
		t.Fatalf("switching back to basic failed: code=%d body=%s", rec.Code, rec.Body.String())
	}
}
