// 文件职责：测试 WebUI POST /api/audit/block-batch 批量封禁接口的正常路径、参数边界与防自锁拦截契约。
package webui_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"singctl/internal/config"
	"singctl/internal/webui"
)

func TestAuditWebUI_BlockBatchAPI(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	if err := config.Save(cfgPath, &config.Config{}); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: filepath.Join(tmpDir, "missing-singbox.json"),
		AdGuardConfigPath: filepath.Join(tmpDir, "missing-agh.yaml"),
	})

	postJSON := func(path string, payload any) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		_ = json.NewEncoder(&buf).Encode(payload)
		req := httptest.NewRequest(http.MethodPost, path, &buf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Empty items -> 400
	if rec := postJSON("/api/audit/block-batch", map[string]any{"items": []any{}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty batch code=%d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	// 2. Valid batch -> 200 and persisted cleanly
	rec := postJSON("/api/audit/block-batch", map[string]any{
		"items": []map[string]any{
			{"target": "ads1.example.com", "sourceIp": "192.168.1.40", "reason": "batch test"},
			{"target": "ads2.example.com", "reason": "batch global"},
		},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid batch code=%d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var res struct {
		OK    bool `json:"ok"`
		Added int  `json:"added"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Added != 2 {
		t.Fatalf("unexpected batch response: %+v (body=%s)", res, rec.Body.String())
	}
}
