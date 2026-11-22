// 文件职责：验证 serverweb 接入 common/httpx 后的 4MiB 防 OOM 请求体上限、畸形/尾随垃圾 JSON 拦截、遥测组合字段与静态缓存头契约。
package serverweb_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/common/httpx"
	"singctl/internal/serverweb"
)

func TestServerWeb_HTTPXBodyLimitsAndTelemetrySniffingComposition(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sbCfgPath, []byte(`{"inbounds":[]}`), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       filepath.Join(tmpDir, "sub-store"),
		FleetFilePath:     filepath.Join(tmpDir, "fleet.yaml"),
		BanFilePath:       filepath.Join(tmpDir, "bans.json"),
		AuditFilePath:     filepath.Join(tmpDir, "audit.json"),
		Username:          "opsadmin",
		Password:          "Password123",
	})
	defer srv.Limiter().Close()
	srv.SniffTracker().EnableSystemProbe = false

	doWrite := func(method, path, contentType, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.SetBasicAuth("opsadmin", "Password123")
		req.RemoteAddr = "127.0.0.1:41000"
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	oversized := `{"sni":"` + strings.Repeat("a", int(httpx.DefaultMaxBodyBytes)+1024) + `.example.com"}`
	cases := []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		wantCode    int
	}{
		{
			name:        "missing_json_content_type_rejected_415",
			method:      http.MethodPut,
			path:        "/api/server/sni",
			contentType: "text/plain",
			body:        `{"sni":"www.example.com"}`,
			wantCode:    http.StatusUnsupportedMediaType,
		},
		{
			name:        "oversized_write_body_rejected_413",
			method:      http.MethodPut,
			path:        "/api/server/sni",
			contentType: "application/json",
			body:        oversized,
			wantCode:    http.StatusRequestEntityTooLarge,
		},
		{
			name:        "trailing_garbage_json_rejected_400",
			method:      http.MethodPut,
			path:        "/api/server/sni",
			contentType: "application/json",
			body:        `{"sni":"www.example.com"}{"injected":true}`,
			wantCode:    http.StatusBadRequest,
		},
		{
			name:        "oversized_backup_restore_rejected_413",
			method:      http.MethodPost,
			path:        "/api/server/backup/restore",
			contentType: "application/json",
			body:        `{"passphrase":"StrongPass#2026","data":"` + strings.Repeat("x", int(httpx.DefaultMaxBodyBytes)+1024) + `"}`,
			wantCode:    http.StatusRequestEntityTooLarge,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doWrite(tc.method, tc.path, tc.contentType, tc.body)
			if rec.Code != tc.wantCode {
				t.Fatalf("%s: status = %d, want %d (body=%s)", tc.name, rec.Code, tc.wantCode, rec.Body.String())
			}
		})
	}

	// Verify /api/server/telemetry/snapshot preserves "sniffing" field via boundary composition
	srv.SniffTracker().Observe("198.51.100.77", "TLS/443 握手探测", "masqueraded", 4)
	snapReq := httptest.NewRequest(http.MethodGet, "/api/server/telemetry/snapshot", nil)
	snapReq.SetBasicAuth("opsadmin", "Password123")
	snapReq.RemoteAddr = "127.0.0.1:41001"
	snapRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(snapRec, snapReq)
	if snapRec.Code != http.StatusOK {
		t.Fatalf("GET /api/server/telemetry/snapshot status = %d: %s", snapRec.Code, snapRec.Body.String())
	}
	var snapPayload struct {
		Sniffing *serverweb.SniffSummary `json:"sniffing"`
	}
	if err := json.Unmarshal(snapRec.Body.Bytes(), &snapPayload); err != nil {
		t.Fatalf("unmarshal telemetry snapshot: %v", err)
	}
	if snapPayload.Sniffing == nil || snapPayload.Sniffing.TotalSniffIPs != 1 {
		t.Fatalf("expected composed sniffing summary with TotalSniffIPs=1, got %+v", snapPayload.Sniffing)
	}

	// Verify static index.html no-store and hashed /assets/*.js immutable Cache-Control
	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /, got %d", rootRec.Code)
	}
	if cc := rootRec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("expected no-store Cache-Control on /, got %q", cc)
	}

	html := rootRec.Body.String()
	idx := strings.Index(html, "assets/")
	if idx < 0 {
		t.Fatalf("expected embedded index.html to reference assets/*, got:\n%s", html)
	}
	rest := html[idx:]
	endIdx := strings.IndexAny(rest, `"' >`)
	if endIdx <= 0 {
		t.Fatalf("failed to parse asset path from %q", rest)
	}
	assetPath := "/" + rest[:endIdx]
	assetReq := httptest.NewRequest(http.MethodGet, assetPath, nil)
	assetRec := httptest.NewRecorder()
	srv.Mux.ServeHTTP(assetRec, assetReq)
	if assetRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for %s, got %d", assetPath, assetRec.Code)
	}
	if cc := assetRec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Fatalf("expected immutable Cache-Control on %s, got %q", assetPath, cc)
	}
}
