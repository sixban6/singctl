// 文件职责：验证服务端 WebUI（静态页面与 API）严格零外联 CSP、无内联脚本与安全响应头契约。
package serverweb_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"singctl/internal/serverweb"
)

var scriptTagRE = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

func hasInlineScript(html string) bool {
	for _, m := range scriptTagRE.FindAllStringSubmatch(html, -1) {
		attrs := strings.ToLower(m[1])
		body := strings.TrimSpace(m[2])
		if !strings.Contains(attrs, "src=") && body != "" {
			return true
		}
	}
	return false
}

func TestServerWebUISecurityHeadersAndStrictCSP(t *testing.T) {
	tmp := t.TempDir()
	srv := serverweb.New(serverweb.Options{
		ConfigPath:  filepath.Join(tmp, "singctl.yaml"),
		SubStoreDir: filepath.Join(tmp, "sub-store"),
		BanFilePath: filepath.Join(tmp, "bans.json"),
		AuditFilePath: filepath.Join(tmp, "audit.json"),
		Username:    "admin",
		Password:    "test-pass-123",
	})

	t.Run("static index HTML enforces strict self-only CSP and contains zero inline scripts", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on GET /, got %d", rec.Code)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatal("missing Content-Security-Policy header on serverweb GET /")
		}
		for _, want := range []string{
			"default-src 'self'",
			"script-src 'self'",
			"connect-src 'self'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
		} {
			if !strings.Contains(csp, want) {
				t.Errorf("serverweb CSP %q missing required directive %q", csp, want)
			}
		}
		if strings.Contains(csp, "'unsafe-eval'") || strings.Contains(csp, "https://") {
			t.Errorf("serverweb CSP must not allow external origins or unsafe-eval: %q", csp)
		}
		for _, seg := range strings.Split(csp, ";") {
			seg = strings.TrimSpace(seg)
			if strings.HasPrefix(seg, "script-src") && strings.Contains(seg, "'unsafe-inline'") {
				t.Errorf("serverweb script-src must not allow 'unsafe-inline': %q", seg)
			}
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("Referrer-Policy = %q, want no-referrer", got)
		}
		if hasInlineScript(rec.Body.String()) {
			t.Errorf("serverweb index.html must not contain inline <script> blocks under strict script-src 'self'")
		}
	})

	t.Run("API responses include strict CSP and security headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/server/status", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)

		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Fatal("missing Content-Security-Policy header on serverweb API response")
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", got)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("Referrer-Policy = %q, want no-referrer", got)
		}
	})
}
