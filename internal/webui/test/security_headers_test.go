// 文件职责：验证客户端 WebUI（静态页面、内嵌 401 登录页及 API）严格 CSP 与安全响应头契约。
package webui_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"singctl/internal/webui"
)

var inlineScriptTagRE = regexp.MustCompile(`(?s)<script\b[^>]*>(.*?)</script>`)

func TestClientWebUISecurityHeadersAndCSP(t *testing.T) {
	tmp := t.TempDir()
	srv := webui.New(webui.Options{
		ConfigPath: filepath.Join(tmp, "singctl.yaml"),
		Password:   "test-pass-123",
	})
	tok := srv.SessionToken()

	t.Run("authenticated index HTML enforces strict CSP with leak probe allowlist", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for authenticated /, got %d", rec.Code)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatal("missing Content-Security-Policy header on GET /")
		}
		for _, want := range []string{
			"default-src 'self'",
			"script-src 'self'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"frame-ancestors 'none'",
			"https://ipv4.geojs.io",
			"https://ipv6.geojs.io",
			"https://myip.ipip.net",
			"https://*.edns.ip-api.com",
		} {
			if !strings.Contains(csp, want) {
				t.Errorf("CSP %q missing required directive %q", csp, want)
			}
		}
		if strings.Contains(csp, "'unsafe-eval'") {
			t.Errorf("CSP must not allow 'unsafe-eval': %q", csp)
		}
		for _, seg := range strings.Split(csp, ";") {
			seg = strings.TrimSpace(seg)
			if strings.HasPrefix(seg, "script-src") && strings.Contains(seg, "'unsafe-inline'") {
				t.Errorf("script-src must not allow 'unsafe-inline': %q", seg)
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
	})

	t.Run("unauthenticated 401 login page uses exact sha256 script hash without unsafe-inline", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated /, got %d", rec.Code)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if csp == "" {
			t.Fatal("missing Content-Security-Policy on 401 login page")
		}
		m := inlineScriptTagRE.FindStringSubmatch(rec.Body.String())
		if len(m) < 2 || strings.TrimSpace(m[1]) == "" {
			t.Fatalf("expected inline login script in 401 page")
		}
		sum := sha256.Sum256([]byte(m[1]))
		wantHash := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"

		if !strings.Contains(csp, wantHash) {
			t.Errorf("401 login CSP %q missing exact script hash %s", csp, wantHash)
		}
		if !strings.Contains(csp, "connect-src 'self'") {
			t.Errorf("401 login CSP %q must restrict connect-src strictly to 'self'", csp)
		}
		if strings.Contains(csp, "geojs.io") {
			t.Errorf("401 login CSP %q must not expose leak-probe domains before auth", csp)
		}
		for _, seg := range strings.Split(csp, ";") {
			seg = strings.TrimSpace(seg)
			if strings.HasPrefix(seg, "script-src") && strings.Contains(seg, "'unsafe-inline'") {
				t.Errorf("401 login script-src must not allow 'unsafe-inline': %q", seg)
			}
		}
		if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("X-Frame-Options = %q, want DENY", got)
		}
	})

	t.Run("API endpoints include strict security headers", func(t *testing.T) {
		cases := []struct {
			name   string
			path   string
			authed bool
		}{
			{"public auth check", "/api/auth/check", false},
			{"authenticated health", "/api/health", true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, tc.path, nil)
				if tc.authed {
					req.Header.Set("Authorization", "Bearer "+tok)
				}
				rec := httptest.NewRecorder()
				srv.Mux.ServeHTTP(rec, req)

				if rec.Header().Get("Content-Security-Policy") == "" {
					t.Errorf("%s missing Content-Security-Policy", tc.path)
				}
				if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
					t.Errorf("%s X-Frame-Options = %q, want DENY", tc.path, got)
				}
				if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
					t.Errorf("%s Referrer-Policy = %q, want no-referrer", tc.path, got)
				}
			})
		}
	})
}
