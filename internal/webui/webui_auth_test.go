package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebUIAuthMethods(t *testing.T) {
	const pass = "secret123"
	server := New(Options{
		Password: pass,
	})

	token := server.sessionToken()
	if token == "" {
		t.Fatalf("sessionToken should not be empty")
	}

	// 1. 无凭据请求，应被拒绝并返回 401
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for empty auth, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("expected WWW-Authenticate header, got %q", rec.Header().Get("WWW-Authenticate"))
		}
	}

	// 2. 正确的 Basic Auth，放行且自动下发持久化 Cookie
	var sessionCookie *http.Cookie
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.SetBasicAuth("admin", pass)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for basic auth, got %d", rec.Code)
		}
		// 校验下发了 singctl_session Cookie
		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == sessionCookieName {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("expected %s cookie in response, but found none", sessionCookieName)
		}
		if sessionCookie.Value != token {
			t.Fatalf("cookie value mismatch: got %q, want %q", sessionCookie.Value, token)
		}
		if sessionCookie.MaxAge <= 0 {
			t.Fatalf("expected positive MaxAge for persistence, got %d", sessionCookie.MaxAge)
		}
	}

	// 3. 携带 Cookie 免密请求，无需 Basic Auth 放行 (适配 iOS 添加到主屏幕场景)
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with session cookie, got %d", rec.Code)
		}
	}

	// 4. 携带 Bearer Token 请求放行
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with Bearer token, got %d", rec.Code)
		}
	}

	// 5. 携带 URL ?token= 请求放行
	{
		req := httptest.NewRequest("GET", "/api/status?token="+token, nil)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with ?token=, got %d", rec.Code)
		}
	}

	// 6. 携带 URL ?password= 请求放行
	{
		req := httptest.NewRequest("GET", "/api/status?password="+pass, nil)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with ?password=, got %d", rec.Code)
		}
	}

	// 7. 伪造篡改的 Token / Cookie，应被拒绝
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid_fake_token"})
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for fake token, got %d", rec.Code)
		}
	}

	// 8. 静态资源免密测试 (受 authOnly 保护)
	{
		// 8.1 无认证访问静态资源 -> 401
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for static root without auth, got %d", rec.Code)
		}

		// 8.2 带 Cookie 访问静态资源 -> 200
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.AddCookie(sessionCookie)
		rec2 := httptest.NewRecorder()
		server.mux.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Fatalf("expected 200 for static root with cookie, got %d", rec2.Code)
		}

		// 8.3 带 ?token= 访问静态资源 -> 200
		req3 := httptest.NewRequest("GET", "/?token="+token, nil)
		rec3 := httptest.NewRecorder()
		server.mux.ServeHTTP(rec3, req3)
		if rec3.Code != http.StatusOK {
			t.Fatalf("expected 200 for static root with ?token=, got %d", rec3.Code)
		}
	}

	// 9. 获取免密 URL (/api/session/url)
	{
		req := httptest.NewRequest("GET", "/api/session/url", nil)
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for /api/session/url, got %d", rec.Code)
		}
		var res map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to parse json response: %v", err)
		}
		if !strings.Contains(res["url"], "?token="+token) {
			t.Fatalf("expected url to contain ?token=, got %q", res["url"])
		}
	}

	// 10. 登出测试 (/api/logout)
	{
		req := httptest.NewRequest("POST", "/api/logout", nil)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		server.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for /api/logout, got %d", rec.Code)
		}
		var cleared bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName && c.MaxAge < 0 {
				cleared = true
				break
			}
		}
		if !cleared {
			t.Fatalf("expected %s cookie to be cleared with negative MaxAge", sessionCookieName)
		}
	}
}

func TestWebUIAuthDisabled(t *testing.T) {
	// 未设置密码时，一切直接放行
	server := New(Options{
		Password: "",
	})
	req := httptest.NewRequest("GET", "/api/status", nil)
	rec := httptest.NewRecorder()
	server.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when auth disabled, got %d", rec.Code)
	}
}
