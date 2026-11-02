package serverweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerWebAuthAndStatic(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	_ = os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  web_admin:
    enabled: true
    port: 8092
    path: "/test123"
    username: "singctl"
    password: "ServerPassword888"
`), 0600)

	srv := New(Options{
		ConfigPath: cfgPath,
		Username:   "singctl",
		Password:   "ServerPassword888",
	})

	token := srv.sessionToken()
	if token == "" {
		t.Fatalf("expected non-empty session token")
	}

	// 1. 请求静态首页 -> 200 OK (由前端展示登录弹窗)
	{
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for static root, got %d", rec.Code)
		}
	}

	// 2. 无认证直接请求敏感 API -> 401
	{
		req := httptest.NewRequest("GET", "/api/server/status", nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauth API, got %d", rec.Code)
		}
	}

	// 3. 携带 Basic Auth 请求 API -> 200
	{
		req := httptest.NewRequest("GET", "/api/server/status", nil)
		req.SetBasicAuth("singctl", "ServerPassword888")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for basic auth, got %d", rec.Code)
		}
		var st map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("failed to parse status JSON: %v", err)
		}
		if st["authEnabled"] != true {
			t.Fatalf("expected authEnabled=true, got %v", st["authEnabled"])
		}
	}

	// 4. Session URL 请求 (包含 HTTPS Caddy 路径)
	{
		req := httptest.NewRequest("GET", "/api/server/session/url", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for session url, got %d", rec.Code)
		}
		var res map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if !strings.Contains(res["url"], "/sr/") {
			t.Fatalf("expected url to contain admin path with /sr/ prefix, got %q", res["url"])
		}
	}

	// 5. POST /api/server/login 验证用户名与密码
	{
		// 密码错误
		req := httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong password, got %d", rec.Code)
		}

		// 用户名错误
		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"wronguser","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong username, got %d", rec.Code)
		}

		// 用户名与密码均正确
		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for correct login, got %d", rec.Code)
		}
		var loginRes map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &loginRes)
		if loginRes["token"] != token {
			t.Fatalf("expected token %s, got %v", token, loginRes["token"])
		}
		if len(rec.Result().Cookies()) == 0 {
			t.Fatalf("expected Set-Cookie on successful login")
		}
	}

	// 6. PUT /api/server/credentials 修改账号与密码 (8位且含大小写+数字)
	{
		// 原密码错误 -> 403
		req := httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"bad","newUsername":"myuser","newPassword":"NewPassword888"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for wrong current password, got %d", rec.Code)
		}

		// 格式不合规（无大写字母） -> 400
		req = httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"ServerPassword888","newUsername":"myuser","newPassword":"weakpassword123"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for password missing uppercase, got %d", rec.Code)
		}

		// 正确修改
		req = httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"ServerPassword888","newUsername":"myuser","newPassword":"NewPassword888"}`))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for credentials update, got %d: %s", rec.Code, rec.Body.String())
		}

		// 验证内存更新
		if srv.getUsername() != "myuser" || srv.getPassword() != "NewPassword888" {
			t.Fatalf("expected memory credentials updated, got user=%s pass=%s", srv.getUsername(), srv.getPassword())
		}
	}
}
