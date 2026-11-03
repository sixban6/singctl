package serverweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

	cookieHeader := func(rec *httptest.ResponseRecorder) string {
		t.Helper()
		cookies := rec.Result().Cookies()
		if len(cookies) == 0 {
			t.Fatal("expected Set-Cookie")
		}
		return cookies[0].Name + "=" + cookies[0].Value
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

	// 3. URL 里的口令不能登录
	{
		req := httptest.NewRequest("GET", "/api/server/status?password=ServerPassword888", nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for query password, got %d", rec.Code)
		}
	}

	var sessionCookie string

	// 4. POST /api/server/login 验证用户名与密码，响应里不带会话令牌
	{
		req := httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong password, got %d", rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"wronguser","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong username, got %d", rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for correct login, got %d", rec.Code)
		}
		var loginRes map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &loginRes)
		if _, ok := loginRes["token"]; ok {
			t.Fatal("login response must not include a session token")
		}
		sessionCookie = cookieHeader(rec)
	}

	// 5. Cookie 可以访问状态接口，响应里没有会话令牌
	{
		req := httptest.NewRequest("GET", "/api/server/status", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for session cookie, got %d", rec.Code)
		}
		var st map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
			t.Fatalf("failed to parse status JSON: %v", err)
		}
		if st["authEnabled"] != true {
			t.Fatalf("expected authEnabled=true, got %v", st["authEnabled"])
		}
		if _, ok := st["sessionToken"]; ok {
			t.Fatal("status response must not include sessionToken")
		}
	}

	// 6. Basic Auth 仍然可用，且无状态请求绝不向客户端签发 Cookie、不泄漏 Session
	{
		srv.sessionsMu.Lock()
		sessionsBefore := len(srv.sessions)
		srv.sessionsMu.Unlock()

		req := httptest.NewRequest("GET", "/api/server/session/url", nil)
		req.SetBasicAuth("singctl", "ServerPassword888")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for basic auth, got %d", rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("expected no Set-Cookie for stateless basic auth request, got %v", rec.Result().Cookies())
		}
		srv.sessionsMu.Lock()
		sessionsAfter := len(srv.sessions)
		srv.sessionsMu.Unlock()
		if sessionsAfter != sessionsBefore {
			t.Fatalf("stateless basic auth must not create sessions: before=%d, after=%d", sessionsBefore, sessionsAfter)
		}

		var res map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		if !strings.Contains(res["url"], "/sr/") {
			t.Fatalf("expected url to contain admin path with /sr/ prefix, got %q", res["url"])
		}
		if _, ok := res["token"]; ok {
			t.Fatal("session url must not include a token")
		}
	}

	// 7. 退出后旧 Cookie 失效
	{
		req := httptest.NewRequest("POST", "/api/server/logout", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for logout, got %d", rec.Code)
		}

		req = httptest.NewRequest("GET", "/api/server/status", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout, got %d", rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected re-login 200, got %d", rec.Code)
		}
		sessionCookie = cookieHeader(rec)
	}

	// 8. PUT /api/server/credentials 修改账号与密码，旧会话同时失效
	{
		req := httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"bad","newUsername":"myuser","newPassword":"NewPassword888"}`))
		req.Header.Set("Cookie", sessionCookie)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for wrong current password, got %d", rec.Code)
		}

		req = httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"ServerPassword888","newUsername":"myuser","newPassword":"weakpassword123"}`))
		req.Header.Set("Cookie", sessionCookie)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for password missing uppercase, got %d", rec.Code)
		}

		req = httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"ServerPassword888","newUsername":"myuser","newPassword":"NewPassword888"}`))
		req.Header.Set("Cookie", sessionCookie)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for credentials update, got %d: %s", rec.Code, rec.Body.String())
		}
		newCookie := cookieHeader(rec)

		if srv.getUsername() != "myuser" || srv.getPassword() != "NewPassword888" {
			t.Fatalf("expected memory credentials updated, got user=%s pass=%s", srv.getUsername(), srv.getPassword())
		}

		req = httptest.NewRequest("GET", "/api/server/status", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected old session revoked after password change, got %d", rec.Code)
		}
		sessionCookie = newCookie
	}

	// 9. 伪造转发头不能绕过封禁；未登录不能解封
	{
		remoteIP := "198.51.100.88"
		loginFail := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"myuser","password":"bad"}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "127.0.0.1:40000"
			req.Header.Set("X-Real-IP", remoteIP)
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			req.Header.Set("CF-Connecting-IP", "127.0.0.1")
			rec := httptest.NewRecorder()
			srv.mux.ServeHTTP(rec, req)
			return rec
		}

		for i := 1; i <= 2; i++ {
			rec := loginFail()
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("attempt %d: expected 401, got %d", i, rec.Code)
			}
		}
		rec := loginFail()
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attempt 3: expected 429, got %d (%s)", rec.Code, rec.Body.String())
		}

		req := httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"myuser","password":"NewPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Real-IP", remoteIP)
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("while banned: expected 429, got %d", rec.Code)
		}

		unbanReq := httptest.NewRequest("POST", "/api/server/unban", strings.NewReader(fmt.Sprintf(`{"ip":"%s"}`, remoteIP)))
		unbanReq.Header.Set("Content-Type", "application/json")
		unbanReq.RemoteAddr = "127.0.0.1:9999"
		unbanReq.Header.Set("X-Forwarded-For", "127.0.0.1")
		unbanRec := httptest.NewRecorder()
		srv.mux.ServeHTTP(unbanRec, unbanReq)
		if unbanRec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated unban, got %d", unbanRec.Code)
		}

		unbanReq = httptest.NewRequest("POST", "/api/server/unban", strings.NewReader(fmt.Sprintf(`{"ip":"%s"}`, remoteIP)))
		unbanReq.Header.Set("Content-Type", "application/json")
		unbanReq.Header.Set("Cookie", sessionCookie)
		unbanRec = httptest.NewRecorder()
		srv.mux.ServeHTTP(unbanRec, unbanReq)
		if unbanRec.Code != http.StatusOK {
			t.Fatalf("expected 200 for authenticated unban, got %d (%s)", unbanRec.Code, unbanRec.Body.String())
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"myuser","password":"NewPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Real-IP", remoteIP)
		rec = httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("after unban: expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
	}

	// 10. GET /api/server/audit-logs 返回最近管理操作且不含密码或令牌
	{
		req := httptest.NewRequest("GET", "/api/server/audit-logs", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for audit-logs, got %d", rec.Code)
		}
		var res struct {
			Logs []AuditEntry `json:"logs"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("failed to parse audit logs: %v", err)
		}
		if len(res.Logs) == 0 {
			t.Fatal("expected audit logs to be recorded")
		}
		raw := rec.Body.String()
		if strings.Contains(raw, "NewPassword888") || strings.Contains(raw, "ServerPassword888") {
			t.Fatalf("audit logs must never contain passwords, got: %s", raw)
		}
	}
}

func TestWriteConfigBackupKeepsThree(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("v0"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 4; i++ {
		old, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeConfigBackup(path, old); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(fmt.Sprintf("v%d", i)), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	matches, err := filepath.Glob(path + ".*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 backups, got %d (%v)", len(matches), matches)
	}
	for _, name := range matches {
		st, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatalf("backup %s mode = %o, want 0600", name, st.Mode().Perm())
		}
	}
}

func TestSessionPruningAndCap(t *testing.T) {
	srv := New(Options{Username: "singctl", Password: "Password123"})

	// 1. 模拟存入已过期的会话（绝对超时或空闲超时）
	srv.sessionsMu.Lock()
	srv.sessions["expired_idle"] = sessionRecord{
		created: time.Now().Add(-1 * time.Hour),
		last:    time.Now().Add(-3 * time.Hour), // 超过 2h 空闲
	}
	srv.sessions["expired_absolute"] = sessionRecord{
		created: time.Now().Add(-13 * time.Hour), // 超过 12h 绝对超时
		last:    time.Now(),
	}
	srv.sessions["alive"] = sessionRecord{
		created: time.Now().Add(-10 * time.Minute),
		last:    time.Now().Add(-5 * time.Minute),
	}
	srv.sessionsMu.Unlock()

	// 2. 签发新会话时应当自动剔除所有过期会话
	newID := srv.issueSession()
	if newID == "" {
		t.Fatal("expected session to be issued")
	}

	srv.sessionsMu.Lock()
	if _, exists := srv.sessions["expired_idle"]; exists {
		t.Error("expected expired_idle to be pruned")
	}
	if _, exists := srv.sessions["expired_absolute"]; exists {
		t.Error("expected expired_absolute to be pruned")
	}
	if _, exists := srv.sessions["alive"]; !exists {
		t.Error("expected alive session to be preserved")
	}
	if _, exists := srv.sessions[newID]; !exists {
		t.Error("expected newID to exist")
	}

	// 3. 模拟填充大量会话，验证 maxActiveSessions 容量上限与淘汰机制
	for i := 0; i < maxActiveSessions+10; i++ {
		id := fmt.Sprintf("mock_session_%d", i)
		srv.sessions[id] = sessionRecord{
			created: time.Now(),
			last:    time.Now().Add(time.Duration(i) * time.Second),
		}
	}
	srv.sessionsMu.Unlock()

	// 再次签发新会话，触发容量淘汰
	_ = srv.issueSession()

	srv.sessionsMu.Lock()
	defer srv.sessionsMu.Unlock()
	if len(srv.sessions) > maxActiveSessions {
		t.Fatalf("sessions count (%d) exceeded maxActiveSessions (%d)", len(srv.sessions), maxActiveSessions)
	}
}
