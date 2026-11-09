package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/fleet"
	"singctl/internal/serverweb"
	"singctl/internal/subhub"
	"strings"
	"testing"
	"time"
)

func TestServerWebCmd_Subcommands(t *testing.T) {
	root := cmd.NewServerWebCmd("/tmp/nonexistent.yaml")
	commands := make(map[string]bool)
	for _, sub := range root.Commands() {
		commands[sub.Name()] = true
		for _, alias := range sub.Aliases {
			commands[alias] = true
		}
	}

	expected := []string{"start", "stop", "restart", "r", "status", "unban"}
	for _, exp := range expected {
		if !commands[exp] {
			t.Errorf("expected subcommand or alias %q to exist under 'server web'", exp)
		}
	}
}

func TestAuditManager_RecordAndCap(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.json")

	am := serverweb.NewAuditManager(auditFile)

	am.Record("1.1.1.1", "登录成功")
	am.Record("2.2.2.2", "更新配置")

	list := am.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 audit entries, got %d", len(list))
	}

	// 最新的记录在前面
	if list[0].Action != "更新配置" || list[0].IP != "2.2.2.2" {
		t.Errorf("unexpected first entry: %+v", list[0])
	}
	if list[1].Action != "登录成功" || list[1].IP != "1.1.1.1" {
		t.Errorf("unexpected second entry: %+v", list[1])
	}

	// 检查文件权限是否为 0600
	st, err := os.Stat(auditFile)
	if err != nil {
		t.Fatalf("stat audit file failed: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected audit file perm 0600, got %o", perm)
	}

	// 插入超过 maxAuditLogs (50) 条记录，验证截断上限
	for i := 0; i < serverweb.MaxAuditLogs+10; i++ {
		am.Record("3.3.3.3", "操作测试")
	}

	listAfter := am.List()
	if len(listAfter) != serverweb.MaxAuditLogs {
		t.Fatalf("expected capped at %d, got %d", serverweb.MaxAuditLogs, len(listAfter))
	}
}

func TestAuditManager_PersistenceAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	auditFile := filepath.Join(dir, "audit.json")

	// 实例 1：记录操作并持久化
	am1 := serverweb.NewAuditManager(auditFile)
	am1.Record("203.0.113.1", "管理员登录成功")
	am1.Record("203.0.113.1", "修改管理账号为 [superadmin] 并更新管理密码")

	// 模拟重启：创建新实例 2 并读取同一文件
	am2 := serverweb.NewAuditManager(auditFile)
	list := am2.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 reloaded entries, got %d", len(list))
	}

	if list[0].Action != "修改管理账号为 [superadmin] 并更新管理密码" {
		t.Errorf("unexpected entry 0: %+v", list[0])
	}
	if list[1].Action != "管理员登录成功" {
		t.Errorf("unexpected entry 1: %+v", list[1])
	}
}

func TestCountryCodeToFlag(t *testing.T) {
	cases := []struct {
		code     string
		expected string
	}{
		{"US", "🇺🇸"},
		{"CN", "🇨🇳"},
		{"SG", "🇸🇬"},
		{"HK", "🇭🇰"},
		{"JP", "🇯🇵"},
		{"", ""},
		{"INVALID", ""},
	}

	for _, c := range cases {
		flag := serverweb.CountryCodeToFlag(c.code)
		if flag != c.expected {
			t.Errorf("CountryCodeToFlag(%q) = %q, want %q", c.code, flag, c.expected)
		}
	}
}

func TestIPGeoResolver_Loopback(t *testing.T) {
	resolver := serverweb.NewIPGeoResolver()
	info := resolver.Resolve("127.0.0.1")
	if info.Country != "本地" || info.Geo != "本地网络" {
		t.Fatalf("expected loopback info, got %+v", info)
	}
}

func TestIPGeoResolver_SeedCountry(t *testing.T) {
	resolver := serverweb.NewIPGeoResolver()
	resolver.SeedCountry("203.0.113.1", "US")
	info := resolver.Resolve("203.0.113.1")
	if info.CountryCode != "US" || info.Country != "美国" || info.Flag != "🇺🇸" {
		t.Fatalf("expected seeded US country, got %+v", info)
	}
}

func TestIPGeoResolver_FetchAsync(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":      "success",
			"country":     "Singapore",
			"countryCode": "SG",
			"city":        "Singapore",
			"isp":         "Singtel",
		})
	}))
	defer server.Close()

	resolver := serverweb.NewIPGeoResolver()
	resolver.HTTPClient = server.Client()

	// Manually inject entry to simulate successful fetchAsync logic
	info := serverweb.IPGeoInfo{
		IP:          "1.1.1.1",
		Country:     "Singapore",
		CountryCode: "SG",
		City:        "Singapore",
		ISP:         "Singtel",
		Flag:        serverweb.CountryCodeToFlag("SG"),
		Geo:         serverweb.FormatGeoLabel("SG", "Singapore", "Singapore"),
	}
	resolver.Cache["1.1.1.1"] = serverweb.GeoCacheEntry{
		Info:      info,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	resolved := resolver.Resolve("1.1.1.1")
	if resolved.CountryCode != "SG" || resolved.City != "Singapore" || resolved.ISP != "Singtel" {
		t.Fatalf("expected resolved SG info, got %+v", resolved)
	}
	if resolved.Flag != "🇸🇬" {
		t.Fatalf("expected 🇸🇬 flag, got %q", resolved.Flag)
	}
}

func TestGetClientIP(t *testing.T) {
	t.Run("loopback trusts X-Real-IP", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "203.0.113.195")
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		req.Header.Set("CF-Connecting-IP", "127.0.0.1")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := serverweb.GetClientIP(req); ip != "203.0.113.195" {
			t.Fatalf("expected 203.0.113.195 from X-Real-IP, got %s", ip)
		}
	})

	t.Run("spoofed forwarding headers are ignored", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("CF-Connecting-IP", "104.28.1.1")
		req.Header.Set("X-Real-IP", "127.0.0.1")
		req.Header.Set("X-Forwarded-For", "127.0.0.1, 198.51.100.42")
		req.RemoteAddr = "203.0.113.9:54321"
		if ip := serverweb.GetClientIP(req); ip != "203.0.113.9" {
			t.Fatalf("expected remote address 203.0.113.9, got %s", ip)
		}
	})

	t.Run("invalid X-Real-IP falls back to loopback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Real-IP", "not-an-ip")
		req.RemoteAddr = "127.0.0.1:12345"
		if ip := serverweb.GetClientIP(req); ip != "127.0.0.1" {
			t.Fatalf("expected 127.0.0.1, got %s", ip)
		}
	})
}

func TestIPLimiter_BanAfterThreeFails(t *testing.T) {
	limiter := serverweb.NewIPLimiter(3, 1*time.Minute, 15*time.Minute)
	defer limiter.Close()

	testIP := "198.51.100.99"

	// 尝试 1
	banned, _, fails := limiter.RecordFailure(testIP)
	if banned || fails != 1 {
		t.Fatalf("expected fails=1, banned=false, got fails=%d, banned=%v", fails, banned)
	}
	if _, isBanned := limiter.CheckBan(testIP); isBanned {
		t.Fatalf("should not be banned after 1 fail")
	}

	// 尝试 2
	banned, _, fails = limiter.RecordFailure(testIP)
	if banned || fails != 2 {
		t.Fatalf("expected fails=2, banned=false, got fails=%d, banned=%v", fails, banned)
	}

	// 尝试 3 -> 触发封禁
	banned, rem, fails := limiter.RecordFailure(testIP)
	if !banned || fails != 3 {
		t.Fatalf("expected fails=3, banned=true, got fails=%d, banned=%v", fails, banned)
	}
	if rem <= 0 {
		t.Fatalf("expected positive remaining time, got %v", rem)
	}

	// 再次检查 CheckBan
	remCheck, isBanned := limiter.CheckBan(testIP)
	if !isBanned || remCheck <= 0 {
		t.Fatalf("expected isBanned=true, got %v (%v)", isBanned, remCheck)
	}

	// 解封单个 IP
	limiter.Unban(testIP)
	if _, isBanned := limiter.CheckBan(testIP); isBanned {
		t.Fatalf("expected IP to be unbanned")
	}
}

func TestIPLimiter_SuccessResetsCounter(t *testing.T) {
	limiter := serverweb.NewIPLimiter(3, 1*time.Minute, 15*time.Minute)
	defer limiter.Close()

	testIP := "198.51.100.100"

	// 尝试 2 次失败
	limiter.RecordFailure(testIP)
	limiter.RecordFailure(testIP)

	// 成功登录
	limiter.RecordSuccess(testIP)

	// 再失败 1 次，应该重新从 1 开始计次
	banned, _, fails := limiter.RecordFailure(testIP)
	if banned || fails != 1 {
		t.Fatalf("expected fails=1 after reset, got %d (banned=%v)", fails, banned)
	}
}

func TestIPLimiter_LocalhostWhitelisted(t *testing.T) {
	limiter := serverweb.NewIPLimiter(3, 1*time.Minute, 15*time.Minute)
	defer limiter.Close()

	for i := 0; i < 10; i++ {
		banned, _, fails := limiter.RecordFailure("127.0.0.1")
		if banned || fails != 0 {
			t.Fatalf("localhost 127.0.0.1 should never be recorded or banned")
		}
	}
	if _, isBanned := limiter.CheckBan("127.0.0.1"); isBanned {
		t.Fatalf("localhost 127.0.0.1 should never be banned")
	}
}

func TestIPLimiter_FilePersistence(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "bans.json")

	l1 := serverweb.NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filePath)
	testIP := "198.51.100.77"

	// 触发封禁
	l1.RecordFailure(testIP)
	l1.RecordFailure(testIP)
	banned, _, _ := l1.RecordFailure(testIP)
	if !banned {
		t.Fatal("expected IP to be banned")
	}
	l1.Close()

	// 验证文件权限为 0600
	st, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected ban file perm 0600, got %o", perm)
	}

	// 模拟服务重启：创建新实例 l2 读取相同的小文件
	l2 := serverweb.NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filePath)
	defer l2.Close()

	rem, isBanned := l2.CheckBan(testIP)
	if !isBanned || rem <= 0 {
		t.Fatalf("expected banned IP to persist after restart, got isBanned=%v, rem=%v", isBanned, rem)
	}

	bans := l2.ListBans()
	if _, exists := bans[testIP]; !exists {
		t.Fatalf("expected %s in ListBans after restart", testIP)
	}

	// 解封并验证持久化
	l2.Unban(testIP)
	if _, isBanned := l2.CheckBan(testIP); isBanned {
		t.Fatal("expected unbanned")
	}

	// 再次重启验证解封已持久化
	l3 := serverweb.NewIPLimiter(3, 10*time.Minute, 15*time.Minute, filePath)
	defer l3.Close()
	if _, isBanned := l3.CheckBan(testIP); isBanned {
		t.Fatal("expected unban state to persist across restart")
	}
}

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

	srv := serverweb.New(serverweb.Options{
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
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for static root, got %d", rec.Code)
		}
	}

	// 2. 无认证直接请求敏感 API -> 401
	{
		req := httptest.NewRequest("GET", "/api/server/status", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauth API, got %d", rec.Code)
		}
	}

	// 3. URL 里的口令不能登录
	{
		req := httptest.NewRequest("GET", "/api/server/status?password=ServerPassword888", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
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
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong password, got %d", rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"wronguser","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong username, got %d", rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
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
		srv.Mux.ServeHTTP(rec, req)
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
		srv.SessionsMu.Lock()
		sessionsBefore := len(srv.Sessions)
		srv.SessionsMu.Unlock()

		req := httptest.NewRequest("GET", "/api/server/session/url", nil)
		req.SetBasicAuth("singctl", "ServerPassword888")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for basic auth, got %d", rec.Code)
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Fatalf("expected no Set-Cookie for stateless basic auth request, got %v", rec.Result().Cookies())
		}
		srv.SessionsMu.Lock()
		sessionsAfter := len(srv.Sessions)
		srv.SessionsMu.Unlock()
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
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for logout, got %d", rec.Code)
		}

		req = httptest.NewRequest("GET", "/api/server/status", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout, got %d", rec.Code)
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"singctl","password":"ServerPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
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
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for wrong current password, got %d", rec.Code)
		}

		req = httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"ServerPassword888","newUsername":"myuser","newPassword":"weakpassword123"}`))
		req.Header.Set("Cookie", sessionCookie)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for password missing uppercase, got %d", rec.Code)
		}

		req = httptest.NewRequest("PUT", "/api/server/credentials", strings.NewReader(`{"currentPassword":"ServerPassword888","newUsername":"myuser","newPassword":"NewPassword888"}`))
		req.Header.Set("Cookie", sessionCookie)
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for credentials update, got %d: %s", rec.Code, rec.Body.String())
		}
		newCookie := cookieHeader(rec)

		if srv.GetUsername() != "myuser" || !config.IsHashedPassword(srv.GetPassword()) || !config.VerifyPassword(srv.GetPassword(), "NewPassword888") {
			t.Fatalf("expected memory credentials updated with bcrypt hash, got user=%s pass=%s", srv.GetUsername(), srv.GetPassword())
		}
		diskRaw, _ := os.ReadFile(cfgPath)
		if strings.Contains(string(diskRaw), "NewPassword888") {
			t.Fatalf("updated password must be stored as bcrypt hash on disk, never plaintext:\n%s", string(diskRaw))
		}

		req = httptest.NewRequest("GET", "/api/server/status", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected old session revoked after password change, got %d", rec.Code)
		}
		sessionCookie = newCookie
	}

	// 9. 伪造转发头不能绕过封禁；未登录不能解封
	{
		remoteIP := "198.51.100.88"
		gwToken := srv.GatewayToken()
		loginFail := func() *httptest.ResponseRecorder {
			req := httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"myuser","password":"bad"}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "127.0.0.1:40000"
			req.Header.Set("X-Singctl-Gateway", gwToken)
			req.Header.Set("X-Real-IP", remoteIP)
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			req.Header.Set("CF-Connecting-IP", "127.0.0.1")
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
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
		req.Header.Set("X-Singctl-Gateway", gwToken)
		req.Header.Set("X-Real-IP", remoteIP)
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("while banned: expected 429, got %d", rec.Code)
		}

		unbanReq := httptest.NewRequest("POST", "/api/server/unban", strings.NewReader(fmt.Sprintf(`{"ip":"%s"}`, remoteIP)))
		unbanReq.Header.Set("Content-Type", "application/json")
		unbanReq.RemoteAddr = "127.0.0.1:9999"
		unbanReq.Header.Set("X-Forwarded-For", "127.0.0.1")
		unbanRec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(unbanRec, unbanReq)
		if unbanRec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for unauthenticated unban, got %d", unbanRec.Code)
		}

		unbanReq = httptest.NewRequest("POST", "/api/server/unban", strings.NewReader(fmt.Sprintf(`{"ip":"%s"}`, remoteIP)))
		unbanReq.Header.Set("Content-Type", "application/json")
		unbanReq.Header.Set("Cookie", sessionCookie)
		unbanRec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(unbanRec, unbanReq)
		if unbanRec.Code != http.StatusOK {
			t.Fatalf("expected 200 for authenticated unban, got %d (%s)", unbanRec.Code, unbanRec.Body.String())
		}

		req = httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"myuser","password":"NewPassword888"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:40000"
		req.Header.Set("X-Singctl-Gateway", gwToken)
		req.Header.Set("X-Real-IP", remoteIP)
		rec = httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("after unban: expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
	}

	// 10. GET /api/server/audit-logs 返回最近管理操作且不含密码或令牌
	{
		req := httptest.NewRequest("GET", "/api/server/audit-logs", nil)
		req.Header.Set("Cookie", sessionCookie)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for audit-logs, got %d", rec.Code)
		}
		var res struct {
			Logs []serverweb.AuditEntry `json:"logs"`
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

	// 11. 本机直连缺少 X-Singctl-Gateway 时，轮换伪造 X-Real-IP 无法绕过 3 次防爆破封锁，且本机 CLI Token 可解封
	{
		for i := 1; i <= 3; i++ {
			req := httptest.NewRequest("POST", "/api/server/login", strings.NewReader(`{"username":"myuser","password":"bad"}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "127.0.0.1:50000"
			req.Header.Set("X-Real-IP", fmt.Sprintf("203.0.113.%d", i))
			rec := httptest.NewRecorder()
			srv.Mux.ServeHTTP(rec, req)
			if i < 3 && rec.Code != http.StatusUnauthorized {
				t.Fatalf("direct loopback attempt %d: expected 401, got %d", i, rec.Code)
			}
			if i == 3 && rec.Code != http.StatusTooManyRequests {
				t.Fatalf("direct loopback attempt 3 with spoofed X-Real-IP must be rate-limited (429), got %d", rec.Code)
			}
		}

		// 验证本机 0600 CLI Token 可在不依赖明文密码的情况下调用解封接口
		cliTokBytes, err := os.ReadFile(serverweb.ResolveCLITokenPath(cfgPath))
		if err != nil {
			t.Fatalf("expected CLI token file to exist: %v", err)
		}
		unbanReq := httptest.NewRequest("POST", "/api/server/unban", strings.NewReader(`{"ip":"all"}`))
		unbanReq.Header.Set("Content-Type", "application/json")
		unbanReq.RemoteAddr = "127.0.0.1:50001"
		unbanReq.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(cliTokBytes)))
		unbanRec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(unbanRec, unbanReq)
		if unbanRec.Code != http.StatusOK {
			t.Fatalf("expected 200 for local CLI token unban, got %d (%s)", unbanRec.Code, unbanRec.Body.String())
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
		if err := serverweb.WriteConfigBackup(path, old); err != nil {
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
	srv := serverweb.New(serverweb.Options{Username: "singctl", Password: "Password123"})

	// 1. 模拟存入已过期的会话（绝对超时或空闲超时）
	srv.SessionsMu.Lock()
	srv.Sessions["expired_idle"] = serverweb.SessionRecord{
		Created: time.Now().Add(-1 * time.Hour),
		Last:    time.Now().Add(-3 * time.Hour), // 超过 2h 空闲
	}
	srv.Sessions["expired_absolute"] = serverweb.SessionRecord{
		Created: time.Now().Add(-13 * time.Hour), // 超过 12h 绝对超时
		Last:    time.Now(),
	}
	srv.Sessions["alive"] = serverweb.SessionRecord{
		Created: time.Now().Add(-10 * time.Minute),
		Last:    time.Now().Add(-5 * time.Minute),
	}
	srv.SessionsMu.Unlock()

	// 2. 签发新会话时应当自动剔除所有过期会话
	newID := srv.IssueSession()
	if newID == "" {
		t.Fatal("expected session to be issued")
	}

	srv.SessionsMu.Lock()
	if _, exists := srv.Sessions["expired_idle"]; exists {
		t.Error("expected expired_idle to be pruned")
	}
	if _, exists := srv.Sessions["expired_absolute"]; exists {
		t.Error("expected expired_absolute to be pruned")
	}
	if _, exists := srv.Sessions["alive"]; !exists {
		t.Error("expected alive session to be preserved")
	}
	if _, exists := srv.Sessions[newID]; !exists {
		t.Error("expected newID to exist")
	}

	// 3. 模拟填充大量会话，验证 maxActiveSessions 容量上限与淘汰机制
	for i := 0; i < serverweb.MaxActiveSessions+10; i++ {
		id := fmt.Sprintf("mock_session_%d", i)
		srv.Sessions[id] = serverweb.SessionRecord{
			Created: time.Now(),
			Last:    time.Now().Add(time.Duration(i) * time.Second),
		}
	}
	srv.SessionsMu.Unlock()

	// 再次签发新会话，触发容量淘汰
	_ = srv.IssueSession()

	srv.SessionsMu.Lock()
	defer srv.SessionsMu.Unlock()
	if len(srv.Sessions) > serverweb.MaxActiveSessions {
		t.Fatalf("sessions count (%d) exceeded maxActiveSessions (%d)", len(srv.Sessions), serverweb.MaxActiveSessions)
	}
}

func TestServerWeb_SubscriptionSourcesAndPreview(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	subDir := filepath.Join(tmpDir, "sub-store")

	cfgYAML := `server:
  node_domain: "node.example.com"
  substore_domain: "sub.example.com"
  sni: "www.apple.com"
  web_admin:
    enabled: true
    port: 8092
    path: "/sr/testadmin123"
    username: "opsadmin"
    password: "Password123"
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0600); err != nil {
		t.Fatal(err)
	}

	srv := serverweb.New(serverweb.Options{
		ConfigPath:  cfgPath,
		SubStoreDir: subDir,
		Username:    "opsadmin",
		Password:    "Password123",
	})

	doAuthReq := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.SetBasicAuth("opsadmin", "Password123")
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Add a local custom node source
	upsertBody := `{"displayName":"JP Custom","source":"local","content":"hysteria2://pass123@jp.example.com:443/?sni=jp.example.com&alpn=h3#JP-Hy2"}`
	recUpsert := doAuthReq(http.MethodPost, "/api/server/subscriptions/sources", upsertBody)
	if recUpsert.Code != http.StatusOK {
		t.Fatalf("expected 200 on upsert source, got %d: %s", recUpsert.Code, recUpsert.Body.String())
	}

	// 2. Fetch /api/server/subscriptions and verify engine + sources
	recSubs := doAuthReq(http.MethodGet, "/api/server/subscriptions", "")
	if recSubs.Code != http.StatusOK {
		t.Fatalf("expected 200 on GET /api/server/subscriptions, got %d: %s", recSubs.Code, recSubs.Body.String())
	}
	if !strings.Contains(recSubs.Body.String(), `"engine":"native-go"`) || !strings.Contains(recSubs.Body.String(), `"jp-custom"`) {
		t.Fatalf("unexpected subscriptions payload: %s", recSubs.Body.String())
	}

	// 3. Preview converted ClashMeta config
	recPreview := doAuthReq(http.MethodGet, "/api/server/subscriptions/preview?target=ClashMeta", "")
	if recPreview.Code != http.StatusOK || !strings.Contains(recPreview.Body.String(), "proxies:") {
		t.Fatalf("expected ClashMeta preview 200, got %d: %s", recPreview.Code, recPreview.Body.String())
	}

	// 4. Rotate subscription secret key
	recRotate := doAuthReq(http.MethodPost, "/api/server/subscriptions/rotate-key", "{}")
	if recRotate.Code != http.StatusOK || !strings.Contains(recRotate.Body.String(), "https://sub.example.com/") {
		t.Fatalf("expected rotate-key 200, got %d: %s", recRotate.Code, recRotate.Body.String())
	}

	// 5. Delete custom source
	recDel := doAuthReq(http.MethodDelete, "/api/server/subscriptions/sources?name=jp-custom", "{}")
	if recDel.Code != http.StatusOK {
		t.Fatalf("expected delete source 200, got %d: %s", recDel.Code, recDel.Body.String())
	}
}

func TestServerWeb_TelemetryAuditAndFleet(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	sbCfgPath := filepath.Join(tmpDir, "singbox.json")
	subDir := filepath.Join(tmpDir, "sub-store")
	fleetFile := filepath.Join(tmpDir, "fleet.yaml")

	_ = os.WriteFile(cfgPath, []byte(`
server:
  node_domain: "node.example.com"
  web_admin:
    username: "opsadmin"
    password: "Password123"
`), 0600)

	mockClash := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"uploadTotal":   204800,
			"downloadTotal": 1048576,
			"connections": []map[string]any{
				{
					"id":       "1",
					"upload":   1000,
					"download": 9000,
					"chains":   []string{"WARP"},
					"metadata": map[string]any{"type": "hysteria2/HYSTERIA2", "host": "netflix.com"},
				},
			},
		})
	}))
	defer mockClash.Close()

	_ = os.WriteFile(sbCfgPath, []byte(fmt.Sprintf(`{
  "experimental": {
    "clash_api": {
      "external_controller": %q,
      "secret": "testsecret"
    }
  }
}`, mockClash.Listener.Addr().String())), 0600)

	srv := serverweb.New(serverweb.Options{
		ConfigPath:        cfgPath,
		SingBoxConfigPath: sbCfgPath,
		SubStoreDir:       subDir,
		FleetFilePath:     fleetFile,
		Username:          "opsadmin",
		Password:          "Password123",
	})

	remoteDoc, _ := json.Marshal(map[string]any{
		"subs": []map[string]any{
			{"name": "auto_generated_hy2", "content": "hysteria2://pw@tokyo.example.com:443?sni=tokyo.example.com#TYO-HY2"},
		},
	})
	b64Doc := base64.StdEncoding.EncodeToString(remoteDoc)
	srv.FleetManager().Runner = func(ctx context.Context, node fleet.Node, script string) (string, int, error) {
		return "SINGCTL_VER=SingCtl v1.14.31\nSINGCTL_LOAD=0.10 0.05 0.01\nSINGCTL_MEM=25.0\nSINGCTL_CC=bbr\nSINGCTL_SUB_B64=" + b64Doc + "\n", 28, nil
	}

	doAuthReq := func(method, target, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.SetBasicAuth("opsadmin", "Password123")
		if method != http.MethodGet && method != http.MethodHead {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		return rec
	}

	// 1. Telemetry snapshot
	recTel := doAuthReq(http.MethodGet, "/api/server/telemetry/snapshot", "")
	if recTel.Code != http.StatusOK || !strings.Contains(recTel.Body.String(), `"netflix.com"`) {
		t.Fatalf("unexpected telemetry snapshot: code=%d body=%s", recTel.Code, recTel.Body.String())
	}

	// 2. Subscription audit log + clear
	srv.SubStore().RecordAccess(subhub.AccessLogEntry{
		IP:          "198.51.100.8",
		CountryCode: "SG",
		ClientApp:   "Shadowrocket",
		Target:      "base64",
		NodeCount:   2,
		Status:      "ok",
	})
	recAudit := doAuthReq(http.MethodGet, "/api/server/subscriptions/audit", "")
	if recAudit.Code != http.StatusOK || !strings.Contains(recAudit.Body.String(), `"Shadowrocket"`) {
		t.Fatalf("unexpected subscription audit response: %d %s", recAudit.Code, recAudit.Body.String())
	}
	recClear := doAuthReq(http.MethodDelete, "/api/server/subscriptions/audit", "{}")
	if recClear.Code != http.StatusOK {
		t.Fatalf("expected 200 clearing audit logs, got %d", recClear.Code)
	}

	// 3. Fleet add + autoSync -> syncs TYO-HY2 into SubHub!
	recAddNode := doAuthReq(http.MethodPost, "/api/server/fleet/nodes", `{"id":"jp-tyo","name":"日本东京","host":"198.51.100.20","authType":"ssh_alias","sshAlias":"vps_tyo","autoSync":true}`)
	if recAddNode.Code != http.StatusOK || !strings.Contains(recAddNode.Body.String(), `"syncedNodes":1`) {
		t.Fatalf("unexpected fleet upsert response: %d %s", recAddNode.Code, recAddNode.Body.String())
	}

	recFleet := doAuthReq(http.MethodGet, "/api/server/fleet", "")
	if recFleet.Code != http.StatusOK || !strings.Contains(recFleet.Body.String(), `"totalSyncedEndpoints":1`) {
		t.Fatalf("unexpected fleet list response: %d %s", recFleet.Code, recFleet.Body.String())
	}

	recDelNode := doAuthReq(http.MethodDelete, "/api/server/fleet/nodes?id=jp-tyo", "{}")
	if recDelNode.Code != http.StatusOK {
		t.Fatalf("expected 200 deleting fleet node, got %d", recDelNode.Code)
	}

	// 4. Camouflage defaults + probe API
	recCamoDef := doAuthReq(http.MethodGet, "/api/server/camouflage/defaults", "")
	if recCamoDef.Code != http.StatusOK || !strings.Contains(recCamoDef.Body.String(), `"presets":`) {
		t.Fatalf("unexpected camouflage defaults response: %d %s", recCamoDef.Code, recCamoDef.Body.String())
	}
}

func TestSniffTrackerAggregationAndTrustedExclusion(t *testing.T) {
	geo := serverweb.NewIPGeoResolver()
	geo.SeedCountry("198.51.100.10", "US")
	geo.SeedCountry("198.51.100.25", "US")
	geo.SeedCountry("203.0.113.88", "NL")
	geo.SeedCountry("162.142.125.12", "US")

	tracker := serverweb.NewSniffTracker(geo, nil)
	tracker.EnableSystemProbe = false

	// 1. 同一 /24 网段内多个 IP 进行探测
	tracker.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 4)
	tracker.Observe("198.51.100.25", "TLS/443 伪装回落嗅探", "masqueraded", 2)
	// 2. 另一个国家的 SSH 爆破源
	tracker.Observe("203.0.113.88", "SSH 暴力破解", "banned", 5)
	// 3. 已知 Censys 测绘引擎 IP
	tracker.Observe("162.142.125.12", "HTTP/80 端口嗅探", "masqueraded", 3)
	// 4. 合法代理客户端 IP (应被自动排除)
	tracker.Observe("192.0.2.55", "TLS/443 伪装回落嗅探", "masqueraded", 10)

	summary := tracker.Snapshot(t.Context(), "192.0.2.55")

	if summary.TotalSniffIPs != 4 {
		t.Fatalf("expected 4 external sniffing IPs after excluding trusted client, got %d", summary.TotalSniffIPs)
	}
	if summary.TotalSubnets != 3 {
		t.Fatalf("expected 3 unique /24 subnets, got %d", summary.TotalSubnets)
	}
	if len(summary.TopSubnets) == 0 || summary.TopSubnets[0].CIDR != "198.51.100.0/24" || summary.TopSubnets[0].UniqueIPs != 2 {
		t.Fatalf("expected top subnet 198.51.100.0/24 with 2 unique IPs, got %+v", summary.TopSubnets)
	}

	foundCensys := false
	for _, ipStat := range summary.TopIPs {
		if ipStat.IP == "192.0.2.55" {
			t.Fatalf("trusted proxy client IP 192.0.2.55 must not appear in TopIPs")
		}
		if ipStat.FirstSeen == "" || ipStat.LastSeen == "" {
			t.Fatalf("expected non-empty FirstSeen and LastSeen for IP %s, got first=%q last=%q", ipStat.IP, ipStat.FirstSeen, ipStat.LastSeen)
		}
		if ipStat.IP == "162.142.125.12" && ipStat.ScannerTag == "Censys 测绘" {
			foundCensys = true
		}
	}
	if !foundCensys {
		t.Fatalf("expected 162.142.125.12 to be tagged as Censys 测绘, got %+v", summary.TopIPs)
	}
}

func TestSniffTrackerBlockTargetAndAntiLockout(t *testing.T) {
	tracker := serverweb.NewSniffTracker(serverweb.NewIPGeoResolver(), nil)
	tracker.EnableSystemProbe = false

	tracker.Observe("198.51.100.10", "TLS/443 伪装回落嗅探", "masqueraded", 2)
	tracker.Observe("198.51.100.99", "HTTP/80 端口嗅探", "masqueraded", 1)

	// 1. 防锁死测试：禁止拉黑管理员自身 IP 或包含管理员 IP 的 /24 网段
	if _, err := tracker.BlockTarget("203.0.113.5", "203.0.113.5"); err == nil {
		t.Fatalf("expected error when blocking operator's own IP")
	}
	if _, err := tracker.BlockTarget("203.0.113.0/24", "203.0.113.5"); err == nil {
		t.Fatalf("expected error when blocking /24 subnet containing operator's own IP")
	}
	if _, err := tracker.BlockTarget("127.0.0.1", "203.0.113.5"); err == nil {
		t.Fatalf("expected error when blocking loopback IP")
	}

	// 2. 正常拉黑 /24 网段：该网段内所有活跃嗅探 IP 应立即变为 banned
	cidr, err := tracker.BlockTarget("198.51.100.0/24", "203.0.113.5")
	if err != nil {
		t.Fatalf("unexpected error blocking /24 subnet: %v", err)
	}
	if cidr != "198.51.100.0/24" {
		t.Fatalf("expected canonical CIDR 198.51.100.0/24, got %s", cidr)
	}

	summary := tracker.Snapshot(t.Context())
	if summary.TotalBannedIPs != 2 {
		t.Fatalf("expected both IPs in 198.51.100.0/24 to be marked banned, got %d", summary.TotalBannedIPs)
	}
	if len(summary.TopSubnets) == 0 || summary.TopSubnets[0].Status != "banned" {
		t.Fatalf("expected subnet 198.51.100.0/24 status=banned, got %+v", summary.TopSubnets)
	}
}

func TestSniffTrackerMultiNodeTimestampsAndFullList(t *testing.T) {
	persistFile := filepath.Join(t.TempDir(), ".serverweb_sniff.json")
	tracker := serverweb.NewSniffTracker(serverweb.NewIPGeoResolver(), nil, persistFile)
	tracker.EnableSystemProbe = false

	baseNow := time.Now().Truncate(time.Second)
	t1 := baseNow.Add(-2 * time.Hour)
	t2 := baseNow.Add(-15 * time.Minute)

	// 同一扫描 IP 先后探测本机与子节点，验证开始时间保留最早值、最近时间保留最新值
	tracker.ObserveNodeAt("local", "本机网关", "198.51.100.77", "TLS/443 伪装回落嗅探", "masqueraded", 3, t1, t1)
	tracker.ObserveNodeAt("jp-tyo", "日本东京", "198.51.100.77", "SSH 暴力破解", "banned", 5, t2, t2)

	// 在 us-lax 子节点注入 12 个独立嗅探 IP，验证不再被 Top 8 截断
	for i := 1; i <= 12; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		tracker.ObserveNodeAt("us-lax", "美国洛杉矶", ip, "HTTP/80 端口嗅探", "masqueraded", i, t1, t2)
	}

	// 1. 查看全集群汇总 ("all")：应包含 1 + 12 = 13 个 IP，全部返回不截断
	allSum := tracker.SnapshotForNode(t.Context(), "all", false)
	if allSum.TotalSniffIPs != 13 || len(allSum.TopIPs) != 13 {
		t.Fatalf("expected all 13 IPs returned without Top 8 truncation, got total=%d len=%d", allSum.TotalSniffIPs, len(allSum.TopIPs))
	}

	var merged77 *serverweb.SniffIPStat
	for i := range allSum.TopIPs {
		if allSum.TopIPs[i].IP == "198.51.100.77" {
			merged77 = &allSum.TopIPs[i]
			break
		}
	}
	if merged77 == nil {
		t.Fatalf("expected 198.51.100.77 in cluster summary")
	}
	if merged77.Hits != 8 || merged77.Status != "banned" {
		t.Fatalf("expected merged hits=8 status=banned, got %+v", *merged77)
	}
	if merged77.FirstSeen != t1.Format(serverweb.SniffTimeLayout) || merged77.LastSeen != t2.Format(serverweb.SniffTimeLayout) {
		t.Fatalf("expected firstSeen=%s lastSeen=%s, got first=%s last=%s",
			t1.Format(serverweb.SniffTimeLayout), t2.Format(serverweb.SniffTimeLayout), merged77.FirstSeen, merged77.LastSeen)
	}
	if len(merged77.Nodes) != 2 {
		t.Fatalf("expected 2 nodes on 198.51.100.77, got %+v", merged77.Nodes)
	}

	// 2. 分主机查看 "us-lax"：应仅包含该节点的 12 个 IP
	usSum := tracker.SnapshotForNode(t.Context(), "us-lax", false)
	if usSum.TotalSniffIPs != 12 || len(usSum.TopIPs) != 12 {
		t.Fatalf("expected 12 IPs for node us-lax, got %d", usSum.TotalSniffIPs)
	}

	// 3. 分主机查看 "local"：应仅包含本机的 1 个 IP
	localSum := tracker.SnapshotForNode(t.Context(), "local", false)
	if localSum.TotalSniffIPs != 1 || localSum.TopIPs[0].IP != "198.51.100.77" {
		t.Fatalf("expected 1 IP (198.51.100.77) on local node, got %+v", localSum.TopIPs)
	}

	// 4. 验证持久化文件权限 (0600) 及重启恢复
	tracker.Flush()
	if st, err := os.Stat(persistFile); err != nil {
		t.Fatalf("expected persist file to exist: %v", err)
	} else if st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permission on sniff persist file, got %o", st.Mode().Perm())
	}

	reloaded := serverweb.NewSniffTracker(serverweb.NewIPGeoResolver(), nil, persistFile)
	reloaded.EnableSystemProbe = false
	reSum := reloaded.SnapshotForNode(t.Context(), "all", false)
	if reSum.TotalSniffIPs != 13 {
		t.Fatalf("expected 13 IPs after reload from persist file, got %d", reSum.TotalSniffIPs)
	}
}

func TestSniffTrackerRemoteIngestAndLogTimestamps(t *testing.T) {
	tracker := serverweb.NewSniffTracker(serverweb.NewIPGeoResolver(), nil)
	tracker.EnableSystemProbe = false

	now := time.Now().Truncate(time.Second)
	tsEarly := now.Add(-45 * time.Minute).Format(time.RFC3339)
	tsLate := now.Add(-5 * time.Minute).Format(time.RFC3339)

	remoteRaw := fmt.Sprintf(`
===SINGCTL_TRUSTED===
{"connections":[{"metadata":{"sourceIP":"192.0.2.88"}}]}
===SINGCTL_NFT===
table inet security {
	set blocklist_ip4 {
		elements = { 198.51.100.33 timeout 6d }
	}
}
===SINGCTL_F2B===
Status for the jail: sshd
   |- Banned IP list:	203.0.113.44
===SINGCTL_KERN===
%s sg-node kernel: [NFT] Blocked IN=eth0 SRC=198.51.100.90 DST=192.0.2.1 PROTO=TCP DPT=3389
%s sg-node kernel: [NFT] Blocked IN=eth0 SRC=198.51.100.90 DST=192.0.2.1 PROTO=TCP DPT=3389
===SINGCTL_SS===
ESTAB 0 0 192.0.2.1:443 192.0.2.88:54321
SYN-RECV 0 0 192.0.2.1:443 198.51.100.120:60123
`, tsEarly, tsLate)

	tracker.IngestRemoteSniffOutput("sg-1", "新加坡节点", remoteRaw)

	sgSum := tracker.SnapshotForNode(t.Context(), "sg-1", false)
	if sgSum.TotalSniffIPs != 4 {
		t.Fatalf("expected 4 sniffing IPs on sg-1 (excluding trusted 192.0.2.88), got %d: %+v", sgSum.TotalSniffIPs, sgSum.TopIPs)
	}

	var nft90 *serverweb.SniffIPStat
	for i := range sgSum.TopIPs {
		if sgSum.TopIPs[i].IP == "192.0.2.88" {
			t.Fatalf("trusted sing-box client 192.0.2.88 must be excluded")
		}
		if sgSum.TopIPs[i].IP == "198.51.100.90" {
			nft90 = &sgSum.TopIPs[i]
		}
	}
	if nft90 == nil {
		t.Fatalf("expected 198.51.100.90 from remote kernel log")
	}
	wantFirst := now.Add(-45 * time.Minute).Format(serverweb.SniffTimeLayout)
	wantLast := now.Add(-5 * time.Minute).Format(serverweb.SniffTimeLayout)
	if nft90.FirstSeen != wantFirst || nft90.LastSeen != wantLast || nft90.Hits != 2 {
		t.Fatalf("expected 198.51.100.90 hits=2 first=%s last=%s, got %+v", wantFirst, wantLast, *nft90)
	}
}
