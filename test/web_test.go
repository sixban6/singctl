package test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
	"singctl/internal/webui"
	"strconv"
	"strings"
	"testing"
	"time"
)

func withWebStatePath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	webui.WebStatePathOverride = filepath.Join(dir, webui.WebStateName)
	t.Cleanup(func() { webui.WebStatePathOverride = "" })
}

func TestWebStateReadWrite(t *testing.T) {
	withWebStatePath(t)

	st := webui.WebState{Pid: 12345, Listen: "127.0.0.1:8090"}
	if err := webui.WriteWebStateAtomic(st); err != nil {
		t.Fatal(err)
	}
	got, err := webui.ReadWebState()
	if err != nil {
		t.Fatal(err)
	}
	if got != st {
		t.Errorf("expected %+v, got %+v", st, got)
	}
}

func TestAcquireWebLock_ExcludesConcurrent(t *testing.T) {
	withWebStatePath(t)

	// 状态文件指向一个真实的“web 命名”进程 → 第二次启动必须被拒
	pid := spawnWebNamedProcess(t, "30")
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(webui.WebStatePath(),
		[]byte(`{"pid":`+strconv.Itoa(pid)+`,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := webui.AcquireWebLock(webui.WebState{Pid: os.Getpid(), Listen: ":8090"}); err == nil {
		t.Fatal("expected acquire to fail while web-named process holds state")
	} else if err != webui.ErrWebAlreadyRunning {
		t.Fatalf("expected errWebAlreadyRunning, got %v", err)
	}
	if _, running := webui.WebStatus(); !running {
		t.Error("web-named process should be detected as running webui")
	}
}

func TestAcquireWebLock_CleansStale(t *testing.T) {
	withWebStatePath(t)

	// 死 PID 的残留状态文件应被清理
	if err := os.WriteFile(webui.WebStatePath(), []byte(`{"pid":99999999,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := webui.AcquireWebLock(webui.WebState{Pid: os.Getpid(), Listen: ":8090"}); err != nil {
		t.Fatalf("expected stale state cleaned, got %v", err)
	}
}

func TestWebProcMatches_OwnPidFalse(t *testing.T) {
	// 测试二进制命令行不含 web/w 参数
	if webui.WebProcMatches(os.Getpid()) {
		t.Error("own pid (no web arg) should not match")
	}
	if !webui.WebProcMatches(0) && false {
		t.Fail()
	}
	// 死 PID
	if webui.WebProcMatches(99999999) {
		t.Error("dead pid should not match")
	}
}

// spawnWebNamedProcess 启动一个 argv0 为 "web" 的 sleep 进程,
// 用于真实校验命令行匹配与 StopWeb 的完整停止流程(依赖 bash 的 exec -a)。
func spawnWebNamedProcess(t *testing.T, seconds string) int {
	t.Helper()
	cmd := exec.Command("bash", "-c", "exec -a web sleep "+seconds)
	if err := cmd.Start(); err != nil {
		t.Skip("bash not available")
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd.Process.Pid
}

func TestWebProcMatches_NamedProcessTrue(t *testing.T) {
	pid := spawnWebNamedProcess(t, "30")
	time.Sleep(100 * time.Millisecond) // 等 exec 生效

	if !webui.WebProcMatches(pid) {
		t.Errorf("pid %d (argv0=web) should match", pid)
	}
}

func TestStopWeb_KillsWebProcess(t *testing.T) {
	withWebStatePath(t)

	pid := spawnWebNamedProcess(t, "30")
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(webui.WebStatePath(),
		[]byte(`{"pid":`+strconv.Itoa(pid)+`,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}

	stopped, err := webui.StopWeb()
	if err != nil || !stopped {
		t.Fatalf("expected stopped=true, got stopped=%v err=%v", stopped, err)
	}
	if webui.ProcessAlive(pid) {
		t.Error("process should have been terminated")
	}
	if _, err := os.Stat(webui.WebStatePath()); !os.IsNotExist(err) {
		t.Error("state file should be removed after stop")
	}
}

func TestStopWeb_NotRunning(t *testing.T) {
	withWebStatePath(t)

	stopped, err := webui.StopWeb()
	if err != nil {
		t.Fatal(err)
	}
	if stopped {
		t.Error("expected stopped=false when not running")
	}
}

func TestStopWeb_StaleStateOnlyCleansFile(t *testing.T) {
	withWebStatePath(t)

	// 状态文件指向一个无关存活进程(sleep,命令行不含 web)→ 只清理文件,不动进程
	sleep := exec.Command("sleep", "30")
	if err := sleep.Start(); err != nil {
		t.Skip("sleep not available")
	}
	t.Cleanup(func() {
		_ = sleep.Process.Kill()
		_, _ = sleep.Process.Wait()
	})

	if err := os.WriteFile(webui.WebStatePath(),
		[]byte(`{"pid":`+strconv.Itoa(sleep.Process.Pid)+`,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}

	stopped, err := webui.StopWeb()
	if err != nil || stopped {
		t.Fatalf("expected stopped=false (stale), got %v %v", stopped, err)
	}
	if !webui.ProcessAlive(sleep.Process.Pid) {
		t.Error("unrelated process must NOT be killed")
	}
	if _, err := os.Stat(webui.WebStatePath()); !os.IsNotExist(err) {
		t.Error("stale state file should be cleaned")
	}
}

func TestFormatListenURLs(t *testing.T) {
	// 指定具体地址 → 原样
	got := webui.FormatListenURLs("192.168.1.1:9000")
	if len(got) != 1 || got[0] != "192.168.1.1:9000" {
		t.Errorf("unexpected: %v", got)
	}
	// 通配 → 至少含 127.0.0.1
	got = webui.FormatListenURLs(":8090")
	if len(got) == 0 || !strings.HasSuffix(got[len(got)-1], ":8090") {
		t.Errorf("unexpected: %v", got)
	}
}

func TestMaskURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"标准订阅链接", "https://sub.example.com/api/v1/client/subscribe?token=abcdef123456", "https://******"},
		{"带端口的链接", "http://provider.io:8443/token/xyz?flag=1", "http://******"},
		{"畸形链接", "not-a-url", "https://******"},
		{"空链接", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := webui.MaskURL(tc.in); got != tc.want {
				t.Fatalf("maskURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestWebUIAuthMethods(t *testing.T) {
	const pass = "secret123"
	server := webui.New(webui.Options{
		Password: pass,
	})

	token := server.SessionToken()
	if token == "" {
		t.Fatalf("sessionToken should not be empty")
	}

	// 1. 无凭据请求，应被拒绝并返回 401
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
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
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK for basic auth, got %d", rec.Code)
		}
		// 校验下发了 singctl_session Cookie
		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == webui.SessionCookieName {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("expected %s cookie in response, but found none", webui.SessionCookieName)
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
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with session cookie, got %d", rec.Code)
		}
	}

	// 4. 携带 Bearer Token 请求放行
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with Bearer token, got %d", rec.Code)
		}
	}

	// 5. 携带 URL ?token= 请求放行
	{
		req := httptest.NewRequest("GET", "/api/status?token="+token, nil)
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with ?token=, got %d", rec.Code)
		}
	}

	// 6. 携带 URL ?password= 请求放行
	{
		req := httptest.NewRequest("GET", "/api/status?password="+pass, nil)
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 OK with ?password=, got %d", rec.Code)
		}
	}

	// 7. 伪造篡改的 Token / Cookie，应被拒绝
	{
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.AddCookie(&http.Cookie{Name: webui.SessionCookieName, Value: "invalid_fake_token"})
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for fake token, got %d", rec.Code)
		}
	}

	// 8. 静态资源免密测试 (受 authOnly 保护)
	{
		// 8.1 无认证访问静态资源 -> 401
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for static root without auth, got %d", rec.Code)
		}

		// 8.2 带 Cookie 访问静态资源 -> 200
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.AddCookie(sessionCookie)
		rec2 := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusOK {
			t.Fatalf("expected 200 for static root with cookie, got %d", rec2.Code)
		}

		// 8.3 带 ?token= 访问静态资源 -> 200
		req3 := httptest.NewRequest("GET", "/?token="+token, nil)
		rec3 := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec3, req3)
		if rec3.Code != http.StatusOK {
			t.Fatalf("expected 200 for static root with ?token=, got %d", rec3.Code)
		}
	}

	// 9. 获取免密 URL (/api/session/url)
	{
		req := httptest.NewRequest("GET", "/api/session/url", nil)
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		server.Mux.ServeHTTP(rec, req)
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
		server.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 for /api/logout, got %d", rec.Code)
		}
		var cleared bool
		for _, c := range rec.Result().Cookies() {
			if c.Name == webui.SessionCookieName && c.MaxAge < 0 {
				cleared = true
				break
			}
		}
		if !cleared {
			t.Fatalf("expected %s cookie to be cleared with negative MaxAge", webui.SessionCookieName)
		}
	}
}

func TestWebUIAuthDisabled(t *testing.T) {
	// 未设置密码时，一切直接放行
	server := webui.New(webui.Options{
		Password: "",
	})
	req := httptest.NewRequest("GET", "/api/status", nil)
	rec := httptest.NewRecorder()
	server.Mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when auth disabled, got %d", rec.Code)
	}
}

// withIOSStub 写一个最小的 singctl.yaml 并注入 iosGenerate 桩, 返回还原函数
func withIOSStub(t *testing.T) (cfgPath string, restore func()) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "singctl.yaml")
	yaml := `subs:
  - name: test
    url: https://example.com/sub
`
	if err := os.WriteFile(cfgPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	old := webui.IOSGenerate
	webui.IOSGenerate = func(*config.Config) (string, error) {
		return `{"outbounds":[],"route":{"rule_set":[{"type":"remote","tag":"rs","url":"https://x/rs.srs"}]}}`, nil
	}
	return cfgPath, func() { webui.IOSGenerate = old }
}

func TestIOSConfigDownload(t *testing.T) {
	cfgPath, restore := withIOSStub(t)
	defer restore()

	s := webui.New(webui.Options{ConfigPath: cfgPath})
	ts := httptest.NewServer(s.Mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/gen/ios")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "singctl-ios.json") {
		t.Fatalf("expected attachment filename, got %q", cd)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"type":"remote"`) {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestIOSConfigDownloadPassword(t *testing.T) {
	cfgPath, restore := withIOSStub(t)
	defer restore()

	s := webui.New(webui.Options{ConfigPath: cfgPath, Password: "secret123"})
	ts := httptest.NewServer(s.Mux)
	defer ts.Close()

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"无凭据拒绝", "/api/gen/ios", 401},
		{"错误口令拒绝", "/api/gen/ios?password=wrong", 401},
		{"正确口令放行", "/api/gen/ios?password=secret123", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.url)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("%s: expected %d, got %d", tc.url, tc.want, resp.StatusCode)
			}
		})
	}
}

func TestIOSConfigURLEndpoint(t *testing.T) {
	cfgPath, restore := withIOSStub(t)
	defer restore()

	s := webui.New(webui.Options{ConfigPath: cfgPath, Listen: ":8090", Password: "ios-test-secret"})
	ts := httptest.NewServer(s.Mux)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/gen/ios/url", nil)
	req.Header.Set("Authorization", "Bearer "+s.SessionToken())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// 沙箱/无网环境可能拿不到局域网 IP(500), 此时仍继续验证带 token 直接下载 /api/gen/ios
	if resp.StatusCode == 200 {
		var d struct {
			URL       string `json:"url"`
			ImportURL string `json:"importUrl"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(d.URL, "/api/gen/ios?token=") || strings.Contains(d.URL, "password=") {
			t.Fatalf("url should carry ?token= without plaintext password, got %q", d.URL)
		}
		if !strings.HasPrefix(d.ImportURL, "sing-box://import-remote-profile?url=") {
			t.Fatalf("expected SFI importUrl scheme, got %q", d.ImportURL)
		}
		parsedDL, err := url.Parse(d.URL)
		if err != nil {
			t.Fatal(err)
		}
		dlResp, err := http.Get(ts.URL + parsedDL.RequestURI())
		if err != nil {
			t.Fatal(err)
		}
		defer dlResp.Body.Close()
		if dlResp.StatusCode != 200 {
			t.Fatalf("GET /api/gen/ios with returned ?token= failed: %d", dlResp.StatusCode)
		}
		dlBody, _ := io.ReadAll(dlResp.Body)
		if err := singbox.CheckIOSCompatibility(string(dlBody)); err != nil {
			t.Fatalf("CheckIOSCompatibility failed: %v", err)
		}
		return
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected 200 or 500, got %d", resp.StatusCode)
	}
}

// withOverrides 将 sing-box 配置路径/安装路径重定向到临时目录
func withOverrides(t *testing.T) (sbConfigPath string) {
	t.Helper()
	dir := t.TempDir()

	sbConfigPath = filepath.Join(dir, "config.json")
	oldCfg, oldBin := constant.SingBoxConfigFile, constant.SingBoxInstallDir
	constant.SingBoxConfigFile = sbConfigPath
	// 指向不存在的路径 → 视为未安装 sing-box;同时屏蔽 PATH 兜底,
	// 避免测试机上真实安装的 sing-box 干扰确定性
	constant.SingBoxInstallDir = filepath.Join(dir, "sing-box-not-exist")
	oldWebLook := webui.LookPathFunc
	oldSBLook := singbox.LookPathFunc
	stubNotFound := func(string) (string, error) {
		return "", fmt.Errorf("not found in test")
	}
	webui.LookPathFunc = stubNotFound
	singbox.LookPathFunc = stubNotFound
	t.Cleanup(func() {
		constant.SingBoxConfigFile = oldCfg
		constant.SingBoxInstallDir = oldBin
		webui.LookPathFunc = oldWebLook
		singbox.LookPathFunc = oldSBLook
	})
	return sbConfigPath
}

func newTestServer(t *testing.T, sbConfigPath string) *httptest.Server {
	t.Helper()
	dir := filepath.Dir(sbConfigPath)
	s := webui.New(webui.Options{ConfigPath: filepath.Join(dir, "singctl.yaml")})
	ts := httptest.NewServer(s.Mux)
	t.Cleanup(ts.Close)
	return ts
}

func doJSON(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestSbConfigHandlers(t *testing.T) {
	sbConfigPath := withOverrides(t)
	ts := newTestServer(t, sbConfigPath)

	// 1. GET: 文件不存在
	code, body := doJSON(t, "GET", ts.URL+"/api/sbconfig", "")
	if code != 200 || !strings.Contains(body, `"exists":false`) {
		t.Fatalf("expected 200 exists:false, got %d %s", code, body)
	}

	// 2. PUT 非法 JSON → 400
	code, _ = doJSON(t, "PUT", ts.URL+"/api/sbconfig", `{"content":"{broken"}`)
	if code != 400 {
		t.Fatalf("expected 400 for invalid json, got %d", code)
	}

	// 3. PUT 合法 JSON → ok(未安装 sing-box → checked=false, 强制 0600)
	code, body = doJSON(t, "PUT", ts.URL+"/api/sbconfig", `{"content":"{\"log\":{\"level\":\"info\"}}"}`)
	if code != 200 || !strings.Contains(body, `"checked":false`) {
		t.Fatalf("expected 200 checked:false, got %d %s", code, body)
	}
	if info, statErr := os.Stat(sbConfigPath); statErr != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected sb config mode 0600 after PUT, err=%v mode=%v", statErr, info.Mode().Perm())
	}

	// 4. 再改一次 → 产生 1 个备份
	code, body = doJSON(t, "PUT", ts.URL+"/api/sbconfig", `{"content":"{\"log\":{\"level\":\"warn\"}}"}`)
	if code != 200 {
		t.Fatalf("put failed: %d %s", code, body)
	}
	_, body = doJSON(t, "GET", ts.URL+"/api/sbconfig", "")
	if !strings.Contains(body, `"backups":["config.json.webui-bak-`) || !strings.Contains(body, `\"level\":\"warn\"`) {
		t.Fatalf("expected 1 backup + new content, got %s", body)
	}

	// 5. 恢复非法名称 → 400
	code, _ = doJSON(t, "POST", ts.URL+"/api/sbconfig/restore", `{"name":"../../etc/passwd"}`)
	if code != 400 {
		t.Fatalf("expected 400 for traversal attempt, got %d", code)
	}
	code, _ = doJSON(t, "POST", ts.URL+"/api/sbconfig/restore", `{"name":"other.json.webui-bak-x"}`)
	if code != 400 {
		t.Fatalf("expected 400 for wrong prefix, got %d", code)
	}

	// 6. 恢复合法备份 → 内容回到第一版
	code, body = doJSON(t, "POST", ts.URL+"/api/sbconfig/restore", `{"name":"config.json.webui-bak-20060102-150405"}`)
	if code != 404 {
		t.Fatalf("expected 404 for nonexistent backup, got %d %s", code, body)
	}
	// 用真实备份名
	_, body = doJSON(t, "GET", ts.URL+"/api/sbconfig", "")
	start := strings.Index(body, `config.json.webui-bak-`)
	end := strings.Index(body[start:], `"`)
	realName := body[start : start+end]
	code, _ = doJSON(t, "POST", ts.URL+"/api/sbconfig/restore", fmt.Sprintf(`{"name":%q}`, realName))
	if code != 200 {
		t.Fatalf("restore failed: %d", code)
	}
	_, body = doJSON(t, "GET", ts.URL+"/api/sbconfig", "")
	if !strings.Contains(body, `\"level\":\"info\"`) {
		t.Fatalf("expected restored content, got %s", body)
	}
	if info, statErr := os.Stat(sbConfigPath); statErr != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("expected sb config mode 0600 after restore, err=%v mode=%v", statErr, info.Mode().Perm())
	}
}

func TestSbConfigCheckWithFakeBinary(t *testing.T) {
	sbConfigPath := withOverrides(t)
	dir := filepath.Dir(sbConfigPath)

	// 伪造 sing-box:check 子命令按内容决定成败
	fake := filepath.Join(dir, "sing-box")
	script := `#!/bin/sh
if [ "$1" = "check" ]; then
  if grep -q '"level": "good"' "$3"; then exit 0; fi
  echo "FATAL: invalid config in test"
  exit 1
fi
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	constant.SingBoxInstallDir = fake // fileExists 命中,无需 PATH 查找

	ts := newTestServer(t, sbConfigPath)

	// check 失败 → 400 且带上游错误信息
	code, body := doJSON(t, "PUT", ts.URL+"/api/sbconfig", `{"content":"{\"log\":{\"level\": \"bad\"}}"}`)
	if code != 400 || !strings.Contains(body, "invalid config in test") {
		t.Fatalf("expected 400 with check output, got %d %s", code, body)
	}

	// check 通过 → 保存成功且 checked=true
	code, body = doJSON(t, "PUT", ts.URL+"/api/sbconfig", `{"content":"{\"log\":{\"level\": \"good\"}}"}`)
	if code != 200 || !strings.Contains(body, `"checked":true`) {
		t.Fatalf("expected 200 checked:true, got %d %s", code, body)
	}
}

func TestClashProxyRemovedAndNativeSbProxies(t *testing.T) {
	sbConfigPath := withOverrides(t)

	// 上游伪 clash API（要求 Bearer 鉴权）
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer topsecret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/version":
			_, _ = w.Write([]byte(`{"version":"1.14.4","meta":true}`))
		case "/configs":
			_, _ = w.Write([]byte(`{"mode":"rule"}`))
		case "/proxies":
			_, _ = w.Write([]byte(`{"proxies":{"Proxy":{"type":"Selector","now":"Node-A","all":["Node-A","#DC"]},"Node-A":{"type":"VLESS","history":[{"delay":42}]},"#DC":{"type":"Direct"}}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(up.Close)

	cfgJSON := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":%q,"secret":"topsecret"}}}`,
		strings.TrimPrefix(up.URL, "http://"))
	if err := os.WriteFile(sbConfigPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	ts := newTestServer(t, sbConfigPath)

	// 原免鉴权 /clash/* 与根路径反代应已下线（返回 404，不再透传上游）
	for _, oldPath := range []string{"/clash/version", "/clash/ui/", "/version", "/proxies"} {
		code, body := doJSON(t, "GET", ts.URL+oldPath, "")
		if code == 200 || strings.Contains(body, "1.14.4") {
			t.Fatalf("legacy clash proxy route %s should be removed, got %d %s", oldPath, code, body)
		}
	}

	// 新版原生聚合接口走 /api/sb/proxies 并由服务端携带 secret 访问回环 Clash API
	code, body := doJSON(t, "GET", ts.URL+"/api/sb/proxies", "")
	if code != 200 || !strings.Contains(body, `"primaryNode":"Node-A"`) {
		t.Fatalf("expected /api/sb/proxies to return Node-A snapshot, got %d %s", code, body)
	}
}

func TestTsStartArgs(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		want   []string
	}{
		{
			name:   "router mode",
			params: map[string]any{"mode": "router"},
			want:   []string{"ts", "start", "--mode", "router"},
		},
		{
			name:   "gateway with accept routes",
			params: map[string]any{"mode": "Gateway", "acceptRoutes": true},
			want:   []string{"ts", "start", "--mode", "gateway", "--accept-routes"},
		},
		{
			name:   "explicit flags",
			params: map[string]any{"exitNode": true, "router": true},
			want:   []string{"ts", "start", "--exit-node", "--router"},
		},
		{
			name:   "client mode only",
			params: map[string]any{"mode": "client"},
			want:   []string{"ts", "start", "--mode", "client"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := webui.TsStartArgs(tc.params)
			if strings.Join(got, " ") != strings.Join(tc.want, " ") {
				t.Errorf("tsStartArgs(%v) = %v, want %v", tc.params, got, tc.want)
			}
		})
	}
}

func TestActionWhitelist(t *testing.T) {
	for name, def := range webui.Actions {
		if def.Title == "" {
			t.Errorf("action %q missing title", name)
		}
		args := def.Build(nil)
		if len(args) == 0 {
			t.Errorf("action %q produced no args", name)
		}
	}
	if _, ok := webui.Actions["sb-start"]; !ok {
		t.Error("sb-start action missing")
	}
}

func TestNDJSONWriterStripsANSI(t *testing.T) {
	rec := httptest.NewRecorder()
	w := webui.NewNDJSONWriter(rec)
	// 模拟一行带颜色转义的输出
	_, _ = w.Write([]byte("\x1b[0;32m[SUCCESS] done\x1b[0m\n\x1b[0;31m[ERROR] bad\x1b[0m\n"))

	scanner := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	var lines []string
	for scanner.Scan() {
		if scanner.Text() != "" {
			lines = append(lines, scanner.Text())
		}
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 ndjson lines, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "[SUCCESS] done") || strings.Contains(lines[0], "\x1b") {
		t.Errorf("ANSI not stripped or content wrong: %q", lines[0])
	}
	if !strings.Contains(lines[1], "[ERROR] bad") {
		t.Errorf("second line wrong: %q", lines[1])
	}
}

func TestConfigDTOApplyPreservesNodeRules(t *testing.T) {
	cfg := &config.Config{
		Subs: []config.Subscription{
			{
				Name:        "main",
				URL:         "https://example.com/sub1",
				RemoveEmoji: true,
				Include:     "HK|JP",
				Exclude:     "剩余|到期",
				Rename:      []config.RenameRule{{Match: " VIP$", Replace: ""}},
			},
		},
	}

	// Simulate WebUI basic form submission where include/exclude/rename are omitted (nil)
	formDTO := webui.ConfigDTO{
		Subs: []webui.SubDTO{
			{
				Name:        "main",
				URL:         "https://example.com/sub1-updated",
				RemoveEmoji: false,
			},
		},
	}
	formDTO.ApplyTo(cfg)

	if len(cfg.Subs) != 1 {
		t.Fatalf("expected 1 sub, got %d", len(cfg.Subs))
	}
	got := cfg.Subs[0]
	if got.URL != "https://example.com/sub1-updated" || got.RemoveEmoji {
		t.Fatalf("basic fields not updated: %+v", got)
	}
	if got.Include != "HK|JP" || got.Exclude != "剩余|到期" || len(got.Rename) != 1 {
		t.Fatalf("expected omitted node rules to be preserved, got: %+v", got)
	}

	// Explicit override in DTO updates/clears rules
	empty := ""
	newInc := "US"
	overrideDTO := webui.ConfigDTO{
		Subs: []webui.SubDTO{
			{
				Name:    "main",
				URL:     "https://example.com/sub1-updated",
				Include: &newInc,
				Exclude: &empty,
				Rename:  []config.RenameRule{},
			},
		},
	}
	overrideDTO.ApplyTo(cfg)
	got = cfg.Subs[0]
	if got.Include != "US" || got.Exclude != "" || len(got.Rename) != 0 {
		t.Fatalf("expected explicit node rule overrides to apply, got: %+v", got)
	}
}

func TestWatchdogWebAPI_GetPutToggleAndLogsFilter(t *testing.T) {
	withTestPaths(t)
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	initCfg := &config.Config{
		Subs: []config.Subscription{
			{Name: "main", URL: "https://example.com/sub"},
		},
	}
	if err := config.Save(cfgPath, initCfg); err != nil {
		t.Fatal(err)
	}

	srv := webui.New(webui.Options{
		ConfigPath: cfgPath,
		Version:    "1.14.102",
	})

	// 1. GET /api/watchdog defaults to failover.enabled = true
	{
		req := httptest.NewRequest(http.MethodGet, "/api/watchdog", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/watchdog failed: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Config struct {
				Failover struct {
					Enabled bool     `json:"enabled"`
					Groups  []string `json:"groups"`
				} `json:"failover"`
			} `json:"config"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if !body.Config.Failover.Enabled {
			t.Fatal("expected failover.enabled=true by default")
		}
		if len(body.Config.Failover.Groups) != len(config.DefaultWatchdogFailoverGroups) {
			t.Fatalf("expected default groups, got %v", body.Config.Failover.Groups)
		}
	}

	// 2. PUT /api/watchdog/config: customize groups & parameters, then toggle enabled=false
	{
		payload := `{
			"interval": 120,
			"sub_sync_enabled": false,
			"failover": {
				"enabled": false,
				"groups": ["#VPS", "Game", "Streaming"],
				"has_groups": true,
				"patrol_interval": 45,
				"probe_timeout_ms": 3000,
				"confirm_retries": 2,
				"auto_failback": true,
				"failback_cooldown": 240,
				"max_failback_delay_ms": 500,
				"probe_urls": ["https://example.com/generate_204"],
				"has_probe_urls": true
			}
		}`
		req := httptest.NewRequest(http.MethodPut, "/api/watchdog/config", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT /api/watchdog/config failed: %d %s", rec.Code, rec.Body.String())
		}

		fi, err := os.Stat(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("expected singctl.yaml mode 0600, got %o", fi.Mode().Perm())
		}

		saved, err := config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if saved.Watchdog.Failover.IsEnabled() {
			t.Fatal("expected failover disabled after PUT")
		}
		if saved.Watchdog.SubSyncInterval != -1 {
			t.Fatalf("expected sub_sync_interval=-1, got %d", saved.Watchdog.SubSyncInterval)
		}
		if len(saved.Watchdog.Failover.EffectiveGroups()) != 3 || saved.Watchdog.Failover.EffectiveConfirmRetries() != 2 {
			t.Fatalf("unexpected saved failover config: %+v", saved.Watchdog.Failover)
		}
	}

	// 3. PUT /api/watchdog/config: 1-click toggle enabled=true preserves custom groups
	{
		req := httptest.NewRequest(http.MethodPut, "/api/watchdog/config", strings.NewReader(`{"failover":{"enabled":true}}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("toggle enabled=true failed: %d %s", rec.Code, rec.Body.String())
		}
		saved, _ := config.Load(cfgPath)
		if !saved.Watchdog.Failover.IsEnabled() || len(saved.Watchdog.Failover.EffectiveGroups()) != 3 {
			t.Fatalf("expected enabled=true while keeping custom groups, got %+v", saved.Watchdog.Failover)
		}
	}

	// 4. GET /api/logs?name=events filters key watchdog events cleanly
	{
		sampleLog := strings.Join([]string{
			"Platform for singgen:linux",
			"2026-11-12 15:00:00 [INFO] 守护进程启动...",
			"2026-11-12 15:05:00 [WATCHDOG] GROUP_FAILOVER healthy=false restarts=0/3 | 策略组 [#VPS] 切备",
		}, "\n") + "\n"
		if err := os.WriteFile(daemon.GetDaemonLogPath(), []byte(sampleLog), 0600); err != nil {
			t.Fatal(err)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/logs?name=events&tail=100", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/logs?name=events failed: %d", rec.Code)
		}
		var out struct {
			Content string `json:"content"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if !strings.Contains(out.Content, "GROUP_FAILOVER") || strings.Contains(out.Content, "Platform for singgen:") {
			t.Fatalf("unexpected events log output: %q", out.Content)
		}
	}

	// 5. GET /api/logs returns newest lines first, and POST /api/logs/clear truncates daemon & webui logs in place
	{
		origWebLog := webui.WebLogPathOverride
		webLogPath := filepath.Join(tmpDir, "webui.log")
		webui.WebLogPathOverride = webLogPath
		t.Cleanup(func() { webui.WebLogPathOverride = origWebLog })

		orderedLog := strings.Join([]string{
			"2026-11-21 15:00:00 [INFO] older entry",
			"2026-11-21 15:05:00 [WARN] middle entry",
			"2026-11-21 15:10:00 [ERROR] newest entry",
		}, "\n") + "\n"
		if err := os.WriteFile(daemon.GetDaemonLogPath(), []byte(orderedLog), 0600); err != nil {
			t.Fatal(err)
		}

		reqRev := httptest.NewRequest(http.MethodGet, "/api/logs?name=daemon&tail=100", nil)
		recRev := httptest.NewRecorder()
		srv.Mux.ServeHTTP(recRev, reqRev)
		if recRev.Code != http.StatusOK {
			t.Fatalf("GET /api/logs?name=daemon failed: %d", recRev.Code)
		}
		var revOut struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(recRev.Body.Bytes(), &revOut); err != nil {
			t.Fatal(err)
		}
		idxNewest := strings.Index(revOut.Content, "newest entry")
		idxMiddle := strings.Index(revOut.Content, "middle entry")
		idxOlder := strings.Index(revOut.Content, "older entry")
		if idxNewest < 0 || idxMiddle <= idxNewest || idxOlder <= idxMiddle {
			t.Fatalf("expected reverse chronological order (newest first), got:\n%s", revOut.Content)
		}

		reqClear := httptest.NewRequest(http.MethodPost, "/api/logs/clear", strings.NewReader(`{"name":"daemon"}`))
		reqClear.Header.Set("Content-Type", "application/json")
		recClear := httptest.NewRecorder()
		srv.Mux.ServeHTTP(recClear, reqClear)
		if recClear.Code != http.StatusOK {
			t.Fatalf("POST /api/logs/clear daemon failed: %d %s", recClear.Code, recClear.Body.String())
		}
		info, err := os.Stat(daemon.GetDaemonLogPath())
		if err != nil || info.Size() != 0 {
			t.Fatalf("expected truncated 0-byte daemon log file, stat=%v size=%d", err, func() int64 {
				if info != nil {
					return info.Size()
				}
				return -1
			}())
		}

		reqAfter := httptest.NewRequest(http.MethodGet, "/api/logs?name=daemon&tail=100", nil)
		recAfter := httptest.NewRecorder()
		srv.Mux.ServeHTTP(recAfter, reqAfter)
		var afterOut struct {
			Content string `json:"content"`
		}
		_ = json.Unmarshal(recAfter.Body.Bytes(), &afterOut)
		if afterOut.Content != "(暂无日志记录)" {
			t.Fatalf("expected empty placeholder after daemon clear, got %q", afterOut.Content)
		}

		if err := os.WriteFile(webLogPath, []byte("2026-11-21 15:11:00 [INFO] webui line\n"), 0600); err != nil {
			t.Fatal(err)
		}
		reqClearWeb := httptest.NewRequest(http.MethodPost, "/api/logs/clear", strings.NewReader(`{"name":"webui"}`))
		reqClearWeb.Header.Set("Content-Type", "application/json")
		recClearWeb := httptest.NewRecorder()
		srv.Mux.ServeHTTP(recClearWeb, reqClearWeb)
		if recClearWeb.Code != http.StatusOK {
			t.Fatalf("POST /api/logs/clear webui failed: %d %s", recClearWeb.Code, recClearWeb.Body.String())
		}
		if wInfo, wErr := os.Stat(webLogPath); wErr != nil || wInfo.Size() != 0 {
			t.Fatalf("expected truncated 0-byte webui log file, stat=%v", wErr)
		}
	}
}

func TestWebStatePermissionsAndMetadata(t *testing.T) {
	withWebStatePath(t)

	st := webui.WebState{
		Pid:        24680,
		Listen:     ":8090",
		ConfigPath: "/etc/singctl/singctl.yaml",
		Password:   "test-pass-placeholder",
	}
	if err := webui.WriteWebStateAtomic(st); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(webui.WebStatePath())
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions on web state file, got %o", fi.Mode().Perm())
		}
	}
	got, err := webui.ReadWebState()
	if err != nil {
		t.Fatal(err)
	}
	if got != st {
		t.Fatalf("state mismatch: got %+v, want %+v", got, st)
	}
}

func TestBuildCleanSubprocessEnv(t *testing.T) {
	t.Setenv("SINGCTL_WEB_BACKGROUND", "1")
	t.Setenv("SINGCTL_WEB_READY_FD", "3")
	t.Setenv("SINGCTL_FROM_WEBUI", "1")
	t.Setenv("SINGCTL_WEB_PASSWORD", "old-pass")

	env := webui.BuildCleanSubprocessEnv("SINGCTL_WEB_PASSWORD=new-pass", "CUSTOM_FLAG=ok")
	var sawPass int
	var sawCustom bool
	for _, kv := range env {
		switch {
		case strings.HasPrefix(kv, "SINGCTL_WEB_BACKGROUND="):
			t.Fatalf("SINGCTL_WEB_BACKGROUND must be stripped, got %q", kv)
		case strings.HasPrefix(kv, "SINGCTL_WEB_READY_FD="):
			t.Fatalf("SINGCTL_WEB_READY_FD must be stripped, got %q", kv)
		case strings.HasPrefix(kv, "SINGCTL_FROM_WEBUI="):
			t.Fatalf("SINGCTL_FROM_WEBUI must be stripped, got %q", kv)
		case strings.HasPrefix(kv, "SINGCTL_WEB_PASSWORD="):
			sawPass++
			if kv != "SINGCTL_WEB_PASSWORD=new-pass" {
				t.Fatalf("unexpected password env: %q", kv)
			}
		case kv == "CUSTOM_FLAG=ok":
			sawCustom = true
		}
	}
	if sawPass != 1 || !sawCustom {
		t.Fatalf("expected deduplicated SINGCTL_WEB_PASSWORD (count=1) and CUSTOM_FLAG=ok, got count=%d custom=%v", sawPass, sawCustom)
	}
}

func TestChildReadyWithOptions_PreservesListenAndProtectsNonPipeFd3(t *testing.T) {
	withWebStatePath(t)

	// 打开一个真实 TCP Listener，验证即便未预置管道，ChildReadyWithOptions 也绝不会误关 Socket FD，
	// 同时会清除自身 SINGCTL_WEB_BACKGROUND 环境变量并保留用户原始 :8090 配置而非 [::]:8090。
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	t.Setenv("SINGCTL_WEB_BACKGROUND", "1")
	t.Setenv("SINGCTL_WEB_READY_FD", "3")

	webui.ChildReadyWithOptions(webui.Options{
		Listen:     ":8090",
		ConfigPath: "/tmp/example-singctl.yaml",
		Password:   "unit-test-pass",
	}, "[::]:8090")

	if os.Getenv("SINGCTL_WEB_BACKGROUND") != "" {
		t.Fatal("expected SINGCTL_WEB_BACKGROUND to be cleared in child")
	}
	st, err := webui.ReadWebState()
	if err != nil {
		t.Fatal(err)
	}
	if st.Listen != ":8090" {
		t.Fatalf("expected original Listen ':8090' preserved, got %q", st.Listen)
	}
	if st.Password != "unit-test-pass" || st.ConfigPath != "/tmp/example-singctl.yaml" {
		t.Fatalf("expected metadata preserved in WebState, got %+v", st)
	}

	// 验证已有 TCP Listener 未被误关闭，仍可正常拨号连接
	conn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if dialErr != nil {
		t.Fatalf("listener socket broken after ChildReadyWithOptions: %v", dialErr)
	}
	_ = conn.Close()
}

func TestWebUIEmbeddedLoginAndCacheControl(t *testing.T) {
	const pass = "test-login-pass-2026"
	srv := webui.New(webui.Options{
		Password: pass,
		Version:  "1.99.0",
	})

	// 1. 未授权访问首页 `/`：返回 401 + 自包含 HTML 登录页 + no-store + 不带 WWW-Authenticate（防浏览器乱弹窗/白屏）
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 on unauthenticated /, got %d", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("expected no WWW-Authenticate on HTML login gate, got %q", rec.Header().Get("WWW-Authenticate"))
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("expected Cache-Control: no-store on /, got %q", rec.Header().Get("Cache-Control"))
		}
		if !strings.Contains(rec.Body.String(), "/api/auth/login") {
			t.Fatalf("expected embedded login HTML form on unauthenticated /, got body len=%d", rec.Body.Len())
		}
	}

	// 2. 前端 XHR 请求携带 X-Requested-With 访问受保护接口时，返回 401 JSON 且不含 WWW-Authenticate
	{
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.Header.Set("X-Requested-With", "SingCtlWebUI")
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("expected no WWW-Authenticate for XHR request, got %q", rec.Header().Get("WWW-Authenticate"))
		}
	}

	// 3. 公开探测接口 /api/auth/check（未登录时不暴露版本号）
	{
		req := httptest.NewRequest(http.MethodGet, "/api/auth/check", nil)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on /api/auth/check, got %d", rec.Code)
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if body["authRequired"] != true || body["authenticated"] != false {
			t.Fatalf("unexpected /api/auth/check response: %+v", body)
		}
		if _, leaked := body["version"]; leaked {
			t.Fatalf("unauthenticated /api/auth/check must not expose version: %+v", body)
		}
	}

	// 4. 错误口令登录 -> 401；正确口令登录 -> 200 + 下发 30 天 Cookie + Token
	var authCookie *http.Cookie
	{
		badReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"wrong"}`))
		badReq.Header.Set("Content-Type", "application/json")
		badReq.RemoteAddr = "198.51.100.10:54321"
		badRec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(badRec, badReq)
		if badRec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 for wrong password, got %d", badRec.Code)
		}

		okReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"`+pass+`"}`))
		okReq.Header.Set("Content-Type", "application/json")
		okReq.RemoteAddr = "198.51.100.10:54321"
		okRec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(okRec, okReq)
		if okRec.Code != http.StatusOK {
			t.Fatalf("expected 200 for valid password, got %d: %s", okRec.Code, okRec.Body.String())
		}
		for _, c := range okRec.Result().Cookies() {
			if c.Name == webui.SessionCookieName {
				authCookie = c
				break
			}
		}
		if authCookie == nil || authCookie.Value != srv.SessionToken() {
			t.Fatalf("expected valid %s cookie after login", webui.SessionCookieName)
		}
	}

	// 5. 登录后访问 `/` 返回 200 且强制 Cache-Control: no-store（确保升级新二进制后浏览器不读旧 index.html 缓存）
	{
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(authCookie)
		rec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 on authenticated /, got %d", rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Cache-Control"), "no-store") {
			t.Fatalf("expected no-store on authenticated /, got %q", rec.Header().Get("Cache-Control"))
		}
	}

	// 6. 防爆破限流：同 IP 连续输错 8 次后触发 429 锁定
	{
		for i := 0; i < 8; i++ {
			r := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"bad"}`))
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "203.0.113.99:40000"
			w := httptest.NewRecorder()
			srv.Mux.ServeHTTP(w, r)
		}
		lockedReq := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"password":"`+pass+`"}`))
		lockedReq.Header.Set("Content-Type", "application/json")
		lockedReq.RemoteAddr = "203.0.113.99:40000"
		lockedRec := httptest.NewRecorder()
		srv.Mux.ServeHTTP(lockedRec, lockedReq)
		if lockedRec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 after brute-force attempts, got %d", lockedRec.Code)
		}
	}
}

func TestWebUISelfUpdateDetachedRestart_EndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX subprocess hot-restart e2e test runs on unix")
	}

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "singctl-web.pid")
	logPath := filepath.Join(tmpDir, "singctl-web.log")
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	binPath := filepath.Join(tmpDir, "singctl")
	binV2Path := filepath.Join(tmpDir, "singctl-v2")

	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: test\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// 选取空闲本地回环端口
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}

	// 编译模拟旧版 v1.99.1 与新版 v1.99.2 两个真实 singctl 二进制
	buildV1 := exec.Command("go", "build", "-ldflags", "-X main.Version=1.99.1", "-o", binPath, "./cmd/singctl")
	buildV1.Dir = repoRoot
	if out, bErr := buildV1.CombinedOutput(); bErr != nil {
		t.Fatalf("build v1 failed: %v\n%s", bErr, string(out))
	}
	buildV2 := exec.Command("go", "build", "-ldflags", "-X main.Version=1.99.2", "-o", binV2Path, "./cmd/singctl")
	buildV2.Dir = repoRoot
	if out, bErr := buildV2.CombinedOutput(); bErr != nil {
		t.Fatalf("build v2 failed: %v\n%s", bErr, string(out))
	}

	baseEnv := append(os.Environ(),
		"SINGCTL_WEB_STATE_PATH="+statePath,
		"SINGCTL_WEB_LOG_PATH="+logPath,
	)

	t.Cleanup(func() {
		stopCmd := exec.Command(binPath, "web", "stop")
		stopCmd.Env = baseEnv
		_ = stopCmd.Run()
	})

	const webPass = "e2e-update-pass"

	// 1. 启动 v1.99.1 后台 WebUI 服务
	startCmd := exec.Command(binPath, "--config", cfgPath, "web", "start", "-l", listenAddr, "--password", webPass)
	startCmd.Env = baseEnv
	if out, sErr := startCmd.CombinedOutput(); sErr != nil {
		t.Fatalf("web start v1 failed: %v\n%s", sErr, string(out))
	}

	webui.WebStatePathOverride = statePath
	webui.WebLogPathOverride = logPath
	webui.ExecutablePathOverride = binPath
	t.Cleanup(func() {
		webui.WebStatePathOverride = ""
		webui.WebLogPathOverride = ""
		webui.ExecutablePathOverride = ""
	})

	st1, err := webui.ReadWebState()
	if err != nil {
		t.Fatalf("read web state v1 failed: %v", err)
	}

	// 2. 通过 /api/auth/login 登录 v1，拿到持久化 Cookie
	client := &http.Client{Timeout: 3 * time.Second}
	loginResp, err := client.Post(
		"http://"+listenAddr+"/api/auth/login",
		"application/json",
		strings.NewReader(`{"password":"`+webPass+`"}`),
	)
	if err != nil {
		t.Fatalf("login v1 failed: %v", err)
	}
	var sessionCookie *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == webui.SessionCookieName {
			sessionCookie = c
			break
		}
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK || sessionCookie == nil {
		t.Fatalf("expected 200 and session cookie on v1 login, got status=%d cookie=%v", loginResp.StatusCode, sessionCookie)
	}

	// 3. 原子替换磁盘二进制为 v1.99.2，并在污染了 SINGCTL_WEB_BACKGROUND=1 的环境下触发 ScheduleDetachedRestart
	if err := os.Rename(binV2Path, binPath); err != nil {
		t.Fatalf("replace binary with v2 failed: %v", err)
	}
	t.Setenv("SINGCTL_WEB_STATE_PATH", statePath)
	t.Setenv("SINGCTL_WEB_LOG_PATH", logPath)
	t.Setenv("SINGCTL_WEB_BACKGROUND", "1")
	t.Setenv("SINGCTL_WEB_READY_FD", "3")

	// 注意：此处当前进程是 go test，不能传 go test 自身的 PID 给 oldpid，
	// 因此先验证模拟 WebUI 自身触发异步重启（ScheduleDetachedRestart 停止 st1.Pid 并拉起新版 v1.99.2 后台守护进程）：
	// 为避免测试进程自身被 $2 oldpid SIGTERM，这里先测 CLI RestartWeb，再在独立子进程内测 ScheduleDetachedRestart！
	if err := webui.RestartWeb(cfgPath); err != nil {
		logBytes, _ := os.ReadFile(logPath)
		t.Fatalf("RestartWeb to v2 failed: %v\nlog:\n%s", err, string(logBytes))
	}

	st2, err := webui.ReadWebState()
	if err != nil {
		t.Fatalf("read web state v2 failed: %v", err)
	}
	if st2.Pid == st1.Pid || !webui.ProcessAlive(st2.Pid) {
		t.Fatalf("expected new alive v2 pid (old=%d, new=%d)", st1.Pid, st2.Pid)
	}

	// 4. 验证升级重启后：原 Cookie 免重新登录直接访问 /api/status 返回 200 且版本已升为 1.99.2！
	statusReq, _ := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/api/status", nil)
	statusReq.AddCookie(sessionCookie)
	statusResp, err := client.Do(statusReq)
	if err != nil {
		logBytes, _ := os.ReadFile(logPath)
		t.Fatalf("GET /api/status on v2 failed (port dead / FD3 bug?): %v\nlog:\n%s", err, string(logBytes))
	}
	var statusBody struct {
		SingctlVersion string `json:"singctlVersion"`
		AuthEnabled    bool   `json:"authEnabled"`
	}
	_ = json.NewDecoder(statusResp.Body).Decode(&statusBody)
	_ = statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK with pre-upgrade session cookie, got %d", statusResp.StatusCode)
	}
	if statusBody.SingctlVersion != "1.99.2" || !statusBody.AuthEnabled {
		t.Fatalf("expected singctlVersion=1.99.2 & authEnabled=true, got %+v", statusBody)
	}

	// 5. 再通过真实子进程验证 ScheduleDetachedRestart（父进程带 SINGCTL_WEB_BACKGROUND=1 环境变量且无 fd3 管道）
	testExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helperCmd := exec.Command(testExe, "-test.run=^TestHelperTriggerDetachedRestart$")
	helperCmd.Env = append(baseEnv,
		"GO_WANT_DETACHED_RESTART_HELPER=1",
		"HELPER_BIN_PATH="+binPath,
		"HELPER_CFG_PATH="+cfgPath,
		"HELPER_LISTEN="+listenAddr,
		"HELPER_PASS="+webPass,
		"SINGCTL_WEB_BACKGROUND=1",
		"SINGCTL_WEB_READY_FD=3",
	)
	if hErr := helperCmd.Start(); hErr != nil {
		t.Fatalf("start helper ScheduleDetachedRestart failed: %v", hErr)
	}
	t.Cleanup(func() {
		if helperCmd.Process != nil {
			_ = helperCmd.Process.Kill()
			_, _ = helperCmd.Process.Wait()
		}
	})

	// 等待异步 ScheduleDetachedRestart (sleep 1 + stop + start) 完成并校验新 PID 存活、端口与鉴权完好
	deadline := time.Now().Add(8 * time.Second)
	var recovered bool
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		st3, rErr := webui.ReadWebState()
		if rErr != nil || st3.Pid == st2.Pid || !webui.ProcessAlive(st3.Pid) {
			continue
		}
		chkReq, _ := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/api/auth/check", nil)
		chkReq.AddCookie(sessionCookie)
		chkResp, cErr := client.Do(chkReq)
		if cErr != nil {
			continue
		}
		var chk map[string]any
		_ = json.NewDecoder(chkResp.Body).Decode(&chk)
		_ = chkResp.Body.Close()
		if chkResp.StatusCode == http.StatusOK && chk["authenticated"] == true && chk["version"] == "1.99.2" {
			recovered = true
			break
		}
	}
	if !recovered {
		logBytes, _ := os.ReadFile(logPath)
		t.Fatalf("WebUI did not recover after ScheduleDetachedRestart under SINGCTL_WEB_BACKGROUND=1!\nlog:\n%s", string(logBytes))
	}
}

func TestHelperTriggerDetachedRestart(t *testing.T) {
	if os.Getenv("GO_WANT_DETACHED_RESTART_HELPER") != "1" {
		return
	}
	webui.ExecutablePathOverride = os.Getenv("HELPER_BIN_PATH")
	webui.ScheduleDetachedRestart(
		os.Getenv("HELPER_CFG_PATH"),
		os.Getenv("HELPER_LISTEN"),
		os.Getenv("HELPER_PASS"),
	)
	// 模拟真实 WebUI 进程保持存活，等待 1 秒后被重启脚本平滑接管终止
	time.Sleep(10 * time.Second)
}

func TestLegacyV1_14_120_WebUIClickUpdateAutoHeals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX v1.14.120 ScheduleDetachedRestart simulation runs on unix")
	}

	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "singctl-web.pid")
	logPath := filepath.Join(tmpDir, "singctl-web.log")
	cfgPath := filepath.Join(tmpDir, "singctl.yaml")
	binPath := filepath.Join(tmpDir, "singctl")

	if err := os.WriteFile(cfgPath, []byte("subs:\n  - name: test\n    url: https://example.com/sub\n"), 0600); err != nil {
		t.Fatal(err)
	}

	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	buildCmd := exec.Command("go", "build", "-ldflags", "-X main.Version=1.14.129", "-o", binPath, "./cmd/singctl")
	buildCmd.Dir = repoRoot
	if out, bErr := buildCmd.CombinedOutput(); bErr != nil {
		t.Fatalf("build failed: %v\n%s", bErr, string(out))
	}

	baseEnv := append(os.Environ(),
		"SINGCTL_WEB_STATE_PATH="+statePath,
		"SINGCTL_WEB_LOG_PATH="+logPath,
	)
	t.Cleanup(func() {
		stopCmd := exec.Command(binPath, "web", "stop")
		stopCmd.Env = baseEnv
		_ = stopCmd.Run()
	})

	const legacyPass = "legacy-120-pass"
	expectedToken := webui.New(webui.Options{Password: legacyPass}).SessionToken()

	// 1:1 复现 v1.14.120 的旧版 ScheduleDetachedRestart 命令：
	// - 遗留 SINGCTL_WEB_BACKGROUND=1，且没有 SINGCTL_WEB_READY_FD
	// - 把 stdout/stderr 重定向到了 >/dev/null 2>&1
	// - 使用 append 追加 SINGCTL_WEB_PASSWORD
	legacyShArgs := []string{
		"-c",
		`sleep 0.2; "$1" web stop >/dev/null 2>&1 || true; exec "$@" >/dev/null 2>&1`,
		"--",
		binPath,
		binPath,
		"--config", cfgPath,
		"web", "start", "-l", listenAddr,
	}
	cmd := exec.Command("/bin/sh", legacyShArgs...)
	cmd.Env = append(baseEnv,
		"SINGCTL_WEB_BACKGROUND=1",
		"SINGCTL_WEB_PASSWORD=",
		"SINGCTL_WEB_PASSWORD="+legacyPass,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start legacy restart script failed: %v", err)
	}

	// 等待新版二进制自动识别旧版环境、剥离污染标记并完成正规后台守护启动
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(8 * time.Second)
	var healed bool
	for time.Now().Before(deadline) {
		time.Sleep(250 * time.Millisecond)
		req, _ := http.NewRequest(http.MethodGet, "http://"+listenAddr+"/api/status", nil)
		req.AddCookie(&http.Cookie{Name: webui.SessionCookieName, Value: expectedToken})
		resp, rErr := client.Do(req)
		if rErr != nil {
			continue
		}
		var body struct {
			SingctlVersion string `json:"singctlVersion"`
			AuthEnabled    bool   `json:"authEnabled"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && body.SingctlVersion == "1.14.129" && body.AuthEnabled {
			healed = true
			break
		}
	}
	if !healed {
		logBytes, _ := os.ReadFile(logPath)
		t.Fatalf("v1.14.120 click-update simulation failed to auto-heal!\nlog:\n%s", string(logBytes))
	}
}
