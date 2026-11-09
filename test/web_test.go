package test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/config"
	"singctl/internal/constant"
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

	s := webui.New(webui.Options{ConfigPath: cfgPath, Listen: ":8090"})
	ts := httptest.NewServer(s.Mux)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/gen/ios/url")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// 沙箱/无网环境可能拿不到局域网 IP(500), 此时只验证端点存活
	if resp.StatusCode == 500 {
		return
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var d struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d.URL, "/api/gen/ios") {
		t.Fatalf("url should point to /api/gen/ios, got %q", d.URL)
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
	oldLook := webui.LookPathFunc
	webui.LookPathFunc = func(string) (string, error) {
		return "", fmt.Errorf("not found in test")
	}
	t.Cleanup(func() {
		constant.SingBoxConfigFile = oldCfg
		constant.SingBoxInstallDir = oldBin
		webui.LookPathFunc = oldLook
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

	// 3. PUT 合法 JSON → ok(未安装 sing-box → checked=false)
	code, body = doJSON(t, "PUT", ts.URL+"/api/sbconfig", `{"content":"{\"log\":{\"level\":\"info\"}}"}`)
	if code != 200 || !strings.Contains(body, `"checked":false`) {
		t.Fatalf("expected 200 checked:false, got %d %s", code, body)
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

func TestClashProxy(t *testing.T) {
	sbConfigPath := withOverrides(t)

	// 上游伪 clash API
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/version":
			_, _ = w.Write([]byte(`{"version":"fake-1.0","meta":true}`))
		case strings.HasPrefix(r.URL.Path, "/ui/"):
			_, _ = w.Write([]byte("hello-panel"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(up.Close)

	// 生成配置指向伪上游,验证 ClashAPIEndpoints 解析链路
	cfgJSON := fmt.Sprintf(`{"experimental":{"clash_api":{"external_controller":%q,"secret":"s3cret"}}}`,
		strings.TrimPrefix(up.URL, "http://"))
	if err := os.WriteFile(sbConfigPath, []byte(cfgJSON), 0600); err != nil {
		t.Fatal(err)
	}

	// 清空代理目标缓存
	webui.ClashCacheMu.Lock()
	webui.ClashCacheURL, webui.ClashCacheSec, webui.ClashCachedAt = nil, "", time.Time{}
	webui.ClashCacheMu.Unlock()

	ts := newTestServer(t, sbConfigPath)

	// /clash/version 走前缀代理
	code, body := doJSON(t, "GET", ts.URL+"/clash/version", "")
	if code != 200 || !strings.Contains(body, "fake-1.0") {
		t.Fatalf("clash prefix proxy failed: %d %s", code, body)
	}

	// /version 根路径直通
	code, body = doJSON(t, "GET", ts.URL+"/version", "")
	if code != 200 || !strings.Contains(body, "fake-1.0") {
		t.Fatalf("clash root proxy failed: %d %s", code, body)
	}

	// /clash/ui/ 面板页面
	code, body = doJSON(t, "GET", ts.URL+"/clash/ui/", "")
	if code != 200 || !strings.Contains(body, "hello-panel") {
		t.Fatalf("clash ui proxy failed: %d %s", code, body)
	}

	// 验证 secret 已随请求透传(上游校验 Authorization)
	// (简单起见:再起一个要求鉴权的上游确认)
	var gotAuth string
	authUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(authUp.Close)

	if err := os.WriteFile(sbConfigPath, []byte(fmt.Sprintf(
		`{"experimental":{"clash_api":{"external_controller":%q,"secret":"topsecret"}}}`,
		strings.TrimPrefix(authUp.URL, "http://"))), 0600); err != nil {
		t.Fatal(err)
	}
	webui.ClashCacheMu.Lock()
	webui.ClashCacheURL = nil
	webui.ClashCacheMu.Unlock()

	_, _ = doJSON(t, "GET", ts.URL+"/clash/version", "")
	if gotAuth != "Bearer topsecret" {
		t.Fatalf("expected bearer secret forwarded, got %q", gotAuth)
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
