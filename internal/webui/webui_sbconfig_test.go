package webui

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"singctl/internal/constant"
)

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
	oldLook := lookPathFunc
	lookPathFunc = func(string) (string, error) {
		return "", fmt.Errorf("not found in test")
	}
	t.Cleanup(func() {
		constant.SingBoxConfigFile = oldCfg
		constant.SingBoxInstallDir = oldBin
		lookPathFunc = oldLook
	})
	return sbConfigPath
}

func newTestServer(t *testing.T, sbConfigPath string) *httptest.Server {
	t.Helper()
	dir := filepath.Dir(sbConfigPath)
	s := New(Options{ConfigPath: filepath.Join(dir, "singctl.yaml")})
	ts := httptest.NewServer(s.mux)
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
	clashCacheMu.Lock()
	clashCacheURL, clashCacheSec, clashCachedAt = nil, "", time.Time{}
	clashCacheMu.Unlock()

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
	clashCacheMu.Lock()
	clashCacheURL = nil
	clashCacheMu.Unlock()

	_, _ = doJSON(t, "GET", ts.URL+"/clash/version", "")
	if gotAuth != "Bearer topsecret" {
		t.Fatalf("expected bearer secret forwarded, got %q", gotAuth)
	}
}
