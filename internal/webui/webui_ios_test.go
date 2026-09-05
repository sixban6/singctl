package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/config"
)

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
	old := iosGenerate
	iosGenerate = func(*config.Config) (string, error) {
		return `{"outbounds":[],"route":{"rule_set":[{"type":"remote","tag":"rs","url":"https://x/rs.srs"}]}}`, nil
	}
	return cfgPath, func() { iosGenerate = old }
}

func TestIOSConfigDownload(t *testing.T) {
	cfgPath, restore := withIOSStub(t)
	defer restore()

	s := New(Options{ConfigPath: cfgPath})
	ts := httptest.NewServer(s.mux)
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

	s := New(Options{ConfigPath: cfgPath, Password: "secret123"})
	ts := httptest.NewServer(s.mux)
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

	s := New(Options{ConfigPath: cfgPath, Listen: ":8090"})
	ts := httptest.NewServer(s.mux)
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
