package singbox

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// buildFakeDashboardZip 构造带 GitHub archive 顶层目录的模拟 dashboard zip
func buildFakeDashboardZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name    string
		content string
	}{
		{"sing-box-dashboard-gh-pages/index.html", "<html>dash</html>"},
		{"sing-box-dashboard-gh-pages/assets/app.js", "console.log(1)"},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(f.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProvisionDashboard(t *testing.T) {
	zipData := buildFakeDashboardZip(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write(zipData)
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "dashboard")
	cfgJSON := `{"services":[{"type":"api","tag":"api-in","dashboard":{"enabled":true,"path":"` +
		filepath.ToSlash(dir) + `","download_url":"` + srv.URL + `/dash.zip"}}]}`

	if err := ProvisionDashboard(cfgJSON); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.html")); err != nil {
		t.Fatalf("index.html should be extracted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "assets", "app.js")); err != nil {
		t.Fatalf("nested asset should be extracted: %v", err)
	}

	// 幂等: index.html 已存在时跳过下载(关闭 server 后再次调用应仍成功)
	srv.Close()
	if err := ProvisionDashboard(cfgJSON); err != nil {
		t.Fatalf("idempotent re-run should skip download: %v", err)
	}
}

func TestProvisionDashboardNoAPIService(t *testing.T) {
	// 无 services(如 iOS 客户端配置) → 直接成功返回
	if err := ProvisionDashboard(`{"inbounds":[]}`); err != nil {
		t.Fatalf("no api service should be a no-op, got: %v", err)
	}
}
