// 文件职责：测试审计规则集导入在无代理审计模式下优先使用 singctl.yaml 配置的 github.mirror_url 下载 GitHub 规则集。
package audit_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"singctl/internal/audit"
	"singctl/internal/config"
)

func TestEnforcer_FetchRuleSetPayload_UsesConfiguredGitHubMirror(t *testing.T) {
	var requestedPaths []string
	mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":3,"rules":[{"domain_suffix":["ad.example.com"]}]}`))
	}))
	defer mirrorSrv.Close()

	cfg := &config.Config{
		GitHub: config.GitHubConfig{
			MirrorURL: mirrorSrv.URL,
		},
	}
	enforcer := audit.NewEnforcer(cfg, filepath.Join(t.TempDir(), "singctl.yaml"))
	enforcer.SetDeps(mirrorSrv.Client(), func() string { return "" })

	spec := audit.RuleSetImportSpec{
		Tag:       "custom-ad",
		SourceURL: "https://raw.githubusercontent.com/example/rules/main/custom-ad.json",
	}
	body, err := enforcer.FetchRuleSetPayload(t.Context(), spec, filepath.Join(t.TempDir(), "custom-ad.srs"))
	if err != nil {
		t.Fatalf("FetchRuleSetPayload via configured mirror failed: %v", err)
	}
	if !strings.Contains(string(body), "ad.example.com") {
		t.Fatalf("unexpected payload: %s", string(body))
	}
	if len(requestedPaths) != 1 || !strings.Contains(requestedPaths[0], "/https://raw.githubusercontent.com/example/rules/main/custom-ad.json") {
		t.Fatalf("expected mirrorSrv called with raw github path, got %v", requestedPaths)
	}
}
