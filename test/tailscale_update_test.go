package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"singctl/internal/util/github"
)

// TestTailscaleVersionFromAsset 验证当 Release Tag 固定为 "latest" 时，
// 能否从 Asset name (例如 tailscale_1.94.2_amd64.tgz) 里正确解析版本号。
func TestTailscaleVersionFromAsset(t *testing.T) {
	// 启动一个模拟 GitHub API 的 Web Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 返回 auto_fetch_tailscale 的特有结构：Tag 为 latest，但 Asset 里有真实版本
		releases := []github.Release{
			{
				TagName: "latest",
				Assets: []github.Asset{
					{
						Name:               "tailscale_1.94.2_amd64.tgz",
						BrowserDownloadURL: "https://example.com/tailscale_1.94.2_amd64.tgz",
					},
				},
			},
		}
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	// 这里我们只验证提取逻辑，直接匹配 "tailscale_" 开头的文件
	filter := func(name string) bool {
		return strings.HasPrefix(name, "tailscale_")
	}

	fetcher := github.NewReleaseFetcher("", server.Client())
	downloadURL, err := fetcher.FindAssetURLFromURL(server.URL, filter)
	if err != nil {
		t.Fatalf("unexpected error finding asset: %v", err)
	}

	// 模拟 tailscale.go 中的解析逻辑
	version := "latest"
	re := regexp.MustCompile(`tailscale_([\d\.]+)_`)
	matches := re.FindStringSubmatch(downloadURL)
	if len(matches) > 1 {
		version = matches[1]
	}

	if version != "1.94.2" {
		t.Errorf("expected parsed version '1.94.2', got '%s'", version)
	}
}
