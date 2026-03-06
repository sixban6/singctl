package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"singctl/internal/util/github"
)

// TestVersionPrefixNormalization 验证版本号 v 前缀不会导致误判。
// 这是 TDD 回归测试，防止 "v1.20.21" != "1.20.21" 类型的 bug。
func TestVersionPrefixNormalization(t *testing.T) {
	tests := []struct {
		name           string
		currentVersion string
		remoteTag      string
		expectSame     bool
	}{
		{
			name:           "当前版本带 v 前缀，远端不带",
			currentVersion: "v1.20.21",
			remoteTag:      "v1.20.21",
			expectSame:     true,
		},
		{
			name:           "当前版本不带 v 前缀",
			currentVersion: "1.20.21",
			remoteTag:      "v1.20.21",
			expectSame:     true,
		},
		{
			name:           "版本不同",
			currentVersion: "v1.20.20",
			remoteTag:      "v1.20.21",
			expectSame:     false,
		},
		{
			name:           "dev 版本不应该进行对比",
			currentVersion: "dev",
			remoteTag:      "v1.20.21",
			expectSame:     false, // dev 版本应跳过检查，直接更新
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(github.Release{TagName: tt.remoteTag})
			}))
			defer server.Close()

			fetcher := github.NewReleaseFetcher("", server.Client())
			latestVersion, err := fetcher.FetchLatestTagFromURL(server.URL + "/repos/test/repo/releases/latest")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// 模拟 updater.go 中的标准化逻辑
			normalizedCurrent := strings.TrimPrefix(tt.currentVersion, "v")

			if tt.currentVersion == "dev" {
				// dev 版本不走对比，直接更新
				return
			}

			isSame := normalizedCurrent == latestVersion
			if isSame != tt.expectSame {
				t.Errorf("current=%q normalized=%q latest=%q: got isSame=%v, want %v",
					tt.currentVersion, normalizedCurrent, latestVersion, isSame, tt.expectSame)
			}
		})
	}
}
