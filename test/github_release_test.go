package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"singctl/internal/util/github"
)

func TestFetchLatestTag(t *testing.T) {
	tests := []struct {
		name       string
		response   github.Release
		statusCode int
		want       string
		wantErr    bool
	}{
		{
			name:       "标准 v 前缀",
			response:   github.Release{TagName: "v1.12.0"},
			statusCode: http.StatusOK,
			want:       "1.12.0",
		},
		{
			name:       "无 v 前缀",
			response:   github.Release{TagName: "1.13.0"},
			statusCode: http.StatusOK,
			want:       "1.13.0",
		},
		{
			name:       "API 错误",
			statusCode: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// 验证请求路径包含 /releases/latest
				if !strings.HasSuffix(r.URL.Path, "/releases/latest") {
					t.Errorf("expected path ending with /releases/latest, got %s", r.URL.Path)
				}
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					json.NewEncoder(w).Encode(tt.response)
				}
			}))
			defer server.Close()

			// 使用测试服务器的 URL 作为 mirror，绕过真实 GitHub API
			fetcher := github.NewReleaseFetcher("", server.Client())
			// 通过 FetchLatestTagFromURL 直接传 URL（测试辅助）
			got, err := fetcher.FetchLatestTagFromURL(server.URL + "/repos/test/repo/releases/latest")

			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFindAssetURL(t *testing.T) {
	releases := []github.Release{
		{
			TagName: "v1.13.0-rc.1",
			Assets: []github.Asset{
				{Name: "sing-box-1.13.0-rc.1-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux.tar.gz"},
			},
		},
		{
			TagName: "v1.13.0-rc.1",
			Assets: []github.Asset{
				{Name: "SFM-1.13.0-rc.1-Apple.pkg", BrowserDownloadURL: "https://example.com/sfm.pkg"},
				{Name: "sing-box-1.13.0-rc.1-windows-amd64.zip", BrowserDownloadURL: "https://example.com/win.zip"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(releases)
	}))
	defer server.Close()

	fetcher := github.NewReleaseFetcher("", server.Client())

	t.Run("找到 macOS GUI", func(t *testing.T) {
		url, err := fetcher.FindAssetURLFromURL(
			server.URL+"/repos/test/repo/releases",
			func(name string) bool {
				return strings.HasPrefix(name, "SFM-") && strings.HasSuffix(name, "-Apple.pkg")
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if url != "https://example.com/sfm.pkg" {
			t.Errorf("got %q, want %q", url, "https://example.com/sfm.pkg")
		}
	})

	t.Run("找到 Windows 资产", func(t *testing.T) {
		url, err := fetcher.FindAssetURLFromURL(
			server.URL+"/repos/test/repo/releases",
			func(name string) bool {
				return strings.HasPrefix(name, "sing-box-") && strings.HasSuffix(name, "-windows-amd64.zip")
			},
		)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if url != "https://example.com/win.zip" {
			t.Errorf("got %q, want %q", url, "https://example.com/win.zip")
		}
	})

	t.Run("未找到匹配资产", func(t *testing.T) {
		_, err := fetcher.FindAssetURLFromURL(
			server.URL+"/repos/test/repo/releases",
			func(name string) bool { return strings.Contains(name, "nonexistent") },
		)
		if err == nil {
			t.Error("expected error, got nil")
		}
	})
}
