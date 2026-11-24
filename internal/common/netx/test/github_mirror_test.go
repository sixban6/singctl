// 文件职责：测试 GitHub 规则集与资源下载的镜像候选地址构造（优先用户配置镜像、幂等防重复前缀、非 GitHub 直连与防注入）。
package netx_test

import (
	"slices"
	"testing"

	"singctl/internal/common/netx"
)

func TestBuildGitHubDownloadCandidates(t *testing.T) {
	cases := []struct {
		name      string
		rawURL    string
		mirrorURL string
		want      []string
	}{
		{
			name:      "raw_github_uses_configured_mirror_first",
			rawURL:    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
			mirrorURL: "https://gh-proxy.com/",
			want: []string{
				"https://gh-proxy.com/https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
				"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt",
			},
		},
		{
			name:      "github_repo_raw_uses_configured_mirror",
			rawURL:    "https://github.com/example/rules/raw/main/ad.srs",
			mirrorURL: "https://mirror.example.com",
			want: []string{
				"https://mirror.example.com/https://github.com/example/rules/raw/main/ad.srs",
				"https://github.com/example/rules/raw/main/ad.srs",
			},
		},
		{
			name:      "already_mirrored_url_not_double_prefixed",
			rawURL:    "https://gh-proxy.com/https://raw.githubusercontent.com/a/b/main/c.srs",
			mirrorURL: "https://gh-proxy.com",
			want: []string{
				"https://gh-proxy.com/https://raw.githubusercontent.com/a/b/main/c.srs",
			},
		},
		{
			name:      "non_github_url_never_prefixed",
			rawURL:    "https://anti-ad.net/anti-ad-for-smartdns.conf",
			mirrorURL: "https://gh-proxy.com",
			want: []string{
				"https://anti-ad.net/anti-ad-for-smartdns.conf",
			},
		},
		{
			name:      "empty_or_official_mirror_direct_only",
			rawURL:    "https://raw.githubusercontent.com/a/b/main/c.srs",
			mirrorURL: "https://github.com",
			want: []string{
				"https://raw.githubusercontent.com/a/b/main/c.srs",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := netx.BuildGitHubDownloadCandidates(tc.rawURL, tc.mirrorURL)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("BuildGitHubDownloadCandidates(%q, %q) = %v, want %v", tc.rawURL, tc.mirrorURL, got, tc.want)
			}
		})
	}
}
