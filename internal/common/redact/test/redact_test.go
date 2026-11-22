// 文件职责：验证 redact.MaskURL 对订阅链接中 BasicAuth 凭据、公网 IPv4/IPv6 段、查询密钥及多字节 UTF-8 域名的脱敏保护。
package redact_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"singctl/internal/common/redact"
)

func TestMaskURL_TableDriven(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantExact  string
		forbidSubs []string
	}{
		{name: "empty returns 未配置", in: "", wantExact: "未配置"},
		{name: "missing scheme returns ***", in: "just-a-secret-token", wantExact: "***"},
		{name: "scheme only returns ***", in: "https://", wantExact: "***"},
		{
			name:       "strips userinfo credentials on single-label host",
			in:         "https://admin:my_super_secret_token@intranet/api/sub",
			forbidSubs: []string{"admin", "my_super_secret_token", "/api/sub"},
		},
		{
			name:       "masks IPv4 trailing octets and path secret",
			in:         "https://203.0.113.45:8443/sub/secret_key",
			wantExact:  "https://203.***.***.***:8443/***",
			forbidSubs: []string{"113.45", "secret_key"},
		},
		{
			name:       "masks IPv6 literal host and query",
			in:         "https://[2001:db8::dead:beef]:8443/sub?token=abc123",
			wantExact:  "https://[***]:8443/***",
			forbidSubs: []string{"dead", "beef", "abc123"},
		},
		{
			name:       "preserves valid UTF-8 on multi-byte IDN domain",
			in:         "https://订阅节点.example.com/api/v1?token=secret",
			forbidSubs: []string{"节点", "secret"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redact.MaskURL(tc.in)
			if !utf8.ValidString(got) {
				t.Fatalf("MaskURL(%q) produced invalid UTF-8: %q", tc.in, got)
			}
			if tc.wantExact != "" && got != tc.wantExact {
				t.Fatalf("MaskURL(%q) = %q, want %q", tc.in, got, tc.wantExact)
			}
			for _, bad := range tc.forbidSubs {
				if strings.Contains(got, bad) {
					t.Fatalf("MaskURL(%q) = %q leaked %q", tc.in, got, bad)
				}
			}
		})
	}
}
