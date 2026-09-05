package singbox

import (
	"runtime"
	"strings"
	"testing"
)

func TestResolvePlatform(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"空值回退当前系统", "", runtime.GOOS, false},
		{"auto回退当前系统", "auto", runtime.GOOS, false},
		{"显式darwin", "darwin", "darwin", false},
		{"显式windows", "windows", "windows", false},
		{"显式linux", "linux", "linux", false},
		{"显式ios", "ios", "ios", false},
		{"非法平台", "android", "", true},
		{"注入攻击", "ios;rm -rf /", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolvePlatform(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ResolvePlatform(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckIOSCompatibility(t *testing.T) {
	t.Run("远程规则集通过", func(t *testing.T) {
		json := `{"route":{"rule_set":[{"type":"remote","tag":"geoip-cn","format":"binary","url":"https://example.com/geoip-cn.srs"}]}}`
		if err := CheckIOSCompatibility(json); err != nil {
			t.Fatalf("remote rule_set should pass: %v", err)
		}
	})

	t.Run("本地规则集拒绝", func(t *testing.T) {
		json := `{"route":{"rule_set":[{"type":"local","tag":"geoip-cn","format":"binary","path":"/etc/sing-box/geoip-cn.srs"}]}}`
		err := CheckIOSCompatibility(json)
		if err == nil {
			t.Fatal("local rule_set should be rejected")
		}
		if !strings.Contains(err.Error(), "geoip-cn") {
			t.Fatalf("error should mention offending tag, got: %v", err)
		}
	})

	t.Run("无规则集通过", func(t *testing.T) {
		json := `{"outbounds":[{"type":"direct","tag":"direct"}]}`
		if err := CheckIOSCompatibility(json); err != nil {
			t.Fatalf("no rule_set should pass: %v", err)
		}
	})

	t.Run("非法JSON报错", func(t *testing.T) {
		if err := CheckIOSCompatibility("not-json"); err == nil {
			t.Fatal("invalid json should error")
		}
	})
}
