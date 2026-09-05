package singbox

import (
	"encoding/json"
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

func TestApplyIOSDownloadDetour(t *testing.T) {
	t.Run("注入直连tag到缺省条目", func(t *testing.T) {
		in := `{
			"outbounds": [
				{"type":"selector","tag":"Proxy"},
				{"type":"direct","tag":"DirectConn"}
			],
			"route": {
				"final": "Proxy",
				"rule_set": [
					{"type":"remote","tag":"rs1","url":"https://x/rs1.srs"},
					{"type":"remote","tag":"rs2","url":"https://x/rs2.srs","download_detour":"Proxy"}
				]
			}
		}`
		out, err := ApplyIOSDownloadDetour(in)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Route struct {
				RuleSet []struct {
					Tag            string `json:"tag"`
					DownloadDetour string `json:"download_detour"`
				} `json:"rule_set"`
			} `json:"route"`
		}
		if err := json.Unmarshal([]byte(out), &cfg); err != nil {
			t.Fatal(err)
		}
		rs := cfg.Route.RuleSet
		if len(rs) != 2 {
			t.Fatalf("expected 2 rule_set, got %d", len(rs))
		}
		if rs[0].DownloadDetour != "DirectConn" {
			t.Fatalf("rs1 should get DirectConn, got %q", rs[0].DownloadDetour)
		}
		if rs[1].DownloadDetour != "Proxy" {
			t.Fatalf("rs2 existing detour should be preserved, got %q", rs[1].DownloadDetour)
		}
	})

	t.Run("无直连出站时保持原样", func(t *testing.T) {
		in := `{"outbounds":[{"type":"selector","tag":"Proxy"}],"route":{"rule_set":[{"type":"remote","tag":"rs1"}]}}`
		out, err := ApplyIOSDownloadDetour(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, `"download_detour"`) {
			t.Fatalf("should remain unchanged without direct outbound, got %s", out)
		}
	})

	t.Run("非法JSON报错", func(t *testing.T) {
		if _, err := ApplyIOSDownloadDetour("not-json"); err == nil {
			t.Fatal("invalid json should error")
		}
	})

	t.Run("兼容direct缺省tag", func(t *testing.T) {
		in := `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rule_set":[{"type":"remote","tag":"rs1"}]}}`
		out, err := ApplyIOSDownloadDetour(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, `"download_detour":"direct"`) {
			t.Fatalf("should resolve plain direct tag, got %s", out)
		}
	})
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
