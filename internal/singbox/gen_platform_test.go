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

func TestApplyIOSPlatformAdjustments(t *testing.T) {
	t.Run("剥离api service并保留default_http_client", func(t *testing.T) {
		in := `{
			"inbounds":[{"type":"tun","tag":"tun-in"}],
			"outbounds":[{"type":"selector","tag":"Proxy"},{"type":"direct","tag":"DirectConn"}],
			"http_clients":[{"tag":"hc-direct","detour":"DirectConn"}],
			"services":[{"type":"api","tag":"api-in","listen":"192.168.31.1","listen_port":9091}],
			"route":{"final":"Proxy","default_http_client":"hc-direct","rule_set":[{"type":"remote","tag":"rs1","url":"https://x/rs1.srs"}]}
		}`
		out, err := ApplyIOSPlatformAdjustments(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "api-in") || strings.Contains(out, "192.168.31.1") {
			t.Fatalf("api service should be stripped, got %s", out)
		}
		if strings.Contains(out, `"services"`) {
			t.Fatalf("empty services key should be removed, got %s", out)
		}
		if !strings.Contains(out, `"default_http_client":"hc-direct"`) {
			t.Fatalf("existing default_http_client should be preserved, got %s", out)
		}
		if strings.Contains(out, `"download_detour"`) {
			t.Fatalf("per-entry download_detour should NOT be injected when default_http_client exists, got %s", out)
		}
	})

	t.Run("无default_http_client时从http_clients注入", func(t *testing.T) {
		in := `{
			"outbounds":[{"type":"direct","tag":"DirectConn"}],
			"http_clients":[{"tag":"hc-direct","detour":"DirectConn"}],
			"route":{"rule_set":[{"type":"remote","tag":"rs1"}]}
		}`
		out, err := ApplyIOSPlatformAdjustments(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, `"default_http_client":"hc-direct"`) {
			t.Fatalf("default_http_client should be injected, got %s", out)
		}
	})

	t.Run("无http_clients时回退逐条download_detour", func(t *testing.T) {
		in := `{
			"outbounds":[{"type":"direct","tag":"direct"}],
			"route":{"rule_set":[{"type":"remote","tag":"rs1"}]}
		}`
		out, err := ApplyIOSPlatformAdjustments(in)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, `"download_detour":"direct"`) {
			t.Fatalf("legacy fallback should inject download_detour, got %s", out)
		}
	})

	t.Run("保留非api service", func(t *testing.T) {
		in := `{
			"outbounds":[],
			"services":[{"type":"api","tag":"api-in"},{"type":"ss","tag":"ss-in","listen":"127.0.0.1","listen_port":8388}],
			"route":{"rule_set":[]}
		}`
		out, err := ApplyIOSPlatformAdjustments(in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "api-in") {
			t.Fatalf("api service should be stripped, got %s", out)
		}
		if !strings.Contains(out, "ss-in") {
			t.Fatalf("non-api services should be kept, got %s", out)
		}
	})

	t.Run("非法JSON报错", func(t *testing.T) {
		if _, err := ApplyIOSPlatformAdjustments("not-json"); err == nil {
			t.Fatal("invalid json should error")
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
