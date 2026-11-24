// 文件职责：测试二级级联路由上级网关 DNS 协同上游（udp://<private-gw>:53 -> SmartDNS -set-mark 0x1）的校验、防环路与配置渲染。
package smartdns_test

import (
	"strings"
	"testing"

	"singctl/internal/smartdns"
)

func TestSmartDNS_UpstreamGatewayDirectiveAndValidation(t *testing.T) {
	validCases := []struct {
		in   string
		want string
	}{
		{"udp://192.168.1.1:53", "server 192.168.1.1:53 -set-mark 0x1"},
		{"udp://192.168.1.1", "server 192.168.1.1:53 -set-mark 0x1"},
		{"udp://10.0.0.1:53", "server 10.0.0.1:53 -set-mark 0x1"},
		{"udp://172.16.1.1:53", "server 172.16.1.1:53 -set-mark 0x1"},
	}
	for _, tc := range validCases {
		got, err := smartdns.FormatUpstreamDirective(tc.in)
		if err != nil {
			t.Fatalf("FormatUpstreamDirective(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("FormatUpstreamDirective(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalidCases := []string{
		"udp://127.0.0.1:53",
		"udp://0.0.0.0:53",
		"udp://169.254.1.1:53",
		"udp://8.8.8.8:53",          // public plain UDP must still be rejected
		"udp://223.5.5.5:53",        // public plain UDP must still be rejected
		"udp://192.168.1.1:5353",   // non-53 port on gateway UDP rejected
		"udp://router.local:53",    // non-IP host rejected
		"udp://192.168.1.1:53;foo", // injection rejected
		"https://192.168.1.1/dns-query",
	}
	for _, bad := range invalidCases {
		if got, err := smartdns.FormatUpstreamDirective(bad); err == nil {
			t.Fatalf("FormatUpstreamDirective(%q) expected error, got %q", bad, got)
		}
	}

	// BuildConfig with gateway upstream renders -set-mark 0x1 without public bootstrap DNS
	conf, err := smartdns.BuildConfig(smartdns.ConfigInput{
		DNSPort:   5354,
		Upstreams: []string{"udp://192.168.1.1:53"},
	}, "/etc/singctl/smartdns-rules.d", "/tmp/audit.log", "/tmp/sd.log")
	if err != nil {
		t.Fatalf("BuildConfig failed: %v", err)
	}
	if !strings.Contains(conf, "server 192.168.1.1:53 -set-mark 0x1") {
		t.Fatalf("expected marked gateway upstream in smartdns.conf:\n%s", conf)
	}
	if strings.Contains(conf, "-bootstrap-dns") {
		t.Fatalf("pure IP gateway upstream must not inject public bootstrap DNS:\n%s", conf)
	}
}
