package netinfo

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestToIPv4Subnet24(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"202.101.172.35", "202.101.172.0/24"},
		{"202.96.209.133", "202.96.209.0/24"},
		{"192.168.1.1", "192.168.1.0/24"},
		{"240e:1f:1::1", ""},
		{"invalid", ""},
	}
	for _, tt := range tests {
		if got := ToIPv4Subnet24(tt.in); got != tt.want {
			t.Errorf("ToIPv4Subnet24(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsPublicAnycastDNS(t *testing.T) {
	anycast := []string{"223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8", "1.1.1.1"}
	for _, ip := range anycast {
		if !IsPublicAnycastDNS(ip) {
			t.Errorf("IsPublicAnycastDNS(%q) = false, want true", ip)
		}
	}

	regional := []string{"202.101.172.35", "202.96.209.5", "202.96.128.86", "211.136.192.6"}
	for _, ip := range regional {
		if IsPublicAnycastDNS(ip) {
			t.Errorf("IsPublicAnycastDNS(%q) = true, want false", ip)
		}
	}
}

func TestResolveClientSubnet_RegionalDNS(t *testing.T) {
	// Regional ISP DNS should directly resolve to its /24 subnet without network calls
	got := ResolveClientSubnet(context.Background(), "202.101.172.35")
	if got != "202.101.172.0/24" {
		t.Errorf("ResolveClientSubnet(202.101.172.35) = %q, want 202.101.172.0/24", got)
	}
}

func TestLookupRegionalISPSubnet(t *testing.T) {
	tests := []struct {
		region string
		city   string
		isp    string
		want   string
	}{
		{"浙江", "杭州", "电信", "202.101.172.0/24"},
		{"Zhejiang", "Hangzhou", "China Telecom", "202.101.172.0/24"},
		{"广东", "深圳", "电信", "202.96.134.0/24"},
		{"广东", "广州", "电信", "202.96.128.0/24"},
		{"江苏", "南京", "电信", "218.2.135.0/24"},
		{"江苏", "苏州", "电信", "61.177.7.0/24"},
		{"北京", "北京", "联通", "202.106.0.0/24"},
		{"上海", "上海", "移动", "211.136.112.0/24"},
	}
	for _, tt := range tests {
		got := LookupRegionalISPSubnet(tt.region, tt.city, tt.isp)
		if got != tt.want {
			t.Errorf("LookupRegionalISPSubnet(%q, %q, %q) = %q, want %q", tt.region, tt.city, tt.isp, got, tt.want)
		}
	}
}

func TestParseIPIPNetOutput(t *testing.T) {
	line := "当前 IP：115.192.0.1  来自于：中国 浙江 杭州  电信"
	region, city, isp := parseIPIPNetOutput(line)
	if region != "浙江" || city != "杭州" || isp != "电信" {
		t.Errorf("parseIPIPNetOutput got (%q, %q, %q)", region, city, isp)
	}
	if subnet := LookupRegionalISPSubnet(region, city, isp); subnet != "202.101.172.0/24" {
		t.Errorf("LookupRegionalISPSubnet from ipip.net got %q, want 202.101.172.0/24", subnet)
	}
}

func TestParseUbusInterfaceDNS(t *testing.T) {
	sample := []byte(`{
		"interface": [
			{
				"interface": "loopback",
				"up": true,
				"dns-server": ["127.0.0.1"]
			},
			{
				"interface": "lan",
				"up": true,
				"dns-server": ["192.168.10.3"]
			},
			{
				"interface": "wan",
				"up": true,
				"dns-server": ["202.101.172.35", "202.101.172.46", "240e:5a::1"]
			}
		]
	}`)
	got := parseUbusInterfaceDNS(sample)
	want := []string{"202.101.172.35", "202.101.172.46"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseUbusInterfaceDNS = %v, want %v", got, want)
	}
}

func TestParseSystemdResolvedConf(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "resolved.conf")
	content := `[Resolve]
# Some comment
DNS=202.101.172.35#dns.telecom.cn 223.5.5.5
FallbackDNS=119.29.29.29
`
	if err := os.WriteFile(tmp, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := parseSystemdResolvedConf(tmp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"202.101.172.35", "223.5.5.5", "119.29.29.29"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSystemdResolvedConf = %v, want %v", got, want)
	}
}
