package test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"singctl/internal/util/netinfo"
	"strings"
	"testing"
	"time"
)

func TestNetinfoGet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network-dependent test in short mode")
	}

	result, err := netinfo.Get()
	if err != nil {
		t.Fatalf("netinfo.Get() failed: %v", err)
	}

	// 验证结果
	t.Logf("Network info: %+v", result)

	// 验证局域网 IPv4
	if result.LANIPv4 == "" {
		t.Error("Expected LAN IPv4 to be set")
	} else {
		ip := net.ParseIP(result.LANIPv4)
		if ip == nil || ip.To4() == nil {
			t.Errorf("Invalid LAN IPv4: %s", result.LANIPv4)
		}
	}

	// 验证公网 IP：实现中公网 IP 获取已按需停用（见 netinfo.Get），
	// 因此只要求其为空或为合法 IP。
	if result.PublicIP != "" {
		ip := net.ParseIP(result.PublicIP)
		if ip == nil {
			t.Errorf("Invalid Public IP: %s", result.PublicIP)
		}
	}

	// 验证 DNS 服务器
	if len(result.DNSServers) == 0 {
		t.Error("Expected at least one DNS server")
	} else {
		for i, dns := range result.DNSServers {
			ip := net.ParseIP(dns)
			if ip == nil {
				t.Errorf("Invalid DNS server[%d]: %s", i, dns)
			}
		}
	}
}

func TestNetinfoGetWithTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network-dependent test in short mode")
	}

	// 测试短超时
	_, err := netinfo.GetWithTimeout(100 * time.Millisecond)
	// 短超时可能会失败，这是正常的
	if err != nil {
		t.Logf("Short timeout test failed as expected: %v", err)
	}

	// 测试正常超时
	result, err := netinfo.GetWithTimeout(10 * time.Second)
	if err != nil {
		t.Fatalf("Normal timeout test failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestNetinfoSystemDNS(t *testing.T) {
	// 测试读取系统 DNS（Unix 系统）
	if _, err := os.Stat("/etc/resolv.conf"); os.IsNotExist(err) {
		t.Skip("Skipping DNS test: /etc/resolv.conf not found")
	}

	// 通过直接调用 Get() 来测试 DNS 解析
	result, err := netinfo.Get()
	if err != nil {
		if testing.Short() {
			t.Skipf("Skipping DNS test in short mode: %v", err)
		}
		t.Fatalf("Failed to get network info: %v", err)
	}

	if len(result.DNSServers) == 0 {
		t.Error("No DNS servers found")
	}

	// 验证 DNS 服务器格式
	for _, dns := range result.DNSServers {
		if net.ParseIP(dns) == nil {
			t.Errorf("Invalid DNS server format: %s", dns)
		}
		// 不应该是空字符串
		if strings.TrimSpace(dns) == "" {
			t.Error("DNS server should not be empty")
		}
	}

	t.Logf("Found DNS servers: %v", result.DNSServers)
}

func TestNetinfoLocalIPs(t *testing.T) {
	// 这个测试通过 Get() 间接测试 localIPs 函数
	result, err := netinfo.Get()
	if err != nil {
		if testing.Short() {
			t.Skipf("Skipping local IP test in short mode: %v", err)
		}
		t.Fatalf("Failed to get network info: %v", err)
	}

	// 应该至少有 IPv4 地址
	if result.LANIPv4 == "" {
		t.Error("Expected LAN IPv4 address")
	}

	// 验证 IPv4 格式
	if result.LANIPv4 != "" {
		ip := net.ParseIP(result.LANIPv4)
		if ip == nil || ip.To4() == nil {
			t.Errorf("Invalid IPv4 address: %s", result.LANIPv4)
		}
		// 应该是私有地址
		if !ip.IsPrivate() && !ip.IsLoopback() {
			t.Logf("Warning: LAN IPv4 %s is not a private address", result.LANIPv4)
		}
	}

	// IPv6 可能为空，但如果有的话应该是有效的
	if result.LANIPv6 != "" {
		ip := net.ParseIP(result.LANIPv6)
		if ip == nil || ip.To4() != nil {
			t.Errorf("Invalid IPv6 address: %s", result.LANIPv6)
		}
	}

	t.Logf("LAN IPv4: %s, LAN IPv6: %s", result.LANIPv4, result.LANIPv6)
}

func TestNetinfoPublicIP(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping public IP test in short mode")
	}

	result, err := netinfo.Get()
	if err != nil {
		t.Fatalf("Failed to get network info: %v", err)
	}

	// 实现中公网 IP 获取已停用（netinfo.Get 里 r.PublicIP = ""），
	// 这里验证停用行为：为空即符合预期；若未来重新启用，则校验格式与公网性。
	if result.PublicIP == "" {
		t.Log("Public IP lookup is disabled in netinfo.Get, got empty value as expected")
		return
	}

	ip := net.ParseIP(result.PublicIP)
	if ip == nil {
		t.Errorf("Invalid public IP address: %s", result.PublicIP)
	}

	// 公网 IP 不应该是私有地址
	if ip != nil && ip.IsPrivate() {
		t.Errorf("Public IP %s should not be a private address", result.PublicIP)
	}

	t.Logf("Public IP: %s", result.PublicIP)
}

// 基准测试
func BenchmarkNetinfoGet(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := netinfo.Get()
		if err != nil {
			b.Fatalf("netinfo.Get() failed: %v", err)
		}
	}
}

func TestBandwidthRunSpeedTest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping bandwidth test in short mode")
	}

	// This integration test will actually run the speed test against external servers
	// so it might take a while.
	err := netinfo.RunSpeedTest()
	if err != nil {
		t.Fatalf("RunSpeedTest failed: %v", err)
	}
}

func TestSelectPrimaryLANIPv4(t *testing.T) {
	t.Run("prefers br-lan over pppoe-wan public IP and tun", func(t *testing.T) {
		candidates := []netinfo.InterfaceCandidate{
			{Name: "pppoe-wan", Up: true, IPv4Addrs: []string{"203.0.113.45"}},
			{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.8.8"}},
			{Name: "tailscale0", Up: true, IPv4Addrs: []string{"100.101.102.103"}},
			{Name: "br-lan", Up: true, IPv4Addrs: []string{"192.168.1.1"}},
		}
		got := netinfo.SelectPrimaryLANIPv4(candidates, "pppoe-wan")
		if got != "192.168.1.1" {
			t.Fatalf("SelectPrimaryLANIPv4 = %q, want 192.168.1.1", got)
		}
	})

	t.Run("side router uses preferred physical interface and ignores docker/tun", func(t *testing.T) {
		candidates := []netinfo.InterfaceCandidate{
			{Name: "docker0", Up: true, IPv4Addrs: []string{"172.17.0.1"}},
			{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.8.8"}},
			{Name: "eth0", Up: true, IPv4Addrs: []string{"10.0.0.2"}},
		}
		got := netinfo.SelectPrimaryLANIPv4(candidates, "eth0")
		if got != "10.0.0.2" {
			t.Fatalf("SelectPrimaryLANIPv4 = %q, want 10.0.0.2", got)
		}
	})

	t.Run("falls back safely to 127.0.0.1 when only public or virtual IPs exist", func(t *testing.T) {
		candidates := []netinfo.InterfaceCandidate{
			{Name: "eth0", Up: true, IPv4Addrs: []string{"198.51.100.12"}},
			{Name: "tun0", Up: true, IPv4Addrs: []string{"10.8.8.8"}},
			{Name: "tailscale0", Up: true, IPv4Addrs: []string{"100.64.0.9"}},
		}
		got := netinfo.SelectPrimaryLANIPv4(candidates, "eth0")
		if got != "127.0.0.1" {
			t.Fatalf("SelectPrimaryLANIPv4 = %q, want 127.0.0.1", got)
		}
	})
}

func TestParseUbusLANStatusIP(t *testing.T) {
	raw := []byte(`{"up":true,"ipv4-address":[{"address":"192.168.2.1","mask":24}]}`)
	if got := netinfo.ParseUbusLANStatusIP(raw); got != "192.168.2.1" {
		t.Fatalf("parseUbusLANStatusIP = %q, want 192.168.2.1", got)
	}
}

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
		if got := netinfo.ToIPv4Subnet24(tt.in); got != tt.want {
			t.Errorf("ToIPv4Subnet24(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsPublicAnycastDNS(t *testing.T) {
	anycast := []string{"223.5.5.5", "119.29.29.29", "114.114.114.114", "8.8.8.8", "1.1.1.1"}
	for _, ip := range anycast {
		if !netinfo.IsPublicAnycastDNS(ip) {
			t.Errorf("IsPublicAnycastDNS(%q) = false, want true", ip)
		}
	}

	regional := []string{"202.101.172.35", "202.96.209.5", "202.96.128.86", "211.136.192.6"}
	for _, ip := range regional {
		if netinfo.IsPublicAnycastDNS(ip) {
			t.Errorf("IsPublicAnycastDNS(%q) = true, want false", ip)
		}
	}
}

func TestResolveClientSubnet_RegionalDNS(t *testing.T) {
	// Regional ISP DNS should directly resolve to its /24 subnet without network calls
	got := netinfo.ResolveClientSubnet(context.Background(), "202.101.172.35")
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
		got := netinfo.LookupRegionalISPSubnet(tt.region, tt.city, tt.isp)
		if got != tt.want {
			t.Errorf("LookupRegionalISPSubnet(%q, %q, %q) = %q, want %q", tt.region, tt.city, tt.isp, got, tt.want)
		}
	}
}

func TestParseIPIPNetOutput(t *testing.T) {
	line := "当前 IP：115.192.0.1  来自于：中国 浙江 杭州  电信"
	region, city, isp := netinfo.ParseIPIPNetOutput(line)
	if region != "浙江" || city != "杭州" || isp != "电信" {
		t.Errorf("parseIPIPNetOutput got (%q, %q, %q)", region, city, isp)
	}
	if subnet := netinfo.LookupRegionalISPSubnet(region, city, isp); subnet != "202.101.172.0/24" {
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
	got := netinfo.ParseUbusInterfaceDNS(sample)
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
	got, err := netinfo.ParseSystemdResolvedConf(tmp)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"202.101.172.35", "223.5.5.5", "119.29.29.29"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseSystemdResolvedConf = %v, want %v", got, want)
	}
}
