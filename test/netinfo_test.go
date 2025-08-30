package test

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"singctl/internal/netinfo"
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

	// 验证公网 IP
	if result.PublicIP == "" {
		t.Error("Expected Public IP to be set")
	} else {
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

	if result.PublicIP == "" {
		t.Error("Expected public IP address")
	}

	// 验证公网 IP 格式
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