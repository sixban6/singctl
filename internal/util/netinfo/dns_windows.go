//go:build windows

package netinfo

import (
	"net"
	"os/exec"
	"regexp"
	"strings"
)

func systemDNS() ([]string, error) {
	// 尝试多种方式获取DNS服务器
	methods := []func() ([]string, error){
		getDNSFromIPConfig,
		getDNSFromPowerShell,
		getDNSFromRegistry,
	}

	for _, method := range methods {
		if servers, err := method(); err == nil && len(servers) > 0 {
			return servers, nil
		}
	}

	// 所有方法都失败，使用公共DNS
	return []string{"8.8.8.8", "1.1.1.1"}, nil
}

// 使用 ipconfig /all 获取DNS服务器
func getDNSFromIPConfig() ([]string, error) {
	cmd := exec.Command("ipconfig", "/all")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// 解析输出中的DNS服务器
	var servers []string
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 匹配DNS服务器行
		if strings.Contains(strings.ToLower(line), "dns server") || 
		   strings.Contains(strings.ToLower(line), "dns 服务器") {
			// 提取IP地址
			ipRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
			matches := ipRegex.FindAllString(line, -1)
			for _, match := range matches {
				if ip := net.ParseIP(match); ip != nil && !ip.IsLoopback() {
					servers = append(servers, match)
				}
			}
		}
	}
	
	return filterLocalAddresses(servers), nil
}

// 使用 PowerShell 获取DNS服务器
func getDNSFromPowerShell() ([]string, error) {
	cmd := exec.Command("powershell", "-Command", 
		"Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 'IPv4'} | Select-Object -ExpandProperty ServerAddresses")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			if ip := net.ParseIP(line); ip != nil && !ip.IsLoopback() {
				servers = append(servers, line)
			}
		}
	}
	
	return filterLocalAddresses(servers), nil
}

// 从Windows注册表获取DNS服务器 (备用方法)
func getDNSFromRegistry() ([]string, error) {
	// 使用 reg query 命令访问注册表
	cmd := exec.Command("reg", "query", 
		`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		"/s", "/f", "NameServer", "/t", "REG_SZ")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var servers []string
	lines := strings.Split(string(output), "\n")
	
	for _, line := range lines {
		if strings.Contains(strings.ToUpper(line), "NAMESERVER") {
			// 提取IP地址
			parts := strings.Split(line, "REG_SZ")
			if len(parts) > 1 {
				dnsStr := strings.TrimSpace(parts[1])
				// DNS服务器可能用逗号或空格分隔
				dnsServers := regexp.MustCompile(`[,\s]+`).Split(dnsStr, -1)
				for _, dns := range dnsServers {
					dns = strings.TrimSpace(dns)
					if ip := net.ParseIP(dns); ip != nil && !ip.IsLoopback() {
						servers = append(servers, dns)
					}
				}
			}
		}
	}
	
	return filterLocalAddresses(servers), nil
}

func filterLocalAddresses(servers []string) []string {
	var realServers []string
	for _, server := range servers {
		ip := net.ParseIP(server)
		if ip != nil && !ip.IsLoopback() && !isLocalNetwork(ip) {
			realServers = append(realServers, server)
		}
	}
	return realServers
}

func isLocalNetwork(ip net.IP) bool {
	// 检查是否为本地网络地址
	localNets := []string{
		"127.0.0.0/8",    // 回环
		"169.254.0.0/16", // 链路本地
		"::1/128",        // IPv6 回环  
		"fe80::/10",      // IPv6 链路本地
	}
	
	for _, cidr := range localNets {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}