//go:build !windows

package netinfo

import (
	"bufio"
	"net"
	"os"
	"strings"
)

func systemDNS() ([]string, error) {
	// 尝试多种方式获取DNS服务器
	methods := []func() ([]string, error){
		getDNSFromResolvConf,
		getDNSFromSystemdResolved,
		getDNSFromNetworkManager,
		getDNSFromRouterDHCP,
	}

	for _, method := range methods {
		if servers, err := method(); err == nil && len(servers) > 0 {
			return servers, nil
		}
	}

	// 所有方法都失败，使用公共DNS
	return []string{"8.8.8.8", "1.1.1.1"}, nil
}

func parseResolvConf(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && net.ParseIP(fields[1]) != nil {
				servers = append(servers, fields[1])
			}
		}
	}
	return servers, nil
}

// 从 /etc/resolv.conf 获取，过滤本地地址
func getDNSFromResolvConf() ([]string, error) {
	servers, err := parseResolvConf("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return filterLocalAddresses(servers), nil
}

// systemd-resolved 系统
func getDNSFromSystemdResolved() ([]string, error) {
	paths := []string{
		"/run/systemd/resolve/resolv.conf",
		"/etc/systemd/resolved.conf",
	}

	for _, path := range paths {
		if servers, err := parseResolvConf(path); err == nil {
			filtered := filterLocalAddresses(servers)
			if len(filtered) > 0 {
				return filtered, nil
			}
		}
	}
	return nil, nil
}

// NetworkManager 系统
func getDNSFromNetworkManager() ([]string, error) {
	// 尝试从 NetworkManager 的状态获取
	paths := []string{
		"/var/run/NetworkManager/resolv.conf",
		"/etc/NetworkManager/system-connections",
	}
	
	for _, path := range paths {
		if servers, err := parseResolvConf(path); err == nil {
			filtered := filterLocalAddresses(servers)
			if len(filtered) > 0 {
				return filtered, nil
			}
		}
	}
	return nil, nil
}

// OpenWrt/ImmortalWrt 系统 - 从路由器DHCP配置获取
func getDNSFromRouterDHCP() ([]string, error) {
	// OpenWrt/ImmortalWrt 常见路径
	paths := []string{
		"/tmp/resolv.conf.auto",    // OpenWrt DHCP自动生成
		"/tmp/resolv.conf.d/base",  // OpenWrt基础DNS
		"/var/resolv.conf.auto",    // 另一种可能路径
		"/etc/config/dhcp",         // UCI配置（需要解析）
	}

	for _, path := range paths {
		if servers, err := parseResolvConf(path); err == nil {
			filtered := filterLocalAddresses(servers)
			if len(filtered) > 0 {
				return filtered, nil
			}
		}
	}
	return nil, nil
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
		"127.0.0.0/8",   // 回环
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
