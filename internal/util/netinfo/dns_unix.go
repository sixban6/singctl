//go:build !windows

package netinfo

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func systemDNS() ([]string, error) {
	// 优先顺序：
	// 1. OpenWrt ubus / uci / resolv.conf.d（直接在拨号路由上拿到运营商省市级 DNS）
	// 2. systemd-resolved（Ubuntu/Debian/Fedora/Arch 真实上游 DNS，绕过 127.0.0.53 存根）
	// 3. NetworkManager（RHEL/CentOS/桌面 Linux 真实 DHCP DNS）
	// 4. macOS scutil --dns
	// 5. /etc/resolv.conf
	methods := []func() ([]string, error){
		getDNSFromOpenWrtUbus,
		getDNSFromOpenWrtUCI,
		getDNSFromRouterDHCP,
		getDNSFromSystemdResolved,
		getDNSFromNetworkManager,
		getDNSFromMacOSScutil,
		getDNSFromResolvConf,
	}

	var privateFallback []string
	for _, method := range methods {
		servers, err := method()
		if err != nil || len(servers) == 0 {
			continue
		}
		// 优先返回公网 IPv4 DNS（特别是运营商下发的省市级 DNS）
		var publicServers []string
		for _, s := range servers {
			if !IsPrivateIP(s) {
				publicServers = append(publicServers, s)
			} else {
				privateFallback = append(privateFallback, s)
			}
		}
		if len(publicServers) > 0 {
			return deduplicateStrings(publicServers), nil
		}
	}

	// 若未找到公网 DNS，且非 OpenWrt 路由器本机（例如处于局域网内的普通终端），可使用局域网网关 DNS
	if !IsOpenWrt() && len(privateFallback) > 0 {
		lanV4, _, _ := localIPs()
		var usablePrivate []string
		for _, s := range deduplicateStrings(privateFallback) {
			if s != lanV4 { // 避免指向本机自身 IP 造成回环
				usablePrivate = append(usablePrivate, s)
			}
		}
		if len(usablePrivate) > 0 {
			return usablePrivate, nil
		}
	}

	// 所有方法都未命中有效公网 DNS 时，兜底使用国内高可用公共 DNS（绝不使用 8.8.8.8 避免 GFW 抢答污染与海外 ECS）
	return []string{"223.5.5.5", "119.29.29.29"}, nil
}

// ubusInterfaceDump 对应 `ubus call network.interface dump` 的精简结构
type ubusInterfaceDump struct {
	Interface []struct {
		Interface string   `json:"interface"`
		Up        bool     `json:"up"`
		DNSServer []string `json:"dns-server"`
	} `json:"interface"`
}

// getDNSFromOpenWrtUbus 通过 OpenWrt 核心守护进程 netifd 的 ubus 总线直接获取在线接口的真实上游 DNS，
// 完全不依赖文件路径，任何 OpenWrt 版本升级均不受影响。
func getDNSFromOpenWrtUbus() ([]string, error) {
	if _, err := exec.LookPath("ubus"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ubus", "call", "network.interface", "dump").Output()
	if err != nil || len(out) == 0 {
		return nil, err
	}

	return parseUbusInterfaceDNS(out), nil
}

func parseUbusInterfaceDNS(raw []byte) []string {
	var dump ubusInterfaceDump
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil
	}
	var wanServers, otherServers []string
	for _, iface := range dump.Interface {
		if !iface.Up || len(iface.DNSServer) == 0 {
			continue
		}
		name := strings.ToLower(iface.Interface)
		if name == "loopback" || name == "lan" {
			continue
		}
		if strings.HasPrefix(name, "wan") || strings.Contains(name, "pppoe") || strings.Contains(name, "modem") {
			wanServers = append(wanServers, iface.DNSServer...)
		} else {
			otherServers = append(otherServers, iface.DNSServer...)
		}
	}
	combined := append(wanServers, otherServers...)
	return filterLocalAddresses(combined)
}

// getDNSFromOpenWrtUCI 通过 `uci get dhcp.@dnsmasq[0].resolvfile` 动态查询当前固件配置的上游 DNS 文件路径。
func getDNSFromOpenWrtUCI() ([]string, error) {
	if _, err := exec.LookPath("uci"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	out, err := exec.CommandContext(ctx, "uci", "-q", "get", "dhcp.@dnsmasq[0].resolvfile").Output()
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return nil, nil
	}
	servers, err := parseResolvConf(path)
	if err != nil {
		return nil, err
	}
	return filterLocalAddresses(servers), nil
}

// OpenWrt/ImmortalWrt 系统 - 扫描已知路径与 resolv.conf.d 通配目录
func getDNSFromRouterDHCP() ([]string, error) {
	paths := []string{
		"/tmp/resolv.conf.d/resolv.conf.auto", // OpenWrt 21.02+ / 23.05+ / 24.10+ 标准路径
		"/var/resolv.conf.d/resolv.conf.auto",
		"/tmp/resolv.conf.auto", // 旧版 OpenWrt 路径
		"/var/resolv.conf.auto",
		"/tmp/resolv.conf.d/base",
	}

	for _, pattern := range []string{"/tmp/resolv.conf.d/*", "/var/resolv.conf.d/*", "/tmp/resolv.conf*"} {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if filepath.Base(m) == "resolv.conf" {
					continue // 跳过指向 127.0.0.1 的软链接
				}
				paths = append(paths, m)
			}
		}
	}

	var collected []string
	for _, path := range deduplicateStrings(paths) {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			continue
		}
		if servers, err := parseResolvConf(path); err == nil {
			filtered := filterLocalAddresses(servers)
			collected = append(collected, filtered...)
		}
	}
	if len(collected) > 0 {
		return deduplicateStrings(collected), nil
	}
	return nil, nil
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
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
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

// systemd-resolved 系统（Ubuntu / Debian / Fedora / Arch）
func getDNSFromSystemdResolved() ([]string, error) {
	// 1. 优先读取 systemd-resolved 生成的真实上游 resolv.conf（而非 127.0.0.53 stub）
	if servers, err := parseResolvConf("/run/systemd/resolve/resolv.conf"); err == nil {
		if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
			return filtered, nil
		}
	}

	// 2. 解析 /etc/systemd/resolved.conf 中的 INI 格式 DNS= 配置
	if servers, err := parseSystemdResolvedConf("/etc/systemd/resolved.conf"); err == nil {
		if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
			return filtered, nil
		}
	}

	// 3. 调用 resolvectl dns 提取接口上游 DNS
	if _, err := exec.LookPath("resolvectl"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "resolvectl", "dns").Output(); err == nil && len(out) > 0 {
			var servers []string
			for _, line := range strings.Split(string(out), "\n") {
				if idx := strings.Index(line, ":"); idx >= 0 {
					for _, field := range strings.Fields(line[idx+1:]) {
						if net.ParseIP(field) != nil {
							servers = append(servers, field)
						}
					}
				}
			}
			if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
				return filtered, nil
			}
		}
	}

	return nil, nil
}

func parseSystemdResolvedConf(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		key := strings.TrimSpace(parts[0])
		if key != "DNS" && key != "FallbackDNS" {
			continue
		}
		for _, token := range strings.Fields(parts[1]) {
			// 支持去除 #server_name 形式的 DoT 注释后缀
			if idx := strings.Index(token, "#"); idx > 0 {
				token = token[:idx]
			}
			if net.ParseIP(token) != nil {
				servers = append(servers, token)
			}
		}
	}
	return servers, nil
}

// NetworkManager 系统（RHEL / CentOS / Rocky / 桌面 Linux）
func getDNSFromNetworkManager() ([]string, error) {
	paths := []string{
		"/run/NetworkManager/no-stub-resolv.conf",
		"/run/NetworkManager/resolv.conf",
		"/var/run/NetworkManager/no-stub-resolv.conf",
		"/var/run/NetworkManager/resolv.conf",
	}

	for _, path := range paths {
		if servers, err := parseResolvConf(path); err == nil {
			if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
				return filtered, nil
			}
		}
	}

	if _, err := exec.LookPath("nmcli"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "nmcli", "-t", "-f", "IP4.DNS", "dev", "show").Output(); err == nil && len(out) > 0 {
			var servers []string
			for _, line := range strings.Split(string(out), "\n") {
				if idx := strings.Index(line, ":"); idx >= 0 {
					candidate := strings.TrimSpace(line[idx+1:])
					if net.ParseIP(candidate) != nil {
						servers = append(servers, candidate)
					}
				}
			}
			if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
				return filtered, nil
			}
		}
	}

	return nil, nil
}

// macOS 系统通过 scutil --dns 提取当前活跃的 IPv4 DNS
func getDNSFromMacOSScutil() ([]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	if _, err := exec.LookPath("scutil"); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--dns").Output()
	if err != nil || len(out) == 0 {
		return nil, err
	}
	var servers []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			if idx := strings.Index(line, ":"); idx >= 0 {
				candidate := strings.TrimSpace(line[idx+1:])
				if net.ParseIP(candidate) != nil {
					servers = append(servers, candidate)
				}
			}
		}
	}
	return filterLocalAddresses(servers), nil
}

// filterLocalAddresses 仅保留合法的 IPv4 单播 DNS 地址（剔除 IPv6、回环、链路本地及 FakeIP 地址）
func filterLocalAddresses(servers []string) []string {
	var realServers []string
	for _, server := range servers {
		ip := net.ParseIP(strings.TrimSpace(server))
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil {
			continue // 仅保留 IPv4 DNS，防止 ipv4_only 模式下注入 IPv6 nameserver
		}
		if ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsMulticast() || isLocalNetwork(ip4) {
			continue
		}
		realServers = append(realServers, ip4.String())
	}
	return deduplicateStrings(realServers)
}

func isLocalNetwork(ip net.IP) bool {
	localNets := []string{
		"127.0.0.0/8",    // 回环（含 127.0.0.53 systemd-resolved stub）
		"169.254.0.0/16", // 链路本地
		"198.18.0.0/15",  // sing-box / clash FakeIP 保留段
		"100.64.0.0/10",  // Tailscale / CGNAT（避免把 MagicDNS 100.100.100.100 当成运营商国内 DNS）
	}

	for _, cidr := range localNets {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func deduplicateStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
