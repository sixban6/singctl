//go:build windows

// 文件职责：在 Windows 平台上通过 ipconfig / PowerShell / 注册表解析系统上游 IPv4 DNS。
package netx

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"singctl/internal/common/execx"
)

var (
	winIPv4Re     = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	winDNSSplitRe = regexp.MustCompile(`[,\s]+`)
)

func systemDNS() ([]string, error) {
	for _, method := range []func() ([]string, error){
		getDNSFromIPConfig,
		getDNSFromPowerShell,
		getDNSFromRegistry,
	} {
		if servers, err := method(); err == nil && len(servers) > 0 {
			return servers, nil
		}
	}
	return []string{"223.5.5.5", "119.29.29.29"}, nil
}

func getDNSFromIPConfig() ([]string, error) {
	output, err := execx.Output(context.Background(), 3*time.Second, "ipconfig", "/all")
	if err != nil {
		return nil, err
	}
	var servers []string
	for line := range strings.SplitSeq(string(output), "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.Contains(lower, "dns server") || strings.Contains(lower, "dns 服务器") {
			for _, match := range winIPv4Re.FindAllString(line, -1) {
				if ip := net.ParseIP(match); ip != nil && !ip.IsLoopback() {
					servers = append(servers, match)
				}
			}
		}
	}
	return filterWinLocalAddresses(servers), nil
}

func getDNSFromPowerShell() ([]string, error) {
	output, err := execx.Output(context.Background(), 4*time.Second, "powershell", "-Command",
		"Get-DnsClientServerAddress | Where-Object {$_.AddressFamily -eq 'IPv4'} | Select-Object -ExpandProperty ServerAddresses")
	if err != nil {
		return nil, err
	}
	var servers []string
	for line := range strings.SplitSeq(string(output), "\n") {
		line = strings.TrimSpace(line)
		if ip := net.ParseIP(line); ip != nil && !ip.IsLoopback() {
			servers = append(servers, line)
		}
	}
	return filterWinLocalAddresses(servers), nil
}

func getDNSFromRegistry() ([]string, error) {
	output, err := execx.Output(context.Background(), 3*time.Second, "reg", "query",
		`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`,
		"/s", "/f", "NameServer", "/t", "REG_SZ")
	if err != nil {
		return nil, err
	}
	var servers []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.Contains(strings.ToUpper(line), "NAMESERVER") {
			if _, rhs, ok := strings.Cut(line, "REG_SZ"); ok {
				for _, dns := range winDNSSplitRe.Split(strings.TrimSpace(rhs), -1) {
					dns = strings.TrimSpace(dns)
					if ip := net.ParseIP(dns); ip != nil && !ip.IsLoopback() {
						servers = append(servers, dns)
					}
				}
			}
		}
	}
	return filterWinLocalAddresses(servers), nil
}

func filterWinLocalAddresses(servers []string) []string {
	var out []string
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ip4 := ip.To4(); ip4 != nil && !isReservedLocalIPv4(ip4) {
			out = append(out, ip4.String())
		}
	}
	return out
}

// ParseUbusInterfaceDNS 在非 Unix 编译时保留纯解析能力以保持跨平台 API 对称。
func ParseUbusInterfaceDNS([]byte) []string { return nil }

// ParseSystemdResolvedConf 在非 Unix 编译时保留同签名占位。
func ParseSystemdResolvedConf(string) ([]string, error) { return nil, nil }
