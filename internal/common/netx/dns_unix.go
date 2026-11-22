//go:build !windows

// 文件职责：在 Unix（OpenWrt ubus/uci、systemd-resolved、NetworkManager、macOS scutil）上解析真实上游 IPv4 DNS。
package netx

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

	"singctl/internal/common/execx"
	"singctl/internal/common/sysinfo"
)

func systemDNS() ([]string, error) {
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

	if !sysinfo.IsOpenWrt() && len(privateFallback) > 0 {
		lanV4, _, _ := localIPs()
		var usablePrivate []string
		for _, s := range deduplicateStrings(privateFallback) {
			if s != lanV4 {
				usablePrivate = append(usablePrivate, s)
			}
		}
		if len(usablePrivate) > 0 {
			return usablePrivate, nil
		}
	}
	return []string{"223.5.5.5", "119.29.29.29"}, nil
}

type ubusInterfaceDump struct {
	Interface []struct {
		Interface string   `json:"interface"`
		Up        bool     `json:"up"`
		DNSServer []string `json:"dns-server"`
	} `json:"interface"`
}

func getDNSFromOpenWrtUbus() ([]string, error) {
	if _, err := exec.LookPath("ubus"); err != nil {
		return nil, err
	}
	out, err := execx.Output(context.Background(), 2*time.Second, "ubus", "call", "network.interface", "dump")
	if err != nil || len(out) == 0 {
		return nil, err
	}
	return ParseUbusInterfaceDNS(out), nil
}

// ParseUbusInterfaceDNS 从 OpenWrt netifd `ubus call network.interface dump` 输出中提取公网/上游 IPv4 DNS。
func ParseUbusInterfaceDNS(raw []byte) []string {
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
	return filterLocalAddresses(append(wanServers, otherServers...))
}

func getDNSFromOpenWrtUCI() ([]string, error) {
	if _, err := exec.LookPath("uci"); err != nil {
		return nil, err
	}
	out, err := execx.Output(context.Background(), 1500*time.Millisecond, "uci", "-q", "get", "dhcp.@dnsmasq[0].resolvfile")
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

func getDNSFromRouterDHCP() ([]string, error) {
	paths := []string{
		"/tmp/resolv.conf.d/resolv.conf.auto",
		"/var/resolv.conf.d/resolv.conf.auto",
		"/tmp/resolv.conf.auto",
		"/var/resolv.conf.auto",
		"/tmp/resolv.conf.d/base",
	}
	for _, pattern := range []string{"/tmp/resolv.conf.d/*", "/var/resolv.conf.d/*", "/tmp/resolv.conf*"} {
		if matches, err := filepath.Glob(pattern); err == nil {
			for _, m := range matches {
				if filepath.Base(m) != "resolv.conf" {
					paths = append(paths, m)
				}
			}
		}
	}
	var collected []string
	for _, path := range deduplicateStrings(paths) {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			if servers, err := parseResolvConf(path); err == nil {
				collected = append(collected, filterLocalAddresses(servers)...)
			}
		}
	}
	return deduplicateStrings(collected), nil
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

func getDNSFromResolvConf() ([]string, error) {
	servers, err := parseResolvConf("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return filterLocalAddresses(servers), nil
}

func getDNSFromSystemdResolved() ([]string, error) {
	if servers, err := parseResolvConf("/run/systemd/resolve/resolv.conf"); err == nil {
		if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
			return filtered, nil
		}
	}
	if servers, err := ParseSystemdResolvedConf("/etc/systemd/resolved.conf"); err == nil {
		if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
			return filtered, nil
		}
	}
	if _, err := exec.LookPath("resolvectl"); err == nil {
		if out, err := execx.Output(context.Background(), 1500*time.Millisecond, "resolvectl", "dns"); err == nil && len(out) > 0 {
			var servers []string
			for line := range strings.SplitSeq(string(out), "\n") {
				if _, rhs, ok := strings.Cut(line, ":"); ok {
					for field := range strings.FieldsSeq(rhs) {
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

// ParseSystemdResolvedConf 解析 /etc/systemd/resolved.conf 中的 DNS= / FallbackDNS= 条目。
func ParseSystemdResolvedConf(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var servers []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, rhs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "DNS" && key != "FallbackDNS" {
			continue
		}
		for token := range strings.FieldsSeq(rhs) {
			if addr, _, hasHash := strings.Cut(token, "#"); hasHash && addr != "" {
				token = addr
			}
			if net.ParseIP(token) != nil {
				servers = append(servers, token)
			}
		}
	}
	return servers, nil
}

func getDNSFromNetworkManager() ([]string, error) {
	for _, path := range []string{
		"/run/NetworkManager/no-stub-resolv.conf",
		"/run/NetworkManager/resolv.conf",
		"/var/run/NetworkManager/no-stub-resolv.conf",
		"/var/run/NetworkManager/resolv.conf",
	} {
		if servers, err := parseResolvConf(path); err == nil {
			if filtered := filterLocalAddresses(servers); len(filtered) > 0 {
				return filtered, nil
			}
		}
	}
	if _, err := exec.LookPath("nmcli"); err == nil {
		if out, err := execx.Output(context.Background(), 1500*time.Millisecond, "nmcli", "-t", "-f", "IP4.DNS", "dev", "show"); err == nil && len(out) > 0 {
			var servers []string
			for line := range strings.SplitSeq(string(out), "\n") {
				if _, rhs, ok := strings.Cut(line, ":"); ok {
					cand := strings.TrimSpace(rhs)
					if net.ParseIP(cand) != nil {
						servers = append(servers, cand)
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

func getDNSFromMacOSScutil() ([]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	if _, err := exec.LookPath("scutil"); err != nil {
		return nil, err
	}
	out, err := execx.Output(context.Background(), 1500*time.Millisecond, "scutil", "--dns")
	if err != nil || len(out) == 0 {
		return nil, err
	}
	var servers []string
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver[") {
			if _, rhs, ok := strings.Cut(line, ":"); ok {
				cand := strings.TrimSpace(rhs)
				if net.ParseIP(cand) != nil {
					servers = append(servers, cand)
				}
			}
		}
	}
	return filterLocalAddresses(servers), nil
}

func filterLocalAddresses(servers []string) []string {
	var realServers []string
	for _, server := range servers {
		ip := net.ParseIP(strings.TrimSpace(server))
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsMulticast() || isReservedLocalIPv4(ip4) {
			continue
		}
		realServers = append(realServers, ip4.String())
	}
	return deduplicateStrings(realServers)
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
