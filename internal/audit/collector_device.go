// 文件职责：负责局域网 DHCP/ARP/IPv6 邻居表设备目录解析、本机多网口 IP 识别与 OpenWrt POSIX 时区对齐。
package audit

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
)

// FormatFriendlyDeviceName 优先将 cfg.HomeDomain 中用户配置的设备昵称与 .home 域名叠加到审计设备展示名上（MAC 优先、IP 兜底）。
func FormatFriendlyDeviceName(cfg *config.Config, ipStr, macStr, fallback string) string {
	if cfg == nil {
		return fallback
	}
	display, fqdn, ok := cfg.HomeDomain.LookupFriendlyName(ipStr, macStr)
	if !ok || fqdn == "" {
		return fallback
	}
	aliasPrefix := fqdn
	if dot := strings.IndexByte(fqdn, '.'); dot > 0 {
		aliasPrefix = fqdn[:dot]
	}
	if display == "" || strings.EqualFold(display, aliasPrefix) || strings.EqualFold(display, fqdn) {
		return fqdn
	}
	return display + " (" + fqdn + ")"
}

type lanDeviceInfo struct {
	Name string
	MAC  string
}

func auditFileFingerprint(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return path + "|missing"
	}
	return fmt.Sprintf("%s|%d|%d", path, info.ModTime().UnixNano(), info.Size())
}

// ParseIPv6Neighbors 解析 `ip -6 neigh show` 输出，提取规范化 IPv6 地址到小写 MAC 的映射。
func ParseIPv6Neighbors(raw string) map[string]string {
	out := make(map[string]string)
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is6() {
			continue
		}
		llIdx := slices.Index(fields, "lladdr")
		if llIdx < 0 || llIdx+1 >= len(fields) {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(fields[llIdx+1]))
		if mac == "" || mac == "00:00:00:00:00:00" || !strings.Contains(mac, ":") {
			continue
		}
		out[addr.String()] = mac
	}
	return out
}

// resolveLANDevicesLocked 从 OpenWrt / Linux DHCP 租约、odhcpd 主机表、ARP/IPv6 邻居表与 /etc/hosts 解析内网 IP 对应的设备主机名与 MAC。
// 对磁盘租约与 hosts 文件采用 mtime+size 指纹校验：未变更时 0 磁盘读取，变更瞬间立即失效重读。
func (c *Collector) resolveLANDevicesLocked() map[string]lanDeviceInfo {
	now := c.currentTimeLocked()
	if c.deviceRefreshInterval > 0 && c.cachedMergedLANDevs != nil && !c.lanDevsFetchedAt.IsZero() {
		if elapsed := now.Sub(c.lanDevsFetchedAt); elapsed >= 0 && elapsed < c.deviceRefreshInterval {
			return c.cachedMergedLANDevs
		}
	}

	var fpBuilder strings.Builder
	fpBuilder.WriteString(auditFileFingerprint(c.hostsFile))
	fpBuilder.WriteByte(';')
	fpBuilder.WriteString(auditFileFingerprint(c.odhcpdHostsFile))
	for _, path := range c.leaseFiles {
		fpBuilder.WriteByte(';')
		fpBuilder.WriteString(auditFileFingerprint(path))
	}
	leaseFp := fpBuilder.String()

	var base map[string]lanDeviceInfo
	if c.cachedLeaseDevs != nil && c.cachedLeaseFp == leaseFp {
		base = maps.Clone(c.cachedLeaseDevs)
	} else {
		base = make(map[string]lanDeviceInfo)
		// 1. 解析 /etc/hosts 与 /tmp/hosts/odhcpd
		for _, hostPath := range []string{c.hostsFile, c.odhcpdHostsFile} {
			if strings.TrimSpace(hostPath) == "" {
				continue
			}
			raw, err := os.ReadFile(hostPath)
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if addr, parseErr := netip.ParseAddr(fields[0]); parseErr == nil {
						canonIP := addr.Unmap().String()
						host := fields[1]
						if host != "localhost" && !strings.HasPrefix(host, "ip6-") {
							prev := base[canonIP]
							prev.Name = cmp.Or(host, prev.Name)
							base[canonIP] = prev
						}
					}
				}
			}
		}

		// 2. 解析 dnsmasq / OpenWrt /tmp/dhcp.leases (<expiry> <mac> <ip> <hostname> <client-id>)
		for _, path := range c.leaseFiles {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(raw), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) < 4 {
					continue
				}
				mac, ip, host := strings.ToLower(strings.TrimSpace(fields[1])), fields[2], fields[3]
				if net.ParseIP(ip) == nil {
					continue
				}
				if host == "*" {
					host = ""
				}
				prev := base[ip]
				base[ip] = lanDeviceInfo{
					Name: cmp.Or(host, prev.Name),
					MAC:  cmp.Or(mac, prev.MAC),
				}
			}
		}
		c.cachedLeaseDevs = maps.Clone(base)
		c.cachedLeaseFp = leaseFp
	}

	// 3. 实时补充 /proc/net/arp 中的动态 MAC 地址（内核虚拟内存文件，零磁盘开销）
	if raw, err := os.ReadFile(c.arpFile); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 4 && net.ParseIP(fields[0]) != nil && strings.Contains(fields[3], ":") {
				ip, mac := fields[0], strings.ToLower(strings.TrimSpace(fields[3]))
				if mac != "00:00:00:00:00:00" {
					prev := base[ip]
					prev.MAC = cmp.Or(prev.MAC, mac)
					base[ip] = prev
				}
			}
		}
	}

	// 4. 缓存刷新 IPv6 邻居表（常规 15s TTL，低内存模式放宽至 3m TTL），将同一物理设备的 IPv6 地址按 MAC 归并至其 IPv4 主机名
	ipv6TTL := cmp.Or(c.ipv6RefreshInterval, 15*time.Second)
	if c.ipv6NeighCmdFunc != nil || (!c.customEndpoints && runtime.GOOS == "linux") {
		needRefresh := c.ipv6NeighCache == nil || c.ipv6NeighFetchedAt.IsZero() || now.Sub(c.ipv6NeighFetchedAt) < 0 || now.Sub(c.ipv6NeighFetchedAt) >= ipv6TTL
		if needRefresh {
			var out []byte
			var err error
			if c.ipv6NeighCmdFunc != nil {
				out, err = c.ipv6NeighCmdFunc()
			} else if ipBin, lpErr := exec.LookPath("ip"); lpErr == nil {
				out, err = exec.Command(ipBin, "-6", "neigh", "show").Output()
			}
			if err == nil {
				c.ipv6NeighCache = ParseIPv6Neighbors(string(out))
				c.ipv6NeighFetchedAt = now
			}
		}
	}
	for ip6, mac := range c.ipv6NeighCache {
		prev := base[ip6]
		prev.MAC = cmp.Or(prev.MAC, mac)
		base[ip6] = prev
	}

	// 按小写 MAC 回填主机名（优先使用 IPv4 记录的友好名称，使 IPv6 临时隐私地址直接识别为对应设备名）
	if len(base) > 0 {
		macNames := make(map[string]string, len(base))
		for ip, info := range base {
			mac := strings.ToLower(strings.TrimSpace(info.MAC))
			if mac == "" || info.Name == "" || info.Name == ip {
				continue
			}
			isV4 := net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
			if existing, exists := macNames[mac]; !exists || (isV4 && existing != info.Name) {
				macNames[mac] = info.Name
			}
		}
		for ip, info := range base {
			mac := strings.ToLower(strings.TrimSpace(info.MAC))
			if mac != "" && info.Name == "" {
				if name := macNames[mac]; name != "" {
					info.Name = name
					base[ip] = info
				}
			}
		}
	}

	c.cachedMergedLANDevs = base
	c.lanDevsFetchedAt = now
	return base
}

// collectLocalInterfaceIPs 枚举当前软路由/主机所有网卡绑定的本机 IP（含 pppoe-wan 公网 IP、br-lan 网关 IP 等）。
func collectLocalInterfaceIPs() map[string]bool {
	out := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				out[v.IP.String()] = true
			}
		case *net.IPAddr:
			if v.IP != nil {
				out[v.IP.String()] = true
			}
		}
	}
	return out
}

// normalizeSourceDeviceIP 将软路由本机发出的连接（源 IP 为本机 WAN 公网 IP 或网关自身接口 IP）统一归并为 127.0.0.1 (本机网关)。
// 若公网 IPv6 源地址命中局域网邻居表或 odhcpd 租约表，则判定为内网双栈设备并保留真实源 IP。
func normalizeSourceDeviceIP(rawIP string, selfIPs map[string]bool, devDir map[string]lanDeviceInfo) string {
	ipStr := strings.TrimSpace(rawIP)
	if ipStr == "" || selfIPs[ipStr] {
		return "127.0.0.1"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip.IsLoopback() {
		return "127.0.0.1"
	}
	// 局域网私有网段 (10/8, 172.16/12, 192.168/16, fc00::/7) 与 Tailscale CGNAT (100.64/10) 保留真实内网设备 IP
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return ipStr
	}
	if ip.To4() == nil {
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			canon := addr.Unmap().String()
			if selfIPs[canon] {
				return "127.0.0.1"
			}
			if _, knownLAN := devDir[canon]; knownLAN {
				return canon
			}
		}
	}
	// 其余非私网公网源 IP 均来自软路由 pppoe-wan 本机 output 链透明劫持，统一归入本机网关
	return "127.0.0.1"
}
func (c *Collector) resolveLocalLocation() *time.Location {
	// 当测试注入了自定义 tzFile / uciSystemFile，或运行在缺少 /usr/share/zoneinfo 导致 time.Local 回退为 UTC 的 OpenWrt 固件上时，主动解析 /etc/TZ 与 /etc/config/system
	if (c.tzFile != "" && c.tzFile != "/etc/TZ") || (c.uciSystemFile != "" && c.uciSystemFile != "/etc/config/system") {
		return ResolveLocalLocationFromFiles(c.tzFile, c.uciSystemFile)
	}
	if time.Local != nil && time.Local.String() != "UTC" {
		return time.Local
	}
	return ResolveLocalLocationFromFiles(c.tzFile, c.uciSystemFile)
}

// InitProcessLocalTimezone 委托 common/sysinfo.InitLocalTimezone 保持历史测试与调用兼容。
func InitProcessLocalTimezone() {
	sysinfo.InitLocalTimezone()
}

// ResolveLocalLocationFromFiles 委托 common/sysinfo.ResolveLocalLocationFromFiles。
func ResolveLocalLocationFromFiles(tzFile, uciSystemFile string) *time.Location {
	return sysinfo.ResolveLocalLocationFromFiles(tzFile, uciSystemFile)
}

// ParsePOSIXTZLocation 委托 common/sysinfo.ParsePOSIXTZLocation。
func ParsePOSIXTZLocation(spec string) *time.Location {
	return sysinfo.ParsePOSIXTZLocation(spec)
}
