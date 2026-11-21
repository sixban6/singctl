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
	"strconv"
	"strings"
	"time"
)

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

// parseIPv6Neighbors 解析 `ip -6 neigh show` 输出，提取规范化 IPv6 地址到小写 MAC 的映射。
func parseIPv6Neighbors(raw string) map[string]string {
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

	// 4. 缓存刷新 IPv6 邻居表 (15 秒 TTL)，将同一物理设备的 IPv6 地址按 MAC 归并至其 IPv4 主机名
	now := time.Now()
	if c.ipv6NeighCmdFunc != nil || (!c.customEndpoints && runtime.GOOS == "linux") {
		if c.ipv6NeighCache == nil || now.Sub(c.ipv6NeighFetchedAt) > 15*time.Second {
			var out []byte
			var err error
			if c.ipv6NeighCmdFunc != nil {
				out, err = c.ipv6NeighCmdFunc()
			} else if ipBin, lpErr := exec.LookPath("ip"); lpErr == nil {
				out, err = exec.Command(ipBin, "-6", "neigh", "show").Output()
			}
			if err == nil {
				c.ipv6NeighCache = parseIPv6Neighbors(string(out))
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

// InitProcessLocalTimezone 在缺少 /usr/share/zoneinfo 的精简 Linux/OpenWrt 系统上（Go 默认回退为 UTC），
// 自动读取 /etc/TZ 与 /etc/config/system 修正全局 time.Local，确保 logger、看门狗与 WebUI 时间戳一致。
func InitProcessLocalTimezone() {
	if time.Local != nil && time.Local.String() != "UTC" {
		return
	}
	if loc := ResolveLocalLocationFromFiles("/etc/TZ", "/etc/config/system"); loc != nil && loc.String() != "UTC" {
		time.Local = loc
	}
}

// ResolveLocalLocationFromFiles 按 TZ 环境变量 -> OpenWrt /etc/TZ -> UCI /etc/config/system -> time.Local 顺序解析真实本地时区。
func ResolveLocalLocationFromFiles(tzFile, uciSystemFile string) *time.Location {
	if envTZ := strings.TrimSpace(os.Getenv("TZ")); envTZ != "" {
		if loc := ParsePOSIXTZLocation(envTZ); loc != nil {
			return loc
		}
	}
	if tzFile != "" {
		if raw, err := os.ReadFile(tzFile); err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					if loc := ParsePOSIXTZLocation(line); loc != nil {
						return loc
					}
				}
			}
		}
	}
	if uciSystemFile != "" {
		if raw, err := os.ReadFile(uciSystemFile); err == nil {
			var zoneName, posixTZ string
			for line := range strings.SplitSeq(string(raw), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) >= 3 && fields[0] == "option" {
					val := strings.Trim(fields[2], "'\"")
					switch fields[1] {
					case "zonename":
						zoneName = val
					case "timezone":
						posixTZ = val
					}
				}
			}
			for _, candidate := range []string{zoneName, posixTZ} {
				if loc := ParsePOSIXTZLocation(candidate); loc != nil {
					return loc
				}
			}
		}
	}
	return time.Local
}

// ParsePOSIXTZLocation 解析 IANA 时区名或 OpenWrt / musl POSIX TZ 字符串（如 "CST-8", "<+08>-8", "EST5EDT", "IST-5:30"）。
// 注意 POSIX TZ 规范符号定义：偏移量表示“本地时间加上该值得到 UTC”，因此 "CST-8" 代表东八区 UTC+8 (+8*3600)。
func ParsePOSIXTZLocation(spec string) *time.Location {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil
	}
	if loc, err := time.LoadLocation(s); err == nil && loc != nil {
		return loc
	}

	switch strings.ToLower(strings.ReplaceAll(s, " ", "_")) {
	case "asia/shanghai", "asia/chongqing", "asia/harbin", "asia/urumqi", "asia/hong_kong", "asia/macau", "asia/taipei", "asia/singapore", "prc":
		return time.FixedZone("CST", 8*3600)
	case "asia/tokyo", "asia/seoul":
		return time.FixedZone("JST", 9*3600)
	}

	var tzName, rest string
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end <= 1 {
			return nil
		}
		tzName = s[1:end]
		rest = s[end+1:]
	} else {
		i := 0
		for i < len(s) && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
			i++
		}
		if i == 0 {
			return nil
		}
		tzName = s[:i]
		rest = s[i:]
	}

	if rest == "" {
		if strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "GMT") {
			return time.UTC
		}
		return nil
	}

	westSign := 1
	switch rest[0] {
	case '-':
		westSign = -1
		rest = rest[1:]
	case '+':
		westSign = 1
		rest = rest[1:]
	}

	// 提取 hh[:mm[:ss]]，忽略后续可能附带的夏令时规则（如 EDT,M3.2.0/2）
	numEnd := 0
	for numEnd < len(rest) && ((rest[numEnd] >= '0' && rest[numEnd] <= '9') || rest[numEnd] == ':') {
		numEnd++
	}
	if numEnd == 0 {
		return nil
	}
	parts := strings.Split(rest[:numEnd], ":")
	if len(parts) > 3 {
		return nil
	}
	hh, err := strconv.Atoi(parts[0])
	if err != nil || hh > 14 {
		return nil
	}
	mm, ss := 0, 0
	if len(parts) >= 2 {
		mm, err = strconv.Atoi(parts[1])
		if err != nil || mm < 0 || mm >= 60 {
			return nil
		}
	}
	if len(parts) == 3 {
		ss, err = strconv.Atoi(parts[2])
		if err != nil || ss < 0 || ss >= 60 {
			return nil
		}
	}

	westSeconds := westSign * (hh*3600 + mm*60 + ss)
	eastSeconds := -westSeconds
	if eastSeconds == 0 && (strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "GMT")) {
		return time.UTC
	}
	return time.FixedZone(tzName, eastSeconds)
}
