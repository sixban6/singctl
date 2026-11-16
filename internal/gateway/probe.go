package gateway

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ParseProcNetRouteDefault 解析 Linux /proc/net/route 内容，提取默认路由出口网卡与网关 IPv4。
func ParseProcNetRouteDefault(raw string) (iface, gwIP string, ok bool) {
	lineIdx := 0
	for line := range strings.SplitSeq(raw, "\n") {
		lineIdx++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || lineIdx == 1 && strings.HasPrefix(trimmed, "Iface") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 4 {
			continue
		}
		// Destination == 00000000 表示默认路由 (0.0.0.0/0)
		if fields[1] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		if err != nil || flags&0x1 == 0 { // RTF_UP
			continue
		}
		rawHex := fields[2]
		if len(rawHex) != 8 {
			continue
		}
		b, err := hex.DecodeString(rawHex)
		if err != nil || len(b) != 4 {
			continue
		}
		// /proc/net/route 按宿主字节序打印 uint32，还原为网络字节序 4 字节 IPv4
		hostU32 := binary.BigEndian.Uint32(b)
		var ipBytes [4]byte
		binary.NativeEndian.PutUint32(ipBytes[:], hostU32)
		addr := netip.AddrFrom4(ipBytes)
		if addr.IsUnspecified() {
			return fields[0], "", true
		}
		return fields[0], addr.String(), true
	}
	return "", "", false
}

// DeriveSuggestedMainRouterIP 根据本机地址前缀与当前默认网关推导推荐的上级主路由 IP。
// 若当前默认网关已误指回本机 IP，标记 selfLooped=true 并自动回退至同网段 .1（若本机即为 .1 则回退 .254）。
func DeriveSuggestedMainRouterIP(hostPrefixOrIP, currentGW string) (suggested string, selfLooped bool) {
	var selfAddr netip.Addr
	if pfx, err := netip.ParsePrefix(strings.TrimSpace(hostPrefixOrIP)); err == nil && pfx.Addr().Is4() {
		selfAddr = pfx.Addr()
	} else if addr, err := netip.ParseAddr(strings.TrimSpace(hostPrefixOrIP)); err == nil && addr.Is4() {
		selfAddr = addr
	}

	if gwAddr, err := netip.ParseAddr(strings.TrimSpace(currentGW)); err == nil && gwAddr.Is4() {
		if selfAddr.IsValid() && gwAddr == selfAddr {
			selfLooped = true
		} else if !gwAddr.IsLoopback() && !gwAddr.IsUnspecified() && !gwAddr.IsMulticast() {
			return gwAddr.String(), false
		}
	}

	if !selfAddr.IsValid() {
		return "", selfLooped
	}
	octets := selfAddr.As4()
	cand1 := netip.AddrFrom4([4]byte{octets[0], octets[1], octets[2], 1})
	if cand1 != selfAddr {
		return cand1.String(), selfLooped
	}
	cand254 := netip.AddrFrom4([4]byte{octets[0], octets[1], octets[2], 254})
	return cand254.String(), selfLooped
}

// ProbeTopology 探测本机主局域网网卡、IPv4 地址段及当前默认路由网关。
func ProbeTopology() TopologyInfo {
	var defIface, defGW string
	if runtime.GOOS == "linux" {
		if raw, err := os.ReadFile("/proc/net/route"); err == nil {
			defIface, defGW, _ = ParseProcNetRouteDefault(string(raw))
		}
	}
	if defIface == "" && defGW == "" {
		defIface, defGW = probeRouteFallback()
	}

	lanIface, lanIP, lanCIDR, hostPrefix := pickPrimaryLANInterface(defIface)
	if lanIface == "" {
		lanIface = defIface
	}
	suggested, looped := DeriveSuggestedMainRouterIP(hostPrefix, defGW)

	return TopologyInfo{
		LANIP:                 lanIP,
		LANCIDR:               lanCIDR,
		HostPrefix:            hostPrefix,
		LANIface:              lanIface,
		CurrentGatewayIP:      defGW,
		SuggestedMainRouterIP: suggested,
		SelfLooped:            looped,
	}
}

func probeRouteFallback() (iface, gw string) {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("route", "-n", "get", "default").Output()
		if err != nil {
			return "", ""
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			trimmed := strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(trimmed, "gateway:"); ok {
				gw = strings.TrimSpace(v)
			} else if v, ok := strings.CutPrefix(trimmed, "interface:"); ok {
				iface = strings.TrimSpace(v)
			}
		}
		return iface, gw
	}
	out, err := exec.Command("ip", "-4", "route", "show", "default").Output()
	if err != nil {
		return "", ""
	}
	fields := strings.Fields(string(out))
	for i := range len(fields) {
		if fields[i] == "via" && i+1 < len(fields) {
			gw = fields[i+1]
		}
		if fields[i] == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}
	return iface, gw
}

func isVirtualTunnelIface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"lo", "tailscale", "tun", "utun", "tap", "wg", "docker", "veth", "virbr", "cni"} {
		if n == prefix || strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

func pickPrimaryLANInterface(preferredIface string) (ifaceName, ipStr, netCIDR, hostPrefix string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", "", ""
	}

	inspectIface := func(ifi net.Interface) (string, string, string, bool) {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			return "", "", "", false
		}
		if isVirtualTunnelIface(ifi.Name) {
			return "", "", "", false
		}
		addrs, aErr := ifi.Addrs()
		if aErr != nil {
			return "", "", "", false
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP == nil {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones <= 0 {
				continue
			}
			addr, pErr := netip.ParseAddr(v4.String())
			if pErr != nil {
				continue
			}
			pfx := netip.PrefixFrom(addr, ones)
			return addr.String(), pfx.Masked().String(), pfx.String(), true
		}
		return "", "", "", false
	}

	if preferredIface != "" {
		for _, ifi := range ifaces {
			if ifi.Name == preferredIface {
				if ip, cidr, hp, ok := inspectIface(ifi); ok {
					return ifi.Name, ip, cidr, hp
				}
			}
		}
	}

	// OpenWrt 优先选择 br-lan
	for _, ifi := range ifaces {
		if ifi.Name == "br-lan" {
			if ip, cidr, hp, ok := inspectIface(ifi); ok {
				return ifi.Name, ip, cidr, hp
			}
		}
	}

	for _, ifi := range ifaces {
		if ip, cidr, hp, ok := inspectIface(ifi); ok {
			return ifi.Name, ip, cidr, hp
		}
	}
	return "", "", "", ""
}
