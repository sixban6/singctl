package netinfo

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"time"
)

// InterfaceCandidate 用于抽象网卡及其 IPv4 地址列表（便于纯内存单元测试）。
type InterfaceCandidate struct {
	Name       string
	Up         bool
	Loopback   bool
	IPv4Addrs  []string
}

// GetPrimaryLANIPv4 获取本机首选局域网（RFC1918 私网）IPv4 地址，供内部管理面板安全绑定。
//
// 安全保证：
//  1. OpenWrt 优先从 uci/ubus 读取 network.lan 的网关地址（如 192.168.1.1），绝不误绑 pppoe-wan 公网 IP；
//  2. Linux 优先匹配 br-lan 或默认路由对应的物理网卡私网地址，剔除 tun/tailscale/docker/pppoe 等虚拟/拨号接口；
//  3. 仅返回合法的 RFC1918 私网 IPv4（192.168.0.0/16、10.0.0.0/8、172.16.0.0/12）；
//  4. 若未找到任何可用局域网私网 IP，强制回退返回 "127.0.0.1"，绝不返回 "0.0.0.0" 或公网 IP。
func GetPrimaryLANIPv4() string {
	if IsOpenWrt() {
		if ip := getOpenWrtPrimaryLANIP(); ip != "" {
			return ip
		}
	}

	preferredDev := getDefaultRouteDevice()
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}

	candidates := make([]InterfaceCandidate, 0, len(ifaces))
	for _, ifc := range ifaces {
		cand := InterfaceCandidate{
			Name:     ifc.Name,
			Up:       ifc.Flags&net.FlagUp != 0,
			Loopback: ifc.Flags&net.FlagLoopback != 0,
		}
		addrs, _ := ifc.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				ip, _, _ = net.ParseCIDR(addr.String())
			}
			if ip4 := ip.To4(); ip4 != nil {
				cand.IPv4Addrs = append(cand.IPv4Addrs, ip4.String())
			}
		}
		candidates = append(candidates, cand)
	}

	return SelectPrimaryLANIPv4(candidates, preferredDev)
}

// SelectPrimaryLANIPv4 从网卡候选列表中筛选最佳 RFC1918 局域网 IPv4 地址。
func SelectPrimaryLANIPv4(candidates []InterfaceCandidate, preferredDev string) string {
	// 1. 优先匹配 br-lan（OpenWrt 标准局域网桥接接口）
	for _, c := range candidates {
		if !c.Up || c.Loopback {
			continue
		}
		if strings.EqualFold(c.Name, "br-lan") {
			if ip := firstRFC1918IPv4(c.IPv4Addrs); ip != "" {
				return ip
			}
		}
	}

	// 2. 优先匹配默认路由所在的非虚拟物理接口（例如旁路由 eth0 / ens18 / en0）
	if preferredDev != "" && !isIgnoredLANInterface(preferredDev) {
		for _, c := range candidates {
			if !c.Up || c.Loopback || c.Name != preferredDev {
				continue
			}
			if ip := firstRFC1918IPv4(c.IPv4Addrs); ip != "" {
				return ip
			}
		}
	}

	// 3. 遍历常规接口：优先 192.168.0.0/16，再考虑 10.0.0.0/8 与 172.16.0.0/12
	var fallbackRFC1918 string
	for _, c := range candidates {
		if !c.Up || c.Loopback || isIgnoredLANInterface(c.Name) {
			continue
		}
		for _, raw := range c.IPv4Addrs {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil || !IsPrivateIP(ip4.String()) {
				continue
			}
			if ip4[0] == 192 && ip4[1] == 168 {
				return ip4.String()
			}
			if fallbackRFC1918 == "" {
				fallbackRFC1918 = ip4.String()
			}
		}
	}

	if fallbackRFC1918 != "" {
		return fallbackRFC1918
	}
	return "127.0.0.1"
}

func firstRFC1918IPv4(addrs []string) string {
	var fallback string
	for _, raw := range addrs {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		ip4 := ip.To4()
		if ip4 == nil || !IsPrivateIP(ip4.String()) {
			continue
		}
		if ip4[0] == 192 && ip4[1] == 168 {
			return ip4.String()
		}
		if fallback == "" {
			fallback = ip4.String()
		}
	}
	return fallback
}

func isIgnoredLANInterface(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" || n == "lo" {
		return true
	}
	if n == "br-lan" {
		return false
	}
	ignoredPrefixes := []string{
		"tun", "tap", "utun", "tailscale", "ts", "wg",
		"docker", "br-", "veth", "virbr", "cni", "flannel", "cali",
		"pppoe", "ppp", "zt", "ham", "sit", "ip6tnl", "gre",
	}
	for _, p := range ignoredPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func getOpenWrtPrimaryLANIP() string {
	// 1. uci -q get network.lan.ipaddr
	if _, err := exec.LookPath("uci"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		out, err := exec.CommandContext(ctx, "uci", "-q", "get", "network.lan.ipaddr").Output()
		cancel()
		if err == nil {
			// network.lan.ipaddr 可能带掩码或空格分隔多个 IP
			for field := range strings.FieldsSeq(strings.TrimSpace(string(out))) {
				ipStr, _, hasSlash := strings.Cut(field, "/")
				if !hasSlash {
					ipStr = field
				}
				if ip := net.ParseIP(ipStr); ip != nil && ip.To4() != nil && IsPrivateIP(ip.To4().String()) {
					return ip.To4().String()
				}
			}
		}
	}

	// 2. ubus call network.interface.lan status
	if _, err := exec.LookPath("ubus"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		out, err := exec.CommandContext(ctx, "ubus", "call", "network.interface.lan", "status").Output()
		cancel()
		if err == nil && len(out) > 0 {
			if ip := parseUbusLANStatusIP(out); ip != "" {
				return ip
			}
		}
	}

	return ""
}

func parseUbusLANStatusIP(raw []byte) string {
	var status struct {
		IPv4Address []struct {
			Address string `json:"address"`
		} `json:"ipv4-address"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return ""
	}
	for _, item := range status.IPv4Address {
		if ip := net.ParseIP(strings.TrimSpace(item.Address)); ip != nil && ip.To4() != nil && IsPrivateIP(ip.To4().String()) {
			return ip.To4().String()
		}
	}
	return ""
}

func getDefaultRouteDevice() string {
	if _, err := exec.LookPath("ip"); err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-4", "-o", "route", "get", "223.5.5.5").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1]
		}
	}
	return ""
}
