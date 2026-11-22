// 文件职责：筛选本机安全的首选局域网 RFC1918 IPv4 监听地址（防误绑 pppoe-wan 公网口或虚拟隧道口）。
package netx

import (
	"context"
	"encoding/json"
	"net"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/common/sysinfo"
)

// InterfaceCandidate 抽象网卡及其 IPv4 地址列表（便于纯内存单元测试）。
type InterfaceCandidate struct {
	Name      string
	Up        bool
	Loopback  bool
	IPv4Addrs []string
}

// GetPrimaryLANIPv4 获取本机首选局域网（RFC1918 私网）IPv4 地址；无可用内网地址时安全回退 "127.0.0.1"。
func GetPrimaryLANIPv4() string {
	if sysinfo.IsOpenWrt() {
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
	for _, p := range []string{
		"tun", "tap", "utun", "tailscale", "ts", "wg",
		"docker", "br-", "veth", "virbr", "cni", "flannel", "cali",
		"pppoe", "ppp", "zt", "ham", "sit", "ip6tnl", "gre",
	} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func getOpenWrtPrimaryLANIP() string {
	if _, err := exec.LookPath("uci"); err == nil {
		if out, err := execx.Output(context.Background(), 1500*time.Millisecond, "uci", "-q", "get", "network.lan.ipaddr"); err == nil {
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
	if _, err := exec.LookPath("ubus"); err == nil {
		if out, err := execx.Output(context.Background(), 1500*time.Millisecond, "ubus", "call", "network.interface.lan", "status"); err == nil && len(out) > 0 {
			if ip := ParseUbusLANStatusIP(out); ip != "" {
				return ip
			}
		}
	}
	return ""
}

// ParseUbusLANStatusIP 从 OpenWrt `ubus call network.interface.lan status` JSON 中提取首个私网 IPv4。
func ParseUbusLANStatusIP(raw []byte) string {
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
	out, err := execx.Output(context.Background(), 1500*time.Millisecond, "ip", "-4", "-o", "route", "get", "223.5.5.5")
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
