// 文件职责：提供公网运营商单播 IPv4 DNS 校验原语（严格剔除回环、私网、CGNAT、FakeIP 及本机接口 IP 防自环）。
package netx

import "net"

// IsPublicISPUnicastIPv4 判断 IPv4 地址是否为合法可路由的公网单播 DNS 地址（严格过滤回环、局域网私网 RFC1918、CGNAT/Tailscale 100.64/10、FakeIP 198.18/15、链路本地、组播/广播及本机接口 IP 防自环）。
func IsPublicISPUnicastIPv4(ip net.IP, localIPSet map[string]struct{}) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if v4.IsLoopback() || v4.IsPrivate() || v4.IsUnspecified() || v4.IsMulticast() ||
		v4.IsLinkLocalUnicast() || v4.IsLinkLocalMulticast() {
		return false
	}
	if v4[0] == 0 || v4[0] >= 240 {
		return false
	}
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return false
	}
	if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
		return false
	}
	if len(localIPSet) > 0 {
		if _, isSelf := localIPSet[v4.String()]; isSelf {
			return false
		}
	}
	return true
}
