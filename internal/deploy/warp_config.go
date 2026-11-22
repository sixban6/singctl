// 文件职责：负责 WARP / wireproxy 配置渲染、规范化重写（MTU=1280 / ResolveStrategy / 死锁消除）、Endpoint 提取替换与候选地址排序核心。
//
// 架构设计原则：
//   - 函数式内核（Functional Core）：所有配置文本变换与候选 Endpoint 优先级去重均为纯内存无副作用函数，
//     输入输出完全确定，便于全边界表驱动单元测试覆盖与高并发安全复用。
package deploy

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strings"
)

func isValidIPv4Endpoint(ep string) bool {
	host, port, err := net.SplitHostPort(strings.TrimSpace(ep))
	if err != nil || host == "" || port == "" || port == "0" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

// BuildWireproxyConfig 渲染标准纯 Go wireproxy 配置（MTU=1280，IPv4 直连 Endpoint）。
// 注意：
//  1. 绝不使用 ResolveStrategy = auto；若 [Interface] Address 包含虚拟 IPv6 地址则设为 ipv6（优先使用每次注册都会轮换的 WARP IPv6 出口，并对纯 IPv4 目标自动回退至 IPv4），纯 IPv4 配置则设为 ipv4。
//  2. wireproxy 在启动阶段若配置了 PersistentKeepalive，会在 Routine: receive incoming v4 启动前抢先触发握手导致死锁。
//  3. MTU 固定 1280，消除外层 Hysteria2/VLESS 与内层 WireGuard 叠加封装触发 PMTU 黑洞导致大包 TLS 握手超时（如 x.com）。
func BuildWireproxyConfig(addressLine, privKey, peerPubKey string, hasIPv6 bool) string {
	return BuildWireproxyConfigWithEndpoint(addressLine, privKey, peerPubKey, WarpCandidateEndpoints[0], hasIPv6)
}

// BuildWireproxyConfigWithEndpoint 使用指定 IPv4 Endpoint 渲染 wireproxy 配置。
func BuildWireproxyConfigWithEndpoint(addressLine, privKey, peerPubKey, endpoint string, hasIPv6 bool) string {
	ep := cmp.Or(strings.TrimSpace(endpoint), WarpCandidateEndpoints[0])
	dnsLine := "1.1.1.1,8.8.8.8,8.8.4.4"
	if hasIPv6 {
		dnsLine = "1.1.1.1,8.8.8.8,8.8.4.4,2606:4700:4700::1111,2001:4860:4860::8888,2001:4860:4860::8844"
	}
	resolveStrategy := "ipv4"
	if strings.Contains(addressLine, ":") {
		resolveStrategy = "ipv6"
	}
	return fmt.Sprintf(`[Interface]
Address = %s
MTU = 1280
PrivateKey = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s

[Socks5]
BindAddress = 127.0.0.1:40000

[Resolve]
ResolveStrategy = %s
`, addressLine, privKey, dnsLine, peerPubKey, ep, resolveStrategy)
}

func renderWireproxyConfigFromReg(privKey string, reg *warpRegResponse, hasIPv6 bool, endpoint string) string {
	var v4Addr, v6Addr, peerPubKey string
	if reg != nil {
		v4Addr = reg.Config.Interface.Addresses.V4
		if !strings.Contains(v4Addr, "/") && v4Addr != "" {
			v4Addr += "/32"
		}
		v6Addr = reg.Config.Interface.Addresses.V6
		if !strings.Contains(v6Addr, "/") && v6Addr != "" {
			v6Addr += "/128"
		}
		if len(reg.Config.Peers) > 0 && reg.Config.Peers[0].PublicKey != "" {
			peerPubKey = reg.Config.Peers[0].PublicKey
		}
	}
	addressLine := v4Addr
	if v6Addr != "" {
		if addressLine != "" {
			addressLine += ", " + v6Addr
		} else {
			addressLine = v6Addr
		}
	}
	addressLine = cmp.Or(addressLine, "172.16.0.2/32")
	peerPubKey = cmp.Or(peerPubKey, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
	return BuildWireproxyConfigWithEndpoint(addressLine, privKey, peerPubKey, endpoint, hasIPv6)
}

func extractRegV4Endpoint(reg *warpRegResponse) string {
	if reg == nil || len(reg.Config.Peers) == 0 {
		return ""
	}
	v4 := strings.TrimSpace(reg.Config.Peers[0].Endpoint.V4)
	if v4 == "" || strings.HasSuffix(v4, ":0") {
		return ""
	}
	host, port, err := net.SplitHostPort(v4)
	if err != nil || host == "" || port == "" || port == "0" {
		return ""
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return v4
}

// BuildOrderedWarpCandidateEndpoints 按优先级合并并去重 WARP Endpoint 候选列表：
// 1) 若现网正在使用的 currentEP 为有效 IPv4 Endpoint，优先保留以降低切换抖动；
// 2) 依次追加配置的候选池（候选池为空时自动回退至 WarpCandidateEndpoints[0]）；
// 3) 追加本次注册返回的新 V4 Endpoint（若有效且未重复）。
func BuildOrderedWarpCandidateEndpoints(candidates []string, currentEP string, reg *WarpRegResponse) []string {
	return buildOrderedWarpCandidateEndpoints(candidates, currentEP, reg)
}

func buildOrderedWarpCandidateEndpoints(candidates []string, currentEP string, reg *warpRegResponse) []string {
	var endpoints []string
	addUnique := func(ep string) {
		ep = strings.TrimSpace(ep)
		if ep != "" && !slices.Contains(endpoints, ep) {
			endpoints = append(endpoints, ep)
		}
	}
	regEP := extractRegV4Endpoint(reg)
	if len(candidates) == 0 {
		if isValidIPv4Endpoint(currentEP) {
			addUnique(currentEP)
		} else {
			addUnique(WarpCandidateEndpoints[0])
		}
		addUnique(regEP)
		return endpoints
	}
	if isValidIPv4Endpoint(currentEP) {
		addUnique(currentEP)
	}
	for _, ep := range candidates {
		addUnique(ep)
	}
	addUnique(regEP)
	return endpoints
}

func orderCandidateEndpointsAfterCurrent(candidates []string, current string) []string {
	idx := slices.Index(candidates, strings.TrimSpace(current))
	if idx < 0 || idx+1 >= len(candidates) {
		return slices.Clone(candidates)
	}
	ordered := make([]string, 0, len(candidates))
	ordered = append(ordered, candidates[idx+1:]...)
	ordered = append(ordered, candidates[:idx+1]...)
	return ordered
}

// NormalizeWireproxyConfigContent 修正既有 wireproxy 配置中的 MTU=1280、双栈可轮换 ResolveStrategy、域名 Endpoint 与启动死锁 PersistentKeepalive
func NormalizeWireproxyConfigContent(content string) (string, bool) {
	lines := strings.Split(content, "\n")

	targetStrategy := "ipv4"
	inInterfaceScan := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inInterfaceScan = strings.EqualFold(trimmed, "[Interface]")
			continue
		}
		if inInterfaceScan && strings.HasPrefix(trimmed, "Address") && !strings.HasPrefix(trimmed, "#") {
			if k, v, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Address" && strings.Contains(v, ":") {
				targetStrategy = "ipv6"
			}
		}
	}

	changed := false
	inInterface := false
	sawMTU := false
	inPeer := false
	hasResolveSection := false
	out := make([]string, 0, len(lines)+4)

	flushMissingMTU := func() {
		if inInterface && !sawMTU {
			out = append(out, "MTU = 1280")
			changed = true
			sawMTU = true
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if !strings.EqualFold(trimmed, "[Interface]") {
				flushMissingMTU()
			}
			inInterface = strings.EqualFold(trimmed, "[Interface]")
			inPeer = strings.EqualFold(trimmed, "[Peer]")
			if strings.EqualFold(trimmed, "[Resolve]") {
				hasResolveSection = true
			}
		}
		if inInterface && strings.HasPrefix(trimmed, "MTU") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == "MTU" {
				sawMTU = true
				if strings.TrimSpace(parts[1]) != "1280" {
					line = "MTU = 1280"
					changed = true
				}
			}
		}
		if strings.HasPrefix(trimmed, "ResolveStrategy") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[1]) != targetStrategy {
				line = "ResolveStrategy = " + targetStrategy
				changed = true
			}
		}
		if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 && strings.Contains(parts[1], "engage.cloudflareclient.com") {
				line = "Endpoint = " + WarpCandidateEndpoints[0]
				changed = true
			}
		}
		if inPeer && strings.HasPrefix(trimmed, "PersistentKeepalive") {
			changed = true
			continue
		}
		out = append(out, line)
	}
	flushMissingMTU()

	if !hasResolveSection {
		for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			out = out[:len(out)-1]
		}
		out = append(out, "", "[Resolve]", "ResolveStrategy = "+targetStrategy, "")
		changed = true
	}

	return strings.Join(out, "\n"), changed
}

// ExtractWireproxyEndpoint 读取配置文件中的 [Peer] Endpoint 值。
func ExtractWireproxyEndpoint(content string) string {
	inPeer := false
	for line := range strings.SplitSeq(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inPeer = strings.EqualFold(trimmed, "[Peer]")
			continue
		}
		if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			if k, v, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Endpoint" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

// ReplaceWireproxyEndpoint 替换配置文件中 [Peer] 段内的 Endpoint。
func ReplaceWireproxyEndpoint(content, newEndpoint string) string {
	lines := strings.Split(content, "\n")
	inPeer := false
	replaced := false
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			inPeer = strings.EqualFold(trimmed, "[Peer]")
		} else if inPeer && strings.HasPrefix(trimmed, "Endpoint") && !strings.HasPrefix(trimmed, "#") {
			if k, _, ok := strings.Cut(trimmed, "="); ok && strings.TrimSpace(k) == "Endpoint" {
				line = "Endpoint = " + strings.TrimSpace(newEndpoint)
				replaced = true
			}
		}
		out = append(out, line)
	}
	if !replaced {
		return content
	}
	return strings.Join(out, "\n")
}
