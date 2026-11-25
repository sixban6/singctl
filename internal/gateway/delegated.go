// 文件职责：提供主路由旁路由托管协同能力（旁路由 IP 安全校验、在线与端口探活、主网 DHCP 接管状态识别及本机 TProxy 残留清理）。
package gateway

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	// SideRouterWebUIPort 为旁路由 SingCtl WebUI 默认监听端口。
	SideRouterWebUIPort = 8090
	// SideRouterDNSPort 为旁路由 DNS 服务监听端口。
	SideRouterDNSPort = 53

	LANDHCPModeSideDHCP       = "side_dhcp"
	LANDHCPModeMainDHCPOption = "main_dhcp_option"
	LANDHCPModeMainLocal      = "main_local"
	LANDHCPModeUnknown        = "unknown"
)

// SideRouterStatus 描述主路由探测到的旁路由协同与在线状态摘要。
type SideRouterStatus struct {
	Configured  bool   `json:"configured"`
	IP          string `json:"ip,omitempty"`
	Online      bool   `json:"online"`
	WebUIReady  bool   `json:"webuiReady"`
	DNSReady    bool   `json:"dnsReady"`
	LatencyMs   int    `json:"latencyMs,omitempty"`
	LANDHCPMode string `json:"lanDhcpMode,omitempty"`
	LANDHCPHint string `json:"lanDhcpHint,omitempty"`
}

// SideRouterProbeDeps 显式注入旁路由探活与 OpenWrt UCI 查询依赖（nil 自动回退生产实现）。
type SideRouterProbeDeps struct {
	DialTCP func(ctx context.Context, addr string) (time.Duration, error)
	RunUCI  func(ctx context.Context, args ...string) (string, error)
}

// ValidateSideRouterIP 校验并规范化旁路由 IPv4 地址（空字符串表示清空托管配置）。
func ValidateSideRouterIP(rawIP, selfLANIP string) (string, error) {
	trimmed := strings.TrimSpace(rawIP)
	if trimmed == "" {
		return "", nil
	}
	for i := range len(trimmed) {
		c := trimmed[i]
		if c < 0x20 || c == 0x7f {
			return "", fmt.Errorf("旁路由 IP 包含非法控制字符")
		}
	}
	if strings.ContainsAny(trimmed, ";`$|&<> \t") {
		return "", fmt.Errorf("旁路由 IP %q 包含非法字符", trimmed)
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("旁路由 IP %q 必须为合法的 IPv4 地址", trimmed)
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.String() == "255.255.255.255" {
		return "", fmt.Errorf("旁路由 IP %q 不能为回环、组播或广播地址", trimmed)
	}
	if !isRFC1918Private(addr) {
		return "", fmt.Errorf("旁路由 IP %q 必须为局域网私网 IPv4 地址（192.168.x.x / 10.x.x.x / 172.16-31.x.x）", trimmed)
	}
	if self := strings.TrimSpace(selfLANIP); self != "" && addr.String() == self {
		return "", fmt.Errorf("旁路由 IP 不能等于本机局域网 IP (%s)", self)
	}
	return addr.String(), nil
}

func defaultDialTCPProbe(ctx context.Context, addr string) (time.Duration, error) {
	d := net.Dialer{Timeout: 900 * time.Millisecond}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

func probeTCPPortLatency(ctx context.Context, dial func(context.Context, string) (time.Duration, error), ip string, port int) (bool, int) {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	dur, err := dial(ctx, addr)
	if err != nil {
		return false, 0
	}
	ms := int(dur.Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return true, ms
}

// ProbeSideRouterStatus 并发探测旁路由 WebUI (:8090) 与 DNS (:53) 可达性，并识别本机 lan 口 DHCP 协同状态。
func ProbeSideRouterStatus(ctx context.Context, sideIP string, deps SideRouterProbeDeps) SideRouterStatus {
	ip := strings.TrimSpace(sideIP)
	if ip == "" {
		return SideRouterStatus{Configured: false}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()

	dial := deps.DialTCP
	if dial == nil {
		dial = defaultDialTCPProbe
	}

	var (
		webOK, dnsOK bool
		webMs, dnsMs int
		wg           sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		webOK, webMs = probeTCPPortLatency(probeCtx, dial, ip, SideRouterWebUIPort)
	}()
	go func() {
		defer wg.Done()
		dnsOK, dnsMs = probeTCPPortLatency(probeCtx, dial, ip, SideRouterDNSPort)
	}()
	wg.Wait()

	online := webOK || dnsOK
	bestMs := 0
	switch {
	case webOK && dnsOK:
		bestMs = min(webMs, dnsMs)
	case webOK:
		bestMs = webMs
	case dnsOK:
		bestMs = dnsMs
	}

	dhcpMode, dhcpHint := inspectLANDHCPDelegation(probeCtx, ip, deps.RunUCI)
	return SideRouterStatus{
		Configured:  true,
		IP:          ip,
		Online:      online,
		WebUIReady:  webOK,
		DNSReady:    dnsOK,
		LatencyMs:   bestMs,
		LANDHCPMode: dhcpMode,
		LANDHCPHint: dhcpHint,
	}
}

func inspectLANDHCPDelegation(ctx context.Context, sideIP string, runUCI func(context.Context, ...string) (string, error)) (mode, hint string) {
	if runUCI == nil {
		if runtime.GOOS != "linux" || !isOpenWrtSystem() {
			return LANDHCPModeUnknown, ""
		}
		runUCI = func(c context.Context, args ...string) (string, error) {
			out, err := exec.CommandContext(c, "uci", args...).CombinedOutput()
			return string(out), err
		}
	}

	if ignoreOut, err := runUCI(ctx, "get", "dhcp.lan.ignore"); err == nil && strings.TrimSpace(ignoreOut) == "1" {
		return LANDHCPModeSideDHCP, "主网 DHCP 已交由旁路由接管（主路由 lan DHCP 已禁用）"
	}

	if optOut, err := runUCI(ctx, "get", "dhcp.lan.dhcp_option"); err == nil {
		for tok := range strings.FieldsSeq(optOut) {
			if dhcpOptionTargetsIP(tok, sideIP) {
				return LANDHCPModeMainDHCPOption, "主路由 DHCP Option 3/6 已将主网设备网关与 DNS 指向旁路由"
			}
		}
	}
	return LANDHCPModeMainLocal, "当前由主路由负责主网 DHCP（默认网关为主路由）"
}

func dhcpOptionTargetsIP(rawOpt, targetIP string) bool {
	s := strings.TrimSpace(rawOpt)
	var rest string
	switch {
	case strings.HasPrefix(s, "3,"):
		rest = strings.TrimPrefix(s, "3,")
	case strings.HasPrefix(s, "6,"):
		rest = strings.TrimPrefix(s, "6,")
	case strings.HasPrefix(s, "option:router,"):
		rest = strings.TrimPrefix(s, "option:router,")
	case strings.HasPrefix(s, "option:dns-server,"):
		rest = strings.TrimPrefix(s, "option:dns-server,")
	default:
		return false
	}
	return slices.ContainsFunc(strings.Split(rest, ","), func(item string) bool {
		return strings.TrimSpace(item) == targetIP
	})
}

// CleanupLocalTProxyTables 幂等清理本机残留的 sing-box 透明代理 nftables/iptables 规则（供旁路由托管纯直通模式切换调用）。
func CleanupLocalTProxyTables(ctx context.Context, run func(ctx context.Context, name string, args ...string) ([]byte, error)) {
	if ctx == nil {
		ctx = context.Background()
	}
	if run == nil {
		if runtime.GOOS != "linux" {
			return
		}
		run = func(c context.Context, name string, args ...string) ([]byte, error) {
			if _, err := exec.LookPath(name); err != nil {
				return nil, err
			}
			return exec.CommandContext(c, name, args...).CombinedOutput()
		}
	}

	_, _ = run(ctx, "nft", "delete", "table", "inet", "sing-box")
	for _, ipt := range []string{"iptables", "ip6tables"} {
		_, _ = run(ctx, ipt, "-t", "mangle", "-D", "PREROUTING", "-j", "SING_BOX")
		_, _ = run(ctx, ipt, "-t", "mangle", "-D", "OUTPUT", "-j", "SING_BOX_OUTPUT")
		_, _ = run(ctx, ipt, "-t", "mangle", "-F", "SING_BOX")
		_, _ = run(ctx, ipt, "-t", "mangle", "-X", "SING_BOX")
		_, _ = run(ctx, ipt, "-t", "mangle", "-F", "SING_BOX_OUTPUT")
		_, _ = run(ctx, ipt, "-t", "mangle", "-X", "SING_BOX_OUTPUT")
	}
}
