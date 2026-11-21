// 文件职责：负责已知全网扫描器/恶意扫段指纹库初始化与标签匹配（Censys / Shodan / Shadowserver 等）、子网 CIDR 归并、内网地址过滤与 IP 字符串归一化。
//
// 架构设计原则：
//   - 纯函数与只读查询表：扫描器网段库在 sync.Once 内预解析为 net.IPNet 切片，后续并发匹配完全无锁，零竞态风险。
package serverweb

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

type knownScannerCIDR struct {
	net *net.IPNet
	tag string
}

var (
	knownScannerCIDRsOnce sync.Once
	parsedScannerCIDRs    []knownScannerCIDR

	reNFTLogLine      = regexp.MustCompile(`SRC=([0-9a-fA-F:\.]+).*?DPT=([0-9]+)`)
	reIPv4Token       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reNFTTimeout      = regexp.MustCompile(`timeout\s+([0-9a-zA-Z]+)`)
	reNFTExpires      = regexp.MustCompile(`expires\s+([0-9a-zA-Z]+)`)
	reFail2banLogIP   = regexp.MustCompile(`\b(?:Found|Ban)\s+([0-9a-fA-F:\.]+)`)
	reSingBoxSourceIP = regexp.MustCompile(`"sourceIP"\s*:\s*"([^"]+)"`)
)

func initScannerFingerprints() {
	knownScannerCIDRsOnce.Do(func() {
		raw := []struct {
			cidr string
			tag  string
		}{
			// Censys 测绘引擎
			{"162.142.125.0/24", "Censys 测绘"},
			{"167.94.138.0/24", "Censys 测绘"},
			{"167.94.145.0/24", "Censys 测绘"},
			{"167.94.146.0/24", "Censys 测绘"},
			{"199.45.154.0/24", "Censys 测绘"},
			{"199.45.155.0/24", "Censys 测绘"},
			{"206.168.34.0/24", "Censys 测绘"},
			// Shodan 扫描器
			{"66.240.192.0/24", "Shodan 扫描"},
			{"66.240.205.0/24", "Shodan 扫描"},
			{"66.240.236.0/24", "Shodan 扫描"},
			{"71.6.135.0/24", "Shodan 扫描"},
			{"71.6.146.0/24", "Shodan 扫描"},
			{"71.6.158.0/24", "Shodan 扫描"},
			{"71.6.165.0/24", "Shodan 扫描"},
			{"71.6.167.0/24", "Shodan 扫描"},
			{"82.221.105.0/24", "Shodan 扫描"},
			{"85.25.43.0/24", "Shodan 扫描"},
			{"85.25.103.0/24", "Shodan 扫描"},
			{"93.120.27.0/24", "Shodan 扫描"},
			{"188.138.9.0/24", "Shodan 扫描"},
			{"198.20.69.0/24", "Shodan 扫描"},
			{"198.20.70.0/24", "Shodan 扫描"},
			{"198.20.87.0/24", "Shodan 扫描"},
			{"198.20.99.0/24", "Shodan 扫描"},
			// Shadowserver 安全测绘
			{"64.62.156.0/24", "Shadowserver"},
			{"64.62.197.0/24", "Shadowserver"},
			{"74.82.47.0/24", "Shadowserver"},
			{"184.105.139.0/24", "Shadowserver"},
			{"184.105.143.0/24", "Shadowserver"},
			{"184.105.247.0/24", "Shadowserver"},
			{"216.218.206.0/24", "Shadowserver"},
			// PaloAlto Expanse / Rapid7 / BinaryEdge
			{"198.235.24.0/24", "PaloAlto Expanse"},
			{"205.210.31.0/24", "PaloAlto Expanse"},
			{"192.241.128.0/17", "Stretchoid 扫描"},
			{"71.6.232.0/24", "Rapid7 Sonar"},
			{"45.143.200.0/24", "BinaryEdge"},
			{"193.163.125.0/24", "BinaryEdge"},
			// SingCtl 内置高频恶意扫描段 (与 firewall.go 对齐)
			{"218.92.0.0/16", "高频 SSH 爆破集群"},
			{"115.236.113.0/24", "高频探测段"},
			{"159.203.0.0/16", "云主机扫描段"},
			{"91.92.240.0/21", "恶意漏洞扫描段"},
			{"193.142.146.0/24", "恶意端口扫描段"},
			{"45.148.10.0/24", "恶意端口扫描段"},
			{"185.220.101.0/24", "Tor/匿名扫描出口"},
			{"194.26.135.0/24", "恶意端口扫描段"},
			{"79.124.58.0/24", "恶意端口扫描段"},
			{"79.124.60.0/24", "恶意端口扫描段"},
		}
		for _, item := range raw {
			if _, ipNet, err := net.ParseCIDR(item.cidr); err == nil && ipNet != nil {
				parsedScannerCIDRs = append(parsedScannerCIDRs, knownScannerCIDR{
					net: ipNet,
					tag: item.tag,
				})
			}
		}
	})
}

// MatchScannerTag 匹配已知扫描器组织或高危网段标签
func MatchScannerTag(ipStr, isp string) string {
	initScannerFingerprints()
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip != nil {
		for _, item := range parsedScannerCIDRs {
			if item.net.Contains(ip) {
				return item.tag
			}
		}
	}
	lowerISP := strings.ToLower(isp)
	switch {
	case strings.Contains(lowerISP, "censys"):
		return "Censys 测绘"
	case strings.Contains(lowerISP, "shodan"):
		return "Shodan 扫描"
	case strings.Contains(lowerISP, "shadowserver"):
		return "Shadowserver"
	case strings.Contains(lowerISP, "expanse") || strings.Contains(lowerISP, "palo alto"):
		return "PaloAlto Expanse"
	case strings.Contains(lowerISP, "rapid7"):
		return "Rapid7 Sonar"
	case strings.Contains(lowerISP, "binaryedge"):
		return "BinaryEdge"
	case strings.Contains(lowerISP, "stretchoid"):
		return "Stretchoid 扫描"
	case strings.Contains(lowerISP, "alphastrike"):
		return "AlphaStrike 扫描"
	}
	return ""
}

// ComputeSubnetCIDR 将单个 IP 归并为其所属的 /24 (IPv4) 或 /48 (IPv6) 网段
func ComputeSubnetCIDR(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(24, 32)
		network := v4.Mask(mask)
		return fmt.Sprintf("%s/24", network.String())
	}
	mask := net.CIDRMask(48, 128)
	network := ip.Mask(mask)
	return fmt.Sprintf("%s/48", network.String())
}

// isIgnoredInternalIP 判断是否为回环、私有局域网、链路本地或 Tailscale/CGNAT 内网地址
func isIgnoredInternalIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// 排除 100.64.0.0/10 (Tailscale / CGNAT) 与受限广播地址 255.x
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		if v4[0] == 255 {
			return true
		}
	}
	return false
}

func normalizeIPString(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	} else if len(s) > 7 && strings.EqualFold(s[:7], "::ffff:") {
		rest := s[7:]
		if host, _, err := net.SplitHostPort(rest); err == nil && host != "" {
			s = host
		} else {
			s = rest
		}
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if len(s) > 7 && strings.EqualFold(s[:7], "::ffff:") {
		s = s[7:]
	}
	if pct := strings.IndexByte(s, '%'); pct > 0 {
		s = s[:pct]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func formatSniffTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format(SniffTimeLayout)
}

func statusPriority(status string) int {
	switch status {
	case "banned":
		return 3
	case "masqueraded":
		return 2
	default:
		return 1
	}
}
