// 文件职责：提供跨平台本机局域网 IP、RFC1918 私网判定、OpenWrt/Linux 子网发现与连通性缓存辅助。
package netx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/common/sysinfo"
)

const googleCacheTTL = 5 * time.Minute

var (
	googleProbeMu   sync.Mutex
	googleCachedVal bool
	googleCachedAt  time.Time
)

// NetInfoResult 汇总本机局域网地址与系统上游 DNS 列表。
type NetInfoResult struct {
	LANIPv4    string
	LANIPv6    string
	PublicIP   string
	DNSServers []string
}

func (r NetInfoResult) String() string {
	dns0 := ""
	if len(r.DNSServers) > 0 {
		dns0 = r.DNSServers[0]
	}
	return fmt.Sprintf("LAN IPv4: %s\nLAN IPv6: %s\nPublic IP: %s, DNS Server: %s", r.LANIPv4, r.LANIPv6, r.PublicIP, dns0)
}

// Get 默认以 3 秒超时采集本机网卡与系统 DNS 信息。
func Get() (*NetInfoResult, error) { return GetWithTimeout(3 * time.Second) }

// GetWithTimeout 按指定超时采集本机网卡与系统 DNS 信息。
func GetWithTimeout(d time.Duration) (*NetInfoResult, error) {
	_, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	r := &NetInfoResult{}
	var err error
	if r.LANIPv4, r.LANIPv6, err = localIPs(); err != nil {
		return nil, fmt.Errorf("lan ip: %w", err)
	}
	if r.DNSServers, err = systemDNS(); err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	return r, nil
}

func localIPs() (v4, v6 string, _ error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, addr := range addrs {
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				if v4 == "" {
					v4 = ip4.String()
				}
			} else if ip.To16() != nil && !ip.IsLinkLocalUnicast() {
				if v6 == "" {
					v6 = ip.String()
				}
			}
		}
	}
	if v4 == "" && v6 == "" {
		return "", "", errors.New("no usable LAN address")
	}
	return v4, v6, nil
}

// IsPrivateIP 判断输入字符串是否为 RFC1918 私网 IPv4 或 RFC4193 唯一本地 IPv6（ULA）。
func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xF0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	if len(ip) == net.IPv6len {
		return ip[0]&0xFE == 0xFC
	}
	return false
}

// GetLANSubnet 获取用于路由通告的本地局域网 CIDR（OpenWrt 优先走 uci，其余走默认路由网卡）。
func GetLANSubnet() (string, error) {
	if sysinfo.IsOpenWrt() {
		if sub, err := getOpenWrtLANSubnet(); err == nil {
			return sub, nil
		}
	}
	return getDefaultInterfaceSubnet()
}

func getOpenWrtLANSubnet() (string, error) {
	out, err := execx.Output(context.Background(), 2*time.Second, "uci", "get", "network.lan.ipaddr")
	if err != nil {
		return "", fmt.Errorf("failed to get LAN IP: %w", err)
	}
	ipAddr := strings.TrimSpace(string(out))

	out, err = execx.Output(context.Background(), 2*time.Second, "uci", "get", "network.lan.netmask")
	if err != nil {
		return "", fmt.Errorf("failed to get LAN netmask: %w", err)
	}
	netmask := strings.TrimSpace(string(out))

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP address: %s", ipAddr)
	}
	mask := net.ParseIP(netmask)
	if mask == nil || mask.To4() == nil {
		return "", fmt.Errorf("invalid netmask: %s", netmask)
	}
	ipMask := net.IPMask(mask.To4())
	ones, _ := ipMask.Size()
	return fmt.Sprintf("%s/%d", ip.Mask(ipMask).String(), ones), nil
}

func getDefaultInterfaceSubnet() (string, error) {
	out, err := execx.Output(context.Background(), 2*time.Second, "ip", "-o", "route", "get", "8.8.8.8")
	if err != nil {
		return "", fmt.Errorf("failed to get default route: %w", err)
	}
	fields := strings.Fields(string(out))
	var netdev string
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			netdev = fields[i+1]
			break
		}
	}
	if netdev == "" {
		return "", fmt.Errorf("could not determine default network interface")
	}

	out, err = execx.Output(context.Background(), 2*time.Second, "ip", "-o", "-f", "inet", "route", "show", "dev", netdev, "scope", "link")
	if err != nil {
		return "", fmt.Errorf("failed to get route for interface %s: %w", netdev, err)
	}
	for line := range strings.SplitSeq(string(out), "\n") {
		if parts := strings.Fields(line); len(parts) > 0 {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("no subnet found for interface %s", netdev)
}

// BuildGitHubDownloadCandidates 为规则集或远程资源构造按优先级排列的下载候选列表：
// 若目标位于 GitHub 域名且配置了有效的加速镜像前缀（如 https://gh-proxy.com），优先尝试镜像地址并保留直连回退；
// 若已带镜像前缀或非 GitHub 域名，则原样返回单一候选。
func BuildGitHubDownloadCandidates(rawURL, mirrorURL string) []string {
	target := strings.TrimSpace(rawURL)
	if target == "" {
		return nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return []string{target}
	}
	host := strings.ToLower(u.Hostname())
	isGitHub := host == "github.com" ||
		host == "raw.githubusercontent.com" ||
		host == "gist.githubusercontent.com" ||
		host == "objects.githubusercontent.com"
	if !isGitHub {
		return []string{target}
	}

	mirror := strings.TrimRight(strings.TrimSpace(mirrorURL), "/")
	if mirror == "" || strings.EqualFold(mirror, "https://github.com") {
		return []string{target}
	}
	prefix := mirror + "/"
	if strings.HasPrefix(strings.ToLower(target), strings.ToLower(prefix)) {
		return []string{target}
	}
	return []string{prefix + target, target}
}

// GetReachableURL 当 Google 直连不可达且配置了镜像前缀时拼接加速 URL。
func GetReachableURL(downloadURL, mirrorURL string) string {
	mirrorURL = strings.TrimSpace(mirrorURL)
	if mirrorURL == "" || mirrorURL == "https://github.com" || mirrorURL == "https://github.com/" {
		return downloadURL
	}
	if !CheckGoogleConnectivity() {
		return strings.TrimSuffix(mirrorURL, "/") + "/" + downloadURL
	}
	return downloadURL
}

// CheckGoogleConnectivity 检测外网直连可达性（内置 5 分钟内存缓存避免重复阻塞探测）。
func CheckGoogleConnectivity() bool {
	googleProbeMu.Lock()
	defer googleProbeMu.Unlock()

	if !googleCachedAt.IsZero() && time.Since(googleCachedAt) < googleCacheTTL {
		return googleCachedVal
	}
	client := http.Client{Timeout: 2500 * time.Millisecond}
	resp, err := client.Head("https://www.google.com")
	ok := false
	if err == nil {
		_ = resp.Body.Close()
		ok = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	googleCachedVal = ok
	googleCachedAt = time.Now()
	return ok
}
