package netinfo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result 统一结果
type NetInfoResult struct {
	LANIPv4    string   // 局域网 IPv4
	LANIPv6    string   // 局域网 IPv6（如有）
	PublicIP   string   // 公网 IPv4/IPv6
	DNSServers []string // DHCP/RA 下发的 DNS
}

func (r NetInfoResult) String() string {
	return fmt.Sprintf("LAN IPv4: %s\nLAN IPv6: %s\nPublic IP: %s, DNS Server: %s", r.LANIPv4, r.LANIPv6, r.PublicIP, r.DNSServers[0])
}

// Get 默认 3 秒超时
func Get() (*NetInfoResult, error) { return GetWithTimeout(3 * time.Second) }

// GetWithTimeout 可自定义
func GetWithTimeout(d time.Duration) (*NetInfoResult, error) {
	_, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()

	r := &NetInfoResult{}
	var err error

	// 1. 局域网地址
	if r.LANIPv4, r.LANIPv6, err = localIPs(); err != nil {
		return nil, fmt.Errorf("lan ip: %w", err)
	}

	// 2. 公网地址
	//if r.PublicIP, err = publicIP(ctx); err != nil {
	//	return nil, fmt.Errorf("public ip: %w", err)
	//}
	r.PublicIP = ""

	// 3. DNS 服务器（平台实现见 *_unix.go / *_windows.go）
	if r.DNSServers, err = systemDNS(); err != nil {
		return nil, fmt.Errorf("dns: %w", err)
	}
	return r, nil
}

// ------------------------------------------------------------
// 局域网地址：跨平台通用
// ------------------------------------------------------------
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
	return
}

// ------------------------------------------------------------
// 公网地址：通过多个 HTTP 探针并发
// ------------------------------------------------------------
var endpoints = []string{
	"https://api.ipify.org?format=text",
	"https://checkip.amazonaws.com",
	"https://ifconfig.me/ip",
	"https://ipv6.icanhazip.com", // 支持 IPv6
}

func publicIP(ctx context.Context) (string, error) {
	type out struct {
		ip  string
		err error
	}
	ch := make(chan out, len(endpoints))
	for _, url := range endpoints {
		go func(u string) {
			ip, err := simpleGet(ctx, u)
			ch <- out{ip, err}
		}(url)
	}
	for i := 0; i < len(endpoints); i++ {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case o := <-ch:
			if o.err == nil && net.ParseIP(o.ip) != nil {
				return o.ip, nil
			}
		}
	}
	return "", errors.New("all probes failed")
}

func simpleGet(ctx context.Context, url string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	return strings.TrimSpace(string(b)), err
}

func IsPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false // 不是合法 IP
	}

	// IPv4 私有段
	// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1]&0xF0 == 16) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}

	// IPv6 私有段
	// fc00::/7（RFC 4193 唯一本地地址 ULA）
	if len(ip) == net.IPv6len {
		return ip[0]&0xFE == 0xFC
	}

	return false
}
