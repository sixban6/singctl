// 文件职责：负责服务端公网 IP 的一次性外网回显探测与单测测试桩注入/重置。
//
// 架构设计原则：
//   - 网络 I/O 隔离 + 测试可控性：将 HTTP 探测状态封装于独立文件，并通过 SetDiscoveredPublicIPForTest /
//     ResetDiscoveredPublicIPForTest 允许单测零网络请求确定性验证。
package config

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	discoveredPublicIP string
	discoverIPOnce     sync.Once
)

// DiscoverPublicIP probes multiple fast IP echo services to determine the public IP.
func DiscoverPublicIP() string {
	discoverIPOnce.Do(func() {
		endpoints := []string{
			"https://api.ipify.org",
			"https://ip.sb",
			"https://icanhazip.com",
			"https://ifconfig.me/ip",
		}
		client := &http.Client{
			Timeout: 2 * time.Second,
		}
		for _, endpoint := range endpoints {
			resp, err := client.Get(endpoint)
			if err != nil {
				continue
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				continue
			}
			ip := strings.TrimSpace(string(body))
			if parsed := net.ParseIP(ip); parsed != nil {
				discoveredPublicIP = ip
				return
			}
		}
	})
	return discoveredPublicIP
}

// SetDiscoveredPublicIPForTest allows mocking the discovered IP during tests.
func SetDiscoveredPublicIPForTest(ip string) {
	discoveredPublicIP = ip
	discoverIPOnce.Do(func() {})
}

// ResetDiscoveredPublicIPForTest resets the cached IP for tests.
func ResetDiscoveredPublicIPForTest() {
	discoveredPublicIP = ""
	discoverIPOnce = sync.Once{}
}
