// 文件职责：提供可注入 HTTP 客户端与端点的公网 IP 回显探测、GeoIP 地区简写映射及测试桩辅助。
package netx

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var defaultPublicIPEndpoints = []string{
	"https://api.ipify.org",
	"https://ip.sb",
	"https://icanhazip.com",
	"https://ifconfig.me/ip",
}

// Prober 支持显式注入 HTTPClient 与探测端点，便于离线单测零外网确定性验证。
type Prober struct {
	HTTPClient        *http.Client
	PublicIPEndpoints []string
	IPAPIBaseURL      string
	IPWhoisBaseURL    string
}

func (p *Prober) client() *http.Client {
	if p != nil && p.HTTPClient != nil {
		return p.HTTPClient
	}
	return &http.Client{Timeout: 2 * time.Second}
}

// DiscoverPublicIP 依次请求 IP 回显端点获取本机公网 IP。
func (p *Prober) DiscoverPublicIP(ctx context.Context) string {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoints := defaultPublicIPEndpoints
	if p != nil && len(p.PublicIPEndpoints) > 0 {
		endpoints = p.PublicIPEndpoints
	}
	hc := p.client()
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		body, rErr := io.ReadAll(io.LimitReader(resp.Body, 256))
		_ = resp.Body.Close()
		if rErr != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	return ""
}

// DiscoverLocationTag 查询公网 IP 对应的标准节点地域简写（私网/回环 IP 直接返回空串）。
func (p *Prober) DiscoverLocationTag(ctx context.Context, ip string) string {
	if ctx == nil {
		ctx = context.Background()
	}
	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = p.DiscoverPublicIP(ctx)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() {
		return ""
	}

	hc := p.client()
	apiBase := "http://ip-api.com/json/"
	whoisBase := "https://ipwho.is/"
	if p != nil {
		apiBase = cmp.Or(p.IPAPIBaseURL, apiBase)
		whoisBase = cmp.Or(p.IPWhoisBaseURL, whoisBase)
	}

	if req1, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+ip+"?fields=status,country,countryCode,city", nil); err == nil {
		req1.Header.Set("User-Agent", "curl/7.88.1")
		if resp, err := hc.Do(req1); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			var r struct {
				Status      string `json:"status"`
				CountryCode string `json:"countryCode"`
				City        string `json:"city"`
			}
			if json.Unmarshal(body, &r) == nil && strings.EqualFold(r.Status, "success") {
				if tag := CityCountryToTag(r.City, r.CountryCode); tag != "" {
					return tag
				}
			}
		}
	}

	if req2, err := http.NewRequestWithContext(ctx, http.MethodGet, whoisBase+ip, nil); err == nil {
		req2.Header.Set("User-Agent", "curl/7.88.1")
		if resp, err := hc.Do(req2); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			var r struct {
				Success     bool   `json:"success"`
				CountryCode string `json:"country_code"`
				City        string `json:"city"`
			}
			if json.Unmarshal(body, &r) == nil && r.Success {
				if tag := CityCountryToTag(r.City, r.CountryCode); tag != "" {
					return tag
				}
			}
		}
	}
	return ""
}

var (
	probeCacheMu          sync.Mutex
	discoveredPublicIP    string
	publicIPProbed        bool
	discoveredLocationTag string
	locationProbed        bool
)

// DiscoverPublicIP 带进程级一次性缓存探测当前服务器公网 IP。
func DiscoverPublicIP() string {
	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()
	if !publicIPProbed {
		discoveredPublicIP = (&Prober{}).DiscoverPublicIP(context.Background())
		publicIPProbed = true
	}
	return discoveredPublicIP
}

// SetDiscoveredPublicIPForTest 供单元测试显式注入公网 IP。
func SetDiscoveredPublicIPForTest(ip string) {
	probeCacheMu.Lock()
	discoveredPublicIP = ip
	publicIPProbed = true
	probeCacheMu.Unlock()
}

// ResetDiscoveredPublicIPForTest 重置公网 IP 测试桩状态。
func ResetDiscoveredPublicIPForTest() {
	probeCacheMu.Lock()
	discoveredPublicIP = ""
	publicIPProbed = false
	probeCacheMu.Unlock()
}

// DiscoverLocationTag 带进程级一次性缓存探测节点地域标签。
func DiscoverLocationTag(ip string) string {
	probeCacheMu.Lock()
	if discoveredLocationTag != "" {
		tag := discoveredLocationTag
		probeCacheMu.Unlock()
		return tag
	}
	probeCacheMu.Unlock()

	ip = strings.TrimSpace(ip)
	if ip == "" {
		ip = DiscoverPublicIP()
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.IsPrivate() || parsed.IsLoopback() {
		return ""
	}

	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()
	if !locationProbed {
		discoveredLocationTag = (&Prober{}).DiscoverLocationTag(context.Background(), ip)
		locationProbed = true
	}
	return discoveredLocationTag
}

// CachedLocationTag 零网络阻塞返回已缓存的地域标签（未探测或未命中时返回空串）。
func CachedLocationTag() string {
	probeCacheMu.Lock()
	defer probeCacheMu.Unlock()
	return discoveredLocationTag
}

// SetDiscoveredLocationTagForTest 供单元测试显式注入地域标签。
func SetDiscoveredLocationTagForTest(tag string) {
	probeCacheMu.Lock()
	discoveredLocationTag = tag
	locationProbed = true
	probeCacheMu.Unlock()
}

// ResetDiscoveredLocationTagForTest 重置地域标签测试桩状态。
func ResetDiscoveredLocationTagForTest() {
	probeCacheMu.Lock()
	discoveredLocationTag = ""
	locationProbed = false
	probeCacheMu.Unlock()
}

// CityCountryToTag 将城市与 ISO 国家代码映射为标准简洁节点前缀（如 los / sj / sg / jp / hk）。
func CityCountryToTag(city, countryCode string) string {
	c := strings.ToLower(strings.TrimSpace(city))
	cc := strings.ToLower(strings.TrimSpace(countryCode))

	switch {
	case strings.Contains(c, "los angeles"):
		return "los"
	case strings.Contains(c, "san jose") || strings.Contains(c, "santa clara") || strings.Contains(c, "fremont") || strings.Contains(c, "sunnyvale") || strings.Contains(c, "san francisco"):
		return "sj"
	case strings.Contains(c, "seattle"):
		return "sea"
	case strings.Contains(c, "new york") || strings.Contains(c, "brooklyn") || strings.Contains(c, "manhattan") || strings.Contains(c, "queens") || strings.Contains(c, "newark"):
		return "ny"
	case strings.Contains(c, "chicago"):
		return "chi"
	case strings.Contains(c, "dallas") || strings.Contains(c, "fort worth"):
		return "dal"
	case strings.Contains(c, "atlanta"):
		return "atl"
	case strings.Contains(c, "miami"):
		return "mia"
	case strings.Contains(c, "phoenix"):
		return "phx"
	case strings.Contains(c, "ashburn") || strings.Contains(c, "reston") || strings.Contains(c, "herndon"):
		return "ash"
	case strings.Contains(c, "tokyo"):
		return "jp"
	case strings.Contains(c, "osaka"):
		return "osaka"
	case strings.Contains(c, "singapore"):
		return "sg"
	case strings.Contains(c, "hong kong"):
		return "hk"
	case strings.Contains(c, "taipei"):
		return "tw"
	case strings.Contains(c, "seoul"):
		return "kr"
	case strings.Contains(c, "london"):
		return "lon"
	case strings.Contains(c, "frankfurt"):
		return "fra"
	case strings.Contains(c, "paris"):
		return "par"
	case strings.Contains(c, "amsterdam"):
		return "ams"
	case strings.Contains(c, "sydney"):
		return "syd"
	}

	if cc != "" && cc != "us" {
		return cc
	}

	cleanCity := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, c)
	if len(cleanCity) >= 3 {
		return cleanCity[:3]
	}
	return cc
}

// SanitizeTag 清洗节点标签字符串，仅保留小写字母、数字、下划线与连字符。
func SanitizeTag(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	var sb strings.Builder
	for _, r := range tag {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		}
	}
	return strings.Trim(sb.String(), "_-")
}
