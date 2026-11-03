package serverweb

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// IPGeoInfo IP 的地理位置与网络元数据
type IPGeoInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	Flag        string `json:"flag,omitempty"`
	Geo         string `json:"geo,omitempty"` // 格式化展示，例如 "美国 · 洛杉矶" 或 "中国 · 深圳"
}

type geoCacheEntry struct {
	info      IPGeoInfo
	expiresAt time.Time
}

// IPGeoResolver 内存级异步 IP 地理信息解析器 (带 LRU 与 TTL 机制)
type IPGeoResolver struct {
	mu         sync.RWMutex
	cache      map[string]geoCacheEntry
	inFlight   map[string]bool
	httpClient *http.Client
}

var commonCountryNames = map[string]string{
	"CN": "中国",
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",
	"US": "美国",
	"JP": "日本",
	"SG": "新加坡",
	"KR": "韩国",
	"GB": "英国",
	"DE": "德国",
	"FR": "法国",
	"NL": "荷兰",
	"RU": "俄罗斯",
	"CA": "加拿大",
	"AU": "澳大利亚",
}

// CountryCodeToFlag 将 2 位 ISO 国家代码转换为对应的国旗 Emoji
func CountryCodeToFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	r1 := rune(code[0]) - 'A' + 0x1F1E6
	r2 := rune(code[1]) - 'A' + 0x1F1E6
	return string([]rune{r1, r2})
}

func formatGeoLabel(countryCode, country, city string) string {
	countryDisplay := country
	if cn, ok := commonCountryNames[countryCode]; ok {
		countryDisplay = cn
	}
	city = strings.TrimSpace(city)
	if city != "" && countryDisplay != "" {
		return fmt.Sprintf("%s · %s", countryDisplay, city)
	}
	if countryDisplay != "" {
		return countryDisplay
	}
	return city
}

func isPrivateOrLoopbackIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()
}

// NewIPGeoResolver 创建解析器实例
func NewIPGeoResolver() *IPGeoResolver {
	return &IPGeoResolver{
		cache:    make(map[string]geoCacheEntry),
		inFlight: make(map[string]bool),
		httpClient: &http.Client{
			Timeout: 1500 * time.Millisecond,
		},
	}
}

// SeedCountry 根据请求头 (如 Cloudflare CF-IPCountry) 预置国家信息 (0 延迟)
func (r *IPGeoResolver) SeedCountry(ipStr, countryCode string) {
	if isPrivateOrLoopbackIP(ipStr) || countryCode == "" {
		return
	}
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, exists := r.cache[ipStr]
	if !exists || entry.info.CountryCode == "" {
		flag := CountryCodeToFlag(countryCode)
		countryName := countryCode
		if cn, ok := commonCountryNames[countryCode]; ok {
			countryName = cn
		}
		r.cache[ipStr] = geoCacheEntry{
			info: IPGeoInfo{
				IP:          ipStr,
				Country:     countryName,
				CountryCode: countryCode,
				Flag:        flag,
				Geo:         countryName,
			},
			expiresAt: time.Now().Add(1 * time.Hour),
		}
	}
}

// Resolve 解析指定 IP，优先命中缓存，未命中时触发后台异步查询，绝不阻塞当前请求
func (r *IPGeoResolver) Resolve(ipStr string) IPGeoInfo {
	if isPrivateOrLoopbackIP(ipStr) {
		return IPGeoInfo{
			IP:      ipStr,
			Country: "本地",
			City:    "内网/回环",
			ISP:     "本机直连",
			Geo:     "本地网络",
		}
	}

	r.mu.RLock()
	entry, found := r.cache[ipStr]
	inFlight := r.inFlight[ipStr]
	r.mu.RUnlock()

	now := time.Now()
	if found && now.Before(entry.expiresAt) && (entry.info.City != "" || entry.info.ISP != "") {
		return entry.info
	}

	if !inFlight {
		r.mu.Lock()
		if !r.inFlight[ipStr] {
			r.inFlight[ipStr] = true
			go r.fetchAsync(ipStr)
		}
		r.mu.Unlock()
	}

	if found {
		return entry.info
	}
	return IPGeoInfo{IP: ipStr}
}

func (r *IPGeoResolver) fetchAsync(ipStr string) {
	defer func() {
		r.mu.Lock()
		delete(r.inFlight, ipStr)
		r.mu.Unlock()
	}()

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,isp", ipStr)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "singctl-serverweb/1.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		r.mu.Lock()
		r.cache[ipStr] = geoCacheEntry{
			info:      IPGeoInfo{IP: ipStr},
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		r.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var data struct {
		Status      string `json:"status"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.Status != "success" {
		return
	}

	info := IPGeoInfo{
		IP:          ipStr,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		City:        data.City,
		ISP:         data.ISP,
		Flag:        CountryCodeToFlag(data.CountryCode),
		Geo:         formatGeoLabel(data.CountryCode, data.Country, data.City),
	}

	r.mu.Lock()
	if len(r.cache) > 1000 {
		for k := range r.cache {
			delete(r.cache, k)
			if len(r.cache) <= 800 {
				break
			}
		}
	}
	r.cache[ipStr] = geoCacheEntry{
		info:      info,
		expiresAt: time.Now().Add(24 * time.Hour),
	}
	r.mu.Unlock()
}
