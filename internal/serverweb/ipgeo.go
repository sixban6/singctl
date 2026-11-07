package serverweb

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxGeoCacheEntries = 5000
	geoCacheTTL        = 7 * 24 * time.Hour
	geoSaveMinDT       = 5 * time.Second
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
	Info      IPGeoInfo `json:"info"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// IPGeoResolver 支持批量解析 (Batch API)、/24 网段归属地共享与 0600 磁盘持久化的 IP 地理信息解析器
type IPGeoResolver struct {
	mu           sync.RWMutex
	cache        map[string]geoCacheEntry
	subnetCache  map[string]IPGeoInfo
	inFlight     map[string]bool
	pendingQueue []string
	filePath     string
	dirty        bool
	lastSaveAt   time.Time
	httpClient   *http.Client
	batchRunning atomic.Bool
}

// 全球常见及高频扫描来源国家/地区 ISO-3166-1 二位码中文名称表
var commonCountryNames = map[string]string{
	"CN": "中国",
	"HK": "中国香港",
	"TW": "中国台湾",
	"MO": "中国澳门",
	"US": "美国",
	"JP": "日本",
	"SG": "新加坡",
	"KR": "韩国",
	"KP": "朝鲜",
	"GB": "英国",
	"DE": "德国",
	"FR": "法国",
	"NL": "荷兰",
	"RU": "俄罗斯",
	"CA": "加拿大",
	"AU": "澳大利亚",
	"NZ": "新西兰",
	"IN": "印度",
	"BR": "巴西",
	"VN": "越南",
	"ID": "印度尼西亚",
	"TH": "泰国",
	"MY": "马来西亚",
	"PH": "菲律宾",
	"PK": "巴基斯坦",
	"BD": "孟加拉国",
	"LK": "斯里兰卡",
	"NP": "尼泊尔",
	"MM": "缅甸",
	"KH": "柬埔寨",
	"LA": "老挝",
	"MN": "蒙古",
	"KZ": "哈萨克斯坦",
	"UZ": "乌兹别克斯坦",
	"KG": "吉尔吉斯斯坦",
	"TJ": "塔吉克斯坦",
	"TM": "土库曼斯坦",
	"IT": "意大利",
	"ES": "西班牙",
	"PT": "葡萄牙",
	"SE": "瑞典",
	"NO": "挪威",
	"FI": "芬兰",
	"DK": "丹麦",
	"IS": "冰岛",
	"CH": "瑞士",
	"AT": "奥地利",
	"BE": "比利时",
	"LU": "卢森堡",
	"IE": "爱尔兰",
	"PL": "波兰",
	"CZ": "捷克",
	"SK": "斯洛伐克",
	"HU": "匈牙利",
	"RO": "罗马尼亚",
	"BG": "保加利亚",
	"UA": "乌克兰",
	"BY": "白俄罗斯",
	"MD": "摩尔多瓦",
	"LT": "立陶宛",
	"LV": "拉脱维亚",
	"EE": "爱沙尼亚",
	"GR": "希腊",
	"TR": "土耳其",
	"CY": "塞浦路斯",
	"MT": "马耳他",
	"RS": "塞尔维亚",
	"HR": "克罗地亚",
	"SI": "斯洛文尼亚",
	"BA": "波黑",
	"AL": "阿尔巴尼亚",
	"MK": "北马其顿",
	"ME": "黑山",
	"GE": "格鲁吉亚",
	"AM": "亚美尼亚",
	"AZ": "阿塞拜疆",
	"IL": "以色列",
	"AE": "阿联酋",
	"SA": "沙特阿拉伯",
	"IR": "伊朗",
	"IQ": "伊拉克",
	"QA": "卡塔尔",
	"KW": "科威特",
	"OM": "阿曼",
	"BH": "巴林",
	"JO": "约旦",
	"LB": "黎巴嫩",
	"SY": "叙利亚",
	"YE": "也门",
	"AF": "阿富汗",
	"ZA": "南非",
	"EG": "埃及",
	"NG": "尼日利亚",
	"KE": "肯尼亚",
	"ET": "埃塞俄比亚",
	"MA": "摩洛哥",
	"DZ": "阿尔及利亚",
	"TN": "突尼斯",
	"GH": "加纳",
	"TZ": "坦桑尼亚",
	"UG": "乌干达",
	"MU": "毛里求斯",
	"SC": "塞舌尔",
	"MX": "墨西哥",
	"AR": "阿根廷",
	"CL": "智利",
	"CO": "哥伦比亚",
	"PE": "秘鲁",
	"VE": "委内瑞拉",
	"EC": "厄瓜多尔",
	"UY": "乌拉圭",
	"PY": "巴拉圭",
	"BO": "玻利维亚",
	"PA": "巴拿马",
	"CR": "哥斯达黎加",
	"DO": "多米尼加",
	"GT": "危地马拉",
	"HN": "洪都拉斯",
	"SV": "萨尔瓦多",
	"NI": "尼加拉瓜",
	"CU": "古巴",
	"PR": "波多黎各",
	"JM": "牙买加",
	"TT": "特立尼达和多巴哥",
	"BS": "巴哈马",
	"BZ": "伯利兹",
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

func resolveCountryDisplayName(countryCode, rawCountry string) string {
	code := strings.ToUpper(strings.TrimSpace(countryCode))
	if cn, ok := commonCountryNames[code]; ok {
		return cn
	}
	return cmp.Or(strings.TrimSpace(rawCountry), code)
}

func formatGeoLabel(countryCode, country, city string) string {
	countryDisplay := resolveCountryDisplayName(countryCode, country)
	city = strings.TrimSpace(city)
	if city != "" && countryDisplay != "" && !strings.EqualFold(city, country) && city != countryDisplay {
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

// isRFC5737DocumentationIP 判断是否为测试专用保留网段 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
func isRFC5737DocumentationIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return (v4[0] == 192 && v4[1] == 0 && v4[2] == 2) ||
		(v4[0] == 198 && v4[1] == 51 && v4[2] == 100) ||
		(v4[0] == 203 && v4[1] == 0 && v4[2] == 113)
}

// NewIPGeoResolver 创建解析器实例 (可选传入 0600 磁盘缓存路径)
func NewIPGeoResolver(filePath ...string) *IPGeoResolver {
	fp := ""
	if len(filePath) > 0 {
		fp = strings.TrimSpace(filePath[0])
	}
	r := &IPGeoResolver{
		cache:       make(map[string]geoCacheEntry),
		subnetCache: make(map[string]IPGeoInfo),
		inFlight:    make(map[string]bool),
		filePath:    fp,
		httpClient: &http.Client{
			Timeout: 2500 * time.Millisecond,
		},
	}
	r.loadLocked()
	return r
}

func (r *IPGeoResolver) storeResolvedLocked(ipStr string, info IPGeoInfo, ttl time.Duration) {
	info.IP = ipStr
	info.CountryCode = strings.ToUpper(strings.TrimSpace(info.CountryCode))
	info.Country = resolveCountryDisplayName(info.CountryCode, info.Country)
	if info.Flag == "" && info.CountryCode != "" {
		info.Flag = CountryCodeToFlag(info.CountryCode)
	}
	if info.Geo == "" {
		info.Geo = formatGeoLabel(info.CountryCode, info.Country, info.City)
	}

	if len(r.cache) >= maxGeoCacheEntries {
		now := time.Now()
		for k, v := range r.cache {
			if now.After(v.ExpiresAt) {
				delete(r.cache, k)
			}
			if len(r.cache) <= maxGeoCacheEntries-500 {
				break
			}
		}
		if len(r.cache) >= maxGeoCacheEntries {
			for k := range r.cache {
				delete(r.cache, k)
				if len(r.cache) <= maxGeoCacheEntries-500 {
					break
				}
			}
		}
	}

	r.cache[ipStr] = geoCacheEntry{
		Info:      info,
		ExpiresAt: time.Now().Add(ttl),
	}
	if info.CountryCode != "" {
		if cidr := ComputeSubnetCIDR(ipStr); cidr != "" {
			r.subnetCache[cidr] = IPGeoInfo{
				Country:     info.Country,
				CountryCode: info.CountryCode,
				Flag:        info.Flag,
				ISP:         info.ISP,
				Geo:         info.Country,
			}
		}
	}
	r.dirty = true
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
	if !exists || entry.Info.CountryCode == "" {
		countryName := resolveCountryDisplayName(countryCode, countryCode)
		r.storeResolvedLocked(ipStr, IPGeoInfo{
			IP:          ipStr,
			Country:     countryName,
			CountryCode: countryCode,
			Flag:        CountryCodeToFlag(countryCode),
			Geo:         countryName,
		}, 6*time.Hour)
	}
}

// Resolve 解析指定单个 IP，优先命中缓存或同 /24 网段缓存，未命中时加入异步微批队列
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

	now := time.Now()
	r.mu.RLock()
	entry, found := r.cache[ipStr]
	var subFallback IPGeoInfo
	var hasSubFallback bool
	if !found || entry.Info.CountryCode == "" {
		if cidr := ComputeSubnetCIDR(ipStr); cidr != "" {
			subFallback, hasSubFallback = r.subnetCache[cidr]
		}
	}
	r.mu.RUnlock()

	if found && now.Before(entry.ExpiresAt) && entry.Info.CountryCode != "" {
		return entry.Info
	}

	if !isRFC5737DocumentationIP(ipStr) {
		r.enqueueForBatch(ipStr)
	}

	if found && entry.Info.CountryCode != "" {
		return entry.Info
	}
	if hasSubFallback && subFallback.CountryCode != "" {
		cp := subFallback
		cp.IP = ipStr
		return cp
	}
	return IPGeoInfo{IP: ipStr}
}

// ResolveBatch 批量解析一组 IP：对未缓存 IP 自动通过批量 API (100 IP/批) 快速补齐并共享同 /24 归属地
func (r *IPGeoResolver) ResolveBatch(ctx context.Context, ips []string) map[string]IPGeoInfo {
	out := make(map[string]IPGeoInfo, len(ips))
	if len(ips) == 0 {
		return out
	}

	now := time.Now()
	var missing []string
	seenMissing := make(map[string]struct{})

	r.mu.RLock()
	for _, ip := range ips {
		if isPrivateOrLoopbackIP(ip) {
			out[ip] = IPGeoInfo{
				IP:      ip,
				Country: "本地",
				City:    "内网/回环",
				ISP:     "本机直连",
				Geo:     "本地网络",
			}
			continue
		}
		if entry, ok := r.cache[ip]; ok && now.Before(entry.ExpiresAt) && entry.Info.CountryCode != "" {
			out[ip] = entry.Info
			continue
		}
		if !isRFC5737DocumentationIP(ip) {
			if _, seen := seenMissing[ip]; !seen {
				seenMissing[ip] = struct{}{}
				missing = append(missing, ip)
			}
		}
	}
	r.mu.RUnlock()

	// 若存在未命中缓存的真实公网 IP，立即执行最多 3 批 (300 个 IP) 的同步快速批量查询，剩余交由后台微批队列完成
	if len(missing) > 0 {
		const maxSyncBatches = 3
		const batchSize = 100
		syncLimit := min(len(missing), maxSyncBatches*batchSize)
		syncPart := missing[:syncLimit]
		asyncPart := missing[syncLimit:]

		var wg sync.WaitGroup
		for start := 0; start < len(syncPart); start += batchSize {
			end := min(start+batchSize, len(syncPart))
			chunk := syncPart[start:end]
			wg.Add(1)
			go func(c []string) {
				defer wg.Done()
				bCtx, cancel := context.WithTimeout(ctx, 2200*time.Millisecond)
				defer cancel()
				r.fetchBatchSync(bCtx, c)
			}(chunk)
		}
		wg.Wait()

		for _, ip := range asyncPart {
			r.enqueueForBatch(ip)
		}
	}

	r.mu.Lock()
	for _, ip := range ips {
		if _, done := out[ip]; done {
			continue
		}
		if entry, ok := r.cache[ip]; ok && entry.Info.CountryCode != "" {
			out[ip] = entry.Info
			continue
		}
		if cidr := ComputeSubnetCIDR(ip); cidr != "" {
			if subInfo, ok := r.subnetCache[cidr]; ok && subInfo.CountryCode != "" {
				cp := subInfo
				cp.IP = ip
				out[ip] = cp
				continue
			}
		}
		out[ip] = IPGeoInfo{IP: ip}
	}
	if r.dirty {
		r.saveLocked(false)
	}
	r.mu.Unlock()

	return out
}

func (r *IPGeoResolver) enqueueForBatch(ipStr string) {
	r.mu.Lock()
	if r.inFlight[ipStr] {
		r.mu.Unlock()
		return
	}
	r.inFlight[ipStr] = true
	r.pendingQueue = append(r.pendingQueue, ipStr)
	r.mu.Unlock()

	if r.batchRunning.CompareAndSwap(false, true) {
		go r.drainBatchLoop()
	}
}

func (r *IPGeoResolver) drainBatchLoop() {
	defer r.batchRunning.Store(false)
	time.Sleep(80 * time.Millisecond)

	for {
		r.mu.Lock()
		if len(r.pendingQueue) == 0 {
			if r.dirty {
				r.saveLocked(false)
			}
			r.mu.Unlock()
			return
		}
		take := min(len(r.pendingQueue), 100)
		chunk := make([]string, take)
		copy(chunk, r.pendingQueue[:take])
		r.pendingQueue = r.pendingQueue[take:]
		r.mu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		r.fetchBatchSync(ctx, chunk)
		cancel()

		r.mu.Lock()
		for _, ip := range chunk {
			delete(r.inFlight, ip)
		}
		r.mu.Unlock()
	}
}

func (r *IPGeoResolver) fetchBatchSync(ctx context.Context, chunk []string) {
	if len(chunk) == 0 {
		return
	}
	resolved := r.queryIPAPIBatch(ctx, chunk)
	var unresolved []string
	for _, ip := range chunk {
		if _, ok := resolved[ip]; !ok {
			unresolved = append(unresolved, ip)
		}
	}
	// 若主通道 ip-api.com 批量接口限流或部分未命中，自动使用 HTTPS geojs.io 批量接口兜底
	if len(unresolved) > 0 {
		fallback := r.queryGeoJSBatch(ctx, unresolved)
		for k, v := range fallback {
			resolved[k] = v
		}
	}

	if len(resolved) == 0 {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for ip, info := range resolved {
		r.storeResolvedLocked(ip, info, geoCacheTTL)
	}
}

func (r *IPGeoResolver) queryIPAPIBatch(ctx context.Context, ips []string) map[string]IPGeoInfo {
	out := make(map[string]IPGeoInfo, len(ips))
	bodyBytes, err := json.Marshal(ips)
	if err != nil {
		return out
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp",
		bytes.NewReader(bodyBytes))
	if err != nil {
		return out
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "singctl-serverweb/1.0")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out
	}

	var items []struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		City        string `json:"city"`
		ISP         string `json:"isp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return out
	}
	for _, it := range items {
		if it.Status != "success" || it.Query == "" || it.CountryCode == "" {
			continue
		}
		countryCN := resolveCountryDisplayName(it.CountryCode, it.Country)
		out[it.Query] = IPGeoInfo{
			IP:          it.Query,
			Country:     countryCN,
			CountryCode: strings.ToUpper(it.CountryCode),
			City:        it.City,
			ISP:         it.ISP,
			Flag:        CountryCodeToFlag(it.CountryCode),
			Geo:         formatGeoLabel(it.CountryCode, countryCN, it.City),
		}
	}
	return out
}

func (r *IPGeoResolver) queryGeoJSBatch(ctx context.Context, ips []string) map[string]IPGeoInfo {
	out := make(map[string]IPGeoInfo, len(ips))
	const subChunkSize = 50
	for start := 0; start < len(ips); start += subChunkSize {
		end := min(start+subChunkSize, len(ips))
		sub := ips[start:end]
		url := "https://get.geojs.io/v1/ip/geo.json?ip=" + strings.Join(sub, ",")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "singctl-serverweb/1.0")
		resp, err := r.httpClient.Do(req)
		if err != nil {
			continue
		}
		var items []struct {
			IP          string `json:"ip"`
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
			OrgName     string `json:"organization_name"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || decErr != nil {
			continue
		}
		for _, it := range items {
			if it.IP == "" || it.CountryCode == "" || it.CountryCode == "nil" {
				continue
			}
			countryCN := resolveCountryDisplayName(it.CountryCode, it.Country)
			out[it.IP] = IPGeoInfo{
				IP:          it.IP,
				Country:     countryCN,
				CountryCode: strings.ToUpper(it.CountryCode),
				City:        it.City,
				ISP:         it.OrgName,
				Flag:        CountryCodeToFlag(it.CountryCode),
				Geo:         formatGeoLabel(it.CountryCode, countryCN, it.City),
			}
		}
	}
	return out
}

func (r *IPGeoResolver) loadLocked() {
	if r.filePath == "" {
		return
	}
	raw, err := os.ReadFile(r.filePath)
	if err != nil {
		return
	}
	var entries map[string]geoCacheEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return
	}
	now := time.Now()
	for ip, ent := range entries {
		if now.After(ent.ExpiresAt) || ent.Info.CountryCode == "" {
			continue
		}
		ent.Info.Country = resolveCountryDisplayName(ent.Info.CountryCode, ent.Info.Country)
		ent.Info.Geo = formatGeoLabel(ent.Info.CountryCode, ent.Info.Country, ent.Info.City)
		r.cache[ip] = ent
		if cidr := ComputeSubnetCIDR(ip); cidr != "" {
			r.subnetCache[cidr] = IPGeoInfo{
				Country:     ent.Info.Country,
				CountryCode: ent.Info.CountryCode,
				Flag:        ent.Info.Flag,
				ISP:         ent.Info.ISP,
				Geo:         ent.Info.Country,
			}
		}
	}
}

func (r *IPGeoResolver) saveLocked(force bool) {
	if r.filePath == "" {
		return
	}
	now := time.Now()
	if !force && !r.lastSaveAt.IsZero() && now.Sub(r.lastSaveAt) < geoSaveMinDT {
		return
	}
	r.lastSaveAt = now
	r.dirty = false

	raw, err := json.Marshal(r.cache)
	if err != nil {
		return
	}
	dir := filepath.Dir(r.filePath)
	_ = os.MkdirAll(dir, 0700)
	tmp := fmt.Sprintf("%s.%d.tmp", r.filePath, now.UnixNano())
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, r.filePath); err != nil {
		_ = os.Remove(tmp)
		_ = os.WriteFile(r.filePath, raw, 0600)
		_ = os.Chmod(r.filePath, 0600)
	}
}
