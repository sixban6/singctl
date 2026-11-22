// 文件职责：提供实例级 IP 地理信息双通道批量解析（ip-api / geojs）、/24 网段归属共享与 0600 异步防阻塞持久化缓存。
package ipgeo

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/fsx"
)

const (
	maxGeoCacheEntries   = 5000
	geoCacheTTL          = 7 * 24 * time.Hour
	geoSaveMinDT         = 60 * time.Second
	defaultIPAPIBatchURL = "http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp"
	defaultGeoJSBatchURL = "https://get.geojs.io/v1/ip/geo.json"
)

// Info 描述单个 IP 的地理位置与网络运营商元数据。
type Info struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	City        string `json:"city,omitempty"`
	ISP         string `json:"isp,omitempty"`
	Flag        string `json:"flag,omitempty"`
	Geo         string `json:"geo,omitempty"`
}

// CacheEntry 表示带过期时间的单条 IP 地理缓存记录。
type CacheEntry struct {
	Info      Info      `json:"info"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Resolver 为实例级 IP 地理信息批量解析与网段共享缓存器（无全局可变单例）。
type Resolver struct {
	mu            sync.RWMutex
	Cache         map[string]CacheEntry
	subnetCache   map[string]Info
	inFlight      map[string]bool
	pendingQueue  []string
	filePath      string
	dirty         bool
	lastSaveAt    time.Time
	HTTPClient    *http.Client
	IPAPIBatchURL string
	GeoJSBatchURL string
	batchRunning  atomic.Bool
	rev           atomic.Uint64
	writeSeq      uint64
	writer        *fsx.AsyncSnapshotWriter
}

// NewResolver 创建解析器实例（可选传入 0600 磁盘缓存路径）。
func NewResolver(filePath ...string) *Resolver {
	fp := ""
	if len(filePath) > 0 {
		fp = strings.TrimSpace(filePath[0])
	}
	r := &Resolver{
		Cache:       make(map[string]CacheEntry),
		subnetCache: make(map[string]Info),
		inFlight:    make(map[string]bool),
		filePath:    fp,
		HTTPClient:  &http.Client{Timeout: 2500 * time.Millisecond},
		writer:      fsx.NewAsyncSnapshotWriter(fp, fsx.WriteAtomic0600),
	}
	r.loadLocked()
	return r
}

// Revision 返回 GeoIP 缓存单调递增版本号（供上游嗅探快照缓存零开销判定失效）。
func (r *Resolver) Revision() uint64 {
	if r == nil {
		return 0
	}
	return r.rev.Load()
}

func localGeoInfo(ipStr string) Info {
	return Info{
		IP:      ipStr,
		Country: "本地",
		City:    "内网/回环",
		ISP:     "本机直连",
		Geo:     "本地网络",
	}
}

func (r *Resolver) evictCacheIfFullLocked() {
	if len(r.Cache) < maxGeoCacheEntries {
		return
	}
	now := time.Now()
	for k, v := range r.Cache {
		if now.After(v.ExpiresAt) {
			delete(r.Cache, k)
		}
		if len(r.Cache) <= maxGeoCacheEntries-500 {
			return
		}
	}
	for k := range r.Cache {
		delete(r.Cache, k)
		if len(r.Cache) <= maxGeoCacheEntries-500 {
			return
		}
	}
}

func (r *Resolver) storeResolvedLocked(ipStr string, info Info, ttl time.Duration) {
	info.IP = ipStr
	info.CountryCode = strings.ToUpper(strings.TrimSpace(info.CountryCode))
	info.Country = ResolveCountryDisplayName(info.CountryCode, info.Country)
	if info.Flag == "" && info.CountryCode != "" {
		info.Flag = CountryCodeToFlag(info.CountryCode)
	}
	if info.Geo == "" {
		info.Geo = FormatGeoLabel(info.CountryCode, info.Country, info.City)
	}

	r.evictCacheIfFullLocked()
	r.Cache[ipStr] = CacheEntry{
		Info:      info,
		ExpiresAt: time.Now().Add(ttl),
	}
	if info.CountryCode != "" {
		if cidr := ComputeSubnetCIDR(ipStr); cidr != "" {
			r.subnetCache[cidr] = Info{
				Country:     info.Country,
				CountryCode: info.CountryCode,
				Flag:        info.Flag,
				ISP:         info.ISP,
				Geo:         info.Country,
			}
		}
	}
	r.dirty = true
	r.rev.Add(1)
}

// SeedCountry 根据请求头（如 Cloudflare CF-IPCountry）零延迟预置国家信息。
func (r *Resolver) SeedCountry(ipStr, countryCode string) {
	if r == nil || IsPrivateOrLoopbackIP(ipStr) {
		return
	}
	countryCode = strings.ToUpper(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return
	}

	r.mu.RLock()
	entry, exists := r.Cache[ipStr]
	if exists && entry.Info.CountryCode != "" && time.Until(entry.ExpiresAt) > 30*time.Minute {
		r.mu.RUnlock()
		return
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	entry, exists = r.Cache[ipStr]
	if exists && entry.Info.CountryCode != "" && time.Until(entry.ExpiresAt) > 30*time.Minute {
		return
	}
	countryName := ResolveCountryDisplayName(countryCode, countryCode)
	r.storeResolvedLocked(ipStr, Info{
		IP:          ipStr,
		Country:     countryName,
		CountryCode: countryCode,
		Flag:        CountryCodeToFlag(countryCode),
		Geo:         countryName,
	}, 6*time.Hour)
}

// Resolve 解析单个 IP，优先命中缓存或同 /24 网段缓存，未命中时入队后台批量解析。
func (r *Resolver) Resolve(ipStr string) Info {
	if IsPrivateOrLoopbackIP(ipStr) {
		return localGeoInfo(ipStr)
	}
	if r == nil {
		return Info{IP: ipStr}
	}

	now := time.Now()
	r.mu.RLock()
	entry, found := r.Cache[ipStr]
	var subFallback Info
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
	if !IsRFC5737DocumentationIP(ipStr) {
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
	return Info{IP: ipStr}
}

// ResolveCachedOrEnqueue 非阻塞批量读取已知缓存，未命中 IP 异步入队（适用于 SSE 热路径）。
func (r *Resolver) ResolveCachedOrEnqueue(ips []string) map[string]Info {
	out := make(map[string]Info, len(ips))
	if len(ips) == 0 || r == nil {
		return out
	}

	now := time.Now()
	var missing []string
	seenMissing := make(map[string]struct{})

	r.mu.RLock()
	for _, ip := range ips {
		if IsPrivateOrLoopbackIP(ip) {
			out[ip] = localGeoInfo(ip)
			continue
		}
		if entry, ok := r.Cache[ip]; ok && entry.Info.CountryCode != "" {
			out[ip] = entry.Info
			if now.Before(entry.ExpiresAt) {
				continue
			}
		} else if cidr := ComputeSubnetCIDR(ip); cidr != "" {
			if subInfo, ok := r.subnetCache[cidr]; ok && subInfo.CountryCode != "" {
				cp := subInfo
				cp.IP = ip
				out[ip] = cp
			} else {
				out[ip] = Info{IP: ip}
			}
		} else {
			out[ip] = Info{IP: ip}
		}
		if !IsRFC5737DocumentationIP(ip) {
			if _, seen := seenMissing[ip]; !seen {
				seenMissing[ip] = struct{}{}
				missing = append(missing, ip)
			}
		}
	}
	r.mu.RUnlock()

	for _, ip := range missing {
		r.enqueueForBatch(ip)
	}
	return out
}

// ResolveBatch 批量解析一组 IP：对未缓存 IP 通过双通道批量 API 快速补齐并共享同 /24 归属地。
func (r *Resolver) ResolveBatch(ctx context.Context, ips []string) map[string]Info {
	out := make(map[string]Info, len(ips))
	if len(ips) == 0 || r == nil {
		return out
	}
	if ctx == nil {
		ctx = context.Background()
	}

	now := time.Now()
	var missing []string
	seenMissing := make(map[string]struct{})

	r.mu.RLock()
	for _, ip := range ips {
		if IsPrivateOrLoopbackIP(ip) {
			out[ip] = localGeoInfo(ip)
			continue
		}
		if entry, ok := r.Cache[ip]; ok && now.Before(entry.ExpiresAt) && entry.Info.CountryCode != "" {
			out[ip] = entry.Info
			continue
		}
		if !IsRFC5737DocumentationIP(ip) {
			if _, seen := seenMissing[ip]; !seen {
				seenMissing[ip] = struct{}{}
				missing = append(missing, ip)
			}
		}
	}
	r.mu.RUnlock()

	if len(missing) > 0 {
		const maxSyncBatches = 3
		const batchSize = 100
		syncLimit := min(len(missing), maxSyncBatches*batchSize)
		syncPart := missing[:syncLimit]
		asyncPart := missing[syncLimit:]

		var wg sync.WaitGroup
		for start := 0; start < len(syncPart); start += batchSize {
			chunk := syncPart[start:min(start+batchSize, len(syncPart))]
			wg.Go(func() {
				bCtx, cancel := context.WithTimeout(ctx, 2200*time.Millisecond)
				defer cancel()
				r.fetchBatchSync(bCtx, chunk)
			})
		}
		wg.Wait()

		for _, ip := range asyncPart {
			r.enqueueForBatch(ip)
		}
	}

	r.mu.RLock()
	for _, ip := range ips {
		if _, done := out[ip]; done {
			continue
		}
		if entry, ok := r.Cache[ip]; ok && entry.Info.CountryCode != "" {
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
		out[ip] = Info{IP: ip}
	}
	r.mu.RUnlock()

	r.scheduleAsyncSaveIfNeeded()
	return out
}

func (r *Resolver) enqueueForBatch(ipStr string) {
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

func (r *Resolver) drainBatchLoop() {
	defer r.batchRunning.Store(false)
	time.Sleep(80 * time.Millisecond)

	for {
		r.mu.Lock()
		if len(r.pendingQueue) == 0 {
			r.mu.Unlock()
			r.scheduleAsyncSaveIfNeeded()
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

func (r *Resolver) fetchBatchSync(ctx context.Context, chunk []string) {
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
	if len(unresolved) > 0 {
		for k, v := range r.queryGeoJSBatch(ctx, unresolved) {
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

func (r *Resolver) httpClient() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return &http.Client{Timeout: 2500 * time.Millisecond}
}

func (r *Resolver) queryIPAPIBatch(ctx context.Context, ips []string) map[string]Info {
	out := make(map[string]Info, len(ips))
	bodyBytes, err := json.Marshal(ips)
	if err != nil {
		return out
	}
	endpoint := cmp.Or(strings.TrimSpace(r.IPAPIBatchURL), defaultIPAPIBatchURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return out
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "singctl-ipgeo/1.0")

	resp, err := r.httpClient().Do(req)
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
		countryCN := ResolveCountryDisplayName(it.CountryCode, it.Country)
		out[it.Query] = Info{
			IP:          it.Query,
			Country:     countryCN,
			CountryCode: strings.ToUpper(it.CountryCode),
			City:        it.City,
			ISP:         it.ISP,
			Flag:        CountryCodeToFlag(it.CountryCode),
			Geo:         FormatGeoLabel(it.CountryCode, countryCN, it.City),
		}
	}
	return out
}

func (r *Resolver) queryGeoJSBatch(ctx context.Context, ips []string) map[string]Info {
	out := make(map[string]Info, len(ips))
	baseURL := cmp.Or(strings.TrimSpace(r.GeoJSBatchURL), defaultGeoJSBatchURL)
	const subChunkSize = 50
	for start := 0; start < len(ips); start += subChunkSize {
		sub := ips[start:min(start+subChunkSize, len(ips))]
		sep := "?"
		if strings.Contains(baseURL, "?") {
			sep = "&"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+sep+"ip="+strings.Join(sub, ","), nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "singctl-ipgeo/1.0")
		resp, err := r.httpClient().Do(req)
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
			countryCN := ResolveCountryDisplayName(it.CountryCode, it.Country)
			out[it.IP] = Info{
				IP:          it.IP,
				Country:     countryCN,
				CountryCode: strings.ToUpper(it.CountryCode),
				City:        it.City,
				ISP:         it.OrgName,
				Flag:        CountryCodeToFlag(it.CountryCode),
				Geo:         FormatGeoLabel(it.CountryCode, countryCN, it.City),
			}
		}
	}
	return out
}

func (r *Resolver) loadLocked() {
	if r.filePath == "" {
		return
	}
	raw, err := os.ReadFile(r.filePath)
	if err != nil {
		return
	}
	var entries map[string]CacheEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return
	}
	now := time.Now()
	for ip, ent := range entries {
		if now.After(ent.ExpiresAt) || ent.Info.CountryCode == "" {
			continue
		}
		ent.Info.Country = ResolveCountryDisplayName(ent.Info.CountryCode, ent.Info.Country)
		ent.Info.Geo = FormatGeoLabel(ent.Info.CountryCode, ent.Info.Country, ent.Info.City)
		r.Cache[ip] = ent
		if cidr := ComputeSubnetCIDR(ip); cidr != "" {
			r.subnetCache[cidr] = Info{
				Country:     ent.Info.Country,
				CountryCode: ent.Info.CountryCode,
				Flag:        ent.Info.Flag,
				ISP:         ent.Info.ISP,
				Geo:         ent.Info.Country,
			}
		}
	}
	if len(r.Cache) > 0 {
		r.rev.Add(1)
	}
}

func (r *Resolver) snapshotPersistBytesLocked(force bool) ([]byte, uint64) {
	if r.filePath == "" || !r.dirty {
		return nil, 0
	}
	now := time.Now()
	if !force && !r.lastSaveAt.IsZero() && now.Sub(r.lastSaveAt) < geoSaveMinDT {
		return nil, 0
	}
	r.lastSaveAt = now
	r.dirty = false

	raw, err := json.Marshal(r.Cache)
	if err != nil {
		return nil, 0
	}
	r.writeSeq++
	return raw, r.writeSeq
}

func (r *Resolver) scheduleAsyncSaveIfNeeded() {
	if r == nil || r.filePath == "" || r.writer == nil {
		return
	}
	r.mu.Lock()
	raw, seq := r.snapshotPersistBytesLocked(false)
	r.mu.Unlock()
	if len(raw) > 0 {
		r.writer.Submit(raw, seq, 0)
	}
}

// Flush 将待持久化 Geo 缓存刷新到磁盘（0600）。
func (r *Resolver) Flush() {
	if r == nil || r.filePath == "" || r.writer == nil {
		return
	}
	r.mu.Lock()
	raw, seq := r.snapshotPersistBytesLocked(true)
	r.mu.Unlock()
	if len(raw) > 0 {
		r.writer.Submit(raw, seq, 25*time.Millisecond)
	}
	r.writer.Flush(500 * time.Millisecond)
}
