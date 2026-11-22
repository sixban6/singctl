// 文件职责：提供 SmartDNS 内存盘逐包审计的 24 小时有界滑动环形 DNS 统计器（零闪存写入、防 OOM 硬上限）。
package localdns

import (
	"cmp"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/adguard"
)

const (
	LowMemoryMaxDomainsPerBucket = 256
	StandardMaxDomainsPerBucket  = 1024
	statsRingBuckets             = 24
	maxTopBlockedDomains         = 12
	maxTopQueriedDomains         = 8
)

type hourBucket struct {
	hourKey        int64
	hasData        bool
	totalQueries   int64
	totalBlocked   int64
	latencySumMs   float64
	latencySamples int64
	queried        map[string]int64
	blocked        map[string]int64
}

// StatsRing 提供并发安全、零闪存写入、硬上限防 OOM 的 24 小时 DNS 统计环形缓冲区。
type StatsRing struct {
	mu                  sync.Mutex
	maxDomainsPerBucket int
	buckets             [statsRingBuckets]hourBucket
}

// NewStatsRing 按低内存或标准模式创建 24 小时统计环形缓冲区。
func NewStatsRing(lowMemory bool) *StatsRing {
	if lowMemory {
		return NewStatsRingWithCap(LowMemoryMaxDomainsPerBucket)
	}
	return NewStatsRingWithCap(StandardMaxDomainsPerBucket)
}

// NewStatsRingWithCap 创建指定单桶最大域名容量的 24 小时统计环形缓冲区。
func NewStatsRingWithCap(maxDomainsPerBucket int) *StatsRing {
	if maxDomainsPerBucket <= 0 {
		maxDomainsPerBucket = LowMemoryMaxDomainsPerBucket
	}
	return &StatsRing{
		maxDomainsPerBucket: maxDomainsPerBucket,
	}
}

func normalizeStatsDomain(raw string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if d == "" || strings.ContainsAny(d, " \t\r\n") {
		return ""
	}
	if net.ParseIP(d) != nil {
		return ""
	}
	return d
}

func hourKeyFor(ts time.Time) int64 {
	if ts.IsZero() {
		ts = time.Now()
	}
	return ts.UTC().Truncate(time.Hour).Unix() / 3600
}

func bucketSlot(hourKey int64) int {
	slot := int(hourKey % statsRingBuckets)
	if slot < 0 {
		slot += statsRingBuckets
	}
	return slot
}

// Record 记录一条域名查询/访问与拦截事件（并发安全，单桶域名数受硬上限保护）。
func (r *StatsRing) Record(ts time.Time, domain string, blocked bool, latencyMs float64) {
	if r == nil {
		return
	}
	dom := normalizeStatsDomain(domain)
	if dom == "" {
		return
	}
	hk := hourKeyFor(ts)
	slot := bucketSlot(hk)

	r.mu.Lock()
	defer r.mu.Unlock()

	b := &r.buckets[slot]
	if b.hasData && hk < b.hourKey {
		// 丢弃比当前槽位更旧的乱序过期事件
		return
	}
	if !b.hasData || hk > b.hourKey {
		b.hourKey = hk
		b.hasData = true
		b.totalQueries = 0
		b.totalBlocked = 0
		b.latencySumMs = 0
		b.latencySamples = 0
		if b.queried != nil {
			clear(b.queried)
		}
		if b.blocked != nil {
			clear(b.blocked)
		}
	}

	b.totalQueries++
	if blocked {
		b.totalBlocked++
	}
	if latencyMs > 0 && !math.IsNaN(latencyMs) && !math.IsInf(latencyMs, 0) {
		b.latencySumMs += latencyMs
		b.latencySamples++
	}

	if b.queried == nil {
		b.queried = make(map[string]int64, min(64, r.maxDomainsPerBucket))
	}
	if _, exists := b.queried[dom]; exists || len(b.queried) < r.maxDomainsPerBucket {
		b.queried[dom]++
	}

	if blocked {
		if b.blocked == nil {
			b.blocked = make(map[string]int64, min(32, r.maxDomainsPerBucket))
		}
		if _, exists := b.blocked[dom]; exists || len(b.blocked) < r.maxDomainsPerBucket {
			b.blocked[dom]++
		}
	}
}

// Snapshot 汇总截至 now 的 24 小时统计指标与 Top 排行榜。
func (r *StatsRing) Snapshot(now time.Time, fallbackAvgLatencyMs float64) adguard.ControlStats {
	out := adguard.ControlStats{
		TopBlockedDomains: []adguard.DomainStatItem{},
		TopQueriedDomains: []adguard.DomainStatItem{},
	}
	if r == nil {
		return out
	}
	nowHour := hourKeyFor(now)
	minHour := nowHour - (statsRingBuckets - 1)

	r.mu.Lock()
	var (
		totalQueries   int64
		totalBlocked   int64
		latencySumMs   float64
		latencySamples int64
		queriedTotals  = make(map[string]int64)
		blockedTotals  = make(map[string]int64)
	)
	for i := range r.buckets {
		b := &r.buckets[i]
		if !b.hasData || b.hourKey < minHour || b.hourKey > nowHour {
			continue
		}
		totalQueries += b.totalQueries
		totalBlocked += b.totalBlocked
		latencySumMs += b.latencySumMs
		latencySamples += b.latencySamples
		for dom, cnt := range b.queried {
			queriedTotals[dom] += cnt
		}
		for dom, cnt := range b.blocked {
			blockedTotals[dom] += cnt
		}
	}
	r.mu.Unlock()

	out.NumDNSQueries = totalQueries
	out.NumBlockedFiltering = totalBlocked
	if totalQueries > 0 {
		pct := (float64(totalBlocked) / float64(totalQueries)) * 100
		out.BlockedPercent = math.Round(pct*10) / 10
	}
	if latencySamples > 0 {
		out.AvgProcessingMs = math.Round((latencySumMs/float64(latencySamples))*10) / 10
	} else if fallbackAvgLatencyMs > 0 && !math.IsNaN(fallbackAvgLatencyMs) && !math.IsInf(fallbackAvgLatencyMs, 0) {
		out.AvgProcessingMs = math.Round(fallbackAvgLatencyMs*10) / 10
	}

	out.TopQueriedDomains = topDomainItems(queriedTotals, maxTopQueriedDomains)
	out.TopBlockedDomains = topDomainItems(blockedTotals, maxTopBlockedDomains)
	return out
}

func topDomainItems(counts map[string]int64, limit int) []adguard.DomainStatItem {
	if len(counts) == 0 || limit <= 0 {
		return []adguard.DomainStatItem{}
	}
	items := make([]adguard.DomainStatItem, 0, len(counts))
	for dom, cnt := range counts {
		if cnt > 0 {
			items = append(items, adguard.DomainStatItem{Domain: dom, Count: cnt})
		}
	}
	slices.SortFunc(items, func(a, b adguard.DomainStatItem) int {
		if c := cmp.Compare(b.Count, a.Count); c != 0 {
			return c
		}
		return cmp.Compare(a.Domain, b.Domain)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

// Reset 清空全部 24 小时统计桶。
func (r *StatsRing) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.buckets {
		r.buckets[i] = hourBucket{}
	}
}
