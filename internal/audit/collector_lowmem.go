// 文件职责：提供审计采集器低内存自适应配置（<=512MiB 总内存或 <=256MiB 可用内存）、256 条风险感知有界淘汰及设备缓存降频策略。
package audit

import (
	"cmp"
	"maps"
	"slices"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/clashapi"
)

const (
	// LowMemTotalThresholdBytes 触发审计低内存有界环的总物理内存阈值（复用 sysinfo.LowMemoryThresholdBytes = 512 MiB）。
	LowMemTotalThresholdBytes uint64 = sysinfo.LowMemoryThresholdBytes
	// LowMemAvailThresholdBytes 触发审计低内存有界环的可用内存阈值（复用 sysinfo.LowMemoryAvailableThresholdBytes = 256 MiB）。
	LowMemAvailThresholdBytes uint64 = sysinfo.LowMemoryAvailableThresholdBytes
	// LowMemMaxTrackedFlows 低内存模式下驻留历史流条目硬上限（256 条）。
	LowMemMaxTrackedFlows = 256
	// DefaultMaxTrackedFlows 常规内存模式下驻留历史流条目上限（1500 条）。
	DefaultMaxTrackedFlows = maxPersistedFlows
	// LowMemMaxTrackedConnCursors 低内存模式下活跃连接字节增量游标上限（512 条，防满载 BT 短连接撑爆内存）。
	LowMemMaxTrackedConnCursors = 512
	// LowMemDeviceRefreshInterval 低内存模式下 DHCP/ARP/hosts 设备表最小刷新间隔。
	LowMemDeviceRefreshInterval = 2 * time.Minute
	// LowMemIPv6NeighRefreshInterval 低内存模式下 `ip -6 neigh` 邻居表最小刷新间隔。
	LowMemIPv6NeighRefreshInterval = 3 * time.Minute
)

// CollectorOptions 显式配置审计采集器的低内存预算与邻居表刷新降频参数。
type CollectorOptions struct {
	LowMemory                *bool
	MemTotalBytes            uint64
	MemAvailableBytes        uint64
	MaxTrackedFlows          int
	DeviceRefreshMinInterval time.Duration
	IPv6NeighRefreshInterval time.Duration
}

// IsLowMemoryAuditMemInfo 判断内存快照是否应启用审计采集器低内存有界保护（委托 sysinfo.IsLowMemoryMemInfo）。
func IsLowMemoryAuditMemInfo(mi sysinfo.MemInfo) bool {
	return sysinfo.IsLowMemoryMemInfo(mi)
}

func resolveLowMemoryOption(opts CollectorOptions) bool {
	if opts.LowMemory != nil {
		return *opts.LowMemory
	}
	if opts.MemTotalBytes > 0 || opts.MemAvailableBytes > 0 {
		return IsLowMemoryAuditMemInfo(sysinfo.MemInfo{
			TotalBytes:     opts.MemTotalBytes,
			AvailableBytes: opts.MemAvailableBytes,
		})
	}
	if mi, err := sysinfo.ReadMemInfo(); err == nil {
		return IsLowMemoryAuditMemInfo(mi)
	}
	return false
}

// NewCollectorWithOptions 按显式选项或宿主机内存自适应创建审计采集器。
func NewCollectorWithOptions(cfg *config.Config, opts CollectorOptions) *Collector {
	c := &Collector{
		cfg:             cfg,
		statePath:       defaultStatePath(),
		endpoints:       singbox.ClashAPIEndpoints(),
		secret:          singbox.ClashAPISecret(),
		clashClient:     clashapi.NewClient(clashapi.Options{RequestTimeout: 2500 * time.Millisecond}),
		leaseFiles:      []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/tmp/dnsmasq.leases"},
		arpFile:         "/proc/net/arp",
		hostsFile:       "/etc/hosts",
		odhcpdHostsFile: "/tmp/hosts/odhcpd",
		tzFile:          "/etc/TZ",
		uciSystemFile:   "/etc/config/system",
	}
	c.nowFunc = func() time.Time {
		return time.Now().In(c.resolveLocalLocation())
	}
	c.applyCollectorOptionsLocked(opts, resolveLowMemoryOption(opts))
	return c
}

func (c *Collector) applyCollectorOptionsLocked(opts CollectorOptions, lowMem bool) {
	c.lowMemory = lowMem
	if lowMem {
		c.maxTrackedFlows = cmp.Or(opts.MaxTrackedFlows, LowMemMaxTrackedFlows)
		c.maxConnCursors = LowMemMaxTrackedConnCursors
		c.deviceRefreshInterval = cmp.Or(opts.DeviceRefreshMinInterval, LowMemDeviceRefreshInterval)
		c.ipv6RefreshInterval = cmp.Or(opts.IPv6NeighRefreshInterval, LowMemIPv6NeighRefreshInterval)
		c.selfIPsRefreshInterval = 3 * time.Minute
	} else {
		c.maxTrackedFlows = cmp.Or(opts.MaxTrackedFlows, DefaultMaxTrackedFlows)
		c.maxConnCursors = maxTrackedConnDeltas
		c.deviceRefreshInterval = opts.DeviceRefreshMinInterval
		c.ipv6RefreshInterval = cmp.Or(opts.IPv6NeighRefreshInterval, 15*time.Second)
		c.selfIPsRefreshInterval = 30 * time.Second
	}
}

// SetLowMemoryForTest 供单元测试显式切换采集器的低内存有界与降频模式。
func (c *Collector) SetLowMemoryForTest(enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applyCollectorOptionsLocked(CollectorOptions{}, enabled)
	c.cachedMergedLANDevs = nil
	c.lanDevsFetchedAt = time.Time{}
	c.ipv6NeighFetchedAt = time.Time{}
	if c.cachedState != nil {
		eng := c.resolveEngineLocked()
		c.enforceBoundsLocked(c.cachedState, nil, c.cachedMergedLANDevs, c.cachedSelfIPs, eng, c.currentTimeLocked().Unix())
	}
}

// IsLowMemoryMode 返回当前采集器是否处于低内存保护模式。
func (c *Collector) IsLowMemoryMode() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lowMemory
}

// MaxTrackedFlows 返回当前采集器生效的历史流条目驻留上限。
func (c *Collector) MaxTrackedFlows() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.effectiveMaxFlowsLocked()
}

func (c *Collector) effectiveMaxFlowsLocked() int {
	if c.maxTrackedFlows > 0 {
		return c.maxTrackedFlows
	}
	return DefaultMaxTrackedFlows
}

func (c *Collector) effectiveMaxCursorsLocked() int {
	if c.maxConnCursors > 0 {
		return c.maxConnCursors
	}
	return maxTrackedConnDeltas
}

func (c *Collector) currentTimeLocked() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

func flowProtectionTier(rec FlowRecord) int {
	if rec.Threat == ThreatHighRisk || rec.PCDNKind == "upload" || rec.PCDNKind == "swarm" {
		return 3
	}
	if rec.Threat == ThreatSuspicious || rec.PCDNKind != "" {
		return 2
	}
	if rec.Threat == ThreatNotice {
		return 1
	}
	return 0
}

type scoredFlowCandidate struct {
	entry *persistedFlowEntry
	tier  int
	score int
	act   int
}

func compareFlowRetentionPriority(a, b scoredFlowCandidate) int {
	aProt, bProt := a.tier >= 2, b.tier >= 2
	if aProt != bProt {
		if aProt {
			return -1
		}
		return 1
	}
	if aProt {
		if c := cmp.Compare(b.tier, a.tier); c != 0 {
			return c
		}
		if c := cmp.Compare(b.score, a.score); c != 0 {
			return c
		}
		if c := cmp.Compare(b.act, a.act); c != 0 {
			return c
		}
		if c := cmp.Compare(b.entry.UploadBytes, a.entry.UploadBytes); c != 0 {
			return c
		}
		if c := cmp.Compare(b.entry.LastSeenUnix, a.entry.LastSeenUnix); c != 0 {
			return c
		}
		return cmp.Compare(a.entry.Key, b.entry.Key)
	}

	// 普通流与低风险观察流：优先保留当前仍活跃的连接；对失活流优先淘汰风险分最低、最早失活（LastSeenUnix 最小）的普通流
	if c := cmp.Compare(b.act, a.act); c != 0 {
		return c
	}
	if c := cmp.Compare(b.tier, a.tier); c != 0 {
		return c
	}
	if c := cmp.Compare(b.score, a.score); c != 0 {
		return c
	}
	if c := cmp.Compare(b.entry.LastSeenUnix, a.entry.LastSeenUnix); c != 0 {
		return c
	}
	if c := cmp.Compare(b.entry.UploadBytes, a.entry.UploadBytes); c != 0 {
		return c
	}
	return cmp.Compare(a.entry.Key, b.entry.Key)
}

func trimFlowsRiskAware(
	st *persistedAuditState,
	limit int,
	activeByKey map[string][]string,
	devDir map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	engine *NonlinearEngine,
) bool {
	if st == nil || len(st.Flows) <= limit {
		return false
	}
	if engine == nil {
		engine = NewNonlinearEngine(nil)
	}

	entries := make([]*persistedFlowEntry, 0, len(st.Flows))
	evalFlows := make([]FlowRecord, 0, len(st.Flows))
	for _, e := range st.Flows {
		if e == nil {
			continue
		}
		normDevIP := e.DeviceIP
		if selfIPs != nil || devDir != nil {
			normDevIP = normalizeSourceDeviceIP(e.DeviceIP, selfIPs, devDir)
		}
		devName, _ := resolveFlowDeviceIdentity(normDevIP, e, devDir)
		actCount := len(activeByKey[e.Key])
		entries = append(entries, e)
		evalFlows = append(evalFlows, FlowRecord{
			Key:           e.Key,
			DeviceIP:      normDevIP,
			DeviceName:    devName,
			DeviceRole:    InferDeviceRole(devName),
			Target:        e.Target,
			RawHost:       e.RawHost,
			DestIP:        e.DestIP,
			DestPort:      e.DestPort,
			IsDirectIP:    e.IsDirectIP,
			Network:       e.Network,
			Outbound:      e.Outbound,
			UploadBytes:   e.UploadBytes,
			DownloadBytes: e.DownloadBytes,
			ConnCount:     e.ConnCount,
			ActiveConns:   actCount,
			ActiveSpanSec: max(int64(60), e.LastSeenUnix-e.FirstSeenUnix),
			NightHits:     e.NightHits,
			IntervalCV:    computeIntervalCV(e.ArrivalsUnix),
		})
	}

	engine.AnnotateDirectIPSubnetClusters(evalFlows)
	engine.AnnotatePCDNSwarmBehaviors(evalFlows)

	candidates := make([]scoredFlowCandidate, len(entries))
	for i := range evalFlows {
		engine.EvaluateFlow(&evalFlows[i])
		act := 0
		if evalFlows[i].ActiveConns > 0 {
			act = 1
		}
		candidates[i] = scoredFlowCandidate{
			entry: entries[i],
			tier:  flowProtectionTier(evalFlows[i]),
			score: evalFlows[i].RiskScore,
			act:   act,
		}
	}

	slices.SortFunc(candidates, compareFlowRetentionPriority)
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	trimmed := make(map[string]*persistedFlowEntry, len(candidates))
	for _, cand := range candidates {
		trimmed[cand.entry.Key] = cand.entry
	}
	st.Flows = trimmed
	return true
}

func pruneExcessConnCursors(st *persistedAuditState, maxCursors int, activeByKey map[string][]string, lowMem bool, nowUnix int64) bool {
	if st == nil || len(st.ConnCursors) <= maxCursors {
		return false
	}
	before := len(st.ConnCursors)
	activeConnIDs := make(map[string]struct{}, maxCursors)
	for _, ids := range activeByKey {
		for _, id := range ids {
			activeConnIDs[id] = struct{}{}
		}
	}

	idleTTL := int64(7200)
	if lowMem {
		idleTTL = 120
	}
	maps.DeleteFunc(st.ConnCursors, func(id string, cur connByteCursor) bool {
		if _, active := activeConnIDs[id]; active {
			return false
		}
		return nowUnix > 0 && nowUnix-cur.SeenUnix > idleTTL
	})

	if len(st.ConnCursors) > maxCursors {
		// 满载 BT 短连接洪峰下立即清理本轮已关闭的历史连接游标
		maps.DeleteFunc(st.ConnCursors, func(id string, _ connByteCursor) bool {
			_, active := activeConnIDs[id]
			return !active
		})
	}
	if len(st.ConnCursors) > maxCursors {
		type cursorPair struct {
			id  string
			cur connByteCursor
		}
		all := make([]cursorPair, 0, len(st.ConnCursors))
		for id, cur := range st.ConnCursors {
			all = append(all, cursorPair{id: id, cur: cur})
		}
		slices.SortFunc(all, func(a, b cursorPair) int {
			if c := cmp.Compare(b.cur.SeenUnix, a.cur.SeenUnix); c != 0 {
				return c
			}
			return cmp.Compare(a.id, b.id)
		})
		capped := make(map[string]connByteCursor, maxCursors)
		for _, item := range all[:maxCursors] {
			capped[item.id] = item.cur
		}
		st.ConnCursors = capped
	} else if lowMem && before >= maxCursors*2 {
		// 重建紧凑 map 释放洪峰期扩张的底层哈希桶数组
		st.ConnCursors = maps.Clone(st.ConnCursors)
	}
	return len(st.ConnCursors) != before
}

func (c *Collector) enforceBoundsLocked(
	st *persistedAuditState,
	activeByKey map[string][]string,
	devDir map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	engine *NonlinearEngine,
	nowUnix int64,
) bool {
	if st == nil {
		return false
	}
	curTrimmed := pruneExcessConnCursors(st, c.effectiveMaxCursorsLocked(), activeByKey, c.lowMemory, nowUnix)
	flowTrimmed := trimFlowsRiskAware(st, c.effectiveMaxFlowsLocked(), activeByKey, devDir, selfIPs, engine)
	return curTrimmed || flowTrimmed
}
