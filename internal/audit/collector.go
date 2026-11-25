// 文件职责：定义审计采集器 Collector 聚合入口、生命周期控制（Collect / SampleActiveConnections）及多维引擎协调流水线。
package audit

import (
	"cmp"
	"context"
	"maps"
	"math"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/platform/rtnl"
	"singctl/internal/singbox"
	"singctl/internal/singbox/clashapi"
)

type connRateCursor struct {
	Upload   int64
	Download int64
	SampleAt time.Time
}

type flowLiveRate struct {
	upBps   float64
	downBps float64
}

// Collector 负责从 sing-box Clash API 采集连接、关联局域网 DHCP/ARP 设备名并执行多维非线性分析。
type Collector struct {
	mu                     sync.Mutex
	cfg                    *config.Config
	statePath              string
	endpoints              []string
	secret                 string
	customEndpoints        bool
	clashClient            *clashapi.Client
	leaseFiles             []string
	arpFile                string
	hostsFile              string
	odhcpdHostsFile        string
	tzFile                 string
	uciSystemFile          string
	nowFunc                func() time.Time
	ipv6NeighCmdFunc       func() ([]byte, error)
	ptrLookupFunc          func(ctx context.Context, ip string) (string, error)
	rtnlClient             rtnl.Client
	cachedState            *persistedAuditState
	cachedStateFp          string
	stateDirty             bool
	lastSavedUnix          int64
	lastPollAt             time.Time
	connRateCursors        map[string]connRateCursor
	flowLiveRates          map[string]flowLiveRate
	flowActiveDetails      map[string][]ActiveConnDetail
	cachedEngine           *NonlinearEngine
	cachedEngineFp         string
	cachedSelfIPs          map[string]bool
	selfIPsFetchedAt       time.Time
	cachedLeaseFp          string
	cachedLeaseDevs        map[string]lanDeviceInfo
	cachedMergedLANDevs    map[string]lanDeviceInfo
	lanDevsFetchedAt       time.Time
	ipv6NeighCache         map[string]string
	ipv6NeighFetchedAt     time.Time
	ptrCache               map[string]ptrCacheEntry
	lowMemory              bool
	maxTrackedFlows        int
	maxConnCursors         int
	deviceRefreshInterval  time.Duration
	ipv6RefreshInterval    time.Duration
	selfIPsRefreshInterval time.Duration
}

// NewCollector 创建默认客户端审计采集器（自动兼容 OpenWrt /etc/TZ 与 /etc/config/system 本地时区及低内存自适应预算）。
func NewCollector(cfg *config.Config) *Collector {
	return NewCollectorWithOptions(cfg, CollectorOptions{})
}

// SetTimezoneFilesForTest 供单元测试注入模拟的 OpenWrt /etc/TZ 与 /etc/config/system 路径。
func (c *Collector) SetTimezoneFilesForTest(tzFile, uciSystemFile string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tzFile = tzFile
	c.uciSystemFile = uciSystemFile
}

// SetEndpointsForTest 供单元测试注入模拟 Clash API 地址与状态文件路径。
func (c *Collector) SetEndpointsForTest(endpoints []string, secret, statePath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoints = endpoints
	c.secret = secret
	c.customEndpoints = true
	if statePath != "" {
		c.statePath = statePath
		c.cachedState = nil
		c.cachedStateFp = ""
		c.lastPollAt = time.Time{}
		c.connRateCursors = nil
		c.flowLiveRates = nil
		c.flowActiveDetails = nil
		ResetAICacheForTest(statePath + ".ai-cache.json")
	}
}

// SetLeaseFilesForTest 供单元测试注入模拟 DHCP 租约文件。
func (c *Collector) SetLeaseFilesForTest(leaseFiles []string, arpFile, hostsFile string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.leaseFiles = leaseFiles
	c.arpFile = arpFile
	c.hostsFile = hostsFile
	c.odhcpdHostsFile = ""
	c.cachedLeaseDevs = nil
	c.cachedLeaseFp = ""
	c.cachedMergedLANDevs = nil
	c.lanDevsFetchedAt = time.Time{}
}

// SetNowFuncForTest 供单元测试注入确定性时钟（例如模拟凌晨 03:00 行为）。
func (c *Collector) SetNowFuncForTest(fn func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fn != nil {
		c.nowFunc = fn
	}
}

// SetIPv6NeighCmdForTest 供单元测试注入模拟的 `ip -6 neigh show` 输出，零宿主命令副作用。
func (c *Collector) SetIPv6NeighCmdForTest(fn func() ([]byte, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ipv6NeighCmdFunc = fn
	c.ipv6NeighCache = nil
	c.ipv6NeighFetchedAt = time.Time{}
	c.cachedMergedLANDevs = nil
	c.lanDevsFetchedAt = time.Time{}
}

// SetPTRLookupFuncForTest 供单元测试注入确定性的主路由反向 PTR 解析函数，零宿主网络副作用。
func (c *Collector) SetPTRLookupFuncForTest(fn func(ctx context.Context, ip string) (string, error)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ptrLookupFunc = fn
	c.ptrCache = nil
	c.cachedMergedLANDevs = nil
	c.lanDevsFetchedAt = time.Time{}
}

// CollectOptions 控制审计报告生成的过滤与 AI 增强选项。
type CollectOptions struct {
	DeviceFilter string // 仅筛选特定内网设备 IP 或主机名关键字
	OnlySuspect  bool   // 仅返回关注/可疑/高危流 (RiskScore >= 35)
	EnableAI     bool   // 是否触发 L2 AI / 专家顾问研判
	CallerIP     string // 触发请求的客户端局域网 IP（用于自适应探测调用方本机 Magpie :3425 网关）
	Limit        int    // 最大返回流数量 (0 表示默认 100；< 0 表示不截断返回全量)
	SortBy       string // 排序字段: "active" (默认: 活跃优先+风险评分) | "risk" | "upload" | "download" | "ratio"
	SortAsc      bool   // 是否升序排列 (默认 false 即降序)
}

// UpdateConfig 在常驻采集器上刷新最新配置与 Clash API 访问凭据。
func (c *Collector) UpdateConfig(cfg *config.Config) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	if !c.customEndpoints {
		c.endpoints = singbox.ClashAPIEndpoints()
		c.secret = singbox.ClashAPISecret()
	}
}

// CollectWithConfig 在常驻单例 Collector 上注入最新配置并采样实时连接与历史增量。
func (c *Collector) CollectWithConfig(ctx context.Context, cfg *config.Config, opts CollectOptions) *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg = cfg
	if !c.customEndpoints {
		c.endpoints = singbox.ClashAPIEndpoints()
		c.secret = singbox.ClashAPISecret()
	}
	return c.collectLocked(ctx, opts)
}

// SampleActiveConnections 执行轻量级活跃连接增量采样并持久化至内存快照，跳过全量排序/AI 评分以适配高频后台轮询。
func (c *Collector) SampleActiveConnections(ctx context.Context) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _, _, _, _, _, reachable := c.sampleActiveLocked(ctx, c.nowFunc())
	return reachable
}

// Collect 采样当前活跃连接、合并历史增量窗口、运行非线性风险引擎并生成完整审计报告。
func (c *Collector) Collect(ctx context.Context, opts CollectOptions) *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.collectLocked(ctx, opts)
}

func purgeBlockedFlows(
	state *persistedAuditState,
	selfIPs map[string]bool,
	devDirectory map[string]lanDeviceInfo,
	engine *NonlinearEngine,
) bool {
	before := len(state.Flows)
	maps.DeleteFunc(state.Flows, func(_ string, e *persistedFlowEntry) bool {
		return e == nil || engine.IsBlocked(normalizeSourceDeviceIP(e.DeviceIP, selfIPs, devDirectory), e.Target)
	})
	return len(state.Flows) != before
}

func (c *Collector) shouldSaveSampledStateLocked(state *persistedAuditState, now time.Time) bool {
	if c.stateDirty {
		return true
	}
	stateMissingOnDisk := c.statePath != "" && (c.cachedStateFp == "" || strings.HasSuffix(c.cachedStateFp, "|missing"))
	if stateMissingOnDisk && len(state.Flows) > 0 {
		return true
	}
	return c.lastSavedUnix > 0 && now.Unix()-c.lastSavedUnix >= 3600 && len(state.Flows) > 0
}

func (c *Collector) sampleActiveLocked(ctx context.Context, now time.Time) (
	state *persistedAuditState,
	activeByKey map[string][]string,
	devDirectory map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	engine *NonlinearEngine,
	usedAddr string,
	reachable bool,
) {
	state = c.loadStateLocked(now.Unix())
	devDirectory = c.resolveLANDevicesLocked()
	selfIPs = c.resolveSelfIPsLocked()
	engine = c.resolveEngineLocked()
	activeByKey = make(map[string][]string)

	connsResp, addr, err := c.fetchConnectionsLocked(ctx)
	if err != nil || connsResp == nil {
		if len(state.Flows) > 0 {
			candIPs := make([]string, 0, len(state.Flows))
			for _, e := range state.Flows {
				if e != nil && e.DeviceIP != "" {
					candIPs = append(candIPs, e.DeviceIP)
				}
			}
			c.enrichSideRouterPTRDevicesLocked(ctx, devDirectory, selfIPs, candIPs)
		}
		if purgeBlockedFlows(state, selfIPs, devDirectory, engine) {
			c.stateDirty = true
			if c.statePath != "" {
				c.saveStateLocked(state, activeByKey, now)
			}
		}
		return state, activeByKey, devDirectory, selfIPs, engine, "", false
	}

	candIPs := make([]string, 0, len(connsResp.Connections)+len(state.Flows))
	for _, conn := range connsResp.Connections {
		if src := strings.TrimSpace(conn.Metadata.SourceIP); src != "" {
			candIPs = append(candIPs, src)
		}
	}
	for _, e := range state.Flows {
		if e != nil && e.DeviceIP != "" {
			candIPs = append(candIPs, e.DeviceIP)
		}
	}
	c.enrichSideRouterPTRDevicesLocked(ctx, devDirectory, selfIPs, candIPs)

	ingestedMutated := c.ingestConnectionsLocked(state, connsResp.Connections, devDirectory, selfIPs, activeByKey, engine, now)
	blockTrimmed := purgeBlockedFlows(state, selfIPs, devDirectory, engine)
	boundsTrimmed := c.enforceBoundsLocked(state, activeByKey, devDirectory, selfIPs, engine, now.Unix())
	if ingestedMutated || blockTrimmed || boundsTrimmed {
		c.stateDirty = true
	}
	if c.shouldSaveSampledStateLocked(state, now) {
		c.saveStateLocked(state, activeByKey, now)
	}
	return state, activeByKey, devDirectory, selfIPs, engine, addr, true
}

func engineConfigFingerprint(cfg *config.Config) string {
	if cfg == nil {
		return "nil"
	}
	var b strings.Builder
	if cfg.Audit.IsPCDNBlockEnabled() {
		b.WriteByte('1')
	} else {
		b.WriteByte('0')
	}
	b.WriteByte('|')
	b.WriteString(cfg.Server.GetNodeDomain())
	b.WriteByte('|')
	b.WriteString(cfg.Server.GetSubstoreDomain())
	b.WriteByte('|')
	b.WriteString(strings.TrimSpace(cfg.Server.ServerIP))
	for _, sub := range cfg.Subs {
		b.WriteString("|s:")
		b.WriteString(sub.URL)
	}
	for _, w := range cfg.Audit.Whitelist {
		b.WriteString("|w:")
		b.WriteString(w)
	}
	for _, r := range cfg.CustomRules.Block {
		b.WriteString("|b:")
		b.WriteString(r.SourceIP)
		b.WriteByte('@')
		b.WriteString(r.Target)
	}
	return b.String()
}

func (c *Collector) resolveEngineLocked() *NonlinearEngine {
	fp := engineConfigFingerprint(c.cfg)
	if c.cachedEngine != nil && c.cachedEngineFp == fp {
		return c.cachedEngine
	}
	c.cachedEngine = NewNonlinearEngine(c.cfg)
	c.cachedEngineFp = fp
	return c.cachedEngine
}

func (c *Collector) resolveSelfIPsLocked() map[string]bool {
	now := c.currentTimeLocked()
	ttl := cmp.Or(c.selfIPsRefreshInterval, 30*time.Second)
	if c.cachedSelfIPs != nil && !c.selfIPsFetchedAt.IsZero() && now.Sub(c.selfIPsFetchedAt) >= 0 && now.Sub(c.selfIPsFetchedAt) < ttl {
		return c.cachedSelfIPs
	}
	c.cachedSelfIPs = collectLocalInterfaceIPs()
	c.selfIPsFetchedAt = now
	return c.cachedSelfIPs
}

func newBaseAuditReport(cfg *config.Config, now time.Time) *Report {
	rep := &Report{
		GeneratedAt:   now.Format("2006-01-02 15:04:05"),
		Devices:       []DeviceSummary{},
		Flows:         []FlowRecord{},
		PCDNRuleCount: len(singbox.BuiltinPCDNDomainSuffixes),
	}
	if cfg == nil {
		rep.BlockRules = singbox.EffectiveBlockRules(nil)
		rep.BlockedCount = len(rep.BlockRules)
		rep.PCDNBlockEnabled = true
		return rep
	}
	rep.BlockRules = singbox.EffectiveBlockRules(cfg)
	rep.BlockedCount = len(rep.BlockRules)
	rep.Throttles = slices.Clone(cfg.Audit.Throttles)
	rep.Whitelist = slices.Clone(cfg.Audit.Whitelist)
	rep.WhitelistCount = len(rep.Whitelist)
	rep.DirectDevices = slices.Clone(cfg.Audit.DirectDevices)
	rep.PCDNBlockEnabled = cfg.Audit.IsPCDNBlockEnabled()
	return rep
}

func resolveFlowDeviceIdentity(normDevIP string, entry *persistedFlowEntry, devDirectory map[string]lanDeviceInfo) (name, mac string) {
	if normDevIP == "127.0.0.1" || normDevIP == "::1" {
		return "本机网关 (Localhost)", ""
	}
	name, mac = entry.DeviceName, entry.DeviceMAC
	if info, ok := devDirectory[normDevIP]; ok {
		name = cmp.Or(info.Name, name)
		mac = cmp.Or(info.MAC, mac)
	}
	return cmp.Or(name, normDevIP), mac
}

func buildRawFlowRecords(
	cfg *config.Config,
	state *persistedAuditState,
	activeByKey map[string][]string,
	liveRates map[string]flowLiveRate,
	activeDetails map[string][]ActiveConnDetail,
	devDirectory map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	engine *NonlinearEngine,
	now time.Time,
) []FlowRecord {
	rawFlows := make([]FlowRecord, 0, len(state.Flows))
	displayLoc := now.Location()
	for _, entry := range state.Flows {
		normDevIP := normalizeSourceDeviceIP(entry.DeviceIP, selfIPs, devDirectory)
		if engine.IsBlocked(normDevIP, entry.Target) {
			continue
		}
		devName, devMAC := resolveFlowDeviceIdentity(normDevIP, entry, devDirectory)
		devName = FormatFriendlyDeviceName(cfg, normDevIP, devMAC, devName)
		activeIDs := activeByKey[entry.Key]
		var curUpBps, curDownBps float64
		if len(activeIDs) > 0 && liveRates != nil {
			if lr, ok := liveRates[entry.Key]; ok {
				curUpBps = math.Round(lr.upBps*10) / 10
				curDownBps = math.Round(lr.downBps*10) / 10
			}
		}
		var subDetails []ActiveConnDetail
		if len(activeIDs) > 0 && activeDetails != nil {
			subDetails = slices.Clone(activeDetails[entry.Key])
		}
		rawFlows = append(rawFlows, FlowRecord{
			Key:                entry.Key,
			DeviceIP:           normDevIP,
			DeviceName:         devName,
			DeviceMAC:          devMAC,
			DeviceRole:         InferDeviceRole(devName),
			Target:             entry.Target,
			AppName:            IdentifyApp(entry.Target, entry.DestIP, entry.Rule, entry.RawHost),
			RawHost:            entry.RawHost,
			DestIP:             entry.DestIP,
			DestPort:           entry.DestPort,
			IsDirectIP:         entry.IsDirectIP,
			Network:            entry.Network,
			Outbound:           entry.Outbound,
			Chains:             slices.Clone(entry.Chains),
			Rule:               entry.Rule,
			UploadBytes:        entry.UploadBytes,
			DownloadBytes:      entry.DownloadBytes,
			CurrentUploadBps:   curUpBps,
			CurrentDownloadBps: curDownBps,
			ThrottledRateKBps:  matchThrottleRateKBps(cfg, entry.Target, entry.DestPort),
			ConnCount:          entry.ConnCount,
			ActiveConns:        len(activeIDs),
			ActiveConnIDs:      activeIDs,
			ActiveConnDetails:  subDetails,
			FirstSeen:          time.Unix(entry.FirstSeenUnix, 0).In(displayLoc).Format("15:04:05"),
			LastSeen:           time.Unix(entry.LastSeenUnix, 0).In(displayLoc).Format("15:04:05"),
			LastSeenUnix:       entry.LastSeenUnix,
			ActiveSpanSec:      max(int64(60), entry.LastSeenUnix-entry.FirstSeenUnix),
			NightHits:          entry.NightHits,
			IntervalCV:         computeIntervalCV(entry.ArrivalsUnix),
			AIReview:           LookupCachedAIReview(entry.Target),
		})
	}
	return rawFlows
}

func isIPv4Literal(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	return p != nil && p.To4() != nil
}

func accumulateDeviceSummary(deviceAgg map[string]*DeviceSummary, rec FlowRecord, rep *Report) {
	macNorm := strings.ToLower(strings.TrimSpace(rec.DeviceMAC))
	aggKey := rec.DeviceIP
	if macNorm != "" {
		aggKey = "mac:" + macNorm
	}
	ds, exists := deviceAgg[aggKey]
	if !exists {
		ds = &DeviceSummary{
			DeviceIP:   rec.DeviceIP,
			DeviceName: rec.DeviceName,
			DeviceMAC:  macNorm,
			DeviceRole: rec.DeviceRole,
		}
		deviceAgg[aggKey] = ds
	} else {
		if isIPv4Literal(rec.DeviceIP) && !isIPv4Literal(ds.DeviceIP) {
			ds.DeviceIP = rec.DeviceIP
		}
		if rec.DeviceName != "" && rec.DeviceName != rec.DeviceIP && (ds.DeviceName == "" || ds.DeviceName == ds.DeviceIP) {
			ds.DeviceName = rec.DeviceName
			ds.DeviceRole = InferDeviceRole(ds.DeviceName)
		}
	}

	ds.UploadBytes += rec.UploadBytes
	ds.DownloadBytes += rec.DownloadBytes
	ds.FlowCount++
	ds.ActiveConns += rec.ActiveConns
	if rec.State != EnforcementObserved {
		return
	}
	ds.MaxSecurityScore = max(ds.MaxSecurityScore, rec.SecurityScore)
	ds.MaxPrivacyScore = max(ds.MaxPrivacyScore, rec.PrivacyScore)
	ds.MaxRiskScore = max(ds.MaxRiskScore, rec.RiskScore)
	switch rec.Threat {
	case ThreatHighRisk:
		ds.HighRiskCount++
		rep.HighRiskFlows++
		rep.SuspiciousFlows++
	case ThreatSuspicious:
		ds.SuspiciousCount++
		rep.SuspiciousFlows++
	}
}

func flowMatchesCollectFilter(rec FlowRecord, lowerFilter string, onlySuspect bool) bool {
	if onlySuspect && (rec.State != EnforcementObserved || (rec.RiskScore < 35 && rec.Threat == ThreatNormal)) {
		return false
	}
	if lowerFilter == "" {
		return true
	}
	if rec.SubnetCluster != nil && strings.Contains(strings.ToLower(rec.SubnetCluster.CIDR), lowerFilter) {
		return true
	}
	for _, field := range []string{rec.DeviceIP, rec.DeviceName, rec.DeviceMAC, rec.Target, rec.AppName} {
		if strings.Contains(strings.ToLower(field), lowerFilter) {
			return true
		}
	}
	return false
}

func evaluateAndFilterFlows(
	engine *NonlinearEngine,
	rawFlows []FlowRecord,
	opts CollectOptions,
	rep *Report,
) ([]FlowRecord, map[string]*DeviceSummary) {
	engine.AnnotateDirectIPSubnetClusters(rawFlows)
	engine.AnnotatePCDNSwarmBehaviors(rawFlows)

	lowerFilter := strings.ToLower(strings.TrimSpace(opts.DeviceFilter))
	deviceAgg := make(map[string]*DeviceSummary)
	filtered := make([]FlowRecord, 0, len(rawFlows))
	for i := range rawFlows {
		engine.EvaluateFlow(&rawFlows[i])
		rec := rawFlows[i]
		if rec.PCDNKind != "" {
			rep.PCDNDetectedFlows++
		}
		accumulateDeviceSummary(deviceAgg, rec, rep)
		if flowMatchesCollectFilter(rec, lowerFilter, opts.OnlySuspect) {
			filtered = append(filtered, rec)
		}
	}
	return filtered, deviceAgg
}

func buildSortedDeviceSummaries(deviceAgg map[string]*DeviceSummary, cfg *config.Config) []DeviceSummary {
	devices := make([]DeviceSummary, 0, len(deviceAgg))
	for _, ds := range deviceAgg {
		denom := float64(ds.DownloadBytes) + 65536.0
		ds.UploadRatio = math.Round((float64(ds.UploadBytes)/denom)*100) / 100
		ds.AllowOverseas = cfg == nil || cfg.Audit.IsDeviceOverseasAllowed(ds.DeviceIP)
		devices = append(devices, *ds)
	}
	slices.SortFunc(devices, func(a, b DeviceSummary) int {
		if c := cmp.Compare(b.HighRiskCount, a.HighRiskCount); c != 0 {
			return c
		}
		if c := cmp.Compare(b.SuspiciousCount, a.SuspiciousCount); c != 0 {
			return c
		}
		return cmp.Compare(b.UploadBytes, a.UploadBytes)
	})
	return devices
}

func truncateFlowsToLimit(flows []FlowRecord, limit int) []FlowRecord {
	if limit == 0 && len(flows) > 100 {
		return flows[:100]
	}
	if limit > 0 && len(flows) > limit {
		return flows[:limit]
	}
	return flows
}

func reviewAndReEvaluateWithAI(
	ctx context.Context,
	advisor *Advisor,
	engine *NonlinearEngine,
	flows []FlowRecord,
	opts CollectOptions,
) []FlowRecord {
	advisor.ReviewSuspiciousFlows(ctx, flows, opts.CallerIP)
	reEvaluated := false
	for i := range flows {
		rev := flows[i].AIReview
		if rev == nil || rev.Verdict != AIDoNotBlock || flows[i].RiskScore <= 28 {
			continue
		}
		if rev.Source != "" && rev.Source != "builtin_expert" && rev.Source != "trusted_baseline" {
			engine.EvaluateFlow(&flows[i])
			reEvaluated = true
		}
	}
	if reEvaluated {
		SortFlows(flows, opts.SortBy, opts.SortAsc)
	}
	return flows
}

func (c *Collector) collectLocked(ctx context.Context, opts CollectOptions) *Report {
	now := c.nowFunc()
	rep := newBaseAuditReport(c.cfg, now)

	state, activeByKey, devDirectory, selfIPs, engine, usedAddr, reachable := c.sampleActiveLocked(ctx, now)
	if !reachable {
		if len(state.Flows) == 0 {
			rep.Message = "未检测到运行中的 sing-box 代理实例 (Clash API 不可达)"
			return rep
		}
		rep.Message = "当前 sing-box 控制端口不可达，正在展示最近缓存的设备审计快照"
	} else {
		rep.Reachable = true
		rep.ControllerAddr = usedAddr
	}

	rawFlows := buildRawFlowRecords(c.cfg, state, activeByKey, c.flowLiveRates, c.flowActiveDetails, devDirectory, selfIPs, engine, now)
	allFlows, deviceAgg := evaluateAndFilterFlows(engine, rawFlows, opts, rep)
	rep.TotalFlows = len(state.Flows)
	rep.Devices = buildSortedDeviceSummaries(deviceAgg, c.cfg)

	SortFlows(allFlows, opts.SortBy, opts.SortAsc)
	allFlows = truncateFlowsToLimit(allFlows, opts.Limit)

	advisor := NewAdvisor(c.auditAIConfig())
	rep.AIEnabled = opts.EnableAI || advisor.IsRemoteLLMConfigured()
	if opts.EnableAI {
		allFlows = reviewAndReEvaluateWithAI(ctx, advisor, engine, allFlows, opts)
	}
	rep.Flows = allFlows
	return rep
}

func (c *Collector) auditAIConfig() config.AuditAIConfig {
	if c.cfg == nil {
		return config.AuditAIConfig{}
	}
	return c.cfg.Audit.AI
}
