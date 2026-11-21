// 文件职责：定义审计采集器 Collector 聚合入口、生命周期控制（Collect / SampleActiveConnections）及多维引擎协调流水线。
package audit

import (
	"cmp"
	"context"
	"maps"
	"math"
	"net"
	"net/http"
	"singctl/internal/config"
	"singctl/internal/singbox"
	"slices"
	"strings"
	"sync"
	"time"
)

// Collector 负责从 sing-box Clash API 采集连接、关联局域网 DHCP/ARP 设备名并执行多维非线性分析。
type Collector struct {
	mu                 sync.Mutex
	cfg                *config.Config
	statePath          string
	endpoints          []string
	secret             string
	customEndpoints    bool
	httpClient         *http.Client
	leaseFiles         []string
	arpFile            string
	hostsFile          string
	odhcpdHostsFile    string
	tzFile             string
	uciSystemFile      string
	nowFunc            func() time.Time
	ipv6NeighCmdFunc   func() ([]byte, error)
	cachedState        *persistedAuditState
	cachedStateFp      string
	stateDirty         bool
	lastSavedUnix      int64
	cachedEngine       *NonlinearEngine
	cachedEngineFp     string
	cachedSelfIPs      map[string]bool
	selfIPsFetchedAt   time.Time
	cachedLeaseFp      string
	cachedLeaseDevs    map[string]lanDeviceInfo
	ipv6NeighCache     map[string]string
	ipv6NeighFetchedAt time.Time
}

// NewCollector 创建默认客户端审计采集器（自动兼容 OpenWrt /etc/TZ 与 /etc/config/system 本地时区）。
func NewCollector(cfg *config.Config) *Collector {
	c := &Collector{
		cfg:       cfg,
		statePath: defaultStatePath(),
		endpoints: singbox.ClashAPIEndpoints(),
		secret:    singbox.ClashAPISecret(),
		httpClient: &http.Client{
			Timeout: 2500 * time.Millisecond,
			Transport: &http.Transport{
				Proxy:               nil,
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
		},
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
	return c
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
}

// SetNowFuncForTest 供单元测试注入确定性时钟（例如模拟凌晨 03:00 行为）。
func (c *Collector) SetNowFuncForTest(fn func() time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if fn != nil {
		c.nowFunc = fn
	}
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
	if err == nil && connsResp != nil {
		reachable = true
		usedAddr = addr
		ingestedMutated := c.ingestConnectionsLocked(state, connsResp.Connections, devDirectory, selfIPs, activeByKey, engine, now)
		beforeBlockTrim := len(state.Flows)
		maps.DeleteFunc(state.Flows, func(_ string, e *persistedFlowEntry) bool {
			return e == nil || engine.IsBlocked(normalizeSourceDeviceIP(e.DeviceIP, selfIPs, devDirectory), e.Target)
		})
		blockTrimmed := len(state.Flows) != beforeBlockTrim

		// 脏写节流优化：15s 后台采样若无新连接、流量增量为 0、且未触发规则/TTL 清理时，
		// 跳过 `/tmp` JSON 全量编码与原子 rename，仅每小时兜底刷盘保活时间戳，显著降低软路由 CPU 与 GC 分配。
		if ingestedMutated || blockTrimmed {
			c.stateDirty = true
		}
		stateMissingOnDisk := c.statePath != "" && (c.cachedStateFp == "" || strings.HasSuffix(c.cachedStateFp, "|missing"))
		idleHeartbeatDue := c.lastSavedUnix > 0 && now.Unix()-c.lastSavedUnix >= 3600 && len(state.Flows) > 0
		if c.stateDirty || (stateMissingOnDisk && len(state.Flows) > 0) || idleHeartbeatDue {
			c.saveStateLocked(state, activeByKey, now)
		}
	} else {
		beforeBlockTrim := len(state.Flows)
		maps.DeleteFunc(state.Flows, func(_ string, e *persistedFlowEntry) bool {
			return e == nil || engine.IsBlocked(normalizeSourceDeviceIP(e.DeviceIP, selfIPs, devDirectory), e.Target)
		})
		if len(state.Flows) != beforeBlockTrim {
			c.stateDirty = true
			if c.statePath != "" {
				c.saveStateLocked(state, activeByKey, now)
			}
		}
	}
	return state, activeByKey, devDirectory, selfIPs, engine, usedAddr, reachable
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
	now := time.Now()
	if c.cachedSelfIPs != nil && now.Sub(c.selfIPsFetchedAt) < 30*time.Second {
		return c.cachedSelfIPs
	}
	c.cachedSelfIPs = collectLocalInterfaceIPs()
	c.selfIPsFetchedAt = now
	return c.cachedSelfIPs
}

func (c *Collector) collectLocked(ctx context.Context, opts CollectOptions) *Report {

	now := c.nowFunc()
	rep := &Report{
		GeneratedAt: now.Format("2006-01-02 15:04:05"),
		Devices:     []DeviceSummary{},
		Flows:       []FlowRecord{},
	}
	if c.cfg != nil {
		rep.BlockRules = singbox.EffectiveBlockRules(c.cfg)
		rep.BlockedCount = len(rep.BlockRules)
		rep.Throttles = slices.Clone(c.cfg.Audit.Throttles)
		rep.Whitelist = slices.Clone(c.cfg.Audit.Whitelist)
		rep.WhitelistCount = len(rep.Whitelist)
		rep.PCDNBlockEnabled = c.cfg.Audit.IsPCDNBlockEnabled()
	} else {
		rep.BlockRules = singbox.EffectiveBlockRules(nil)
		rep.BlockedCount = len(rep.BlockRules)
		rep.PCDNBlockEnabled = true
	}
	rep.PCDNRuleCount = len(singbox.BuiltinPCDNDomainSuffixes)

	state, activeByKey, devDirectory, selfIPs, engine, usedAddr, reachable := c.sampleActiveLocked(ctx, now)
	if reachable {
		rep.Reachable = true
		rep.ControllerAddr = usedAddr
	} else {
		rep.Reachable = false
		if len(state.Flows) > 0 {
			rep.Message = "当前 sing-box 控制端口不可达，正在展示最近缓存的设备审计快照"
		} else {
			rep.Message = "未检测到运行中的 sing-box 代理实例 (Clash API 不可达)"
			return rep
		}
	}

	rawFlows := make([]FlowRecord, 0, len(state.Flows))
	allFlows := make([]FlowRecord, 0, len(state.Flows))
	deviceAgg := make(map[string]*DeviceSummary)
	lowerFilter := strings.ToLower(strings.TrimSpace(opts.DeviceFilter))

	for _, entry := range state.Flows {
		normDevIP := normalizeSourceDeviceIP(entry.DeviceIP, selfIPs, devDirectory)
		if engine.IsBlocked(normDevIP, entry.Target) {
			continue
		}
		devName, devMAC := entry.DeviceName, entry.DeviceMAC
		if info, ok := devDirectory[normDevIP]; ok {
			if info.Name != "" {
				devName = info.Name
			}
			if info.MAC != "" {
				devMAC = info.MAC
			}
		}
		if normDevIP == "127.0.0.1" || normDevIP == "::1" {
			devName = "本机网关 (Localhost)"
			devMAC = ""
		} else if devName == "" {
			devName = normDevIP
		}

		activeIDs := activeByKey[entry.Key]
		appName := IdentifyApp(entry.Target, entry.DestIP, entry.Rule, entry.RawHost)
		cachedAI := LookupCachedAIReview(entry.Target)
		activeSpanSec := max(int64(60), entry.LastSeenUnix-entry.FirstSeenUnix)
		displayLoc := now.Location()
		rawFlows = append(rawFlows, FlowRecord{
			Key:               entry.Key,
			DeviceIP:          normDevIP,
			DeviceName:        devName,
			DeviceMAC:         devMAC,
			DeviceRole:        InferDeviceRole(devName),
			Target:            entry.Target,
			AppName:           appName,
			RawHost:           entry.RawHost,
			DestIP:            entry.DestIP,
			DestPort:          entry.DestPort,
			IsDirectIP:        entry.IsDirectIP,
			Network:           entry.Network,
			Outbound:          entry.Outbound,
			Chains:            slices.Clone(entry.Chains),
			Rule:              entry.Rule,
			UploadBytes:       entry.UploadBytes,
			DownloadBytes:     entry.DownloadBytes,
			ThrottledRateKBps: matchThrottleRateKBps(c.cfg, entry.Target, entry.DestPort),
			ConnCount:         entry.ConnCount,
			ActiveConns:       len(activeIDs),
			ActiveConnIDs:     activeIDs,
			FirstSeen:         time.Unix(entry.FirstSeenUnix, 0).In(displayLoc).Format("15:04:05"),
			LastSeen:          time.Unix(entry.LastSeenUnix, 0).In(displayLoc).Format("15:04:05"),
			ActiveSpanSec:     activeSpanSec,
			NightHits:         entry.NightHits,
			IntervalCV:        computeIntervalCV(entry.ArrivalsUnix),
			AIReview:          cachedAI,
		})
	}

	// 先在全局层面按 (设备, 目的网段) 聚合标注纯裸 IP 同网段聚集簇与跨网段 UDP 蜂群，再逐条评分汇总
	engine.AnnotateDirectIPSubnetClusters(rawFlows)
	engine.AnnotatePCDNSwarmBehaviors(rawFlows)

	for i := range rawFlows {
		engine.EvaluateFlow(&rawFlows[i])
		rec := rawFlows[i]
		if rec.PCDNKind != "" {
			rep.PCDNDetectedFlows++
		}

		// 更新设备维度汇总（同 MAC 的双栈 IPv4/IPv6 流量归并至同一物理设备，优先展示 IPv4 地址；已拉黑或白名单目标不计入活跃告警）
		macNorm := strings.ToLower(strings.TrimSpace(rec.DeviceMAC))
		aggKey := rec.DeviceIP
		if macNorm != "" {
			aggKey = "mac:" + macNorm
		}
		ds, ok := deviceAgg[aggKey]
		if !ok {
			ds = &DeviceSummary{
				DeviceIP:   rec.DeviceIP,
				DeviceName: rec.DeviceName,
				DeviceMAC:  macNorm,
				DeviceRole: rec.DeviceRole,
			}
			deviceAgg[aggKey] = ds
		} else {
			recIsV4 := func(ip string) bool {
				p := net.ParseIP(strings.TrimSpace(ip))
				return p != nil && p.To4() != nil
			}
			if recIsV4(rec.DeviceIP) && !recIsV4(ds.DeviceIP) {
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
		if rec.State == EnforcementObserved {
			if rec.SecurityScore > ds.MaxSecurityScore {
				ds.MaxSecurityScore = rec.SecurityScore
			}
			if rec.PrivacyScore > ds.MaxPrivacyScore {
				ds.MaxPrivacyScore = rec.PrivacyScore
			}
			if rec.RiskScore > ds.MaxRiskScore {
				ds.MaxRiskScore = rec.RiskScore
			}
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

		// 过滤条件检查（支持按设备 IP、设备名称、MAC、目标域名、所属目的网段 CIDR 或识别出的应用名过滤）
		if lowerFilter != "" {
			cidrMatch := rec.SubnetCluster != nil && strings.Contains(strings.ToLower(rec.SubnetCluster.CIDR), lowerFilter)
			if !cidrMatch &&
				!strings.Contains(strings.ToLower(rec.DeviceIP), lowerFilter) &&
				!strings.Contains(strings.ToLower(rec.DeviceName), lowerFilter) &&
				!strings.Contains(strings.ToLower(rec.DeviceMAC), lowerFilter) &&
				!strings.Contains(strings.ToLower(rec.Target), lowerFilter) &&
				!strings.Contains(strings.ToLower(rec.AppName), lowerFilter) {
				continue
			}
		}
		if opts.OnlySuspect && (rec.State != EnforcementObserved || (rec.RiskScore < 35 && rec.Threat == ThreatNormal)) {
			continue
		}
		allFlows = append(allFlows, rec)
	}

	rep.TotalFlows = len(state.Flows)

	// 设备排行按最高风险分 + 上传流量降序排列
	for _, ds := range deviceAgg {
		denom := float64(ds.DownloadBytes) + 65536.0
		ds.UploadRatio = math.Round((float64(ds.UploadBytes)/denom)*100) / 100
		rep.Devices = append(rep.Devices, *ds)
	}
	slices.SortFunc(rep.Devices, func(a, b DeviceSummary) int {
		if c := cmp.Compare(b.HighRiskCount, a.HighRiskCount); c != 0 {
			return c
		}
		if c := cmp.Compare(b.SuspiciousCount, a.SuspiciousCount); c != 0 {
			return c
		}
		return cmp.Compare(b.UploadBytes, a.UploadBytes)
	})

	// 流量列表在截断前按指定字段（默认 "active"：活跃置顶 -> 处置态 -> 威胁等级 -> 风险评分 -> 活跃连接数 -> 上传流量）排序
	SortFlows(allFlows, opts.SortBy, opts.SortAsc)

	if opts.Limit == 0 {
		if len(allFlows) > 100 {
			allFlows = allFlows[:100]
		}
	} else if opts.Limit > 0 && len(allFlows) > opts.Limit {
		allFlows = allFlows[:opts.Limit]
	}

	advisor := NewAdvisor(c.auditAIConfig())
	rep.AIEnabled = opts.EnableAI || advisor.IsRemoteLLMConfigured()
	if opts.EnableAI {
		advisor.ReviewSuspiciousFlows(ctx, allFlows, opts.CallerIP)
		// 当同步开启 --ai 时，若真实大模型复核结论为 AIDoNotBlock，立即执行闭环降权重算并重排
		reEvaluated := false
		for i := range allFlows {
			if rev := allFlows[i].AIReview; rev != nil && rev.Verdict == AIDoNotBlock &&
				rev.Source != "" && rev.Source != "builtin_expert" && rev.Source != "trusted_baseline" &&
				allFlows[i].RiskScore > 28 {
				engine.EvaluateFlow(&allFlows[i])
				reEvaluated = true
			}
		}
		if reEvaluated {
			SortFlows(allFlows, opts.SortBy, opts.SortAsc)
		}
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
