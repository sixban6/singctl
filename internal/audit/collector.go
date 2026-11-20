package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

const (
	maxPersistedFlows       = 1500
	maxTrackedConnDeltas    = 3000
	maxArrivalSamples       = 16
	flowIdleTTLSeconds      = 86400 // 超过 24 小时无流量活动的陈旧流自动淘汰
	currentAuditStateSchema = 2
)

// defaultStatePath 返回设备审计增量快照文件的默认路径（位于 /tmp 内存盘，绝不磨损 OpenWrt 闪存）。
func defaultStatePath() string {
	return filepath.Join(os.TempDir(), "singctl-audit-state.json")
}

// clashConnectionsResponse 对应 sing-box Clash API GET /connections 响应结构。
type clashConnectionsResponse struct {
	DownloadTotal int64             `json:"downloadTotal"`
	UploadTotal   int64             `json:"uploadTotal"`
	Connections   []clashConnection `json:"connections"`
}

type clashConnection struct {
	ID          string   `json:"id"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	Start       string   `json:"start"`
	Chains      []string `json:"chains"`
	Rule        string   `json:"rule"`
	RulePayload string   `json:"rulePayload"`
	Metadata    struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		DestinationIP   string `json:"destinationIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
		SniffHost       string `json:"sniffHost,omitempty"`
	} `json:"metadata"`
}

// persistedFlowEntry 保存单条聚合流的历史累计统计与建连时间序列（用于计算变异系数 CV）。
type persistedFlowEntry struct {
	Key           string   `json:"key"`
	DeviceIP      string   `json:"deviceIp"`
	DeviceName    string   `json:"deviceName,omitempty"`
	DeviceMAC     string   `json:"deviceMac,omitempty"`
	Target        string   `json:"target"`
	RawHost       string   `json:"rawHost,omitempty"`
	DestIP        string   `json:"destIp,omitempty"`
	DestPort      int      `json:"destPort"`
	IsDirectIP    bool     `json:"isDirectIp"`
	Network       string   `json:"network"`
	Outbound      string   `json:"outbound"`
	Chains        []string `json:"chains,omitempty"`
	Rule          string   `json:"rule,omitempty"`
	UploadBytes   int64    `json:"uploadBytes"`
	DownloadBytes int64    `json:"downloadBytes"`
	ConnCount     int      `json:"connCount"`
	FirstSeenUnix int64    `json:"firstSeenUnix"`
	LastSeenUnix  int64    `json:"lastSeenUnix"`
	NightHits     int      `json:"nightHits"`
	ArrivalsUnix  []int64  `json:"arrivalsUnix,omitempty"`
}

type connByteCursor struct {
	Upload   int64 `json:"up"`
	Download int64 `json:"down"`
	SeenUnix int64 `json:"ts"`
}

type persistedAuditState struct {
	SchemaVersion int                            `json:"schemaVersion,omitempty"`
	UpdatedUnix   int64                          `json:"updatedUnix"`
	Flows         map[string]*persistedFlowEntry `json:"flows"`
	ConnCursors   map[string]connByteCursor      `json:"connCursors"`
}

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
				MaxIdleConns:        8,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     60 * time.Second,
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

// Collect 采样当前活跃连接、合并历史增量窗口、运行非线性风险引擎并生成完整审计报告。
func (c *Collector) Collect(ctx context.Context, opts CollectOptions) *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.collectLocked(ctx, opts)
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
		rep.Whitelist = slices.Clone(c.cfg.Audit.Whitelist)
		rep.WhitelistCount = len(rep.Whitelist)
		rep.PCDNBlockEnabled = c.cfg.Audit.IsPCDNBlockEnabled()
	} else {
		rep.BlockRules = singbox.EffectiveBlockRules(nil)
		rep.BlockedCount = len(rep.BlockRules)
		rep.PCDNBlockEnabled = true
	}
	rep.PCDNRuleCount = len(singbox.BuiltinPCDNDomainSuffixes)

	state := c.loadStateLocked(now.Unix())
	devDirectory := c.resolveLANDevicesLocked()
	selfIPs := collectLocalInterfaceIPs()
	engine := NewNonlinearEngine(c.cfg)

	connsResp, usedAddr, err := c.fetchConnectionsLocked(ctx)
	activeByKey := make(map[string][]string)
	if err == nil && connsResp != nil {
		rep.Reachable = true
		rep.ControllerAddr = usedAddr
		c.ingestConnectionsLocked(state, connsResp.Connections, devDirectory, selfIPs, activeByKey, engine, now)
		maps.DeleteFunc(state.Flows, func(_ string, e *persistedFlowEntry) bool {
			return e == nil || engine.IsBlocked(normalizeSourceDeviceIP(e.DeviceIP, selfIPs, devDirectory), e.Target)
		})
		c.saveStateLocked(state, activeByKey, now)
	} else {
		maps.DeleteFunc(state.Flows, func(_ string, e *persistedFlowEntry) bool {
			return e == nil || engine.IsBlocked(normalizeSourceDeviceIP(e.DeviceIP, selfIPs, devDirectory), e.Target)
		})
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
			Key:           entry.Key,
			DeviceIP:      normDevIP,
			DeviceName:    devName,
			DeviceMAC:     devMAC,
			DeviceRole:    InferDeviceRole(devName),
			Target:        entry.Target,
			AppName:       appName,
			RawHost:       entry.RawHost,
			DestIP:        entry.DestIP,
			DestPort:      entry.DestPort,
			IsDirectIP:    entry.IsDirectIP,
			Network:       entry.Network,
			Outbound:      entry.Outbound,
			Chains:        slices.Clone(entry.Chains),
			Rule:          entry.Rule,
			UploadBytes:   entry.UploadBytes,
			DownloadBytes: entry.DownloadBytes,
			ConnCount:     entry.ConnCount,
			ActiveConns:   len(activeIDs),
			ActiveConnIDs: activeIDs,
			FirstSeen:     time.Unix(entry.FirstSeenUnix, 0).In(displayLoc).Format("15:04:05"),
			LastSeen:      time.Unix(entry.LastSeenUnix, 0).In(displayLoc).Format("15:04:05"),
			ActiveSpanSec: activeSpanSec,
			NightHits:     entry.NightHits,
			IntervalCV:    computeIntervalCV(entry.ArrivalsUnix),
			AIReview:      cachedAI,
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

func (c *Collector) fetchConnectionsLocked(ctx context.Context) (*clashConnectionsResponse, string, error) {
	var lastErr error
	for _, ep := range c.endpoints {
		u := strings.TrimRight(ep, "/") + "/connections"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if c.secret != "" {
			req.Header.Set("Authorization", "Bearer "+c.secret)
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("clash api %s returned %d", ep, resp.StatusCode)
			continue
		}
		var parsed clashConnectionsResponse
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if decErr != nil {
			lastErr = decErr
			continue
		}
		return &parsed, ep, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no clash api endpoints available")
	}
	return nil, "", lastErr
}

func (c *Collector) ingestConnectionsLocked(
	state *persistedAuditState,
	conns []clashConnection,
	devDir map[string]lanDeviceInfo,
	selfIPs map[string]bool,
	activeByKey map[string][]string,
	engine *NonlinearEngine,
	now time.Time,
) {
	nowUnix := now.Unix()
	hour := now.Hour()
	isNight := hour >= 1 && hour <= 5

	for _, conn := range conns {
		rawSrc := cmp.Or(strings.TrimSpace(conn.Metadata.SourceIP), "127.0.0.1")
		srcIP := normalizeSourceDeviceIP(rawSrc, selfIPs, devDir)
		network := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
		destPort, _ := strconv.Atoi(strings.TrimSpace(conn.Metadata.DestinationPort))
		rawHost, destIP, target, isDirectIP := resolveConnTarget(conn)
		if target == "" {
			continue
		}
		if len(conn.Chains) > 0 && strings.EqualFold(conn.Chains[0], "block") {
			continue
		}
		if engine != nil && engine.IsBlocked(srcIP, target) {
			continue
		}

		// 计算该连接自上次采样以来的增量字节（支持长连接持续累加且不丢历史）
		var deltaUp, deltaDown int64
		isNewConn := false
		if prev, seen := state.ConnCursors[conn.ID]; seen {
			if conn.Upload >= prev.Upload {
				deltaUp = conn.Upload - prev.Upload
			} else {
				deltaUp = conn.Upload
			}
			if conn.Download >= prev.Download {
				deltaDown = conn.Download - prev.Download
			} else {
				deltaDown = conn.Download
			}
		} else {
			isNewConn = true
			deltaUp = conn.Upload
			deltaDown = conn.Download
		}
		state.ConnCursors[conn.ID] = connByteCursor{
			Upload:   conn.Upload,
			Download: conn.Download,
			SeenUnix: nowUnix,
		}

		key := srcIP + "|" + target + "|" + network
		activeByKey[key] = append(activeByKey[key], conn.ID)

		entry, exists := state.Flows[key]
		if !exists {
			entry = &persistedFlowEntry{
				Key:           key,
				DeviceIP:      srcIP,
				Target:        target,
				RawHost:       rawHost,
				DestIP:        destIP,
				DestPort:      destPort,
				IsDirectIP:    isDirectIP,
				Network:       network,
				FirstSeenUnix: nowUnix,
			}
			state.Flows[key] = entry
		}

		entry.LastSeenUnix = nowUnix
		entry.UploadBytes += deltaUp
		entry.DownloadBytes += deltaDown
		if entry.RawHost == "" && rawHost != "" {
			entry.RawHost = rawHost
		}
		if destPort > 0 {
			entry.DestPort = destPort
		}
		if destIP != "" {
			entry.DestIP = destIP
		}
		if len(conn.Chains) > 0 {
			entry.Outbound = conn.Chains[0]
			chains := make([]string, 0, len(conn.Chains))
			for i := len(conn.Chains) - 1; i >= 0; i-- {
				hop := strings.TrimSpace(conn.Chains[i])
				if hop != "" && !slices.Contains(chains, hop) {
					chains = append(chains, hop)
				}
			}
			if len(chains) > 0 {
				entry.Chains = chains
			}
		}
		if conn.Rule != "" {
			if conn.RulePayload != "" {
				entry.Rule = conn.Rule + "(" + conn.RulePayload + ")"
			} else {
				entry.Rule = conn.Rule
			}
		}
		if devInfo, ok := devDir[srcIP]; ok {
			entry.DeviceName = devInfo.Name
			entry.DeviceMAC = devInfo.MAC
		}

		if isNewConn {
			entry.ConnCount++
			if isNight && deltaUp > 0 {
				entry.NightHits++
			}
			connStartUnix := nowUnix
			if parsedStart, err := time.Parse(time.RFC3339Nano, conn.Start); err == nil {
				connStartUnix = parsedStart.Unix()
			}
			entry.ArrivalsUnix = append(entry.ArrivalsUnix, connStartUnix)
			if len(entry.ArrivalsUnix) > maxArrivalSamples {
				entry.ArrivalsUnix = entry.ArrivalsUnix[len(entry.ArrivalsUnix)-maxArrivalSamples:]
			}
		}
	}
}

// computeIntervalCV 计算建连时间序列的间隔变异系数 CV = sigma / mu。
func computeIntervalCV(arrivals []int64) float64 {
	if len(arrivals) < 4 {
		return 0
	}
	sorted := slices.Clone(arrivals)
	slices.Sort(sorted)

	intervals := make([]float64, 0, len(sorted)-1)
	for i := 1; i < len(sorted); i++ {
		diff := float64(sorted[i] - sorted[i-1])
		if diff >= 0.5 { // 忽略同一毫秒并发建连簇，聚焦周期性间隔
			intervals = append(intervals, diff)
		}
	}
	if len(intervals) < 3 {
		return 0
	}

	var sum float64
	for _, iv := range intervals {
		sum += iv
	}
	mean := sum / float64(len(intervals))
	if mean <= 0.1 {
		return 0
	}

	var sqDiffSum float64
	for _, iv := range intervals {
		d := iv - mean
		sqDiffSum += d * d
	}
	stdDev := math.Sqrt(sqDiffSum / float64(len(intervals)))
	cv := stdDev / mean
	return math.Round(cv*1000) / 1000
}

type lanDeviceInfo struct {
	Name string
	MAC  string
}

func auditFileFingerprint(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	info, err := os.Stat(path)
	if err != nil {
		return path + "|missing"
	}
	return fmt.Sprintf("%s|%d|%d", path, info.ModTime().UnixNano(), info.Size())
}

// parseIPv6Neighbors 解析 `ip -6 neigh show` 输出，提取规范化 IPv6 地址到小写 MAC 的映射。
func parseIPv6Neighbors(raw string) map[string]string {
	out := make(map[string]string)
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 4 {
			continue
		}
		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !addr.Is6() {
			continue
		}
		llIdx := slices.Index(fields, "lladdr")
		if llIdx < 0 || llIdx+1 >= len(fields) {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(fields[llIdx+1]))
		if mac == "" || mac == "00:00:00:00:00:00" || !strings.Contains(mac, ":") {
			continue
		}
		out[addr.String()] = mac
	}
	return out
}

// resolveLANDevicesLocked 从 OpenWrt / Linux DHCP 租约、odhcpd 主机表、ARP/IPv6 邻居表与 /etc/hosts 解析内网 IP 对应的设备主机名与 MAC。
// 对磁盘租约与 hosts 文件采用 mtime+size 指纹校验：未变更时 0 磁盘读取，变更瞬间立即失效重读。
func (c *Collector) resolveLANDevicesLocked() map[string]lanDeviceInfo {
	var fpBuilder strings.Builder
	fpBuilder.WriteString(auditFileFingerprint(c.hostsFile))
	fpBuilder.WriteByte(';')
	fpBuilder.WriteString(auditFileFingerprint(c.odhcpdHostsFile))
	for _, path := range c.leaseFiles {
		fpBuilder.WriteByte(';')
		fpBuilder.WriteString(auditFileFingerprint(path))
	}
	leaseFp := fpBuilder.String()

	var base map[string]lanDeviceInfo
	if c.cachedLeaseDevs != nil && c.cachedLeaseFp == leaseFp {
		base = maps.Clone(c.cachedLeaseDevs)
	} else {
		base = make(map[string]lanDeviceInfo)
		// 1. 解析 /etc/hosts 与 /tmp/hosts/odhcpd
		for _, hostPath := range []string{c.hostsFile, c.odhcpdHostsFile} {
			if strings.TrimSpace(hostPath) == "" {
				continue
			}
			raw, err := os.ReadFile(hostPath)
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					if addr, parseErr := netip.ParseAddr(fields[0]); parseErr == nil {
						canonIP := addr.Unmap().String()
						host := fields[1]
						if host != "localhost" && !strings.HasPrefix(host, "ip6-") {
							prev := base[canonIP]
							prev.Name = cmp.Or(host, prev.Name)
							base[canonIP] = prev
						}
					}
				}
			}
		}

		// 2. 解析 dnsmasq / OpenWrt /tmp/dhcp.leases (<expiry> <mac> <ip> <hostname> <client-id>)
		for _, path := range c.leaseFiles {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			for line := range strings.SplitSeq(string(raw), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) < 4 {
					continue
				}
				mac, ip, host := strings.ToLower(strings.TrimSpace(fields[1])), fields[2], fields[3]
				if net.ParseIP(ip) == nil {
					continue
				}
				if host == "*" {
					host = ""
				}
				prev := base[ip]
				base[ip] = lanDeviceInfo{
					Name: cmp.Or(host, prev.Name),
					MAC:  cmp.Or(mac, prev.MAC),
				}
			}
		}
		c.cachedLeaseDevs = maps.Clone(base)
		c.cachedLeaseFp = leaseFp
	}

	// 3. 实时补充 /proc/net/arp 中的动态 MAC 地址（内核虚拟内存文件，零磁盘开销）
	if raw, err := os.ReadFile(c.arpFile); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 4 && net.ParseIP(fields[0]) != nil && strings.Contains(fields[3], ":") {
				ip, mac := fields[0], strings.ToLower(strings.TrimSpace(fields[3]))
				if mac != "00:00:00:00:00:00" {
					prev := base[ip]
					prev.MAC = cmp.Or(prev.MAC, mac)
					base[ip] = prev
				}
			}
		}
	}

	// 4. 缓存刷新 IPv6 邻居表 (15 秒 TTL)，将同一物理设备的 IPv6 地址按 MAC 归并至其 IPv4 主机名
	now := time.Now()
	if c.ipv6NeighCmdFunc != nil || (!c.customEndpoints && runtime.GOOS == "linux") {
		if c.ipv6NeighCache == nil || now.Sub(c.ipv6NeighFetchedAt) > 15*time.Second {
			var out []byte
			var err error
			if c.ipv6NeighCmdFunc != nil {
				out, err = c.ipv6NeighCmdFunc()
			} else if ipBin, lpErr := exec.LookPath("ip"); lpErr == nil {
				out, err = exec.Command(ipBin, "-6", "neigh", "show").Output()
			}
			if err == nil {
				c.ipv6NeighCache = parseIPv6Neighbors(string(out))
				c.ipv6NeighFetchedAt = now
			}
		}
	}
	for ip6, mac := range c.ipv6NeighCache {
		prev := base[ip6]
		prev.MAC = cmp.Or(prev.MAC, mac)
		base[ip6] = prev
	}

	// 按小写 MAC 回填主机名（优先使用 IPv4 记录的友好名称，使 IPv6 临时隐私地址直接识别为对应设备名）
	macNames := make(map[string]string)
	for ip, info := range base {
		mac := strings.ToLower(strings.TrimSpace(info.MAC))
		if mac == "" || info.Name == "" || info.Name == ip {
			continue
		}
		isV4 := net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
		if existing, exists := macNames[mac]; !exists || (isV4 && existing != info.Name) {
			macNames[mac] = info.Name
		}
	}
	for ip, info := range base {
		mac := strings.ToLower(strings.TrimSpace(info.MAC))
		if mac != "" && info.Name == "" {
			if name := macNames[mac]; name != "" {
				info.Name = name
				base[ip] = info
			}
		}
	}

	return base
}

func (c *Collector) loadStateLocked(nowUnix int64) *persistedAuditState {
	if c.statePath != "" {
		fp := auditFileFingerprint(c.statePath)
		if c.cachedState != nil && c.cachedStateFp == fp {
			if nowUnix > 0 {
				maps.DeleteFunc(c.cachedState.Flows, func(_ string, e *persistedFlowEntry) bool {
					return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
				})
			}
			return c.cachedState
		}
	}

	st := &persistedAuditState{
		SchemaVersion: currentAuditStateSchema,
		Flows:         make(map[string]*persistedFlowEntry),
		ConnCursors:   make(map[string]connByteCursor),
	}
	if c.statePath == "" {
		return st
	}
	raw, err := os.ReadFile(c.statePath)
	if err != nil {
		c.cachedState = st
		c.cachedStateFp = auditFileFingerprint(c.statePath)
		return st
	}
	st.SchemaVersion = 0
	_ = json.Unmarshal(raw, st)
	if st.Flows == nil {
		st.Flows = make(map[string]*persistedFlowEntry)
	}
	if st.ConnCursors == nil {
		st.ConnCursors = make(map[string]connByteCursor)
	}

	// Schema v2 一次性平滑自愈迁移：
	// 1) 清零旧版 OpenWrt UTC 时区回退导致的白天误记 NightHits（保留累计上下行流量）
	// 2) 将旧快照中因证书 CN 嗅探混入的非法非域名 Target（如 "mijia cloud"）回退并归并至真实 DestIP
	if st.SchemaVersion < currentAuditStateSchema {
		migrated := make(map[string]*persistedFlowEntry, len(st.Flows))
		for _, e := range st.Flows {
			if e == nil {
				continue
			}
			e.NightHits = 0
			if !e.IsDirectIP && net.ParseIP(e.Target) == nil && !isValidAuditDomain(e.Target) {
				e.RawHost = cmp.Or(e.RawHost, e.Target)
				if net.ParseIP(e.DestIP) == nil {
					continue
				}
				e.Target = e.DestIP
				e.IsDirectIP = true
				e.Key = e.DeviceIP + "|" + e.Target + "|" + e.Network
			}
			if prev, exists := migrated[e.Key]; exists {
				prev.UploadBytes += e.UploadBytes
				prev.DownloadBytes += e.DownloadBytes
				prev.ConnCount += e.ConnCount
				if e.FirstSeenUnix > 0 && (prev.FirstSeenUnix == 0 || e.FirstSeenUnix < prev.FirstSeenUnix) {
					prev.FirstSeenUnix = e.FirstSeenUnix
				}
				if e.LastSeenUnix > prev.LastSeenUnix {
					prev.LastSeenUnix = e.LastSeenUnix
				}
				prev.RawHost = cmp.Or(prev.RawHost, e.RawHost)
			} else {
				migrated[e.Key] = e
			}
		}
		st.Flows = migrated
		st.SchemaVersion = currentAuditStateSchema
	}

	// 24 小时滑动窗口：淘汰超过 24 小时无活动的陈旧流记录，避免跨日长尾连接无限累积
	if nowUnix > 0 {
		maps.DeleteFunc(st.Flows, func(_ string, e *persistedFlowEntry) bool {
			return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
		})
	}
	c.cachedState = st
	c.cachedStateFp = auditFileFingerprint(c.statePath)
	return st
}

func (c *Collector) saveStateLocked(st *persistedAuditState, activeByKey map[string][]string, now time.Time) {
	if c.statePath == "" || st == nil {
		return
	}
	nowUnix := now.Unix()
	st.SchemaVersion = currentAuditStateSchema
	st.UpdatedUnix = nowUnix

	// 修剪过期连接游标 (超过 2 小时未活动或超出容量上限)
	if len(st.ConnCursors) > maxTrackedConnDeltas {
		maps.DeleteFunc(st.ConnCursors, func(_ string, cur connByteCursor) bool {
			return nowUnix-cur.SeenUnix > 7200
		})
	}

	// 淘汰超过 24 小时未活跃的陈旧流
	maps.DeleteFunc(st.Flows, func(_ string, e *persistedFlowEntry) bool {
		return e == nil || (e.LastSeenUnix > 0 && nowUnix-e.LastSeenUnix > flowIdleTTLSeconds)
	})

	// 修剪聚合流桶 (最多保留 maxPersistedFlows 条记录，优先保护当前活跃连接，恒定内存 < 1MB)
	if len(st.Flows) > maxPersistedFlows {
		entries := make([]*persistedFlowEntry, 0, len(st.Flows))
		for _, e := range st.Flows {
			entries = append(entries, e)
		}
		slices.SortFunc(entries, func(a, b *persistedFlowEntry) int {
			aAct, bAct := 0, 0
			if len(activeByKey[a.Key]) > 0 {
				aAct = 1
			}
			if len(activeByKey[b.Key]) > 0 {
				bAct = 1
			}
			if c := cmp.Compare(bAct, aAct); c != 0 {
				return c
			}
			if c := cmp.Compare(b.UploadBytes, a.UploadBytes); c != 0 {
				return c
			}
			return cmp.Compare(b.LastSeenUnix, a.LastSeenUnix)
		})
		trimmed := make(map[string]*persistedFlowEntry, maxPersistedFlows)
		for _, e := range entries[:maxPersistedFlows] {
			trimmed[e.Key] = e
		}
		st.Flows = trimmed
	}

	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmpPath := c.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err == nil {
		_ = os.Chmod(tmpPath, 0600)
		_ = os.Rename(tmpPath, c.statePath)
	}
	c.cachedState = st
	c.cachedStateFp = auditFileFingerprint(c.statePath)
}

// collectLocalInterfaceIPs 枚举当前软路由/主机所有网卡绑定的本机 IP（含 pppoe-wan 公网 IP、br-lan 网关 IP 等）。
func collectLocalInterfaceIPs() map[string]bool {
	out := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			if v.IP != nil {
				out[v.IP.String()] = true
			}
		case *net.IPAddr:
			if v.IP != nil {
				out[v.IP.String()] = true
			}
		}
	}
	return out
}

// normalizeSourceDeviceIP 将软路由本机发出的连接（源 IP 为本机 WAN 公网 IP 或网关自身接口 IP）统一归并为 127.0.0.1 (本机网关)。
// 若公网 IPv6 源地址命中局域网邻居表或 odhcpd 租约表，则判定为内网双栈设备并保留真实源 IP。
func normalizeSourceDeviceIP(rawIP string, selfIPs map[string]bool, devDir map[string]lanDeviceInfo) string {
	ipStr := strings.TrimSpace(rawIP)
	if ipStr == "" || selfIPs[ipStr] {
		return "127.0.0.1"
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip.IsLoopback() {
		return "127.0.0.1"
	}
	// 局域网私有网段 (10/8, 172.16/12, 192.168/16, fc00::/7) 与 Tailscale CGNAT (100.64/10) 保留真实内网设备 IP
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return ipStr
	}
	if ip.To4() == nil {
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			canon := addr.Unmap().String()
			if selfIPs[canon] {
				return "127.0.0.1"
			}
			if _, knownLAN := devDir[canon]; knownLAN {
				return canon
			}
		}
	}
	// 其余非私网公网源 IP 均来自软路由 pppoe-wan 本机 output 链透明劫持，统一归入本机网关
	return "127.0.0.1"
}

func enforcementActiveRank(s EnforcementState) int {
	switch s {
	case EnforcementBlocked:
		return 1
	case EnforcementWhitelisted:
		return 0
	default: // EnforcementObserved 或未填充态优先排在待处置前列
		return 2
	}
}

func flowActiveBucket(f FlowRecord) int {
	if f.ActiveConns > 0 {
		return 1
	}
	return 0
}

func compareRiskHierarchy(a, b FlowRecord) int {
	if s := cmp.Compare(enforcementActiveRank(b.State), enforcementActiveRank(a.State)); s != 0 {
		return s
	}
	if t := cmp.Compare(b.Threat.SeverityRank(), a.Threat.SeverityRank()); t != 0 {
		return t
	}
	if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
		return r
	}
	if ac := cmp.Compare(b.ActiveConns, a.ActiveConns); ac != 0 {
		return ac
	}
	return cmp.Compare(b.UploadBytes, a.UploadBytes)
}

// SortFlows 对审计流记录按指定字段（默认 "active": 活跃优先+风险评分，或 "risk" | "upload" | "download" | "ratio"）执行稳定排序。
func SortFlows(flows []FlowRecord, sortBy string, asc bool) {
	key := strings.ToLower(strings.TrimSpace(sortBy))
	slices.SortFunc(flows, func(a, b FlowRecord) int {
		var c int
		switch key {
		case "upload":
			c = cmp.Compare(b.UploadBytes, a.UploadBytes)
			if asc {
				c = -c
			}
			if c != 0 {
				return c
			}
			if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
				return r
			}
			return cmp.Compare(b.DownloadBytes, a.DownloadBytes)
		case "download":
			c = cmp.Compare(b.DownloadBytes, a.DownloadBytes)
			if asc {
				c = -c
			}
			if c != 0 {
				return c
			}
			if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
				return r
			}
			return cmp.Compare(b.UploadBytes, a.UploadBytes)
		case "ratio":
			c = cmp.Compare(b.UploadRatio, a.UploadRatio)
			if asc {
				c = -c
			}
			if c != 0 {
				return c
			}
			if u := cmp.Compare(b.UploadBytes, a.UploadBytes); u != 0 {
				return u
			}
			return cmp.Compare(b.RiskScore, a.RiskScore)
		case "risk":
			c = compareRiskHierarchy(a, b)
			if asc {
				c = -c
			}
			return c
		default: // "" 或 "active"：活跃置顶 -> 组内按风险评分层级降序
			if act := cmp.Compare(flowActiveBucket(b), flowActiveBucket(a)); act != 0 {
				c = act
			} else {
				c = compareRiskHierarchy(a, b)
			}
			if asc {
				c = -c
			}
			return c
		}
	})
}

// isValidAuditDomain 校验嗅探出的字符串是否为合法 FQDN 域名（拒绝类似 "Mijia Cloud" 的 TLS 证书 Subject CN 非域名文本）。
func isValidAuditDomain(s string) bool {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil {
		return false
	}
	if !strings.Contains(s, ".") {
		return false
	}
	lastLabel := ""
	for label := range strings.SplitSeq(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			ch := label[i]
			isAlphaNum := (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
			if !isAlphaNum && ch != '-' && ch != '_' {
				return false
			}
		}
		lastLabel = label
	}
	if len(lastLabel) < 2 || strings.Contains(lastLabel, "_") {
		return false
	}
	allDigits := true
	for i := range len(lastLabel) {
		if lastLabel[i] < '0' || lastLabel[i] > '9' {
			allDigits = false
			break
		}
	}
	return !allDigits
}

func (c *Collector) resolveLocalLocation() *time.Location {
	// 当测试注入了自定义 tzFile / uciSystemFile，或运行在缺少 /usr/share/zoneinfo 导致 time.Local 回退为 UTC 的 OpenWrt 固件上时，主动解析 /etc/TZ 与 /etc/config/system
	if (c.tzFile != "" && c.tzFile != "/etc/TZ") || (c.uciSystemFile != "" && c.uciSystemFile != "/etc/config/system") {
		return ResolveLocalLocationFromFiles(c.tzFile, c.uciSystemFile)
	}
	if time.Local != nil && time.Local.String() != "UTC" {
		return time.Local
	}
	return ResolveLocalLocationFromFiles(c.tzFile, c.uciSystemFile)
}

// InitProcessLocalTimezone 在缺少 /usr/share/zoneinfo 的精简 Linux/OpenWrt 系统上（Go 默认回退为 UTC），
// 自动读取 /etc/TZ 与 /etc/config/system 修正全局 time.Local，确保 logger、看门狗与 WebUI 时间戳一致。
func InitProcessLocalTimezone() {
	if time.Local != nil && time.Local.String() != "UTC" {
		return
	}
	if loc := ResolveLocalLocationFromFiles("/etc/TZ", "/etc/config/system"); loc != nil && loc.String() != "UTC" {
		time.Local = loc
	}
}

// ResolveLocalLocationFromFiles 按 TZ 环境变量 -> OpenWrt /etc/TZ -> UCI /etc/config/system -> time.Local 顺序解析真实本地时区。
func ResolveLocalLocationFromFiles(tzFile, uciSystemFile string) *time.Location {
	if envTZ := strings.TrimSpace(os.Getenv("TZ")); envTZ != "" {
		if loc := ParsePOSIXTZLocation(envTZ); loc != nil {
			return loc
		}
	}
	if tzFile != "" {
		if raw, err := os.ReadFile(tzFile); err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					if loc := ParsePOSIXTZLocation(line); loc != nil {
						return loc
					}
				}
			}
		}
	}
	if uciSystemFile != "" {
		if raw, err := os.ReadFile(uciSystemFile); err == nil {
			var zoneName, posixTZ string
			for line := range strings.SplitSeq(string(raw), "\n") {
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) >= 3 && fields[0] == "option" {
					val := strings.Trim(fields[2], "'\"")
					switch fields[1] {
					case "zonename":
						zoneName = val
					case "timezone":
						posixTZ = val
					}
				}
			}
			for _, candidate := range []string{zoneName, posixTZ} {
				if loc := ParsePOSIXTZLocation(candidate); loc != nil {
					return loc
				}
			}
		}
	}
	return time.Local
}

// ParsePOSIXTZLocation 解析 IANA 时区名或 OpenWrt / musl POSIX TZ 字符串（如 "CST-8", "<+08>-8", "EST5EDT", "IST-5:30"）。
// 注意 POSIX TZ 规范符号定义：偏移量表示“本地时间加上该值得到 UTC”，因此 "CST-8" 代表东八区 UTC+8 (+8*3600)。
func ParsePOSIXTZLocation(spec string) *time.Location {
	s := strings.TrimSpace(spec)
	if s == "" {
		return nil
	}
	if loc, err := time.LoadLocation(s); err == nil && loc != nil {
		return loc
	}

	switch strings.ToLower(strings.ReplaceAll(s, " ", "_")) {
	case "asia/shanghai", "asia/chongqing", "asia/harbin", "asia/urumqi", "asia/hong_kong", "asia/macau", "asia/taipei", "asia/singapore", "prc":
		return time.FixedZone("CST", 8*3600)
	case "asia/tokyo", "asia/seoul":
		return time.FixedZone("JST", 9*3600)
	}

	var tzName, rest string
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end <= 1 {
			return nil
		}
		tzName = s[1:end]
		rest = s[end+1:]
	} else {
		i := 0
		for i < len(s) && ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
			i++
		}
		if i == 0 {
			return nil
		}
		tzName = s[:i]
		rest = s[i:]
	}

	if rest == "" {
		if strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "GMT") {
			return time.UTC
		}
		return nil
	}

	westSign := 1
	switch rest[0] {
	case '-':
		westSign = -1
		rest = rest[1:]
	case '+':
		westSign = 1
		rest = rest[1:]
	}

	// 提取 hh[:mm[:ss]]，忽略后续可能附带的夏令时规则（如 EDT,M3.2.0/2）
	numEnd := 0
	for numEnd < len(rest) && ((rest[numEnd] >= '0' && rest[numEnd] <= '9') || rest[numEnd] == ':') {
		numEnd++
	}
	if numEnd == 0 {
		return nil
	}
	parts := strings.Split(rest[:numEnd], ":")
	if len(parts) > 3 {
		return nil
	}
	hh, err := strconv.Atoi(parts[0])
	if err != nil || hh > 14 {
		return nil
	}
	mm, ss := 0, 0
	if len(parts) >= 2 {
		mm, err = strconv.Atoi(parts[1])
		if err != nil || mm < 0 || mm >= 60 {
			return nil
		}
	}
	if len(parts) == 3 {
		ss, err = strconv.Atoi(parts[2])
		if err != nil || ss < 0 || ss >= 60 {
			return nil
		}
	}

	westSeconds := westSign * (hh*3600 + mm*60 + ss)
	eastSeconds := -westSeconds
	if eastSeconds == 0 && (strings.EqualFold(tzName, "UTC") || strings.EqualFold(tzName, "GMT")) {
		return time.UTC
	}
	return time.FixedZone(tzName, eastSeconds)
}

// resolveConnTarget 从 Clash API 单条连接元数据提取规范化目标域名/IP（供采集与连接断开共享）。
func resolveConnTarget(conn clashConnection) (rawHost, destIP, target string, isDirectIP bool) {
	rawHost = cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host))
	destIP = strings.TrimSpace(conn.Metadata.DestinationIP)
	target = strings.TrimSuffix(strings.ToLower(rawHost), ".")
	if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
		target = strings.TrimSuffix(h, ".")
	}
	if target == "" || net.ParseIP(target) != nil {
		isDirectIP = true
		target = cmp.Or(destIP, target)
	} else if !isValidAuditDomain(target) {
		isDirectIP = true
		target = destIP
	}
	return rawHost, destIP, target, isDirectIP
}

// CloseConnectionsRequest 描述 WebUI 临时断开活跃连接的筛选条件。
type CloseConnectionsRequest struct {
	All      bool     `json:"all,omitempty"`
	ConnIDs  []string `json:"connIds,omitempty"`
	DeviceIP string   `json:"deviceIp,omitempty"`
	Target   string   `json:"target,omitempty"`
	Network  string   `json:"network,omitempty"`
}

// CloseConnectionsResult 返回本次踢断活跃连接的结果统计。
type CloseConnectionsResult struct {
	Closed int  `json:"closed"`
	All    bool `json:"all"`
}

// CloseConnections 通过 sing-box Clash API 临时断开指定（或全部）活跃连接，触发客户端重新握手选路。
func (c *Collector) CloseConnections(ctx context.Context, req CloseConnectionsRequest) (CloseConnectionsResult, error) {
	c.mu.Lock()
	if !c.customEndpoints {
		c.endpoints = singbox.ClashAPIEndpoints()
		c.secret = singbox.ClashAPISecret()
	}
	endpoints := slices.Clone(c.endpoints)
	secret := c.secret
	client := c.httpClient
	c.mu.Unlock()

	if len(endpoints) == 0 {
		endpoints = []string{"http://127.0.0.1:9090"}
	}
	if client == nil {
		client = &http.Client{Timeout: 2500 * time.Millisecond}
	}

	var lastErr error
	for _, ep := range endpoints {
		baseURL := strings.TrimRight(strings.TrimSpace(ep), "/")
		if baseURL == "" {
			continue
		}

		if req.All {
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections", nil)
			if err != nil {
				lastErr = err
				continue
			}
			if secret != "" {
				delReq.Header.Set("Authorization", "Bearer "+secret)
			}
			resp, err := client.Do(delReq)
			if err != nil {
				lastErr = err
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK {
				return CloseConnectionsResult{All: true}, nil
			}
			lastErr = fmt.Errorf("Clash API 返回状态 %d", resp.StatusCode)
			continue
		}

		// 收集显式传入的连接 ID，并补充拉取一次活跃连接表以捕捉刚新建的同目标连接
		targetIDs := make([]string, 0, len(req.ConnIDs))
		for _, id := range req.ConnIDs {
			cleanID := strings.TrimSpace(id)
			if cleanID != "" && !slices.Contains(targetIDs, cleanID) {
				targetIDs = append(targetIDs, cleanID)
			}
		}

		wantTarget := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Target)), ".")
		wantDev := strings.TrimSpace(req.DeviceIP)
		wantNet := strings.ToLower(strings.TrimSpace(req.Network))
		reachable := false

		if wantTarget != "" || wantDev != "" || len(targetIDs) == 0 {
			getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/connections", nil)
			if err == nil {
				if secret != "" {
					getReq.Header.Set("Authorization", "Bearer "+secret)
				}
				getResp, err := client.Do(getReq)
				if err != nil {
					lastErr = err
					continue
				}
				if getResp.StatusCode == http.StatusOK {
					reachable = true
					var parsed clashConnectionsResponse
					if decErr := json.NewDecoder(getResp.Body).Decode(&parsed); decErr == nil {
						selfIPs := collectLocalInterfaceIPs()
						devDir := c.resolveLANDevicesLocked()
						for _, conn := range parsed.Connections {
							connSrc := normalizeSourceDeviceIP(strings.TrimSpace(conn.Metadata.SourceIP), selfIPs, devDir)
							_, destIP, connTarget, _ := resolveConnTarget(conn)
							connNet := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
							if wantDev != "" && connSrc != wantDev {
								continue
							}
							if wantNet != "" && connNet != wantNet {
								continue
							}
							if wantTarget != "" && !strings.EqualFold(connTarget, wantTarget) && destIP != wantTarget {
								continue
							}
							if conn.ID != "" && !slices.Contains(targetIDs, conn.ID) {
								targetIDs = append(targetIDs, conn.ID)
							}
						}
					}
				} else {
					lastErr = fmt.Errorf("Clash API /connections 返回状态 %d", getResp.StatusCode)
				}
				getResp.Body.Close()
				if !reachable && len(targetIDs) == 0 {
					continue
				}
			}
		}

		closed := 0
		anySucceeded := reachable
		for _, id := range targetIDs {
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections/"+url.PathEscape(id), nil)
			if err != nil {
				lastErr = err
				continue
			}
			if secret != "" {
				delReq.Header.Set("Authorization", "Bearer "+secret)
			}
			delResp, err := client.Do(delReq)
			if err != nil {
				lastErr = err
				continue
			}
			delResp.Body.Close()
			anySucceeded = true
			if delResp.StatusCode == http.StatusNoContent || delResp.StatusCode == http.StatusOK {
				closed++
			}
		}
		if anySucceeded {
			return CloseConnectionsResult{Closed: closed}, nil
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("未找到可达的 sing-box Clash API 控制端口")
	}
	return CloseConnectionsResult{}, lastErr
}
