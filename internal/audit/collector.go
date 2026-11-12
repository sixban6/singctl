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
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

const (
	maxPersistedFlows       = 400
	maxTrackedConnDeltas    = 1500
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
	Key           string  `json:"key"`
	DeviceIP      string  `json:"deviceIp"`
	DeviceName    string  `json:"deviceName,omitempty"`
	DeviceMAC     string  `json:"deviceMac,omitempty"`
	Target        string  `json:"target"`
	RawHost       string  `json:"rawHost,omitempty"`
	DestIP        string  `json:"destIp,omitempty"`
	DestPort      int     `json:"destPort"`
	IsDirectIP    bool    `json:"isDirectIp"`
	Network       string  `json:"network"`
	Outbound      string  `json:"outbound"`
	Rule          string  `json:"rule,omitempty"`
	UploadBytes   int64   `json:"uploadBytes"`
	DownloadBytes int64   `json:"downloadBytes"`
	ConnCount     int     `json:"connCount"`
	FirstSeenUnix int64   `json:"firstSeenUnix"`
	LastSeenUnix  int64   `json:"lastSeenUnix"`
	NightHits     int     `json:"nightHits"`
	ArrivalsUnix  []int64 `json:"arrivalsUnix,omitempty"`
}

type connByteCursor struct {
	Upload   int64 `json:"up"`
	Download int64 `json:"down"`
	SeenUnix int64 `json:"ts"`
}

type persistedAuditState struct {
	SchemaVersion int                           `json:"schemaVersion,omitempty"`
	UpdatedUnix   int64                         `json:"updatedUnix"`
	Flows         map[string]*persistedFlowEntry `json:"flows"`
	ConnCursors   map[string]connByteCursor     `json:"connCursors"`
}

// Collector 负责从 sing-box Clash API 采集连接、关联局域网 DHCP/ARP 设备名并执行多维非线性分析。
type Collector struct {
	mu             sync.Mutex
	cfg            *config.Config
	statePath      string
	endpoints      []string
	secret         string
	httpClient     *http.Client
	leaseFiles     []string
	arpFile        string
	hostsFile      string
	tzFile         string
	uciSystemFile  string
	nowFunc        func() time.Time
}

// NewCollector 创建默认客户端审计采集器（自动兼容 OpenWrt /etc/TZ 与 /etc/config/system 本地时区）。
func NewCollector(cfg *config.Config) *Collector {
	c := &Collector{
		cfg:           cfg,
		statePath:     defaultStatePath(),
		endpoints:     singbox.ClashAPIEndpoints(),
		secret:        singbox.ClashAPISecret(),
		httpClient:    &http.Client{Timeout: 2500 * time.Millisecond},
		leaseFiles:    []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/tmp/dnsmasq.leases"},
		arpFile:       "/proc/net/arp",
		hostsFile:     "/etc/hosts",
		tzFile:        "/etc/TZ",
		uciSystemFile: "/etc/config/system",
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
	if statePath != "" {
		c.statePath = statePath
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
	Limit        int    // 最大返回流数量 (默认 100)
	SortBy       string // 排序字段: "risk" (默认) | "upload" | "download" | "ratio"
	SortAsc      bool   // 是否升序排列 (默认 false 即降序)
}

// Collect 采样当前活跃连接、合并历史增量窗口、运行非线性风险引擎并生成完整审计报告。
func (c *Collector) Collect(ctx context.Context, opts CollectOptions) *Report {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.nowFunc()
	rep := &Report{
		GeneratedAt: now.Format("2006-01-02 15:04:05"),
		Devices:     []DeviceSummary{},
		Flows:       []FlowRecord{},
	}
	if c.cfg != nil {
		rep.BlockRules = slices.Clone(c.cfg.CustomRules.Block)
		rep.BlockedCount = len(rep.BlockRules)
		rep.Whitelist = slices.Clone(c.cfg.Audit.Whitelist)
		rep.WhitelistCount = len(rep.Whitelist)
	}

	state := c.loadStateLocked(now.Unix())
	devDirectory := c.resolveLANDevicesLocked()
	selfIPs := collectLocalInterfaceIPs()

	connsResp, usedAddr, err := c.fetchConnectionsLocked(ctx)
	activeByKey := make(map[string][]string)
	if err == nil && connsResp != nil {
		rep.Reachable = true
		rep.ControllerAddr = usedAddr
		c.ingestConnectionsLocked(state, connsResp.Connections, devDirectory, selfIPs, activeByKey, now)
		c.saveStateLocked(state, now)
	} else {
		rep.Reachable = false
		if len(state.Flows) > 0 {
			rep.Message = "当前 sing-box 控制端口不可达，正在展示最近缓存的设备审计快照"
		} else {
			rep.Message = "未检测到运行中的 sing-box 代理实例 (Clash API 不可达)"
			return rep
		}
	}

	engine := NewNonlinearEngine(c.cfg)
	allFlows := make([]FlowRecord, 0, len(state.Flows))
	deviceAgg := make(map[string]*DeviceSummary)

	for _, entry := range state.Flows {
		normDevIP := normalizeSourceDeviceIP(entry.DeviceIP, selfIPs)
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
		rec := FlowRecord{
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
		}
		engine.EvaluateFlow(&rec)

		// 更新设备维度汇总（已拉黑或白名单放行的目标不再计入活跃告警数与设备最高风险分，形成治理闭环）
		ds, ok := deviceAgg[rec.DeviceIP]
		if !ok {
			ds = &DeviceSummary{
				DeviceIP:   rec.DeviceIP,
				DeviceName: rec.DeviceName,
				DeviceMAC:  rec.DeviceMAC,
				DeviceRole: rec.DeviceRole,
			}
			deviceAgg[rec.DeviceIP] = ds
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

		// 过滤条件检查（支持按设备 IP、设备名称、目标域名或识别出的应用名如 Telegram/Baidu 过滤）
		if filter := strings.ToLower(strings.TrimSpace(opts.DeviceFilter)); filter != "" {
			if !strings.Contains(strings.ToLower(rec.DeviceIP), filter) &&
				!strings.Contains(strings.ToLower(rec.DeviceName), filter) &&
				!strings.Contains(strings.ToLower(rec.Target), filter) &&
				!strings.Contains(strings.ToLower(rec.AppName), filter) {
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

	// 流量列表在截断 Top-N 前按指定字段（默认：威胁等级 -> 评分 -> 上传流量）排序
	SortFlows(allFlows, opts.SortBy, opts.SortAsc)

	limit := opts.Limit
	if limit <= 0 {
		limit = 100
	}
	if len(allFlows) > limit {
		allFlows = allFlows[:limit]
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
	now time.Time,
) {
	nowUnix := now.Unix()
	hour := now.Hour()
	isNight := hour >= 1 && hour <= 5

	for _, conn := range conns {
		rawSrc := cmp.Or(strings.TrimSpace(conn.Metadata.SourceIP), "127.0.0.1")
		srcIP := normalizeSourceDeviceIP(rawSrc, selfIPs)
		rawHost := cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host))
		destIP := strings.TrimSpace(conn.Metadata.DestinationIP)
		network := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
		destPort, _ := strconv.Atoi(strings.TrimSpace(conn.Metadata.DestinationPort))

		isDirectIP := false
		target := strings.TrimSuffix(strings.ToLower(rawHost), ".")
		if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
			target = strings.TrimSuffix(h, ".")
		}
		if target == "" || net.ParseIP(target) != nil {
			isDirectIP = true
			target = cmp.Or(destIP, target)
		} else if !isValidAuditDomain(target) {
			// 过滤 TLS 证书 Subject CN 非域名字符串（例如 "Mijia Cloud"），保留 rawHost 供应用识别，目标回退为真实目的 IP
			isDirectIP = true
			target = destIP
		}
		if target == "" {
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

// resolveLANDevicesLocked 从 OpenWrt / Linux DHCP 租约、ARP 表与 /etc/hosts 解析内网 IP 对应的设备主机名与 MAC。
func (c *Collector) resolveLANDevicesLocked() map[string]lanDeviceInfo {
	out := make(map[string]lanDeviceInfo)

	// 1. 解析 /etc/hosts
	if raw, err := os.ReadFile(c.hostsFile); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
				host := fields[1]
				if host != "localhost" && !strings.HasPrefix(host, "ip6-") {
					out[fields[0]] = lanDeviceInfo{Name: host}
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
			mac, ip, host := fields[1], fields[2], fields[3]
			if net.ParseIP(ip) == nil {
				continue
			}
			if host == "*" {
				host = ""
			}
			prev := out[ip]
			out[ip] = lanDeviceInfo{
				Name: cmp.Or(host, prev.Name),
				MAC:  cmp.Or(mac, prev.MAC),
			}
		}
	}

	// 3. 补充 /proc/net/arp 中的 MAC 地址
	if raw, err := os.ReadFile(c.arpFile); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 4 && net.ParseIP(fields[0]) != nil && strings.Contains(fields[3], ":") {
				ip, mac := fields[0], fields[3]
				if mac != "00:00:00:00:00:00" {
					prev := out[ip]
					prev.MAC = cmp.Or(prev.MAC, mac)
					out[ip] = prev
				}
			}
		}
	}

	return out
}

func (c *Collector) loadStateLocked(nowUnix int64) *persistedAuditState {
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
	return st
}

func (c *Collector) saveStateLocked(st *persistedAuditState, now time.Time) {
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

	// 修剪聚合流桶 (最多保留 maxPersistedFlows 条高价值记录，恒定内存 < 1MB)
	if len(st.Flows) > maxPersistedFlows {
		entries := make([]*persistedFlowEntry, 0, len(st.Flows))
		for _, e := range st.Flows {
			entries = append(entries, e)
		}
		slices.SortFunc(entries, func(a, b *persistedFlowEntry) int {
			return cmp.Compare(b.UploadBytes, a.UploadBytes)
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
func normalizeSourceDeviceIP(rawIP string, selfIPs map[string]bool) string {
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

// SortFlows 对审计流记录按指定字段（"risk" | "upload" | "download" | "ratio"）执行稳定排序。
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
		default: // "risk"
			if s := cmp.Compare(enforcementActiveRank(b.State), enforcementActiveRank(a.State)); s != 0 {
				c = s
			} else if t := cmp.Compare(b.Threat.SeverityRank(), a.Threat.SeverityRank()); t != 0 {
				c = t
			} else if r := cmp.Compare(b.RiskScore, a.RiskScore); r != 0 {
				c = r
			} else {
				c = cmp.Compare(b.UploadBytes, a.UploadBytes)
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
