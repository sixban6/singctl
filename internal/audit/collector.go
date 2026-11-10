package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
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
	maxPersistedFlows    = 400
	maxTrackedConnDeltas = 1500
	maxArrivalSamples    = 16
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
	UpdatedUnix int64                         `json:"updatedUnix"`
	Flows       map[string]*persistedFlowEntry `json:"flows"`
	ConnCursors map[string]connByteCursor     `json:"connCursors"`
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
	nowFunc        func() time.Time
}

// NewCollector 创建默认客户端审计采集器。
func NewCollector(cfg *config.Config) *Collector {
	return &Collector{
		cfg:        cfg,
		statePath:  defaultStatePath(),
		endpoints:  singbox.ClashAPIEndpoints(),
		secret:     singbox.ClashAPISecret(),
		httpClient: &http.Client{Timeout: 2500 * time.Millisecond},
		leaseFiles: []string{"/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases", "/tmp/dnsmasq.leases"},
		arpFile:    "/proc/net/arp",
		hostsFile:  "/etc/hosts",
		nowFunc:    time.Now,
	}
}

// SetEndpointsForTest 供单元测试注入模拟 Clash API 地址与状态文件路径。
func (c *Collector) SetEndpointsForTest(endpoints []string, secret, statePath string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoints = endpoints
	c.secret = secret
	if statePath != "" {
		c.statePath = statePath
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
	}

	state := c.loadStateLocked()
	devDirectory := c.resolveLANDevicesLocked()

	connsResp, usedAddr, err := c.fetchConnectionsLocked(ctx)
	activeByKey := make(map[string][]string)
	if err == nil && connsResp != nil {
		rep.Reachable = true
		rep.ControllerAddr = usedAddr
		c.ingestConnectionsLocked(state, connsResp.Connections, devDirectory, activeByKey, now)
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
		devName, devMAC := entry.DeviceName, entry.DeviceMAC
		if info, ok := devDirectory[entry.DeviceIP]; ok {
			if info.Name != "" {
				devName = info.Name
			}
			if info.MAC != "" {
				devMAC = info.MAC
			}
		}
		if devName == "" {
			if entry.DeviceIP == "127.0.0.1" || entry.DeviceIP == "::1" {
				devName = "本机网关 (Localhost)"
			} else {
				devName = entry.DeviceIP
			}
		}

		activeIDs := activeByKey[entry.Key]
		rec := FlowRecord{
			Key:           entry.Key,
			DeviceIP:      entry.DeviceIP,
			DeviceName:    devName,
			DeviceMAC:     devMAC,
			DeviceRole:    InferDeviceRole(devName),
			Target:        entry.Target,
			AppName:       IdentifyApp(entry.Target, entry.DestIP, entry.Rule),
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
			FirstSeen:     time.Unix(entry.FirstSeenUnix, 0).Format("15:04:05"),
			LastSeen:      time.Unix(entry.LastSeenUnix, 0).Format("15:04:05"),
			NightHits:     entry.NightHits,
			IntervalCV:    computeIntervalCV(entry.ArrivalsUnix),
		}
		engine.EvaluateFlow(&rec)

		// 更新设备维度汇总
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

		// 过滤条件检查（支持按设备 IP、设备名称、目标域名或识别出的应用名如 Telegram/Baidu 过滤）
		if filter := strings.ToLower(strings.TrimSpace(opts.DeviceFilter)); filter != "" {
			if !strings.Contains(strings.ToLower(rec.DeviceIP), filter) &&
				!strings.Contains(strings.ToLower(rec.DeviceName), filter) &&
				!strings.Contains(strings.ToLower(rec.Target), filter) &&
				!strings.Contains(strings.ToLower(rec.AppName), filter) {
				continue
			}
		}
		if opts.OnlySuspect && rec.RiskScore < 35 && rec.Threat == ThreatNormal {
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

	// 流量列表按威胁等级 -> 风险分 -> 上传流量降序排列
	slices.SortFunc(allFlows, func(a, b FlowRecord) int {
		if c := cmp.Compare(b.Threat.SeverityRank(), a.Threat.SeverityRank()); c != 0 {
			return c
		}
		if c := cmp.Compare(b.RiskScore, a.RiskScore); c != 0 {
			return c
		}
		return cmp.Compare(b.UploadBytes, a.UploadBytes)
	})

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
	activeByKey map[string][]string,
	now time.Time,
) {
	nowUnix := now.Unix()
	hour := now.Hour()
	isNight := hour >= 1 && hour <= 5

	for _, conn := range conns {
		srcIP := cmp.Or(strings.TrimSpace(conn.Metadata.SourceIP), "127.0.0.1")
		rawHost := cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host))
		destIP := strings.TrimSpace(conn.Metadata.DestinationIP)
		network := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.Network), "tcp"))
		destPort, _ := strconv.Atoi(strings.TrimSpace(conn.Metadata.DestinationPort))

		isDirectIP := false
		target := strings.ToLower(rawHost)
		if h, _, err := net.SplitHostPort(target); err == nil && h != "" {
			target = h
		}
		if target == "" || net.ParseIP(target) != nil {
			isDirectIP = true
			target = cmp.Or(destIP, target)
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

func (c *Collector) loadStateLocked() *persistedAuditState {
	st := &persistedAuditState{
		Flows:       make(map[string]*persistedFlowEntry),
		ConnCursors: make(map[string]connByteCursor),
	}
	if c.statePath == "" {
		return st
	}
	raw, err := os.ReadFile(c.statePath)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(raw, st)
	if st.Flows == nil {
		st.Flows = make(map[string]*persistedFlowEntry)
	}
	if st.ConnCursors == nil {
		st.ConnCursors = make(map[string]connByteCursor)
	}
	return st
}

func (c *Collector) saveStateLocked(st *persistedAuditState, now time.Time) {
	if c.statePath == "" || st == nil {
		return
	}
	nowUnix := now.Unix()
	st.UpdatedUnix = nowUnix

	// 修剪过期连接游标 (超过 2 小时未活动或超出容量上限)
	if len(st.ConnCursors) > maxTrackedConnDeltas {
		for id, cur := range st.ConnCursors {
			if nowUnix-cur.SeenUnix > 7200 {
				delete(st.ConnCursors, id)
			}
		}
	}

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
