// 文件职责：定义外部活跃嗅探追踪核心结构（Tracker 及三维态势汇总模型）、消费侧远端节点/限流器契约与 0600 快照持久化。
package sniff

import (
	"cmp"
	"context"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/netdiag/ipgeo"
)

const (
	maxTrackedSniffIPs   = 1000
	sniffEntryTTL        = 24 * time.Hour
	trustedClientTTL     = 2 * time.Hour
	systemHarvestMinDT   = 15 * time.Second
	fleetHarvestMinDT    = 30 * time.Second
	sniffSaveMinDT       = 60 * time.Second
	TimeLayout           = "2006-01-02 15:04:05"
	BanSourceManualSniff = "manual_sniff"
)

// NodeRef 标记某个嗅探源被集群中哪台主机捕获。
type NodeRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host,omitempty"`
}

// NodeSummary 集群中单台主机（或全集群汇总）的嗅探统计摘要。
type NodeSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Host          string `json:"host,omitempty"`
	Online        bool   `json:"online"`
	TotalSniffIPs int    `json:"totalSniffIPs"`
	TotalSubnets  int    `json:"totalSubnets"`
	TotalBanned   int    `json:"totalBanned"`
	LastHarvestAt string `json:"lastHarvestAt,omitempty"`
	Error         string `json:"error,omitempty"`
}

// IPStat 单个外部活跃嗅探 IP 的态势详情。
type IPStat struct {
	IP          string    `json:"ip"`
	Subnet      string    `json:"subnet"`
	Hits        int       `json:"hits"`
	Vector      string    `json:"vector"`
	Status      string    `json:"status"`
	Country     string    `json:"country,omitempty"`
	CountryCode string    `json:"countryCode,omitempty"`
	Flag        string    `json:"flag,omitempty"`
	Geo         string    `json:"geo,omitempty"`
	ISP         string    `json:"isp,omitempty"`
	ScannerTag  string    `json:"scannerTag,omitempty"`
	FirstSeen   string    `json:"firstSeen"`
	LastSeen    string    `json:"lastSeen"`
	Nodes       []NodeRef `json:"nodes,omitempty"`
}

// SubnetStat 按 /24 (IPv4) 或 /48 (IPv6) 聚合的活跃嗅探网段态势。
type SubnetStat struct {
	CIDR        string    `json:"cidr"`
	UniqueIPs   int       `json:"uniqueIPs"`
	TotalHits   int       `json:"totalHits"`
	BannedCount int       `json:"bannedCount"`
	Status      string    `json:"status"`
	Country     string    `json:"country,omitempty"`
	CountryCode string    `json:"countryCode,omitempty"`
	Flag        string    `json:"flag,omitempty"`
	ISP         string    `json:"isp,omitempty"`
	ScannerTag  string    `json:"scannerTag,omitempty"`
	SampleIPs   []string  `json:"sampleIPs,omitempty"`
	FirstSeen   string    `json:"firstSeen"`
	LastSeen    string    `json:"lastSeen"`
	Nodes       []NodeRef `json:"nodes,omitempty"`
}

// CountryStat 按国家/地区聚合的活跃嗅探来源分布。
type CountryStat struct {
	CountryCode   string  `json:"countryCode"`
	Country       string  `json:"country"`
	Flag          string  `json:"flag,omitempty"`
	UniqueIPs     int     `json:"uniqueIPs"`
	UniqueSubnets int     `json:"uniqueSubnets"`
	TotalHits     int     `json:"totalHits"`
	RatioPercent  float64 `json:"ratioPercent"`
}

// Summary 外部活跃嗅探三维聚合快照。
type Summary struct {
	UpdatedAt      string        `json:"updatedAt"`
	SelectedNode   string        `json:"selectedNode"`
	Nodes          []NodeSummary `json:"nodes,omitempty"`
	TotalSniffIPs  int           `json:"totalSniffIPs"`
	TotalSubnets   int           `json:"totalSubnets"`
	TotalCountries int           `json:"totalCountries"`
	TotalBannedIPs int           `json:"totalBannedIPs"`
	TopIPs         []IPStat      `json:"topIPs"`
	TopSubnets     []SubnetStat  `json:"topSubnets"`
	TopCountries   []CountryStat `json:"topCountries"`
}

// RemoteTarget 描述集群远端节点的消费侧纯值元数据（严禁导入 internal/fleet 防循环依赖）。
type RemoteTarget struct {
	ID      string
	Name    string
	Host    string
	Enabled bool
	Online  bool
}

// RemoteExecFunc 在远端目标节点上执行 SSH 脚本并返回输出、往返时延与错误。
type RemoteExecFunc func(ctx context.Context, target RemoteTarget, script string) (stdout string, rttMs int, err error)

// RemoteProvider 为嗅探引擎提供集群远端节点枚举、变更版本号与命令执行回调。
type RemoteProvider struct {
	ListTargets   func() ([]RemoteTarget, error)
	Revision      func() uint64
	Exec          RemoteExecFunc
	TelemetryAddr string
}

// LimiterAttempt 表示本机登录限流器暴露的单条试探记录快照。
type LimiterAttempt struct {
	IP        string
	FailCount int
	LastFail  time.Time
	Banned    bool
	Source    string
}

// BanLimiter 抽象本机登录防爆破限流器的最小消费侧接口。
type BanLimiter interface {
	Revision() uint64
	ListAllAttempts() []LimiterAttempt
	BanManual(ip string, duration time.Duration, reason ...string)
	Unban(ip string) bool
}

type sniffRecord struct {
	ip         string
	nodeID     string
	nodeName   string
	subnet     string
	hits       int
	vector     string
	status     string
	scannerTag string
	firstSeen  time.Time
	lastSeen   time.Time
}

type sniffPersistRecord struct {
	IP         string    `json:"ip"`
	NodeID     string    `json:"nodeId"`
	NodeName   string    `json:"nodeName,omitempty"`
	Subnet     string    `json:"subnet"`
	Hits       int       `json:"hits"`
	Vector     string    `json:"vector"`
	Status     string    `json:"status"`
	ScannerTag string    `json:"scannerTag,omitempty"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
}

type sniffPersistDoc struct {
	BlockedCIDRs     []string             `json:"blockedCidrs,omitempty"`
	NodeBlockedCIDRs map[string][]string  `json:"nodeBlockedCidrs,omitempty"`
	Records          []sniffPersistRecord `json:"records"`
}

type nodeHarvestMeta struct {
	lastHarvest time.Time
	lastError   string
}

type snapshotCacheEntry struct {
	dataRev    uint64
	geoRev     uint64
	limiterRev uint64
	remoteRev  uint64
	nodeCount  int
	builtAt    time.Time
	summary    Summary
}

// Tracker 外部活跃嗅探与探测态势聚合器（支持本机与多节点舰队分主机追踪）。
type Tracker struct {
	mu                 sync.RWMutex
	recordsByNode      map[string]map[string]*sniffRecord
	nodeMeta           map[string]*nodeHarvestMeta
	trustedClients     map[string]time.Time
	manualBlockedCIDRs map[string]*net.IPNet
	nodeBlockedCIDRs   map[string]map[string]*net.IPNet
	lastSystemHarvest  time.Time
	lastPersistAt      time.Time
	dirty              bool
	dataRev            uint64
	snapCache          map[string]snapshotCacheEntry
	filePath           string
	geo                *ipgeo.Resolver
	limiter            BanLimiter
	remote             *RemoteProvider
	EnableSystemProbe  bool
	remoteBgRunning    atomic.Bool
	systemBgRunning    atomic.Bool
	writeSeq           uint64
	writer             *fsx.AsyncSnapshotWriter
	snapshotRebuilds   atomic.Int64
}

// NewTracker 创建嗅探态势追踪器（可选传入 0600 持久化文件路径）。
func NewTracker(geo *ipgeo.Resolver, limiter BanLimiter, filePath ...string) *Tracker {
	fp := ""
	if len(filePath) > 0 {
		fp = strings.TrimSpace(filePath[0])
	}
	t := &Tracker{
		recordsByNode: map[string]map[string]*sniffRecord{
			"local": make(map[string]*sniffRecord),
		},
		nodeMeta:           make(map[string]*nodeHarvestMeta),
		trustedClients:     make(map[string]time.Time),
		manualBlockedCIDRs: make(map[string]*net.IPNet),
		nodeBlockedCIDRs:   make(map[string]map[string]*net.IPNet),
		snapCache:          make(map[string]snapshotCacheEntry),
		filePath:           fp,
		geo:                geo,
		limiter:            limiter,
		EnableSystemProbe:  true,
		writer:             fsx.NewAsyncSnapshotWriter(fp, fsx.WriteAtomic0600),
	}
	t.loadLocked()
	return t
}

// SetRemoteProvider 注入远端集群节点提供器与执行回调。
func (t *Tracker) SetRemoteProvider(p *RemoteProvider) {
	t.mu.Lock()
	t.remote = p
	t.mu.Unlock()
}

// SnapshotRebuilds 返回快照完整重算计数（供性能回归测试断言缓存命中）。
func (t *Tracker) SnapshotRebuilds() int64 {
	if t == nil {
		return 0
	}
	return t.snapshotRebuilds.Load()
}

func (t *Tracker) markDirtyLocked() {
	t.dirty = true
	t.dataRev++
}

func (t *Tracker) bumpDataRevLocked() {
	t.dataRev++
}

func (t *Tracker) ensureNodeMapLocked(nodeID string) map[string]*sniffRecord {
	nodeID = cmp.Or(strings.TrimSpace(nodeID), "local")
	m, ok := t.recordsByNode[nodeID]
	if !ok {
		m = make(map[string]*sniffRecord)
		t.recordsByNode[nodeID] = m
	}
	return m
}

func (t *Tracker) ensureNodeMetaLocked(nodeID string) *nodeHarvestMeta {
	nodeID = cmp.Or(strings.TrimSpace(nodeID), "local")
	meta, ok := t.nodeMeta[nodeID]
	if !ok {
		meta = &nodeHarvestMeta{}
		t.nodeMeta[nodeID] = meta
	}
	return meta
}

func (t *Tracker) hasNonBannedRecordLocked(ipStr string) bool {
	for _, nodeMap := range t.recordsByNode {
		if rec, exists := nodeMap[ipStr]; exists && rec.status != "banned" {
			return true
		}
	}
	return false
}

// MarkTrustedClientIPs 标记已通过鉴权的合法客户端或集群节点白名单 IP（自动从非封禁记录剔除）。
func (t *Tracker) MarkTrustedClientIPs(ips ...string) {
	normIPs := make([]string, 0, len(ips))
	for _, raw := range ips {
		if ipStr := NormalizeIPString(raw); ipStr != "" {
			normIPs = append(normIPs, ipStr)
		}
	}
	if len(normIPs) == 0 {
		return
	}

	now := time.Now()
	t.mu.RLock()
	needsUpdate := false
	for _, ipStr := range normIPs {
		exp, ok := t.trustedClients[ipStr]
		if !ok || exp.Sub(now) <= 30*time.Minute || t.hasNonBannedRecordLocked(ipStr) {
			needsUpdate = true
			break
		}
	}
	t.mu.RUnlock()
	if !needsUpdate {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ipStr := range normIPs {
		t.trustedClients[ipStr] = now.Add(trustedClientTTL)
		for _, nodeMap := range t.recordsByNode {
			if rec, exists := nodeMap[ipStr]; exists && rec.status != "banned" {
				delete(nodeMap, ipStr)
				t.markDirtyLocked()
			}
		}
	}
}

// Observe 记录本机一次外部嗅探或拦截事件。
func (t *Tracker) Observe(rawIP, vector, status string, hitsDelta int) {
	t.ObserveNode("local", "本机网关", rawIP, vector, status, hitsDelta)
}

// ObserveNode 记录指定集群节点的一次外部嗅探或拦截事件。
func (t *Tracker) ObserveNode(nodeID, nodeName, rawIP, vector, status string, hitsDelta int) {
	t.ObserveNodeAt(nodeID, nodeName, rawIP, vector, status, hitsDelta, time.Time{}, time.Time{})
}

// ObserveNodeAt 记录指定集群节点带显式开始/最近时间的嗅探事件。
func (t *Tracker) ObserveNodeAt(nodeID, nodeName, rawIP, vector, status string, hitsDelta int, firstTime, lastTime time.Time) {
	ipStr := NormalizeIPString(rawIP)
	if ipStr == "" || IsIgnoredInternalIP(ipStr) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observeNodeAtLocked(nodeID, nodeName, ipStr, vector, status, hitsDelta, false, firstTime, lastTime)
}

func defaultNodeDisplayName(nodeID, nodeName string) string {
	if nodeName != "" {
		return nodeName
	}
	if nodeID == "local" {
		return "本机网关"
	}
	return nodeID
}

func (t *Tracker) resolveEffectiveBanStatusLocked(nodeID, ipStr, status string) string {
	if status == "banned" {
		return status
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return status
	}
	for _, cidrNet := range t.manualBlockedCIDRs {
		if cidrNet.Contains(ip) {
			return "banned"
		}
	}
	for _, cidrNet := range t.nodeBlockedCIDRs[nodeID] {
		if cidrNet.Contains(ip) {
			return "banned"
		}
	}
	return status
}

func newSniffRecord(nodeID, nodeName, ipStr, vector, status string, hits int, firstTime, lastTime, now time.Time) *sniffRecord {
	fs := firstTime
	if fs.IsZero() {
		fs = cmp.Or(lastTime, now)
	}
	ls := lastTime
	if ls.IsZero() || ls.Before(fs) {
		ls = fs
	}
	return &sniffRecord{
		ip:         ipStr,
		nodeID:     nodeID,
		nodeName:   nodeName,
		subnet:     ComputeSubnetCIDR(ipStr),
		hits:       hits,
		vector:     cmp.Or(vector, "异常端口探测"),
		status:     cmp.Or(status, "observing"),
		scannerTag: MatchScannerTag(ipStr, ""),
		firstSeen:  fs,
		lastSeen:   ls,
	}
}

func (t *Tracker) observeNodeAtLocked(nodeID, nodeName, ipStr, vector, status string, hitsDelta int, setExactHits bool, firstTime, lastTime time.Time) {
	now := time.Now()
	nodeID = cmp.Or(strings.TrimSpace(nodeID), "local")
	nodeName = defaultNodeDisplayName(nodeID, nodeName)

	if exp, trusted := t.trustedClients[ipStr]; trusted && now.Before(exp) && status != "banned" {
		return
	}
	hitsDelta = max(1, hitsDelta)
	status = t.resolveEffectiveBanStatusLocked(nodeID, ipStr, status)

	nodeMap := t.ensureNodeMapLocked(nodeID)
	rec, exists := nodeMap[ipStr]
	if !exists {
		if len(nodeMap) >= maxTrackedSniffIPs {
			t.evictOldestInMapLocked(nodeMap, now)
		}
		nodeMap[ipStr] = newSniffRecord(nodeID, nodeName, ipStr, vector, status, hitsDelta, firstTime, lastTime, now)
		t.markDirtyLocked()
		return
	}

	t.updateExistingRecordLocked(rec, nodeName, vector, status, hitsDelta, setExactHits, firstTime, lastTime, now)
}

func (t *Tracker) updateExistingRecordLocked(rec *sniffRecord, nodeName, vector, status string, hitsDelta int, setExactHits bool, firstTime, lastTime, now time.Time) {
	if nodeName != "" && rec.nodeName != nodeName {
		rec.nodeName = nodeName
		t.bumpDataRevLocked()
	}
	if rec.firstSeen.IsZero() {
		rec.firstSeen = cmp.Or(firstTime, rec.lastSeen, now)
		t.bumpDataRevLocked()
	} else if !firstTime.IsZero() && firstTime.Before(rec.firstSeen) {
		rec.firstSeen = firstTime
		t.markDirtyLocked()
	}

	if setExactHits {
		t.calibrateExactHitsLocked(rec, hitsDelta, firstTime, lastTime, now)
	} else {
		rec.hits += hitsDelta
		if !lastTime.IsZero() && lastTime.After(rec.lastSeen) {
			rec.lastSeen = lastTime
		} else {
			rec.lastSeen = now
		}
		t.markDirtyLocked()
	}

	if vector != "" && (rec.vector == "" || rec.vector == "异常端口探测" || status == "banned") && rec.vector != vector {
		rec.vector = vector
		t.markDirtyLocked()
	}
	if statusPriority(status) > statusPriority(rec.status) {
		rec.status = status
		if lastTime.IsZero() {
			rec.lastSeen = now
		}
		t.markDirtyLocked()
	}
}

func (t *Tracker) calibrateExactHitsLocked(rec *sniffRecord, hitsDelta int, firstTime, lastTime, now time.Time) {
	if !firstTime.IsZero() && !lastTime.IsZero() && lastTime.Before(rec.lastSeen) && rec.lastSeen.Sub(firstTime) > time.Minute {
		if rec.vector == "高危端口扫描拦截" || rec.vector == "SSH 暴力破解" {
			rec.lastSeen = lastTime
			t.markDirtyLocked()
		}
	}
	if !lastTime.IsZero() && lastTime.After(rec.lastSeen) {
		rec.lastSeen = lastTime
		t.markDirtyLocked()
	}
	if hitsDelta > rec.hits {
		rec.hits = hitsDelta
		if lastTime.IsZero() {
			rec.lastSeen = now
		}
		t.markDirtyLocked()
	}
}

func (t *Tracker) evictOldestInMapLocked(nodeMap map[string]*sniffRecord, now time.Time) {
	var oldestIP string
	var oldestTime time.Time
	for ip, rec := range nodeMap {
		if now.Sub(rec.lastSeen) > sniffEntryTTL {
			delete(nodeMap, ip)
			t.markDirtyLocked()
			continue
		}
		if oldestIP == "" || rec.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = rec.lastSeen
		}
	}
	if len(nodeMap) >= maxTrackedSniffIPs && oldestIP != "" {
		delete(nodeMap, oldestIP)
		t.markDirtyLocked()
	}
}

func (t *Tracker) loadLocked() {
	if t.filePath == "" {
		return
	}
	data, err := os.ReadFile(t.filePath)
	if err != nil {
		return
	}
	var doc sniffPersistDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return
	}
	now := time.Now()
	for _, cidr := range doc.BlockedCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil && ipNet != nil {
			t.manualBlockedCIDRs[ipNet.String()] = ipNet
		}
	}
	for nid, cidrs := range doc.NodeBlockedCIDRs {
		if t.nodeBlockedCIDRs[nid] == nil {
			t.nodeBlockedCIDRs[nid] = make(map[string]*net.IPNet)
		}
		for _, cidr := range cidrs {
			if _, ipNet, err := net.ParseCIDR(cidr); err == nil && ipNet != nil {
				t.nodeBlockedCIDRs[nid][ipNet.String()] = ipNet
			}
		}
	}
	for _, r := range doc.Records {
		ipStr := NormalizeIPString(r.IP)
		if ipStr == "" || IsIgnoredInternalIP(ipStr) {
			continue
		}
		if !r.LastSeen.IsZero() && now.Sub(r.LastSeen) > sniffEntryTTL {
			continue
		}
		ls := cmp.Or(r.LastSeen, now)
		fs := r.FirstSeen
		if fs.IsZero() || fs.After(ls) {
			fs = ls
		}
		nid := cmp.Or(strings.TrimSpace(r.NodeID), "local")
		t.ensureNodeMapLocked(nid)[ipStr] = &sniffRecord{
			ip:         ipStr,
			nodeID:     nid,
			nodeName:   cmp.Or(r.NodeName, nid),
			subnet:     cmp.Or(r.Subnet, ComputeSubnetCIDR(ipStr)),
			hits:       max(1, r.Hits),
			vector:     cmp.Or(r.Vector, "异常端口探测"),
			status:     cmp.Or(r.Status, "observing"),
			scannerTag: cmp.Or(r.ScannerTag, MatchScannerTag(ipStr, "")),
			firstSeen:  fs,
			lastSeen:   ls,
		}
	}
}

func (t *Tracker) snapshotPersistBytesLocked(now time.Time, force bool) ([]byte, uint64) {
	if t.filePath == "" {
		return nil, 0
	}
	if !force && (!t.dirty || (!t.lastPersistAt.IsZero() && now.Sub(t.lastPersistAt) < sniffSaveMinDT)) {
		return nil, 0
	}
	t.lastPersistAt = now
	t.dirty = false

	doc := sniffPersistDoc{NodeBlockedCIDRs: make(map[string][]string)}
	for cidr := range t.manualBlockedCIDRs {
		doc.BlockedCIDRs = append(doc.BlockedCIDRs, cidr)
	}
	for nid, cmap := range t.nodeBlockedCIDRs {
		for cidr := range cmap {
			doc.NodeBlockedCIDRs[nid] = append(doc.NodeBlockedCIDRs[nid], cidr)
		}
	}
	for nid, nodeMap := range t.recordsByNode {
		for _, rec := range nodeMap {
			if now.Sub(rec.lastSeen) > sniffEntryTTL {
				continue
			}
			doc.Records = append(doc.Records, sniffPersistRecord{
				IP:         rec.ip,
				NodeID:     nid,
				NodeName:   rec.nodeName,
				Subnet:     rec.subnet,
				Hits:       rec.hits,
				Vector:     rec.vector,
				Status:     rec.status,
				ScannerTag: rec.scannerTag,
				FirstSeen:  rec.firstSeen,
				LastSeen:   rec.lastSeen,
			})
		}
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, 0
	}
	t.writeSeq++
	return raw, t.writeSeq
}

func (t *Tracker) persistSnapshot(raw []byte, seq uint64, fastWait time.Duration) {
	if t == nil || t.filePath == "" || t.writer == nil || len(raw) == 0 {
		return
	}
	t.writer.Submit(raw, seq, fastWait)
}

func (t *Tracker) scheduleAsyncSaveIfNeeded() {
	if t == nil || t.filePath == "" || t.writer == nil {
		return
	}
	t.mu.Lock()
	raw, seq := t.snapshotPersistBytesLocked(time.Now(), false)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq, 0)
}

// Flush 将内存中的嗅探与封禁快照立即同步刷新到磁盘（0600）。
func (t *Tracker) Flush() {
	if t == nil || t.filePath == "" || t.writer == nil {
		return
	}
	t.mu.Lock()
	raw, seq := t.snapshotPersistBytesLocked(time.Now(), true)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq, 25*time.Millisecond)
	t.writer.Flush(500 * time.Millisecond)
}
