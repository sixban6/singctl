// 文件职责：定义外部活跃嗅探追踪核心结构（SniffTracker 及三维态势汇总数据模型）、可信白名单快速过滤、记录聚合状态机与 0600 有序落盘持久化。
//
// 架构设计原则：
//   - 高内聚职责拆 file：指纹识别与网段聚合位于 sniff_fingerprints.go；多格式日志提取位于 sniff_parsers.go；
//     本机与远端采集位于 sniff_harvester.go；本机与集群协同封禁位于 sniff_enforcer.go；快照构建位于 sniff_snapshot.go。
//   - 并发读写无锁争抢：MarkTrustedClientIPs 先走 RLock 快路径；异步磁盘落盘通过递增序号 writeSeq 保证不倒序覆盖。
package serverweb

import (
	"cmp"
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/fleet"
)

const (
	maxTrackedSniffIPs = 1000
	sniffEntryTTL      = 24 * time.Hour
	trustedClientTTL   = 2 * time.Hour
	systemHarvestMinDT = 15 * time.Second
	fleetHarvestMinDT  = 30 * time.Second
	sniffSaveMinDT     = 60 * time.Second
	SniffTimeLayout    = "2006-01-02 15:04:05"
)

// SniffNodeRef 标记某个嗅探源被集群中哪台主机捕获
type SniffNodeRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host,omitempty"`
}

// SniffNodeSummary 集群中单台主机（或全集群汇总）的嗅探统计摘要
type SniffNodeSummary struct {
	ID            string `json:"id"`   // "all" | "local" | "<fleet_node_id>"
	Name          string `json:"name"` // "全集群汇总" | "本机网关" | 子节点名称
	Host          string `json:"host,omitempty"`
	Online        bool   `json:"online"`
	TotalSniffIPs int    `json:"totalSniffIPs"`
	TotalSubnets  int    `json:"totalSubnets"`
	TotalBanned   int    `json:"totalBanned"`
	LastHarvestAt string `json:"lastHarvestAt,omitempty"`
	Error         string `json:"error,omitempty"`
}

// SniffIPStat 单个外部活跃嗅探 IP 的态势详情 (含首次开始时间、最近活跃时间及受探主机)
type SniffIPStat struct {
	IP          string         `json:"ip"`
	Subnet      string         `json:"subnet"`
	Hits        int            `json:"hits"`
	Vector      string         `json:"vector"`
	Status      string         `json:"status"` // "banned" | "masqueraded" | "observing"
	Country     string         `json:"country,omitempty"`
	CountryCode string         `json:"countryCode,omitempty"`
	Flag        string         `json:"flag,omitempty"`
	Geo         string         `json:"geo,omitempty"`
	ISP         string         `json:"isp,omitempty"`
	ScannerTag  string         `json:"scannerTag,omitempty"`
	FirstSeen   string         `json:"firstSeen"` // 首次探测/开始时间 (YYYY-MM-DD HH:mm:ss)
	LastSeen    string         `json:"lastSeen"`  // 最近探测/最后时间 (YYYY-MM-DD HH:mm:ss)
	Nodes       []SniffNodeRef `json:"nodes,omitempty"`
}

// SniffSubnetStat 按 /24 (IPv4) 或 /48 (IPv6) 聚合的活跃嗅探网段态势
type SniffSubnetStat struct {
	CIDR        string         `json:"cidr"`
	UniqueIPs   int            `json:"uniqueIPs"`
	TotalHits   int            `json:"totalHits"`
	BannedCount int            `json:"bannedCount"`
	Status      string         `json:"status"` // "banned" | "partial" | "active"
	Country     string         `json:"country,omitempty"`
	CountryCode string         `json:"countryCode,omitempty"`
	Flag        string         `json:"flag,omitempty"`
	ISP         string         `json:"isp,omitempty"`
	ScannerTag  string         `json:"scannerTag,omitempty"`
	SampleIPs   []string       `json:"sampleIPs,omitempty"`
	FirstSeen   string         `json:"firstSeen"` // 该网段首次出现探测时间
	LastSeen    string         `json:"lastSeen"`  // 该网段最近活跃探测时间
	Nodes       []SniffNodeRef `json:"nodes,omitempty"`
}

// SniffCountryStat 按国家/地区聚合的活跃嗅探来源分布
type SniffCountryStat struct {
	CountryCode   string  `json:"countryCode"`
	Country       string  `json:"country"`
	Flag          string  `json:"flag,omitempty"`
	UniqueIPs     int     `json:"uniqueIPs"`
	UniqueSubnets int     `json:"uniqueSubnets"`
	TotalHits     int     `json:"totalHits"`
	RatioPercent  float64 `json:"ratioPercent"`
}

// SniffSummary 外部活跃嗅探三维聚合快照 (支持全集群或分主机查看、全量返回)
type SniffSummary struct {
	UpdatedAt      string             `json:"updatedAt"`
	SelectedNode   string             `json:"selectedNode"` // "all" | "local" | "<node_id>"
	Nodes          []SniffNodeSummary `json:"nodes,omitempty"`
	TotalSniffIPs  int                `json:"totalSniffIPs"`
	TotalSubnets   int                `json:"totalSubnets"`
	TotalCountries int                `json:"totalCountries"`
	TotalBannedIPs int                `json:"totalBannedIPs"`
	TopIPs         []SniffIPStat      `json:"topIPs"`
	TopSubnets     []SniffSubnetStat  `json:"topSubnets"`
	TopCountries   []SniffCountryStat `json:"topCountries"`
}

type sniffRecord struct {
	ip         string
	nodeID     string
	nodeName   string
	subnet     string
	hits       int
	vector     string
	status     string // "banned" | "masqueraded" | "observing"
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

// SniffTracker 外部活跃嗅探与探测态势聚合器 (支持本机与多节点舰队分主机追踪)
type SniffTracker struct {
	mu                 sync.RWMutex
	recordsByNode      map[string]map[string]*sniffRecord
	nodeMeta           map[string]*nodeHarvestMeta
	trustedClients     map[string]time.Time
	manualBlockedCIDRs map[string]*net.IPNet
	nodeBlockedCIDRs   map[string]map[string]*net.IPNet
	lastSystemHarvest  time.Time
	lastPersistAt      time.Time
	dirty              bool
	filePath           string
	geo                *IPGeoResolver
	limiter            *IPLimiter
	fleetMgr           *fleet.Manager
	EnableSystemProbe  bool
	fleetBgRunning     atomic.Bool
	systemBgRunning    atomic.Bool
	saveRunning        atomic.Bool
	diskMu             sync.Mutex
	writeSeq           uint64
	writtenSeq         uint64
}

// NewSniffTracker 创建嗅探态势追踪器 (可选传入 0600 持久化文件路径)
func NewSniffTracker(geo *IPGeoResolver, limiter *IPLimiter, filePath ...string) *SniffTracker {
	fp := ""
	if len(filePath) > 0 {
		fp = strings.TrimSpace(filePath[0])
	}
	t := &SniffTracker{
		recordsByNode: map[string]map[string]*sniffRecord{
			"local": make(map[string]*sniffRecord),
		},
		nodeMeta:           make(map[string]*nodeHarvestMeta),
		trustedClients:     make(map[string]time.Time),
		manualBlockedCIDRs: make(map[string]*net.IPNet),
		nodeBlockedCIDRs:   make(map[string]map[string]*net.IPNet),
		filePath:           fp,
		geo:                geo,
		limiter:            limiter,
		EnableSystemProbe:  true,
	}
	t.loadLocked()
	return t
}

// SetFleetManager 绑定集群节点管理器以支持分主机嗅探采集与协同封禁
func (t *SniffTracker) SetFleetManager(mgr *fleet.Manager) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fleetMgr = mgr
}

func (t *SniffTracker) ensureNodeMapLocked(nodeID string) map[string]*sniffRecord {
	nodeID = cmp.Or(strings.TrimSpace(nodeID), "local")
	m, ok := t.recordsByNode[nodeID]
	if !ok {
		m = make(map[string]*sniffRecord)
		t.recordsByNode[nodeID] = m
	}
	return m
}

func (t *SniffTracker) ensureNodeMetaLocked(nodeID string) *nodeHarvestMeta {
	nodeID = cmp.Or(strings.TrimSpace(nodeID), "local")
	meta, ok := t.nodeMeta[nodeID]
	if !ok {
		meta = &nodeHarvestMeta{}
		t.nodeMeta[nodeID] = meta
	}
	return meta
}

// MarkTrustedClientIPs 标记已通过鉴权的合法客户端或集群白名单 IP (自动从所有主机嗅探列表中剔除)
func (t *SniffTracker) MarkTrustedClientIPs(ips ...string) {
	normIPs := make([]string, 0, len(ips))
	for _, raw := range ips {
		if ipStr := normalizeIPString(raw); ipStr != "" {
			normIPs = append(normIPs, ipStr)
		}
	}
	if len(normIPs) == 0 {
		return
	}

	now := time.Now()
	// 快路径：已在可信白名单（剩余 TTL > 30m）且各节点记录中无非封禁残留时，仅持 RLock 即可返回，零写锁竞争
	t.mu.RLock()
	needsUpdate := false
	for _, ipStr := range normIPs {
		exp, ok := t.trustedClients[ipStr]
		if !ok || exp.Sub(now) <= 30*time.Minute {
			needsUpdate = true
			break
		}
		for _, nodeMap := range t.recordsByNode {
			if rec, exists := nodeMap[ipStr]; exists && rec.status != "banned" {
				needsUpdate = true
				break
			}
		}
		if needsUpdate {
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
				t.dirty = true
			}
		}
	}
}

// Observe 记录本机一次外部嗅探或拦截事件
func (t *SniffTracker) Observe(rawIP, vector, status string, hitsDelta int) {
	t.ObserveNode("local", "本机网关", rawIP, vector, status, hitsDelta)
}

// ObserveNode 记录指定集群节点的一次外部嗅探或拦截事件
func (t *SniffTracker) ObserveNode(nodeID, nodeName, rawIP, vector, status string, hitsDelta int) {
	t.ObserveNodeAt(nodeID, nodeName, rawIP, vector, status, hitsDelta, time.Time{}, time.Time{})
}

// ObserveNodeAt 记录指定集群节点带显式开始/最近时间的嗅探事件
func (t *SniffTracker) ObserveNodeAt(nodeID, nodeName, rawIP, vector, status string, hitsDelta int, firstTime, lastTime time.Time) {
	ipStr := normalizeIPString(rawIP)
	if ipStr == "" || isIgnoredInternalIP(ipStr) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observeNodeAtLocked(nodeID, nodeName, ipStr, vector, status, hitsDelta, false, firstTime, lastTime)
}

// Flush 将内存中的嗅探与封禁快照立即同步持久化到磁盘（0600）
func (t *SniffTracker) Flush() {
	if t == nil || t.filePath == "" {
		return
	}
	t.mu.Lock()
	raw, seq := t.snapshotPersistBytesLocked(time.Now(), true)
	t.mu.Unlock()
	t.persistSnapshot(raw, seq)
}

func (t *SniffTracker) observeNodeAtLocked(nodeID, nodeName, ipStr, vector, status string, hitsDelta int, setExactHits bool, firstTime, lastTime time.Time) {
	now := time.Now()
	nodeID = cmp.Or(strings.TrimSpace(nodeID), "local")
	if nodeName == "" {
		if nodeID == "local" {
			nodeName = "本机网关"
		} else {
			nodeName = nodeID
		}
	}

	// 若属于合法代理用户/管理员白名单且非防火墙强制封禁，直接忽略
	if exp, trusted := t.trustedClients[ipStr]; trusted && now.Before(exp) && status != "banned" {
		return
	}

	subnet := ComputeSubnetCIDR(ipStr)
	if hitsDelta <= 0 {
		hitsDelta = 1
	}

	// 检查该 IP 是否命中全局或该节点已手动封禁的网段
	if ip := net.ParseIP(ipStr); ip != nil {
		for _, cidrNet := range t.manualBlockedCIDRs {
			if cidrNet.Contains(ip) {
				status = "banned"
				break
			}
		}
		if status != "banned" {
			if nBlocked, ok := t.nodeBlockedCIDRs[nodeID]; ok {
				for _, cidrNet := range nBlocked {
					if cidrNet.Contains(ip) {
						status = "banned"
						break
					}
				}
			}
		}
	}

	nodeMap := t.ensureNodeMapLocked(nodeID)
	rec, exists := nodeMap[ipStr]
	if !exists {
		if len(nodeMap) >= maxTrackedSniffIPs {
			t.evictOldestInMapLocked(nodeMap, now)
		}
		fs := firstTime
		ls := lastTime
		if fs.IsZero() {
			if !ls.IsZero() {
				fs = ls
			} else {
				fs = now
			}
		}
		if ls.IsZero() || ls.Before(fs) {
			ls = fs
		}
		rec = &sniffRecord{
			ip:         ipStr,
			nodeID:     nodeID,
			nodeName:   nodeName,
			subnet:     subnet,
			hits:       hitsDelta,
			vector:     cmp.Or(vector, "异常端口探测"),
			status:     cmp.Or(status, "observing"),
			scannerTag: MatchScannerTag(ipStr, ""),
			firstSeen:  fs,
			lastSeen:   ls,
		}
		nodeMap[ipStr] = rec
		t.dirty = true
		return
	}

	if nodeName != "" && rec.nodeName != nodeName {
		rec.nodeName = nodeName
	}
	if rec.firstSeen.IsZero() {
		if !firstTime.IsZero() {
			rec.firstSeen = firstTime
		} else if !rec.lastSeen.IsZero() {
			rec.firstSeen = rec.lastSeen
		} else {
			rec.firstSeen = now
		}
	} else if !firstTime.IsZero() && firstTime.Before(rec.firstSeen) {
		rec.firstSeen = firstTime
		t.dirty = true
	}

	if setExactHits {
		// 若此前仅记录了首次采集时刻的近似时间，而本次从 nftables expires 或日志解析出了更早的真实拦截时间，自动校准
		if !firstTime.IsZero() && !lastTime.IsZero() && lastTime.Before(rec.lastSeen) && rec.lastSeen.Sub(firstTime) > time.Minute {
			if rec.vector == "高危端口扫描拦截" || rec.vector == "SSH 暴力破解" {
				rec.lastSeen = lastTime
				t.dirty = true
			}
		}
		if !lastTime.IsZero() && lastTime.After(rec.lastSeen) {
			rec.lastSeen = lastTime
			t.dirty = true
		}
		if hitsDelta > rec.hits {
			rec.hits = hitsDelta
			if lastTime.IsZero() {
				rec.lastSeen = now
			}
			t.dirty = true
		}
	} else {
		rec.hits += hitsDelta
		if !lastTime.IsZero() && lastTime.After(rec.lastSeen) {
			rec.lastSeen = lastTime
		} else {
			rec.lastSeen = now
		}
		t.dirty = true
	}

	if vector != "" && (rec.vector == "" || rec.vector == "异常端口探测" || status == "banned") {
		if rec.vector != vector {
			rec.vector = vector
			t.dirty = true
		}
	}
	if statusPriority(status) > statusPriority(rec.status) {
		rec.status = status
		if lastTime.IsZero() {
			rec.lastSeen = now
		}
		t.dirty = true
	}
}

func (t *SniffTracker) evictOldestInMapLocked(nodeMap map[string]*sniffRecord, now time.Time) {
	var oldestIP string
	var oldestTime time.Time
	for ip, rec := range nodeMap {
		if now.Sub(rec.lastSeen) > sniffEntryTTL {
			delete(nodeMap, ip)
			continue
		}
		if oldestIP == "" || rec.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = rec.lastSeen
		}
	}
	if len(nodeMap) >= maxTrackedSniffIPs && oldestIP != "" {
		delete(nodeMap, oldestIP)
	}
}

func (t *SniffTracker) loadLocked() {
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
		ipStr := normalizeIPString(r.IP)
		if ipStr == "" || isIgnoredInternalIP(ipStr) {
			continue
		}
		if !r.LastSeen.IsZero() && now.Sub(r.LastSeen) > sniffEntryTTL {
			continue
		}
		fs := r.FirstSeen
		ls := r.LastSeen
		if ls.IsZero() {
			ls = now
		}
		if fs.IsZero() || fs.After(ls) {
			fs = ls
		}
		nid := cmp.Or(strings.TrimSpace(r.NodeID), "local")
		nodeMap := t.ensureNodeMapLocked(nid)
		nodeMap[ipStr] = &sniffRecord{
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

func (t *SniffTracker) scheduleAsyncSaveIfNeeded() {
	if t == nil || t.filePath == "" {
		return
	}
	t.mu.RLock()
	need := t.dirty && (t.lastPersistAt.IsZero() || time.Since(t.lastPersistAt) >= sniffSaveMinDT)
	t.mu.RUnlock()
	if !need || !t.saveRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer t.saveRunning.Store(false)
		t.mu.Lock()
		raw, seq := t.snapshotPersistBytesLocked(time.Now(), false)
		t.mu.Unlock()
		t.persistSnapshot(raw, seq)
	}()
}

func (t *SniffTracker) snapshotPersistBytesLocked(now time.Time, force bool) ([]byte, uint64) {
	if t.filePath == "" {
		return nil, 0
	}
	if !force && (!t.dirty || (!t.lastPersistAt.IsZero() && now.Sub(t.lastPersistAt) < sniffSaveMinDT)) {
		return nil, 0
	}
	t.lastPersistAt = now
	t.dirty = false

	doc := sniffPersistDoc{
		NodeBlockedCIDRs: make(map[string][]string),
	}
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

func (t *SniffTracker) persistSnapshot(raw []byte, seq uint64) {
	if t.filePath == "" || len(raw) == 0 {
		return
	}
	t.diskMu.Lock()
	defer t.diskMu.Unlock()
	if seq > t.writtenSeq {
		if err := writeAtomicFile0600(t.filePath, raw); err == nil {
			t.writtenSeq = seq
		}
	}
}
