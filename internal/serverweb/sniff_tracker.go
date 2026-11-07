package serverweb

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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
	systemHarvestMinDT = 6 * time.Second
	fleetHarvestMinDT  = 20 * time.Second
	sniffSaveMinDT     = 3 * time.Second
	sniffTimeLayout    = "2006-01-02 15:04:05"
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

type knownScannerCIDR struct {
	net *net.IPNet
	tag string
}

var (
	knownScannerCIDRsOnce sync.Once
	parsedScannerCIDRs    []knownScannerCIDR

	reNFTLogLine      = regexp.MustCompile(`SRC=([0-9a-fA-F:\.]+).*?DPT=([0-9]+)`)
	reIPv4Token       = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reNFTTimeout      = regexp.MustCompile(`timeout\s+([0-9a-zA-Z]+)`)
	reNFTExpires      = regexp.MustCompile(`expires\s+([0-9a-zA-Z]+)`)
	reFail2banLogIP   = regexp.MustCompile(`\b(?:Found|Ban)\s+([0-9a-fA-F:\.]+)`)
	reSingBoxSourceIP = regexp.MustCompile(`"sourceIP"\s*:\s*"([^"]+)"`)
)

func initScannerFingerprints() {
	knownScannerCIDRsOnce.Do(func() {
		raw := []struct {
			cidr string
			tag  string
		}{
			// Censys 测绘引擎
			{"162.142.125.0/24", "Censys 测绘"},
			{"167.94.138.0/24", "Censys 测绘"},
			{"167.94.145.0/24", "Censys 测绘"},
			{"167.94.146.0/24", "Censys 测绘"},
			{"199.45.154.0/24", "Censys 测绘"},
			{"199.45.155.0/24", "Censys 测绘"},
			{"206.168.34.0/24", "Censys 测绘"},
			// Shodan 扫描器
			{"66.240.192.0/24", "Shodan 扫描"},
			{"66.240.205.0/24", "Shodan 扫描"},
			{"66.240.236.0/24", "Shodan 扫描"},
			{"71.6.135.0/24", "Shodan 扫描"},
			{"71.6.146.0/24", "Shodan 扫描"},
			{"71.6.158.0/24", "Shodan 扫描"},
			{"71.6.165.0/24", "Shodan 扫描"},
			{"71.6.167.0/24", "Shodan 扫描"},
			{"82.221.105.0/24", "Shodan 扫描"},
			{"85.25.43.0/24", "Shodan 扫描"},
			{"85.25.103.0/24", "Shodan 扫描"},
			{"93.120.27.0/24", "Shodan 扫描"},
			{"188.138.9.0/24", "Shodan 扫描"},
			{"198.20.69.0/24", "Shodan 扫描"},
			{"198.20.70.0/24", "Shodan 扫描"},
			{"198.20.87.0/24", "Shodan 扫描"},
			{"198.20.99.0/24", "Shodan 扫描"},
			// Shadowserver 安全测绘
			{"64.62.156.0/24", "Shadowserver"},
			{"64.62.197.0/24", "Shadowserver"},
			{"74.82.47.0/24", "Shadowserver"},
			{"184.105.139.0/24", "Shadowserver"},
			{"184.105.143.0/24", "Shadowserver"},
			{"184.105.247.0/24", "Shadowserver"},
			{"216.218.206.0/24", "Shadowserver"},
			// PaloAlto Expanse / Rapid7 / BinaryEdge
			{"198.235.24.0/24", "PaloAlto Expanse"},
			{"205.210.31.0/24", "PaloAlto Expanse"},
			{"192.241.128.0/17", "Stretchoid 扫描"},
			{"71.6.232.0/24", "Rapid7 Sonar"},
			{"45.143.200.0/24", "BinaryEdge"},
			{"193.163.125.0/24", "BinaryEdge"},
			// SingCtl 内置高频恶意扫描段 (与 firewall.go 对齐)
			{"218.92.0.0/16", "高频 SSH 爆破集群"},
			{"115.236.113.0/24", "高频探测段"},
			{"159.203.0.0/16", "云主机扫描段"},
			{"91.92.240.0/21", "恶意漏洞扫描段"},
			{"193.142.146.0/24", "恶意端口扫描段"},
			{"45.148.10.0/24", "恶意端口扫描段"},
			{"185.220.101.0/24", "Tor/匿名扫描出口"},
			{"194.26.135.0/24", "恶意端口扫描段"},
			{"79.124.58.0/24", "恶意端口扫描段"},
			{"79.124.60.0/24", "恶意端口扫描段"},
		}
		for _, item := range raw {
			if _, ipNet, err := net.ParseCIDR(item.cidr); err == nil && ipNet != nil {
				parsedScannerCIDRs = append(parsedScannerCIDRs, knownScannerCIDR{
					net: ipNet,
					tag: item.tag,
				})
			}
		}
	})
}

// MatchScannerTag 匹配已知扫描器组织或高危网段标签
func MatchScannerTag(ipStr, isp string) string {
	initScannerFingerprints()
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip != nil {
		for _, item := range parsedScannerCIDRs {
			if item.net.Contains(ip) {
				return item.tag
			}
		}
	}
	lowerISP := strings.ToLower(isp)
	switch {
	case strings.Contains(lowerISP, "censys"):
		return "Censys 测绘"
	case strings.Contains(lowerISP, "shodan"):
		return "Shodan 扫描"
	case strings.Contains(lowerISP, "shadowserver"):
		return "Shadowserver"
	case strings.Contains(lowerISP, "expanse") || strings.Contains(lowerISP, "palo alto"):
		return "PaloAlto Expanse"
	case strings.Contains(lowerISP, "rapid7"):
		return "Rapid7 Sonar"
	case strings.Contains(lowerISP, "binaryedge"):
		return "BinaryEdge"
	case strings.Contains(lowerISP, "stretchoid"):
		return "Stretchoid 扫描"
	case strings.Contains(lowerISP, "alphastrike"):
		return "AlphaStrike 扫描"
	}
	return ""
}

// ComputeSubnetCIDR 将单个 IP 归并为其所属的 /24 (IPv4) 或 /48 (IPv6) 网段
func ComputeSubnetCIDR(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		mask := net.CIDRMask(24, 32)
		network := v4.Mask(mask)
		return fmt.Sprintf("%s/24", network.String())
	}
	mask := net.CIDRMask(48, 128)
	network := ip.Mask(mask)
	return fmt.Sprintf("%s/48", network.String())
}

// isIgnoredInternalIP 判断是否为回环、私有局域网、链路本地或 Tailscale/CGNAT 内网地址
func isIgnoredInternalIP(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// 排除 100.64.0.0/10 (Tailscale / CGNAT)
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		if v4[0] == 255 {
			return true
		}
	}
	return false
}

func formatSniffTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Local().Format(sniffTimeLayout)
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
	enableSystemProbe  bool
	fleetBgRunning     atomic.Bool
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
		enableSystemProbe:  true,
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
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, raw := range ips {
		ipStr := normalizeIPString(raw)
		if ipStr == "" {
			continue
		}
		t.trustedClients[ipStr] = now.Add(trustedClientTTL)
		for _, nodeMap := range t.recordsByNode {
			if rec, exists := nodeMap[ipStr]; exists && rec.status != "banned" {
				delete(nodeMap, ipStr)
				t.dirty = true
			}
		}
	}
}

func normalizeIPString(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	s = strings.TrimPrefix(s, "::ffff:")
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
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

func (t *SniffTracker) observeLocked(ipStr, vector, status string, hitsDelta int, setExactHits bool) {
	t.observeNodeAtLocked("local", "本机网关", ipStr, vector, status, hitsDelta, setExactHits, time.Time{}, time.Time{})
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
		if !firstTime.IsZero() && !lastTime.IsZero() && lastTime.Before(rec.lastSeen) && rec.lastSeen.Sub( firstTime ) > time.Minute {
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

func statusPriority(status string) int {
	switch status {
	case "banned":
		return 3
	case "masqueraded":
		return 2
	default:
		return 1
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

// BlockTarget 手动在本机拉黑单个嗅探 IP 或 /24 网段 (保持向后兼容)
func (t *SniffTracker) BlockTarget(target, operatorIP string, extraProtectedIPs ...string) (string, error) {
	canonical, _, err := t.BlockTargetForNode(context.Background(), target, "local", operatorIP, extraProtectedIPs...)
	return canonical, err
}

// BlockTargetForNode 手动在指定主机 ("local" | "<node_id>" | "all") 一键拉黑单个嗅探 IP 或 /24 网段
func (t *SniffTracker) BlockTargetForNode(ctx context.Context, target, nodeScope, operatorIP string, extraProtectedIPs ...string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, fmt.Errorf("封禁目标不能为空")
	}
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")

	opNorm := normalizeIPString(operatorIP)
	protectedSet := make(map[string]struct{})
	if opNorm != "" {
		protectedSet[opNorm] = struct{}{}
	}
	for _, p := range extraProtectedIPs {
		if norm := normalizeIPString(p); norm != "" {
			protectedSet[norm] = struct{}{}
		}
	}

	t.mu.RLock()
	now := time.Now()
	for ip, exp := range t.trustedClients {
		if now.Before(exp) {
			protectedSet[ip] = struct{}{}
		}
	}
	fleetMgr := t.fleetMgr
	t.mu.RUnlock()

	if fleetMgr != nil && fleetMgr.Store != nil {
		if fNodes, err := fleetMgr.Store.ListPublic(); err == nil {
			for _, fn := range fNodes {
				if norm := normalizeIPString(fn.Host); norm != "" {
					protectedSet[norm] = struct{}{}
				}
			}
		}
	}

	isCIDR := strings.Contains(target, "/")
	var canonicalTarget string
	var parsedNet *net.IPNet
	var isIPv4 bool

	if isCIDR {
		ip, ipNet, err := net.ParseCIDR(target)
		if err != nil || ip == nil || ipNet == nil {
			return "", 0, fmt.Errorf("无效的 CIDR 网段格式: %s", target)
		}
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && ones < 16 {
			return "", 0, fmt.Errorf("为防止误伤大面积网络，IPv4 网段掩码长度须在 /16 至 /32 之间")
		}
		if bits == 128 && ones < 32 {
			return "", 0, fmt.Errorf("IPv6 网段掩码长度须在 /32 至 /128 之间")
		}
		if isIgnoredInternalIP(ip.String()) {
			return "", 0, fmt.Errorf("安全防锁死保护：禁止封禁本地回环、局域网或内网保留网段 (%s)", target)
		}
		for protIPStr := range protectedSet {
			if protIP := net.ParseIP(protIPStr); protIP != nil && ipNet.Contains(protIP) {
				return "", 0, fmt.Errorf("安全防锁死保护：目标网段 (%s) 包含当前管理会话或受保护节点 IP (%s)，已拒绝执行", target, protIPStr)
			}
		}
		canonicalTarget = ipNet.String()
		parsedNet = ipNet
		isIPv4 = bits == 32
	} else {
		ipStr := normalizeIPString(target)
		if ipStr == "" {
			return "", 0, fmt.Errorf("无效的 IP 地址格式: %s", target)
		}
		if isIgnoredInternalIP(ipStr) {
			return "", 0, fmt.Errorf("安全防锁死保护：禁止封禁本地回环或内网保留地址 (%s)", ipStr)
		}
		if _, isProtected := protectedSet[ipStr]; isProtected {
			return "", 0, fmt.Errorf("安全防锁死保护：禁止拉黑您当前所在的管理 IP 或集群受保护节点 (%s)", ipStr)
		}
		canonicalTarget = ipStr
		parsedIP := net.ParseIP(ipStr)
		isIPv4 = parsedIP != nil && parsedIP.To4() != nil
	}

	// 确定目标受控节点集合
	applyLocal := nodeScope == "all" || nodeScope == "local"
	var remoteNodes []fleet.Node
	if fleetMgr != nil && fleetMgr.Store != nil && (nodeScope == "all" || nodeScope != "local") {
		if allNodes, err := fleetMgr.Store.List(); err == nil {
			for _, n := range allNodes {
				if !n.Enabled {
					continue
				}
				if nodeScope == "all" || n.ID == nodeScope {
					remoteNodes = append(remoteNodes, n)
				}
			}
		}
	}

	// 更新内存状态并持久化
	t.mu.Lock()
	targetNodeIDs := make([]string, 0, 1+len(remoteNodes))
	if applyLocal {
		targetNodeIDs = append(targetNodeIDs, "local")
	}
	for _, rn := range remoteNodes {
		targetNodeIDs = append(targetNodeIDs, rn.ID)
	}
	if len(targetNodeIDs) == 0 && nodeScope != "local" {
		targetNodeIDs = append(targetNodeIDs, nodeScope)
	}

	if isCIDR {
		if nodeScope == "all" || nodeScope == "local" {
			t.manualBlockedCIDRs[canonicalTarget] = parsedNet
		}
		for _, nid := range targetNodeIDs {
			if t.nodeBlockedCIDRs[nid] == nil {
				t.nodeBlockedCIDRs[nid] = make(map[string]*net.IPNet)
			}
			t.nodeBlockedCIDRs[nid][canonicalTarget] = parsedNet
			if nodeMap, ok := t.recordsByNode[nid]; ok {
				for _, rec := range nodeMap {
					if recIP := net.ParseIP(rec.ip); recIP != nil && parsedNet.Contains(recIP) {
						rec.status = "banned"
					}
				}
			}
		}
		if nodeScope == "all" {
			for _, nodeMap := range t.recordsByNode {
				for _, rec := range nodeMap {
					if recIP := net.ParseIP(rec.ip); recIP != nil && parsedNet.Contains(recIP) {
						rec.status = "banned"
					}
				}
			}
		}
	} else {
		for _, nid := range targetNodeIDs {
			nodeName := nid
			if nid == "local" {
				nodeName = "本机网关"
			} else {
				for _, rn := range remoteNodes {
					if rn.ID == nid {
						nodeName = cmp.Or(rn.Name, rn.ID)
						break
					}
				}
			}
			t.observeNodeAtLocked(nid, nodeName, canonicalTarget, "管理员手动拉黑", "banned", 1, true, time.Time{}, now)
			if rec, ok := t.recordsByNode[nid][canonicalTarget]; ok {
				rec.status = "banned"
			}
		}
		if nodeScope == "all" {
			for _, nodeMap := range t.recordsByNode {
				if rec, ok := nodeMap[canonicalTarget]; ok {
					rec.status = "banned"
				}
			}
		}
	}
	t.dirty = true
	t.saveLocked(true)
	t.mu.Unlock()

	appliedNodes := 0
	if applyLocal {
		appliedNodes++
		if isCIDR {
			applyNFTBlockCIDR(canonicalTarget, isIPv4)
		} else {
			if t.limiter != nil {
				t.limiter.BanManual(canonicalTarget, 7*24*time.Hour)
			}
			applyNFTBlockIP(canonicalTarget, isIPv4)
		}
	}

	if len(remoteNodes) > 0 && fleetMgr != nil {
		runner := fleetMgr.Runner
		if runner == nil {
			runner = fleet.DefaultSSHRunner
		}
		script := buildRemoteNFTBlockScript(canonicalTarget, isCIDR, isIPv4)
		var wg sync.WaitGroup
		var remoteOK atomic.Int32
		for _, rn := range remoteNodes {
			wg.Add(1)
			go func(node fleet.Node) {
				defer wg.Done()
				rCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				defer cancel()
				if _, _, err := runner(rCtx, node, script); err == nil {
					remoteOK.Add(1)
				}
			}(rn)
		}
		wg.Wait()
		appliedNodes += int(remoteOK.Load())
	}

	return canonicalTarget, appliedNodes, nil
}

func buildRemoteNFTBlockScript(canonicalTarget string, isCIDR, isIPv4 bool) string {
	// canonicalTarget 已通过 net.ParseIP / net.ParseCIDR 严格校验，不含任何 Shell 元字符
	if isCIDR {
		if isIPv4 {
			return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then nft add element inet security blocklist_ip4_forever '{ %s }' 2>/dev/null || true; fi\n", canonicalTarget)
		}
		return ""
	}
	setName := "blocklist_ip6"
	if isIPv4 {
		setName = "blocklist_ip4"
	}
	return fmt.Sprintf("if command -v nft >/dev/null 2>&1; then nft add element inet security %s '{ %s timeout 7d }' 2>/dev/null || true; fi\n", setName, canonicalTarget)
}

func applyNFTBlockIP(ipStr string, isIPv4 bool) {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	setName := "blocklist_ip6"
	if isIPv4 {
		setName = "blocklist_ip4"
	}
	elem := fmt.Sprintf("{ %s timeout 7d }", ipStr)
	_ = exec.CommandContext(ctx, "nft", "add", "element", "inet", "security", setName, elem).Run()
}

func applyNFTBlockCIDR(cidr string, isIPv4 bool) {
	if _, err := exec.LookPath("nft"); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if isIPv4 {
		elem := fmt.Sprintf("{ %s }", cidr)
		_ = exec.CommandContext(ctx, "nft", "add", "element", "inet", "security", "blocklist_ip4_forever", elem).Run()
	}
}

// Snapshot 采集并生成默认视角（全集群/本机）的活跃嗅探态势快照 (用于 SSE 遥测与兼容调用)
func (t *SniffTracker) Snapshot(ctx context.Context, activeProxyClientIPs ...string) SniffSummary {
	// 在高频 SSE 调用中异步触发远程子节点采集，避免阻塞实时波形流
	t.triggerBackgroundFleetHarvestIfNeeded()
	return t.SnapshotForNode(ctx, "all", false, activeProxyClientIPs...)
}

// SnapshotForNode 采集并生成指定主机视角 ("all" | "local" | "<node_id>") 的全量活跃嗅探三维态势快照
func (t *SniffTracker) SnapshotForNode(ctx context.Context, nodeScope string, forceRefresh bool, activeProxyClientIPs ...string) SniffSummary {
	nodeScope = cmp.Or(strings.TrimSpace(nodeScope), "all")
	if len(activeProxyClientIPs) > 0 {
		t.MarkTrustedClientIPs(activeProxyClientIPs...)
	}

	// 1. 同步本机 Web IPLimiter 中的密码试探与封禁记录
	if t.limiter != nil {
		attempts := t.limiter.ListAllAttempts()
		t.mu.Lock()
		for _, att := range attempts {
			if isIgnoredInternalIP(att.IP) {
				continue
			}
			st := "observing"
			if att.Banned {
				st = "banned"
			}
			t.observeNodeAtLocked("local", "本机网关", att.IP, "Web 管理端密码试探", st, att.FailCount, true, att.LastFail, att.LastFail)
		}
		t.mu.Unlock()
	}

	// 2. 采集本机系统级防火墙、fail2ban 与外部探测连接
	if nodeScope == "all" || nodeScope == "local" {
		t.maybeHarvestSystemSources(ctx, forceRefresh)
	}

	// 3. 若配置了节点舰队且请求了子节点或全集群数据，按需并发采集子节点嗅探态势
	var fleetNodes []fleet.Node
	t.mu.RLock()
	fleetMgr := t.fleetMgr
	enableProbe := t.enableSystemProbe
	t.mu.RUnlock()

	if fleetMgr != nil && fleetMgr.Store != nil {
		if list, err := fleetMgr.Store.List(); err == nil {
			fleetNodes = list
			var clusterHosts []string
			for _, fn := range fleetNodes {
				if h := strings.TrimSpace(fn.Host); h != "" {
					clusterHosts = append(clusterHosts, h)
				}
			}
			if len(clusterHosts) > 0 {
				t.MarkTrustedClientIPs(clusterHosts...)
			}
		}
	}

	if enableProbe && len(fleetNodes) > 0 && nodeScope != "local" {
		t.maybeHarvestFleetNodes(ctx, fleetNodes, nodeScope, forceRefresh)
	}

	// 4. 清理过期条目并快照内存记录
	now := time.Now()
	t.mu.Lock()
	for _, nodeMap := range t.recordsByNode {
		for ip, rec := range nodeMap {
			if now.Sub(rec.lastSeen) > sniffEntryTTL {
				delete(nodeMap, ip)
				t.dirty = true
				continue
			}
			if exp, trusted := t.trustedClients[ip]; trusted && now.Before(exp) && rec.status != "banned" {
				delete(nodeMap, ip)
				t.dirty = true
				continue
			}
		}
	}
	if t.dirty {
		t.saveLocked(false)
	}

	// 构建主机节点元数据映射
	nodeInfoMap := map[string]SniffNodeRef{
		"local": {ID: "local", Name: "本机网关"},
	}
	for _, fn := range fleetNodes {
		nodeInfoMap[fn.ID] = SniffNodeRef{
			ID:   fn.ID,
			Name: cmp.Or(fn.Name, fn.ID),
			Host: fn.Host,
		}
	}

	// 计算各主机摘要列表 (Nodes)
	nodeSummaries := make([]SniffNodeSummary, 0, 2+len(fleetNodes))
	clusterIPSet := make(map[string]struct{})
	clusterSubnetSet := make(map[string]struct{})
	clusterBannedSet := make(map[string]struct{})

	buildSingleNodeSummary := func(nid, name, host string, online bool) SniffNodeSummary {
		nm := t.recordsByNode[nid]
		subs := make(map[string]struct{})
		banned := 0
		for _, rec := range nm {
			clusterIPSet[rec.ip] = struct{}{}
			if rec.subnet != "" {
				subs[rec.subnet] = struct{}{}
				clusterSubnetSet[rec.subnet] = struct{}{}
			}
			if rec.status == "banned" {
				banned++
				clusterBannedSet[rec.ip] = struct{}{}
			}
		}
		meta := t.nodeMeta[nid]
		var lastHarv, errStr string
		if meta != nil {
			if !meta.lastHarvest.IsZero() {
				lastHarv = formatSniffTime(meta.lastHarvest)
			}
			errStr = meta.lastError
		}
		return SniffNodeSummary{
			ID:            nid,
			Name:          name,
			Host:          host,
			Online:        online,
			TotalSniffIPs: len(nm),
			TotalSubnets:  len(subs),
			TotalBanned:   banned,
			LastHarvestAt: lastHarv,
			Error:         errStr,
		}
	}

	localSum := buildSingleNodeSummary("local", "本机网关", "", true)
	fleetSums := make([]SniffNodeSummary, 0, len(fleetNodes))
	for _, fn := range fleetNodes {
		fleetSums = append(fleetSums, buildSingleNodeSummary(fn.ID, cmp.Or(fn.Name, fn.ID), fn.Host, fn.Online))
	}
	// 若内存中存在测试注入但未在 fleet.Store 注册的自定义节点，也纳入统计
	for nid, nm := range t.recordsByNode {
		if nid == "local" || len(nm) == 0 {
			continue
		}
		if _, exists := nodeInfoMap[nid]; !exists {
			sampleName := nid
			for _, r := range nm {
				if r.nodeName != "" {
					sampleName = r.nodeName
					break
				}
			}
			nodeInfoMap[nid] = SniffNodeRef{ID: nid, Name: sampleName}
			fleetSums = append(fleetSums, buildSingleNodeSummary(nid, sampleName, "", true))
		}
	}

	nodeSummaries = append(nodeSummaries, SniffNodeSummary{
		ID:            "all",
		Name:          "全集群汇总",
		Online:        true,
		TotalSniffIPs: len(clusterIPSet),
		TotalSubnets:  len(clusterSubnetSet),
		TotalBanned:   len(clusterBannedSet),
		LastHarvestAt: formatSniffTime(now),
	})
	nodeSummaries = append(nodeSummaries, localSum)
	nodeSummaries = append(nodeSummaries, fleetSums...)

	// 提取当前所选视角 (nodeScope) 下的嗅探记录并按 IP 归并
	type mergedRecord struct {
		rec   sniffRecord
		nodes []SniffNodeRef
	}
	mergedByIP := make(map[string]*mergedRecord)

	collectFromNode := func(nid string) {
		nm := t.recordsByNode[nid]
		nRef, ok := nodeInfoMap[nid]
		if !ok {
			nRef = SniffNodeRef{ID: nid, Name: nid}
		}
		for _, r := range nm {
			existing, ok := mergedByIP[r.ip]
			if !ok {
				cp := *r
				if cp.firstSeen.IsZero() {
					cp.firstSeen = cp.lastSeen
				}
				mergedByIP[r.ip] = &mergedRecord{
					rec:   cp,
					nodes: []SniffNodeRef{nRef},
				}
				continue
			}
			existing.rec.hits += r.hits
			if !r.firstSeen.IsZero() && (existing.rec.firstSeen.IsZero() || r.firstSeen.Before(existing.rec.firstSeen)) {
				existing.rec.firstSeen = r.firstSeen
			}
			if r.lastSeen.After(existing.rec.lastSeen) {
				existing.rec.lastSeen = r.lastSeen
			}
			if statusPriority(r.status) > statusPriority(existing.rec.status) {
				existing.rec.status = r.status
			}
			if r.vector != "" && (existing.rec.vector == "" || existing.rec.vector == "异常端口探测") {
				existing.rec.vector = r.vector
			}
			if r.scannerTag != "" && existing.rec.scannerTag == "" {
				existing.rec.scannerTag = r.scannerTag
			}
			hasNode := false
			for _, en := range existing.nodes {
				if en.ID == nRef.ID {
					hasNode = true
					break
				}
			}
			if !hasNode {
				existing.nodes = append(existing.nodes, nRef)
			}
		}
	}

	if nodeScope == "all" {
		collectFromNode("local")
		for _, fs := range fleetSums {
			collectFromNode(fs.ID)
		}
	} else {
		collectFromNode(nodeScope)
	}

	blockedCIDRs := make(map[string]*net.IPNet, len(t.manualBlockedCIDRs))
	for k, v := range t.manualBlockedCIDRs {
		blockedCIDRs[k] = v
	}
	if nodeScope != "all" {
		if nb, ok := t.nodeBlockedCIDRs[nodeScope]; ok {
			for k, v := range nb {
				blockedCIDRs[k] = v
			}
		}
	}
	t.mu.Unlock()

	type enrichedItem struct {
		rec   sniffRecord
		nodes []SniffNodeRef
		geo   IPGeoInfo
		tag   string
	}

	var geoMap map[string]IPGeoInfo
	if t.geo != nil && len(mergedByIP) > 0 {
		ipList := make([]string, 0, len(mergedByIP))
		for ip := range mergedByIP {
			ipList = append(ipList, ip)
		}
		geoMap = t.geo.ResolveBatch(ctx, ipList)
	}

	enriched := make([]enrichedItem, 0, len(mergedByIP))
	totalBanned := 0
	for _, m := range mergedByIP {
		var geo IPGeoInfo
		if geoMap != nil {
			geo = geoMap[m.rec.ip]
		}
		tag := cmp.Or(m.rec.scannerTag, MatchScannerTag(m.rec.ip, geo.ISP))
		if m.rec.status == "banned" {
			totalBanned++
		}
		enriched = append(enriched, enrichedItem{
			rec:   m.rec,
			nodes: m.nodes,
			geo:   geo,
			tag:   tag,
		})
	}

	// 排序单点 IP: 优先按命中次数降序，其次按最近活跃时间降序
	slices.SortFunc(enriched, func(a, b enrichedItem) int {
		if a.rec.hits != b.rec.hits {
			return cmp.Compare(b.rec.hits, a.rec.hits)
		}
		if !a.rec.lastSeen.Equal(b.rec.lastSeen) {
			if a.rec.lastSeen.After(b.rec.lastSeen) {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.rec.ip, b.rec.ip)
	})

	// 返回全量嗅探 IP 列表（解除原 Top 8 截断限制）
	topIPs := make([]SniffIPStat, 0, len(enriched))
	for _, it := range enriched {
		topIPs = append(topIPs, SniffIPStat{
			IP:          it.rec.ip,
			Subnet:      it.rec.subnet,
			Hits:        it.rec.hits,
			Vector:      it.rec.vector,
			Status:      it.rec.status,
			Country:     it.geo.Country,
			CountryCode: it.geo.CountryCode,
			Flag:        it.geo.Flag,
			Geo:         it.geo.Geo,
			ISP:         it.geo.ISP,
			ScannerTag:  it.tag,
			FirstSeen:   formatSniffTime(it.rec.firstSeen),
			LastSeen:    formatSniffTime(it.rec.lastSeen),
			Nodes:       it.nodes,
		})
	}

	// 聚合 /24 (IPv4) 或 /48 (IPv6) 嗅探网段 (含网段级开始时间、最近时间与受探主机)
	type subnetAgg struct {
		cidr        string
		uniqueIPs   int
		totalHits   int
		bannedCount int
		country     string
		countryCode string
		flag        string
		isp         string
		scannerTag  string
		samples     []string
		firstSeen   time.Time
		lastSeen    time.Time
		nodes       []SniffNodeRef
	}
	subnetMap := make(map[string]*subnetAgg)
	for _, it := range enriched {
		cidr := cmp.Or(it.rec.subnet, ComputeSubnetCIDR(it.rec.ip))
		if cidr == "" {
			continue
		}
		agg, exists := subnetMap[cidr]
		if !exists {
			agg = &subnetAgg{
				cidr:       cidr,
				scannerTag: it.tag,
				firstSeen:  it.rec.firstSeen,
				lastSeen:   it.rec.lastSeen,
			}
			subnetMap[cidr] = agg
		}
		agg.uniqueIPs++
		agg.totalHits += it.rec.hits
		if it.rec.status == "banned" {
			agg.bannedCount++
		}
		if !it.rec.firstSeen.IsZero() && (agg.firstSeen.IsZero() || it.rec.firstSeen.Before(agg.firstSeen)) {
			agg.firstSeen = it.rec.firstSeen
		}
		if it.rec.lastSeen.After(agg.lastSeen) {
			agg.lastSeen = it.rec.lastSeen
		}
		if agg.country == "" && it.geo.Country != "" {
			agg.country = it.geo.Country
			agg.countryCode = it.geo.CountryCode
			agg.flag = it.geo.Flag
		}
		if agg.isp == "" && it.geo.ISP != "" {
			agg.isp = it.geo.ISP
		}
		if agg.scannerTag == "" && it.tag != "" {
			agg.scannerTag = it.tag
		}
		if len(agg.samples) < 5 {
			agg.samples = append(agg.samples, it.rec.ip)
		}
		for _, nRef := range it.nodes {
			hasNode := false
			for _, en := range agg.nodes {
				if en.ID == nRef.ID {
					hasNode = true
					break
				}
			}
			if !hasNode {
				agg.nodes = append(agg.nodes, nRef)
			}
		}
	}

	subnets := make([]SniffSubnetStat, 0, len(subnetMap))
	for _, agg := range subnetMap {
		st := "active"
		if _, wholeBanned := blockedCIDRs[agg.cidr]; wholeBanned || (agg.uniqueIPs > 0 && agg.bannedCount == agg.uniqueIPs) {
			st = "banned"
		} else if agg.bannedCount > 0 {
			st = "partial"
		}
		subnets = append(subnets, SniffSubnetStat{
			CIDR:        agg.cidr,
			UniqueIPs:   agg.uniqueIPs,
			TotalHits:   agg.totalHits,
			BannedCount: agg.bannedCount,
			Status:      st,
			Country:     agg.country,
			CountryCode: agg.countryCode,
			Flag:        agg.flag,
			ISP:         agg.isp,
			ScannerTag:  agg.scannerTag,
			SampleIPs:   agg.samples,
			FirstSeen:   formatSniffTime(agg.firstSeen),
			LastSeen:    formatSniffTime(agg.lastSeen),
			Nodes:       agg.nodes,
		})
	}
	slices.SortFunc(subnets, func(a, b SniffSubnetStat) int {
		if a.UniqueIPs != b.UniqueIPs {
			return cmp.Compare(b.UniqueIPs, a.UniqueIPs)
		}
		if a.TotalHits != b.TotalHits {
			return cmp.Compare(b.TotalHits, a.TotalHits)
		}
		return cmp.Compare(a.CIDR, b.CIDR)
	})
	totalSubnets := len(subnets)

	// 聚合活跃嗅探国家/地区 (全量返回)
	type countryAgg struct {
		code    string
		country string
		flag    string
		ips     int
		subnets map[string]struct{}
		hits    int
	}
	countryMap := make(map[string]*countryAgg)
	for _, it := range enriched {
		code := strings.ToUpper(strings.TrimSpace(it.geo.CountryCode))
		name := strings.TrimSpace(it.geo.Country)
		flag := it.geo.Flag
		if code == "" {
			if it.tag != "" {
				code = "SCAN"
				name = it.tag
				flag = "🛰️"
			} else {
				code = "UNK"
				name = "解析中 / 未知地区"
				flag = "🌐"
			}
		} else if name == "" {
			if cn, ok := commonCountryNames[code]; ok {
				name = cn
			} else {
				name = code
			}
		}
		cAgg, exists := countryMap[code]
		if !exists {
			cAgg = &countryAgg{
				code:    code,
				country: name,
				flag:    flag,
				subnets: make(map[string]struct{}),
			}
			countryMap[code] = cAgg
		}
		cAgg.ips++
		cAgg.hits += it.rec.hits
		if it.rec.subnet != "" {
			cAgg.subnets[it.rec.subnet] = struct{}{}
		}
	}

	totalIPCount := len(enriched)
	countries := make([]SniffCountryStat, 0, len(countryMap))
	for _, cAgg := range countryMap {
		ratio := 0.0
		if totalIPCount > 0 {
			ratio = float64(cAgg.ips) * 100.0 / float64(totalIPCount)
			ratio = float64(int(ratio*10+0.5)) / 10.0
		}
		countries = append(countries, SniffCountryStat{
			CountryCode:   cAgg.code,
			Country:       cAgg.country,
			Flag:          cAgg.flag,
			UniqueIPs:     cAgg.ips,
			UniqueSubnets: len(cAgg.subnets),
			TotalHits:     cAgg.hits,
			RatioPercent:  ratio,
		})
	}
	slices.SortFunc(countries, func(a, b SniffCountryStat) int {
		if a.UniqueIPs != b.UniqueIPs {
			return cmp.Compare(b.UniqueIPs, a.UniqueIPs)
		}
		if a.TotalHits != b.TotalHits {
			return cmp.Compare(b.TotalHits, a.TotalHits)
		}
		return cmp.Compare(a.CountryCode, b.CountryCode)
	})
	totalCountries := len(countries)

	return SniffSummary{
		UpdatedAt:      now.Format(time.RFC3339),
		SelectedNode:   nodeScope,
		Nodes:          nodeSummaries,
		TotalSniffIPs:  totalIPCount,
		TotalSubnets:   totalSubnets,
		TotalCountries: totalCountries,
		TotalBannedIPs: totalBanned,
		TopIPs:         topIPs,
		TopSubnets:     subnets,
		TopCountries:   countries,
	}
}

func (t *SniffTracker) triggerBackgroundFleetHarvestIfNeeded() {
	t.mu.RLock()
	fleetMgr := t.fleetMgr
	enableProbe := t.enableSystemProbe
	t.mu.RUnlock()
	if !enableProbe || fleetMgr == nil || fleetMgr.Store == nil {
		return
	}
	if !t.fleetBgRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer t.fleetBgRunning.Store(false)
		nodes, err := fleetMgr.Store.List()
		if err != nil || len(nodes) == 0 {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		t.maybeHarvestFleetNodes(ctx, nodes, "all", false)
	}()
}

func (t *SniffTracker) maybeHarvestSystemSources(ctx context.Context, force bool) {
	now := time.Now()
	t.mu.Lock()
	if !t.enableSystemProbe || (!force && !t.lastSystemHarvest.IsZero() && now.Sub(t.lastSystemHarvest) < systemHarvestMinDT) {
		t.mu.Unlock()
		return
	}
	t.lastSystemHarvest = now
	t.ensureNodeMetaLocked("local").lastHarvest = now
	t.mu.Unlock()

	hCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	// 1. 采集 nftables 动态封禁集 (@blocklist_ip4，支持从 timeout/expires 反推真实封禁时间)
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.CommandContext(hCtx, "nft", "list", "set", "inet", "security", "blocklist_ip4").Output(); err == nil {
			entries := parseNFTSetEntries(string(out), now)
			t.mu.Lock()
			for _, ent := range entries {
				if !isIgnoredInternalIP(ent.ip) {
					t.observeNodeAtLocked("local", "本机网关", ent.ip, "高危端口扫描拦截", "banned", 1, true, ent.observedAt, ent.observedAt)
				}
			}
			t.mu.Unlock()
		}
	}

	// 2. 采集内核日志中 [NFT] Blocked 的精确命中端口、次数与日志时间戳
	harvestNFTKernelLogs(hCtx, t)

	// 3. 采集 fail2ban (sshd / recidive) 封禁 IP 及 /var/log/fail2ban.log 时间戳
	f2bTimeMap := harvestLocalFail2banLogTimes(now)
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		for _, jail := range []string{"sshd", "recidive"} {
			if out, err := exec.CommandContext(hCtx, "fail2ban-client", "status", jail).Output(); err == nil {
				ips := parseFail2banBannedIPs(string(out))
				t.mu.Lock()
				for _, ip := range ips {
					if !isIgnoredInternalIP(ip) {
						ft, lt, hits := time.Time{}, time.Time{}, 3
						if info, ok := f2bTimeMap[ip]; ok {
							ft, lt = info.first, info.last
							if info.hits > hits {
								hits = info.hits
							}
						}
						t.observeNodeAtLocked("local", "本机网关", ip, "SSH 暴力破解", "banned", hits, true, ft, lt)
					}
				}
				t.mu.Unlock()
			}
		}
	}

	// 4. 采集当前套接字 (ss -tan) 上的外部伪装回落与端口试探连接 (实时活跃连接更新 lastSeen=now)
	if _, err := exec.LookPath("ss"); err == nil {
		if out, err := exec.CommandContext(hCtx, "ss", "-tan").Output(); err == nil {
			probes := parseSSExternalProbes(string(out))
			probeNow := time.Now()
			t.mu.Lock()
			for _, p := range probes {
				if !isIgnoredInternalIP(p.ip) {
					t.observeNodeAtLocked("local", "本机网关", p.ip, p.vector, p.status, p.hits, true, time.Time{}, probeNow)
				}
			}
			t.mu.Unlock()
		}
	}
}

const remoteSniffHarvestScript = `
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"
echo "===SINGCTL_TRUSTED==="
if command -v curl >/dev/null 2>&1 && [ -f /etc/sing-box/config.json ]; then
  SECRET=$(sed -n 's/.*"secret"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /etc/sing-box/config.json | head -n 1)
  if [ -n "$SECRET" ]; then
    curl -fsS -m 1 -H "Authorization: Bearer $SECRET" http://127.0.0.1:9099/connections 2>/dev/null || true
  else
    curl -fsS -m 1 http://127.0.0.1:9099/connections 2>/dev/null || true
  fi
fi
echo ""
echo "===SINGCTL_NFT==="
if command -v nft >/dev/null 2>&1; then
  nft list set inet security blocklist_ip4 2>/dev/null || true
fi
echo "===SINGCTL_F2B==="
if command -v fail2ban-client >/dev/null 2>&1; then
  fail2ban-client status sshd 2>/dev/null || true
  fail2ban-client status recidive 2>/dev/null || true
fi
if [ -r /var/log/fail2ban.log ]; then
  tail -c 32768 /var/log/fail2ban.log 2>/dev/null | grep -E "Found |Ban " || true
fi
echo "===SINGCTL_KERN==="
for f in /var/log/kern.log /var/log/syslog /var/log/messages; do
  if [ -r "$f" ]; then
    tail -c 32768 "$f" 2>/dev/null | grep "\[NFT\]" || true
    break
  fi
done
echo "===SINGCTL_SS==="
if command -v ss >/dev/null 2>&1; then
  ss -tan 2>/dev/null || true
fi
`

func (t *SniffTracker) maybeHarvestFleetNodes(ctx context.Context, fleetNodes []fleet.Node, nodeScope string, force bool) {
	t.mu.RLock()
	fleetMgr := t.fleetMgr
	t.mu.RUnlock()
	if fleetMgr == nil {
		return
	}
	runner := fleetMgr.Runner
	if runner == nil {
		runner = fleet.DefaultSSHRunner
	}

	now := time.Now()
	var targets []fleet.Node
	t.mu.Lock()
	for _, fn := range fleetNodes {
		if !fn.Enabled {
			continue
		}
		if nodeScope != "all" && fn.ID != nodeScope {
			continue
		}
		meta := t.ensureNodeMetaLocked(fn.ID)
		if !force && !meta.lastHarvest.IsZero() && now.Sub(meta.lastHarvest) < fleetHarvestMinDT {
			continue
		}
		meta.lastHarvest = now
		targets = append(targets, fn)
	}
	t.mu.Unlock()

	if len(targets) == 0 {
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, fn := range targets {
		wg.Add(1)
		go func(node fleet.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			rCtx, cancel := context.WithTimeout(ctx, 3500*time.Millisecond)
			defer cancel()
			out, _, err := runner(rCtx, node, remoteSniffHarvestScript)
			if err != nil {
				t.mu.Lock()
				t.ensureNodeMetaLocked(node.ID).lastError = err.Error()
				t.mu.Unlock()
				return
			}
			t.mu.Lock()
			t.ensureNodeMetaLocked(node.ID).lastError = ""
			t.mu.Unlock()
			t.ingestRemoteSniffOutput(node.ID, cmp.Or(node.Name, node.ID), out)
		}(fn)
	}
	wg.Wait()
}

func (t *SniffTracker) ingestRemoteSniffOutput(nodeID, nodeName, raw string) {
	var secTrusted, secNFT, secF2B, secKern, secSS strings.Builder
	currentSec := ""
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "===SINGCTL_TRUSTED===":
			currentSec = "trusted"
			continue
		case "===SINGCTL_NFT===":
			currentSec = "nft"
			continue
		case "===SINGCTL_F2B===":
			currentSec = "f2b"
			continue
		case "===SINGCTL_KERN===":
			currentSec = "kern"
			continue
		case "===SINGCTL_SS===":
			currentSec = "ss"
			continue
		}
		switch currentSec {
		case "trusted":
			secTrusted.WriteString(line)
			secTrusted.WriteByte('\n')
		case "nft":
			secNFT.WriteString(line)
			secNFT.WriteByte('\n')
		case "f2b":
			secF2B.WriteString(line)
			secF2B.WriteByte('\n')
		case "kern":
			secKern.WriteString(line)
			secKern.WriteByte('\n')
		case "ss":
			secSS.WriteString(line)
			secSS.WriteByte('\n')
		}
	}

	// 1. 提取该子节点合法代理客户端 IP 并加入全局可信白名单
	if trustedStr := secTrusted.String(); trustedStr != "" {
		matches := reSingBoxSourceIP.FindAllStringSubmatch(trustedStr, -1)
		if len(matches) > 0 {
			var clientIPs []string
			for _, m := range matches {
				if len(m) == 2 && m[1] != "" {
					clientIPs = append(clientIPs, m[1])
				}
			}
			if len(clientIPs) > 0 {
				t.MarkTrustedClientIPs(clientIPs...)
			}
		}
	}

	now := time.Now()
	nftEntries := parseNFTSetEntries(secNFT.String(), now)
	f2bIPs := parseFail2banBannedIPs(secF2B.String())
	f2bTimes := parseFail2banLogTimestamps(secF2B.String(), now)
	ssProbes := parseSSExternalProbes(secSS.String())

	t.mu.Lock()
	for _, ent := range nftEntries {
		if !isIgnoredInternalIP(ent.ip) {
			t.observeNodeAtLocked(nodeID, nodeName, ent.ip, "高危端口扫描拦截", "banned", 1, true, ent.observedAt, ent.observedAt)
		}
	}
	for _, ip := range f2bIPs {
		if !isIgnoredInternalIP(ip) {
			ft, lt, hits := time.Time{}, time.Time{}, 3
			if info, ok := f2bTimes[ip]; ok {
				ft, lt = info.first, info.last
				if info.hits > hits {
					hits = info.hits
				}
			}
			t.observeNodeAtLocked(nodeID, nodeName, ip, "SSH 暴力破解", "banned", hits, true, ft, lt)
		}
	}
	for _, p := range ssProbes {
		if !isIgnoredInternalIP(p.ip) {
			t.observeNodeAtLocked(nodeID, nodeName, p.ip, p.vector, p.status, p.hits, true, time.Time{}, now)
		}
	}
	t.mu.Unlock()

	if kernStr := secKern.String(); kernStr != "" {
		ingestNFTKernelLogContent(t, nodeID, nodeName, kernStr, now)
	}
}

type nftSetEntry struct {
	ip         string
	observedAt time.Time
}

func parseNFTDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var total time.Duration
	if before, after, hasDay := strings.Cut(s, "d"); hasDay {
		if days, err := strconv.Atoi(before); err == nil && days > 0 {
			total += time.Duration(days) * 24 * time.Hour
		}
		s = after
	}
	if s != "" {
		if rem, err := time.ParseDuration(s); err == nil {
			total += rem
		}
	}
	return total
}

func parseNFTSetEntries(raw string, refNow time.Time) []nftSetEntry {
	idx := strings.Index(raw, "elements = {")
	if idx < 0 {
		return nil
	}
	sub := raw[idx+len("elements = {"):]
	if endIdx := strings.IndexByte(sub, '}'); endIdx >= 0 {
		sub = sub[:endIdx]
	}

	seen := make(map[string]struct{})
	out := make([]nftSetEntry, 0, 32)
	for part := range strings.SplitSeq(sub, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tok := reIPv4Token.FindString(part)
		if tok == "" {
			continue
		}
		// 跳过 CIDR 网段前缀 (如 198.51.100.0/24)，避免将网段基址误判为单点活跃 IP
		if strings.Contains(part, tok+"/") {
			continue
		}
		ip := normalizeIPString(tok)
		if ip == "" {
			continue
		}
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}

		var observedAt time.Time
		timeoutDur := 7 * 24 * time.Hour
		if tm := reNFTTimeout.FindStringSubmatch(part); len(tm) == 2 {
			if d := parseNFTDuration(tm[1]); d > 0 {
				timeoutDur = d
			}
		}
		if em := reNFTExpires.FindStringSubmatch(part); len(em) == 2 {
			if expDur := parseNFTDuration(em[1]); expDur > 0 && timeoutDur >= expDur {
				age := timeoutDur - expDur
				if age > sniffEntryTTL {
					continue
				}
				observedAt = refNow.Add(-age)
			}
		}
		out = append(out, nftSetEntry{
			ip:         ip,
			observedAt: observedAt,
		})
	}
	return out
}

func parseNFTSetIPs(raw string) []string {
	entries := parseNFTSetEntries(raw, time.Now())
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.ip)
	}
	return out
}

type fail2banTimeInfo struct {
	first time.Time
	last  time.Time
	hits  int
}

func harvestLocalFail2banLogTimes(refNow time.Time) map[string]fail2banTimeInfo {
	raw, err := readTailBytes("/var/log/fail2ban.log", 64*1024)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return parseFail2banLogTimestamps(string(raw), refNow)
}

func parseFail2banLogTimestamps(raw string, refNow time.Time) map[string]fail2banTimeInfo {
	out := make(map[string]fail2banTimeInfo)
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 20 {
			continue
		}
		m := reFail2banLogIP.FindStringSubmatch(trimmed)
		if len(m) != 2 {
			continue
		}
		ip := normalizeIPString(m[1])
		if ip == "" || isIgnoredInternalIP(ip) {
			continue
		}
		ts, err := time.ParseInLocation(sniffTimeLayout, trimmed[:19], refNow.Location())
		if err != nil {
			continue
		}
		info := out[ip]
		info.hits++
		if info.first.IsZero() || ts.Before(info.first) {
			info.first = ts
		}
		if info.last.IsZero() || ts.After(info.last) {
			info.last = ts
		}
		out[ip] = info
	}
	return out
}

func parseLogLineTimestamp(line string, refNow time.Time) time.Time {
	trimmed := strings.TrimSpace(line)
	if len(trimmed) < 15 {
		return time.Time{}
	}
	// 格式 1: ISO8601 / RFC3339 (如 2026-03-30T10:15:22.123456+08:00 ...)
	if firstSpace := strings.IndexByte(trimmed, ' '); firstSpace > 18 {
		tok := trimmed[:firstSpace]
		if ts, err := time.Parse(time.RFC3339Nano, tok); err == nil {
			return ts
		}
		if ts, err := time.Parse(time.RFC3339, tok); err == nil {
			return ts
		}
	}
	// 格式 2: 传统 Syslog (如 "Mar 30 10:15:22" 或 "Mar  7 10:15:22")
	prefix := trimmed[:15]
	if ts, err := time.ParseInLocation(time.Stamp, prefix, refNow.Location()); err == nil {
		withYear := time.Date(refNow.Year(), ts.Month(), ts.Day(), ts.Hour(), ts.Minute(), ts.Second(), 0, refNow.Location())
		if withYear.After(refNow.Add(24 * time.Hour)) {
			withYear = withYear.AddDate(-1, 0, 0)
		}
		return withYear
	}
	return time.Time{}
}

func harvestNFTKernelLogs(ctx context.Context, t *SniffTracker) {
	var content string
	for _, logPath := range []string{"/var/log/kern.log", "/var/log/syslog", "/var/log/messages"} {
		if raw, err := readTailBytes(logPath, 64*1024); err == nil && len(raw) > 0 {
			content = string(raw)
			break
		}
	}
	if content == "" {
		if out, err := exec.CommandContext(ctx, "dmesg").Output(); err == nil && len(out) > 0 {
			if len(out) > 64*1024 {
				out = out[len(out)-64*1024:]
			}
			content = string(out)
		}
	}
	if content == "" {
		return
	}
	ingestNFTKernelLogContent(t, "local", "本机网关", content, time.Now())
}

func ingestNFTKernelLogContent(t *SniffTracker, nodeID, nodeName, content string, refNow time.Time) {
	type nftHitAgg struct {
		hits      int
		port      string
		firstTime time.Time
		lastTime  time.Time
	}
	aggByIP := make(map[string]*nftHitAgg)
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.Contains(line, "[NFT]") {
			continue
		}
		m := reNFTLogLine.FindStringSubmatch(line)
		if len(m) == 3 {
			ip := normalizeIPString(m[1])
			port := m[2]
			if ip != "" && !isIgnoredInternalIP(ip) {
				ts := parseLogLineTimestamp(line, refNow)
				agg, exists := aggByIP[ip]
				if !exists {
					agg = &nftHitAgg{
						port:      port,
						firstTime: ts,
						lastTime:  ts,
					}
					aggByIP[ip] = agg
				}
				agg.hits++
				if port != "" {
					agg.port = port
				}
				if !ts.IsZero() {
					if agg.firstTime.IsZero() || ts.Before(agg.firstTime) {
						agg.firstTime = ts
					}
					if agg.lastTime.IsZero() || ts.After(agg.lastTime) {
						agg.lastTime = ts
					}
				}
			}
		}
	}
	if len(aggByIP) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, agg := range aggByIP {
		vec := "高危端口扫描"
		if agg.port != "" {
			vec = fmt.Sprintf("高危端口扫描 (:%s)", agg.port)
		}
		t.observeNodeAtLocked(nodeID, nodeName, ip, vec, "banned", agg.hits, true, agg.firstTime, agg.lastTime)
	}
}

func readTailBytes(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	offset := int64(0)
	if size > maxBytes {
		offset = size - maxBytes
	}
	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			return nil, err
		}
	}
	buf := make([]byte, size-offset)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, err
	}
	return buf[:n], nil
}

func parseFail2banBannedIPs(raw string) []string {
	var out []string
	seen := make(map[string]struct{})
	for line := range strings.SplitSeq(raw, "\n") {
		if !strings.Contains(line, "Banned IP list:") {
			continue
		}
		parts := strings.SplitN(line, "Banned IP list:", 2)
		if len(parts) != 2 {
			continue
		}
		for tok := range strings.FieldsSeq(parts[1]) {
			if ip := normalizeIPString(tok); ip != "" {
				if _, ok := seen[ip]; !ok {
					seen[ip] = struct{}{}
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

type ssProbeItem struct {
	ip     string
	vector string
	status string
	hits   int
}

func parseSSExternalProbes(raw string) []ssProbeItem {
	byIP := make(map[string]*ssProbeItem)
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		state := fields[0]
		if state == "LISTEN" || state == "State" {
			continue
		}
		localAddr := fields[3]
		peerAddr := fields[4]

		localPort := extractPortNumber(localAddr)
		peerIP := normalizeIPString(peerAddr)
		if peerIP == "" || isIgnoredInternalIP(peerIP) {
			continue
		}

		var vec, st string
		switch localPort {
		case 80:
			vec = "HTTP/80 端口嗅探"
			st = "masqueraded"
		case 9445:
			vec = "TLS/443 伪装回落嗅探"
			st = "masqueraded"
		case 443:
			if state == "SYN-RECV" || state == "TIME-WAIT" {
				vec = "TLS/443 握手探测"
				st = "masqueraded"
			} else {
				vec = "TLS/443 伪装回落嗅探"
				st = "masqueraded"
			}
		case 22, 2222:
			if state == "SYN-RECV" || state == "TIME-WAIT" {
				vec = fmt.Sprintf("SSH/:%d 端口试探", localPort)
				st = "observing"
			}
		default:
			continue
		}
		if vec == "" {
			continue
		}
		if existing, ok := byIP[peerIP]; ok {
			existing.hits++
		} else {
			byIP[peerIP] = &ssProbeItem{
				ip:     peerIP,
				vector: vec,
				status: st,
				hits:   1,
			}
		}
	}
	out := make([]ssProbeItem, 0, len(byIP))
	for _, v := range byIP {
		out = append(out, *v)
	}
	return out
}

func extractPortNumber(addr string) int {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 || idx+1 >= len(addr) {
		return 0
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0
	}
	return p
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

func (t *SniffTracker) saveLocked(force bool) {
	if t.filePath == "" {
		return
	}
	now := time.Now()
	if !force && !t.lastPersistAt.IsZero() && now.Sub(t.lastPersistAt) < sniffSaveMinDT {
		return
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

	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(t.filePath)
	_ = os.MkdirAll(dir, 0700)
	tmp := fmt.Sprintf("%s.%d.tmp", t.filePath, now.UnixNano())
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, t.filePath); err != nil {
		_ = os.Remove(tmp)
		_ = os.WriteFile(t.filePath, raw, 0600)
		_ = os.Chmod(t.filePath, 0600)
	}
}
