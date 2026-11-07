package serverweb

import (
	"cmp"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxTrackedSniffIPs = 600
	maxTopSniffItems   = 8
	sniffEntryTTL      = 24 * time.Hour
	trustedClientTTL   = 2 * time.Hour
	systemHarvestMinDT = 6 * time.Second
)

// SniffIPStat 单个外部活跃嗅探 IP 的态势详情
type SniffIPStat struct {
	IP          string `json:"ip"`
	Subnet      string `json:"subnet"`
	Hits        int    `json:"hits"`
	Vector      string `json:"vector"`
	Status      string `json:"status"` // "banned" | "masqueraded" | "observing"
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	Flag        string `json:"flag,omitempty"`
	Geo         string `json:"geo,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ScannerTag  string `json:"scannerTag,omitempty"`
	LastSeen    string `json:"lastSeen"`
}

// SniffSubnetStat 按 /24 (IPv4) 或 /48 (IPv6) 聚合的活跃嗅探网段态势
type SniffSubnetStat struct {
	CIDR        string   `json:"cidr"`
	UniqueIPs   int      `json:"uniqueIPs"`
	TotalHits   int      `json:"totalHits"`
	BannedCount int      `json:"bannedCount"`
	Status      string   `json:"status"` // "banned" | "partial" | "active"
	Country     string   `json:"country,omitempty"`
	CountryCode string   `json:"countryCode,omitempty"`
	Flag        string   `json:"flag,omitempty"`
	ISP         string   `json:"isp,omitempty"`
	ScannerTag  string   `json:"scannerTag,omitempty"`
	SampleIPs   []string `json:"sampleIPs,omitempty"`
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

// SniffSummary 外部活跃嗅探三维聚合快照
type SniffSummary struct {
	UpdatedAt      string             `json:"updatedAt"`
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
	subnet     string
	hits       int
	vector     string
	status     string // "banned" | "masqueraded" | "observing"
	scannerTag string
	lastSeen   time.Time
}

type knownScannerCIDR struct {
	net *net.IPNet
	tag string
}

var (
	knownScannerCIDRsOnce sync.Once
	parsedScannerCIDRs    []knownScannerCIDR

	reNFTLogLine = regexp.MustCompile(`SRC=([0-9a-fA-F:\.]+).*?DPT=([0-9]+)`)
	reIPv4Token  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
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
		// 排除 RFC 5737 文档测试保留网段以外的广播地址
		if v4[0] == 255 {
			return true
		}
	}
	return false
}

// SniffTracker 外部活跃嗅探与探测态势聚合器
type SniffTracker struct {
	mu                 sync.RWMutex
	records            map[string]*sniffRecord
	trustedClients     map[string]time.Time
	manualBlockedCIDRs map[string]*net.IPNet
	lastSystemHarvest  time.Time
	geo                *IPGeoResolver
	limiter            *IPLimiter
	enableSystemProbe  bool
}

// NewSniffTracker 创建嗅探态势追踪器
func NewSniffTracker(geo *IPGeoResolver, limiter *IPLimiter) *SniffTracker {
	return &SniffTracker{
		records:            make(map[string]*sniffRecord),
		trustedClients:     make(map[string]time.Time),
		manualBlockedCIDRs: make(map[string]*net.IPNet),
		geo:                geo,
		limiter:            limiter,
		enableSystemProbe:  true,
	}
}

// MarkTrustedClientIPs 标记已通过鉴权的合法客户端或集群白名单 IP (自动从嗅探列表中剔除)
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
		// 若此前误入未封禁观察列表，立即移除以保护合法用户隐私
		if rec, exists := t.records[ipStr]; exists && rec.status != "banned" {
			delete(t.records, ipStr)
		}
	}
}

func normalizeIPString(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// 处理 [::1]:12345 或 1.2.3.4:5678
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	// 去除 IPv4-mapped IPv6 前缀 ::ffff:
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

// Observe 记录一次外部嗅探或拦截事件
func (t *SniffTracker) Observe(rawIP, vector, status string, hitsDelta int) {
	ipStr := normalizeIPString(rawIP)
	if ipStr == "" || isIgnoredInternalIP(ipStr) {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.observeLocked(ipStr, vector, status, hitsDelta, false)
}

func (t *SniffTracker) observeLocked(ipStr, vector, status string, hitsDelta int, setExactHits bool) {
	now := time.Now()
	// 若属于合法代理用户/管理员白名单且非防火墙强制封禁，直接忽略
	if exp, trusted := t.trustedClients[ipStr]; trusted && now.Before(exp) && status != "banned" {
		return
	}

	subnet := ComputeSubnetCIDR(ipStr)
	if hitsDelta <= 0 {
		hitsDelta = 1
	}

	// 检查该 IP 是否命中已手动封禁的 /24 网段
	if ip := net.ParseIP(ipStr); ip != nil {
		for _, cidrNet := range t.manualBlockedCIDRs {
			if cidrNet.Contains(ip) {
				status = "banned"
				break
			}
		}
	}

	rec, exists := t.records[ipStr]
	if !exists {
		if len(t.records) >= maxTrackedSniffIPs {
			t.evictOldestLocked(now)
		}
		rec = &sniffRecord{
			ip:         ipStr,
			subnet:     subnet,
			hits:       hitsDelta,
			vector:     cmp.Or(vector, "异常端口探测"),
			status:     cmp.Or(status, "observing"),
			scannerTag: MatchScannerTag(ipStr, ""),
			lastSeen:   now,
		}
		t.records[ipStr] = rec
		return
	}

	if setExactHits {
		if hitsDelta > rec.hits {
			rec.hits = hitsDelta
		}
	} else {
		rec.hits += hitsDelta
	}
	rec.lastSeen = now
	if vector != "" && (rec.vector == "" || rec.vector == "异常端口探测" || status == "banned") {
		rec.vector = vector
	}
	if statusPriority(status) >= statusPriority(rec.status) {
		rec.status = status
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

func (t *SniffTracker) evictOldestLocked(now time.Time) {
	var oldestIP string
	var oldestTime time.Time
	for ip, rec := range t.records {
		if now.Sub(rec.lastSeen) > sniffEntryTTL {
			delete(t.records, ip)
			continue
		}
		if oldestIP == "" || rec.lastSeen.Before(oldestTime) {
			oldestIP = ip
			oldestTime = rec.lastSeen
		}
	}
	if len(t.records) >= maxTrackedSniffIPs && oldestIP != "" {
		delete(t.records, oldestIP)
	}
}

// BlockTarget 手动一键拉黑单个嗅探 IP 或 /24 网段 (带防锁死保护与零 Shell 注入执行)
func (t *SniffTracker) BlockTarget(target, operatorIP string, extraProtectedIPs ...string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("封禁目标不能为空")
	}

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
	t.mu.RUnlock()

	// 情况 1: CIDR 网段封禁 (例如 198.51.100.0/24)
	if strings.Contains(target, "/") {
		ip, ipNet, err := net.ParseCIDR(target)
		if err != nil || ip == nil || ipNet == nil {
			return "", fmt.Errorf("无效的 CIDR 网段格式: %s", target)
		}
		ones, bits := ipNet.Mask.Size()
		if bits == 32 && ones < 16 {
			return "", fmt.Errorf("为防止误伤大面积网络，IPv4 网段掩码长度须在 /16 至 /32 之间")
		}
		if bits == 128 && ones < 32 {
			return "", fmt.Errorf("IPv6 网段掩码长度须在 /32 至 /128 之间")
		}
		if isIgnoredInternalIP(ip.String()) {
			return "", fmt.Errorf("安全防锁死保护：禁止封禁本地回环、局域网或内网保留网段 (%s)", target)
		}
		for protIPStr := range protectedSet {
			if protIP := net.ParseIP(protIPStr); protIP != nil && ipNet.Contains(protIP) {
				return "", fmt.Errorf("安全防锁死保护：目标网段 (%s) 包含当前管理会话或受保护节点 IP (%s)，已拒绝执行", target, protIPStr)
			}
		}

		canonicalCIDR := ipNet.String()
		t.mu.Lock()
		t.manualBlockedCIDRs[canonicalCIDR] = ipNet
		for _, rec := range t.records {
			if recIP := net.ParseIP(rec.ip); recIP != nil && ipNet.Contains(recIP) {
				rec.status = "banned"
			}
		}
		t.mu.Unlock()

		// 尝试同步写入内核 nftables (若当前环境存在 nft 且具备权限)
		applyNFTBlockCIDR(canonicalCIDR, bits == 32)
		return canonicalCIDR, nil
	}

	// 情况 2: 单个 IP 封禁
	ipStr := normalizeIPString(target)
	if ipStr == "" {
		return "", fmt.Errorf("无效的 IP 地址格式: %s", target)
	}
	if isIgnoredInternalIP(ipStr) {
		return "", fmt.Errorf("安全防锁死保护：禁止封禁本地回环或内网保留地址 (%s)", ipStr)
	}
	if _, isProtected := protectedSet[ipStr]; isProtected {
		return "", fmt.Errorf("安全防锁死保护：禁止拉黑您当前所在的管理 IP 或集群受保护节点 (%s)", ipStr)
	}

	t.mu.Lock()
	t.observeLocked(ipStr, "管理员手动拉黑", "banned", 1, true)
	if rec, ok := t.records[ipStr]; ok {
		rec.status = "banned"
	}
	t.mu.Unlock()

	if t.limiter != nil {
		t.limiter.BanManual(ipStr, 7*24*time.Hour)
	}
	parsedIP := net.ParseIP(ipStr)
	applyNFTBlockIP(ipStr, parsedIP != nil && parsedIP.To4() != nil)
	return ipStr, nil
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

// Snapshot 采集并生成外部活跃嗅探三维态势快照 (Top 8 IP / Top 8 IP段 / Top 8 嗅探国)
func (t *SniffTracker) Snapshot(ctx context.Context, activeProxyClientIPs ...string) SniffSummary {
	if len(activeProxyClientIPs) > 0 {
		t.MarkTrustedClientIPs(activeProxyClientIPs...)
	}

	// 1. 同步 Web IPLimiter 中的密码试探与封禁记录
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
			t.observeLocked(att.IP, "Web 管理端密码试探", st, att.FailCount, true)
		}
		t.mu.Unlock()
	}

	// 2. 低频异步/节流采集系统级防火墙、fail2ban 与外部探测连接 (每 6 秒最多执行一次)
	t.maybeHarvestSystemSources(ctx)

	// 3. 聚合计算 Top IP、Top /24 网段、Top 嗅探国
	now := time.Now()
	t.mu.Lock()
	rawList := make([]sniffRecord, 0, len(t.records))
	for ip, rec := range t.records {
		if now.Sub(rec.lastSeen) > sniffEntryTTL {
			delete(t.records, ip)
			continue
		}
		if exp, trusted := t.trustedClients[ip]; trusted && now.Before(exp) && rec.status != "banned" {
			delete(t.records, ip)
			continue
		}
		rawList = append(rawList, *rec)
	}
	blockedCIDRs := make(map[string]*net.IPNet, len(t.manualBlockedCIDRs))
	for k, v := range t.manualBlockedCIDRs {
		blockedCIDRs[k] = v
	}
	t.mu.Unlock()

	type enrichedItem struct {
		rec sniffRecord
		geo IPGeoInfo
		tag string
	}

	enriched := make([]enrichedItem, 0, len(rawList))
	totalBanned := 0
	for _, rec := range rawList {
		var geo IPGeoInfo
		if t.geo != nil {
			geo = t.geo.Resolve(rec.ip)
		}
		tag := cmp.Or(rec.scannerTag, MatchScannerTag(rec.ip, geo.ISP))
		if rec.status == "banned" {
			totalBanned++
		}
		enriched = append(enriched, enrichedItem{
			rec: rec,
			geo: geo,
			tag: tag,
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

	topIPs := make([]SniffIPStat, 0, min(len(enriched), maxTopSniffItems))
	for i := 0; i < len(enriched) && i < maxTopSniffItems; i++ {
		it := enriched[i]
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
			LastSeen:    it.rec.lastSeen.Format("15:04:05"),
		})
	}

	// 聚合 /24 (IPv4) 或 /48 (IPv6) 嗅探网段
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
			}
			subnetMap[cidr] = agg
		}
		agg.uniqueIPs++
		agg.totalHits += it.rec.hits
		if it.rec.status == "banned" {
			agg.bannedCount++
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
		if len(agg.samples) < 3 {
			agg.samples = append(agg.samples, it.rec.ip)
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
	if len(subnets) > maxTopSniffItems {
		subnets = subnets[:maxTopSniffItems]
	}

	// 聚合活跃嗅探国家/地区
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
	if len(countries) > maxTopSniffItems {
		countries = countries[:maxTopSniffItems]
	}

	return SniffSummary{
		UpdatedAt:      now.Format(time.RFC3339),
		TotalSniffIPs:  totalIPCount,
		TotalSubnets:   totalSubnets,
		TotalCountries: totalCountries,
		TotalBannedIPs: totalBanned,
		TopIPs:         topIPs,
		TopSubnets:     subnets,
		TopCountries:   countries,
	}
}

func (t *SniffTracker) maybeHarvestSystemSources(ctx context.Context) {
	t.mu.Lock()
	if !t.enableSystemProbe || (!t.lastSystemHarvest.IsZero() && time.Since(t.lastSystemHarvest) < systemHarvestMinDT) {
		t.mu.Unlock()
		return
	}
	t.lastSystemHarvest = time.Now()
	t.mu.Unlock()

	hCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	// 1. 采集 nftables 动态封禁集 (@blocklist_ip4)
	if _, err := exec.LookPath("nft"); err == nil {
		if out, err := exec.CommandContext(hCtx, "nft", "list", "set", "inet", "security", "blocklist_ip4").Output(); err == nil {
			ips := parseNFTSetIPs(string(out))
			t.mu.Lock()
			for _, ip := range ips {
				if !isIgnoredInternalIP(ip) {
					t.observeLocked(ip, "高危端口扫描拦截", "banned", 1, true)
				}
			}
			t.mu.Unlock()
		}
	}

	// 2. 采集内核日志中 [NFT] Blocked 的精确命中端口与次数
	harvestNFTKernelLogs(hCtx, t)

	// 3. 采集 fail2ban (sshd / recidive) 封禁 IP
	if _, err := exec.LookPath("fail2ban-client"); err == nil {
		for _, jail := range []string{"sshd", "recidive"} {
			if out, err := exec.CommandContext(hCtx, "fail2ban-client", "status", jail).Output(); err == nil {
				ips := parseFail2banBannedIPs(string(out))
				t.mu.Lock()
				for _, ip := range ips {
					if !isIgnoredInternalIP(ip) {
						t.observeLocked(ip, "SSH 暴力破解", "banned", 3, true)
					}
				}
				t.mu.Unlock()
			}
		}
	}

	// 4. 采集当前套接字 (ss -tan) 上的外部伪装回落与端口试探连接
	if _, err := exec.LookPath("ss"); err == nil {
		if out, err := exec.CommandContext(hCtx, "ss", "-tan").Output(); err == nil {
			probes := parseSSExternalProbes(string(out))
			t.mu.Lock()
			for _, p := range probes {
				if !isIgnoredInternalIP(p.ip) {
					t.observeLocked(p.ip, p.vector, p.status, p.hits, true)
				}
			}
			t.mu.Unlock()
		}
	}
}

func parseNFTSetIPs(raw string) []string {
	idx := strings.Index(raw, "elements = {")
	if idx < 0 {
		return nil
	}
	sub := raw[idx:]
	matches := reIPv4Token.FindAllString(sub, -1)
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if ip := normalizeIPString(m); ip != "" {
			if _, ok := seen[ip]; !ok {
				seen[ip] = struct{}{}
				out = append(out, ip)
			}
		}
	}
	return out
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

	hitsByIP := make(map[string]int)
	portByIP := make(map[string]string)
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.Contains(line, "[NFT]") {
			continue
		}
		m := reNFTLogLine.FindStringSubmatch(line)
		if len(m) == 3 {
			ip := normalizeIPString(m[1])
			port := m[2]
			if ip != "" && !isIgnoredInternalIP(ip) {
				hitsByIP[ip]++
				portByIP[ip] = port
			}
		}
	}
	if len(hitsByIP) == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, count := range hitsByIP {
		port := portByIP[ip]
		vec := "高危端口扫描"
		if port != "" {
			vec = fmt.Sprintf("高危端口扫描 (:%s)", port)
		}
		t.observeLocked(ip, vec, "banned", count, true)
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
				// ESTABLISHED on 443: only tracked if not in trusted proxy clients (filtered by observeLocked)
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
