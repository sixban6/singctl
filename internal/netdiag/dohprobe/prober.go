// 文件职责：执行浏览器安全 DNS（DoH）两阶段流量基线采样、ARP/邻居表同机关联与归属分歧判定。
package dohprobe

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/netdiag"
	"singctl/internal/singbox/clashapi"
)

const (
	gatewayEDNSCacheTTL = 45 * time.Second
	probeSnapshotTTL    = 60 * time.Second
	defaultRecommendMsg = "建议在当前浏览器隐私/安全设置中关闭「使用安全 DNS（DoH）」，让所有域名解析由路由器 AdGuard Home 与 sing-box 统一接管分流与防泄漏（若本机同时开启了第三方代理软件或手动固定外部 DNS，也请一并关闭并恢复自动获取 DNS）。"
)

type connCounter struct {
	Upload   int64
	Download int64
}

type probeSnapshot struct {
	ClientIP  string
	CreatedAt time.Time
	Conns     map[string]connCounter
}

// Prober 管理两阶段 DoH 基线快照与网关 EDNS 出口缓存。
type Prober struct {
	deps Deps

	snapMu    sync.Mutex
	snapshots map[string]probeSnapshot

	ednsMu       sync.Mutex
	ednsProfile  *netdiag.DNSResolverProfile
	ednsCachedAt time.Time
}

// NewProber 创建浏览器安全 DNS 旁路检测器。
func NewProber(deps Deps) *Prober {
	return &Prober{
		deps:      deps,
		snapshots: make(map[string]probeSnapshot),
	}
}

func (p *Prober) now() time.Time {
	if p != nil && p.deps.Now != nil {
		return p.deps.Now()
	}
	return time.Now()
}

// ResolveClientIP 从 HTTP 请求中提取真实局域网客户端 IP（支持本机回环反代透传头）。
func (p *Prober) ResolveClientIP(r *http.Request) string {
	if p != nil && strings.TrimSpace(p.deps.ClientIP) != "" {
		return NormalizeIPString(p.deps.ClientIP)
	}
	if r == nil {
		return ""
	}
	remote := strings.TrimSpace(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if addr, err := netip.ParseAddr(remote); err == nil && addr.Unmap().IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if norm := NormalizeIPString(first); norm != "" {
				return norm
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if norm := NormalizeIPString(xri); norm != "" {
				return norm
			}
		}
	}
	return cmp.Or(NormalizeIPString(remote), remote)
}

// Check 执行两阶段浏览器安全 DNS 旁路检测并返回完整诊断响应。
func (p *Prober) Check(ctx context.Context, clientIP string, viaTailscale bool, req CheckRequest) CheckResponse {
	checkedAt := p.now().UTC().Format(time.RFC3339)
	if skipResp, skipped := checkRemoteSkipGuard(clientIP, viaTailscale, checkedAt); skipped {
		return skipResp
	}
	if strings.EqualFold(strings.TrimSpace(req.Phase), "begin") {
		return p.recordBaselinePhase(ctx, clientIP, checkedAt)
	}
	return p.evaluateFinishPhase(ctx, clientIP, checkedAt, req)
}

func checkRemoteSkipGuard(clientIP string, viaTailscale bool, checkedAt string) (CheckResponse, bool) {
	if viaTailscale {
		return CheckResponse{
			Status:       "skipped_remote",
			Confidence:   "none",
			ClientIP:     clientIP,
			IsLANClient:  false,
			ViaTailscale: true,
			Summary:      "当前正经由 Tailscale 异地隧道管理路由器，已自动跳过本地浏览器 DoH 旁路检测（请在局域网直连环境下检测本机浏览器）。",
			CheckedAt:    checkedAt,
		}, true
	}
	if !IsPrivateLANAddr(clientIP) {
		return CheckResponse{
			Status:      "skipped_remote",
			Confidence:  "none",
			ClientIP:    clientIP,
			IsLANClient: false,
			Summary:     "当前请求来源非局域网终端（例如本机回环或公网地址），已跳过本机浏览器 DoH 旁路归因。",
			CheckedAt:   checkedAt,
		}, true
	}
	return CheckResponse{}, false
}

func (p *Prober) recordBaselinePhase(parentCtx context.Context, clientIP, checkedAt string) CheckResponse {
	bCtx, cancel := context.WithTimeout(parentCtx, 2500*time.Millisecond)
	defer cancel()

	clientIPSet := p.collectClientIPSet(bCtx, clientIP)
	baseline := make(map[string]connCounter)
	if conns, err := p.fetchClashConnections(bCtx); err == nil {
		for _, c := range conns {
			if m, ok := matchPublicDoHConn(c, clientIPSet); ok {
				baseline[m.Key] = connCounter{Upload: c.Upload, Download: c.Download}
			}
		}
	}
	probeID := p.saveSnapshot(clientIP, baseline)
	return CheckResponse{
		Status:      "pending",
		Confidence:  "none",
		ProbeID:     probeID,
		ClientIP:    clientIP,
		IsLANClient: true,
		Summary:     "已记录 DoH 检测前置流量基线快照。",
		CheckedAt:   checkedAt,
	}
}

type activeMatchOutcome struct {
	matched           []EndpointMatch
	providers         []string
	hasRejectedDoH    bool
	idleLeftoverCount int
}

func matchActiveDoHConnections(conns []ClashConn, clientIPSet map[string]struct{}, baseline probeSnapshot, hasBaseline bool) activeMatchOutcome {
	var out activeMatchOutcome
	seenMatch := make(map[string]struct{})
	for _, c := range conns {
		m, ok := matchPublicDoHConn(c, clientIPSet)
		if !ok {
			continue
		}
		if hasBaseline {
			if prev, existed := baseline.Conns[m.Key]; existed {
				deltaUp := c.Upload - prev.Upload
				deltaDown := c.Download - prev.Download
				if deltaUp >= 0 && deltaDown >= 0 {
					activeTraffic := (deltaUp >= 64 && deltaDown >= 64) || (deltaUp+deltaDown) >= 128
					if !activeTraffic {
						out.idleLeftoverCount++
						continue
					}
				}
			}
		}
		if m.IsRejected {
			out.hasRejectedDoH = true
		}
		dedupKey := fmt.Sprintf("%s|%s|%s|%s", m.Endpoint.Provider, m.Endpoint.Host, m.Endpoint.DestIP, m.Endpoint.DestPort)
		if _, exists := seenMatch[dedupKey]; exists {
			continue
		}
		seenMatch[dedupKey] = struct{}{}
		out.matched = append(out.matched, m.Endpoint)
		if !slices.Contains(out.providers, m.Endpoint.Provider) {
			out.providers = append(out.providers, m.Endpoint.Provider)
		}
	}
	return out
}

type divergenceOutcome struct {
	strictConflict   bool
	cnLeakProvider   string
	mismatchProvider string
	signals          []string
}

func analyzeResolverDivergence(active activeMatchOutcome, gwResolver *netdiag.DNSResolverProfile, browserResolvers []EDNSSample, req CheckRequest) divergenceOutcome {
	var div divergenceOutcome
	div.signals = make([]string, 0, 3)

	if len(active.matched) > 0 {
		epDesc := make([]string, 0, len(active.matched))
		for _, m := range active.matched {
			target := cmp.Or(m.Host, m.DestIP)
			if m.DestPort != "" {
				target += ":" + m.DestPort
			}
			epDesc = append(epDesc, fmt.Sprintf("%s (%s)", m.Provider, target))
		}
		prefix := "网关活动连接实时捕捉到当前设备正在直连外部 DoH/DoT 端点: "
		if active.hasRejectedDoH {
			prefix = "网关活动连接实时捕捉到当前设备直连公共 DoH/DoT 并触发防泄漏拦截规则: "
		}
		div.signals = append(div.signals, prefix+strings.Join(epDesc, "、"))
	}

	div.strictConflict = req.BrowserProbeAttempted > 0 &&
		len(browserResolvers) == 0 &&
		req.BrowserProbeFailed >= req.BrowserProbeAttempted &&
		gwResolver != nil
	if div.strictConflict {
		div.signals = append(div.signals, fmt.Sprintf(
			"路由器网关随机域名探测正常（出口 %s），但浏览器侧 %d 次独立解析请求全部失败（典型严格模式 DoH 被网关规则阻断特征）",
			cmp.Or(gwResolver.ISP, gwResolver.IP),
			req.BrowserProbeAttempted,
		))
	}

	if gwResolver == nil || len(browserResolvers) == 0 {
		return div
	}

	gwIsCN := strings.EqualFold(gwResolver.CountryCode, "CN")
	gwFam := NormalizeDNSOrgFamily(gwResolver.ISP, gwResolver.IP)
	allHaveFamily := gwFam != ""
	anySameFamily := false

	for _, br := range browserResolvers {
		if strings.EqualFold(br.CountryCode, "CN") && !gwIsCN {
			div.cnLeakProvider = cmp.Or(br.ISP, br.Country, br.DNSIP)
		}
		brFam := NormalizeDNSOrgFamily(br.ISP, br.DNSIP)
		switch {
		case brFam == "":
			allHaveFamily = false
		case brFam == gwFam:
			anySameFamily = true
		case div.mismatchProvider == "":
			div.mismatchProvider = cmp.Or(br.ISP, br.DNSIP)
		}
	}

	if div.cnLeakProvider != "" {
		div.signals = append(div.signals, fmt.Sprintf(
			"网关 DNS 正常走海外解析（%s），但浏览器请求直接落回国内 DNS 出口（%s）",
			cmp.Or(gwResolver.ISP, gwResolver.CountryCode, gwResolver.IP),
			div.cnLeakProvider,
		))
	} else if allHaveFamily && !anySameFamily && div.mismatchProvider != "" {
		div.signals = append(div.signals, fmt.Sprintf(
			"网关与浏览器递归 DNS 归属完全分歧：网关经 %s，浏览器经 %s",
			cmp.Or(gwResolver.ISP, gwResolver.IP),
			div.mismatchProvider,
		))
	}
	return div
}

func (p *Prober) evaluateFinishPhase(parentCtx context.Context, clientIP, checkedAt string, req CheckRequest) CheckResponse {
	ctx, cancel := context.WithTimeout(parentCtx, 5500*time.Millisecond)
	defer cancel()

	clientIPSet := p.collectClientIPSet(ctx, clientIP)
	browserResolvers := dedupBrowserSamples(req.BrowserSamples)
	baselineSnap, hasBaseline := p.popSnapshot(req.ProbeID, clientIP)

	conns, clashErr := p.fetchClashConnections(ctx)
	gwResolver := p.probeCachedGatewayEDNS(ctx)

	active := matchActiveDoHConnections(conns, clientIPSet, baselineSnap, hasBaseline)
	div := analyzeResolverDivergence(active, gwResolver, browserResolvers, req)

	resp := CheckResponse{
		IdleLeftoverCount: active.idleLeftoverCount,
		ClientIP:          clientIP,
		IsLANClient:       true,
		ViaTailscale:      false,
		MatchedEndpoints:  active.matched,
		GatewayResolver:   gwResolver,
		BrowserResolvers:  browserResolvers,
		Signals:           div.signals,
		CheckedAt:         checkedAt,
	}

	switch {
	case len(active.matched) > 0:
		resp.Status = "detected"
		resp.Confidence = "high"
		resp.DetectedProvider = strings.Join(active.providers, " / ")
		resp.Summary = fmt.Sprintf(
			"检测到当前设备正在绕过网关直接使用浏览器或系统安全 DNS（%s），会导致国内外分流失效、AdGuard 过滤失效甚至与网关防泄漏规则冲突断网。",
			resp.DetectedProvider,
		)
		resp.Recommendation = defaultRecommendMsg
	case div.strictConflict:
		resp.Status = "detected"
		resp.Confidence = "medium"
		resp.DetectedProvider = "浏览器严格安全 DNS（与网关防泄漏规则冲突）"
		resp.Summary = "浏览器侧随机域名探测全部失败而网关侧解析正常，高度符合「浏览器开启国内安全 DNS / 自定义 DoH 被网关防泄漏规则拦截」导致的网页打不开特征。"
		resp.Recommendation = defaultRecommendMsg
	case div.cnLeakProvider != "" || div.mismatchProvider != "":
		resp.Status = "suspected"
		resp.Confidence = "medium"
		resp.DetectedProvider = cmp.Or(div.cnLeakProvider, div.mismatchProvider)
		resp.Summary = fmt.Sprintf(
			"检测到当前浏览器的 DNS 解析出口（%s）与路由器网关出口不一致，怀疑浏览器开启了安全 DNS（DoH）或本机单独固定了 DNS / 代理软件。",
			resp.DetectedProvider,
		)
		resp.Recommendation = defaultRecommendMsg
	case gwResolver == nil && len(browserResolvers) == 0 && clashErr != nil:
		resp.Status = "unavailable"
		resp.Confidence = "none"
		resp.Summary = "暂无法访问网关 Clash 连接表及外部 EDNS 探测节点，请确认 sing-box 正在运行且网络连通后重试。"
	default:
		resp.Status = "clean"
		resp.Confidence = "none"
		if active.idleLeftoverCount > 0 {
			resp.Summary = fmt.Sprintf(
				"未检测到当前浏览器使用自身安全 DNS（DoH），域名解析正正常经由路由器统一接管（已忽略 %d 条先前遗留的零流量空闲 DoH 长连接，无需等待浏览器回收连接池）。",
				active.idleLeftoverCount,
			)
		} else {
			resp.Summary = "未检测到当前浏览器绕过网关使用独立安全 DNS（DoH），域名解析正正常经由路由器统一接管。"
		}
	}
	return resp
}

func (p *Prober) collectClientIPSet(ctx context.Context, clientIP string) map[string]struct{} {
	set := make(map[string]struct{}, 4)
	if norm := NormalizeIPString(clientIP); norm != "" {
		set[norm] = struct{}{}
	}
	if len(set) == 0 {
		return set
	}
	if p.deps.PeerIPsForMAC != nil {
		for _, peer := range p.deps.PeerIPsForMAC(ctx, clientIP) {
			if norm := NormalizeIPString(peer); norm != "" {
				set[norm] = struct{}{}
			}
		}
		return set
	}
	for _, sib := range discoverMACSiblingIPs(ctx, set) {
		set[sib] = struct{}{}
	}
	return set
}

func discoverMACSiblingIPs(ctx context.Context, initialIPs map[string]struct{}) []string {
	ipToMAC := make(map[string]string)
	macToIPs := make(map[string][]string)
	addEntry := func(ipRaw, macRaw string) {
		normIP := NormalizeIPString(ipRaw)
		mac := strings.ToLower(strings.TrimSpace(macRaw))
		if normIP == "" || mac == "" || mac == "00:00:00:00:00:00" || mac == "<incomplete>" {
			return
		}
		ipToMAC[normIP] = mac
		if !slices.Contains(macToIPs[mac], normIP) {
			macToIPs[mac] = append(macToIPs[mac], normIP)
		}
	}

	if f, err := os.Open("/proc/net/arp"); err == nil {
		sc := bufio.NewScanner(f)
		first := true
		for sc.Scan() {
			if first {
				first = false
				continue
			}
			fields := strings.Fields(sc.Text())
			if len(fields) >= 4 {
				addEntry(fields[0], fields[3])
			}
		}
		_ = f.Close()
	}

	if ipBin, err := exec.LookPath("ip"); err == nil {
		nCtx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
		out, err := exec.CommandContext(nCtx, ipBin, "-6", "neigh", "show").Output()
		cancel()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(string(out)))
			for sc.Scan() {
				fields := strings.Fields(sc.Text())
				if len(fields) < 5 {
					continue
				}
				if llIdx := slices.Index(fields, "lladdr"); llIdx >= 0 && llIdx+1 < len(fields) {
					addEntry(fields[0], fields[llIdx+1])
				}
			}
		}
	}

	var siblings []string
	for baseIP := range initialIPs {
		if mac := ipToMAC[baseIP]; mac != "" {
			siblings = append(siblings, macToIPs[mac]...)
		}
	}
	return siblings
}

func (p *Prober) fetchClashConnections(ctx context.Context) ([]ClashConn, error) {
	if p.deps.ClashConnections != nil {
		return p.deps.ClashConnections(ctx)
	}
	if p.deps.SingBoxRunning != nil && !p.deps.SingBoxRunning() {
		return nil, clashapi.ErrUnreachable
	}
	if p.deps.ClashClient == nil {
		return nil, clashapi.ErrUnreachable
	}
	cCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	base, secret, err := p.deps.ClashClient.ResolveEndpoint(cCtx)
	if err != nil {
		return nil, err
	}
	snap, err := p.deps.ClashClient.ConnectionsAt(cCtx, base, secret)
	if err != nil {
		return nil, err
	}
	return ClashConnsFromSnapshot(snap), nil
}

func (p *Prober) probeCachedGatewayEDNS(ctx context.Context) *netdiag.DNSResolverProfile {
	if p.deps.GatewayEDNSProber != nil {
		prof, err := p.deps.GatewayEDNSProber(ctx)
		if err != nil {
			return nil
		}
		return prof
	}

	now := p.now()
	p.ednsMu.Lock()
	if p.ednsProfile != nil && now.Sub(p.ednsCachedAt) < gatewayEDNSCacheTTL {
		cached := *p.ednsProfile
		p.ednsMu.Unlock()
		return &cached
	}
	p.ednsMu.Unlock()

	prof, err := netdiag.ProbeGatewayEDNSOnce(ctx)
	if err != nil || prof == nil {
		return nil
	}

	p.ednsMu.Lock()
	p.ednsProfile = prof
	p.ednsCachedAt = p.now()
	p.ednsMu.Unlock()

	copyProf := *prof
	return &copyProf
}

func (p *Prober) saveSnapshot(clientIP string, conns map[string]connCounter) string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	probeID := hex.EncodeToString(raw[:])

	now := p.now()
	p.snapMu.Lock()
	defer p.snapMu.Unlock()
	if p.snapshots == nil {
		p.snapshots = make(map[string]probeSnapshot)
	}
	for id, snap := range p.snapshots {
		if now.Sub(snap.CreatedAt) > probeSnapshotTTL {
			delete(p.snapshots, id)
		}
	}
	p.snapshots[probeID] = probeSnapshot{
		ClientIP:  clientIP,
		CreatedAt: now,
		Conns:     conns,
	}
	return probeID
}

func (p *Prober) popSnapshot(probeID, clientIP string) (probeSnapshot, bool) {
	id := strings.TrimSpace(probeID)
	if id == "" {
		return probeSnapshot{}, false
	}
	now := p.now()
	p.snapMu.Lock()
	defer p.snapMu.Unlock()
	snap, ok := p.snapshots[id]
	if ok {
		delete(p.snapshots, id)
	}
	if !ok || snap.ClientIP != clientIP || now.Sub(snap.CreatedAt) > probeSnapshotTTL {
		return probeSnapshot{}, false
	}
	return snap, true
}
