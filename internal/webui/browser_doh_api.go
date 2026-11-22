// 文件职责：承载浏览器安全 DNS（DoH）旁路检测两阶段探针采集、ARP/邻居表同机关联与 HTTP API 处理。
package webui

import (
	"bufio"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"singctl/internal/daemon"
	"singctl/internal/netdiag"
)

const (
	gatewayEDNSCacheTTL = 45 * time.Second
	dohProbeSnapshotTTL = 60 * time.Second
)

// BrowserDoHClashConn 表示浏览器安全 DNS 检测所需的一条网关活跃连接摘要。
type BrowserDoHClashConn struct {
	ID        string
	Upload    int64
	Download  int64
	Start     string
	SourceIP  string
	DestIP    string
	DestPort  string
	Host      string
	SniffHost string
	Network   string
	Rule      string
	Chains    []string
}

type dohConnCounter struct {
	Upload   int64
	Download int64
}

type dohProbeSnapshot struct {
	ClientIP  string
	CreatedAt time.Time
	Conns     map[string]dohConnCounter
}

// BrowserDoHTestHooks 仅供离线单元测试注入浏览器安全 DNS 检测依赖。
type BrowserDoHTestHooks struct {
	ClientIP          string
	PeerIPsForMAC     func(clientIP string) []string
	ClashConnections  func(ctx context.Context) ([]BrowserDoHClashConn, error)
	GatewayEDNSProber func(ctx context.Context) (*netdiag.DNSResolverProfile, error)
	SingBoxRunning    func() bool
}

type browserDoHEDNSSample struct {
	DNSIP       string `json:"dnsIp"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	ISP         string `json:"isp,omitempty"`
}

type browserDoHCheckRequest struct {
	Phase                 string                 `json:"phase,omitempty"`
	ProbeID               string                 `json:"probeId,omitempty"`
	BrowserSamples        []browserDoHEDNSSample `json:"browserSamples"`
	BrowserProbeAttempted int                    `json:"browserProbeAttempted"`
	BrowserProbeFailed    int                    `json:"browserProbeFailed"`
}

type browserDoHEndpointMatch struct {
	Provider string `json:"provider"`
	Host     string `json:"host,omitempty"`
	DestIP   string `json:"destIp,omitempty"`
	DestPort string `json:"destPort,omitempty"`
	SourceIP string `json:"sourceIp,omitempty"`
	Network  string `json:"network,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

type browserDoHCheckResponse struct {
	Status            string                      `json:"status"`     // "clean" | "detected" | "suspected" | "skipped_remote" | "unavailable" | "pending"
	Confidence        string                      `json:"confidence"` // "high" | "medium" | "none"
	ProbeID           string                      `json:"probeId,omitempty"`
	IdleLeftoverCount int                         `json:"idleLeftoverCount,omitempty"`
	ClientIP          string                      `json:"clientIp,omitempty"`
	IsLANClient       bool                        `json:"isLanClient"`
	ViaTailscale      bool                        `json:"viaTailscale"`
	DetectedProvider  string                      `json:"detectedProvider,omitempty"`
	MatchedEndpoints  []browserDoHEndpointMatch   `json:"matchedEndpoints,omitempty"`
	GatewayResolver   *netdiag.DNSResolverProfile `json:"gatewayResolver,omitempty"`
	BrowserResolvers  []browserDoHEDNSSample      `json:"browserResolvers,omitempty"`
	Signals           []string                    `json:"signals,omitempty"`
	Summary           string                      `json:"summary"`
	Recommendation    string                      `json:"recommendation,omitempty"`
	CheckedAt         string                      `json:"checkedAt"`
}

func (s *Server) resolveRequestClientIP(r *http.Request) string {
	if s.opts.BrowserDoHForTest != nil && strings.TrimSpace(s.opts.BrowserDoHForTest.ClientIP) != "" {
		return normalizeIPString(s.opts.BrowserDoHForTest.ClientIP)
	}
	remote := remoteClientIP(r)
	if addr, err := netip.ParseAddr(strings.TrimSpace(remote)); err == nil && addr.Unmap().IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if norm := normalizeIPString(first); norm != "" {
				return norm
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if norm := normalizeIPString(xri); norm != "" {
				return norm
			}
		}
	}
	return cmp.Or(normalizeIPString(remote), strings.TrimSpace(remote))
}

func (s *Server) collectClientIPSet(ctx context.Context, clientIP string) map[string]struct{} {
	set := map[string]struct{}{}
	if norm := normalizeIPString(clientIP); norm != "" {
		set[norm] = struct{}{}
	}
	if len(set) == 0 {
		return set
	}

	if s.opts.BrowserDoHForTest != nil {
		if s.opts.BrowserDoHForTest.PeerIPsForMAC != nil {
			for _, peer := range s.opts.BrowserDoHForTest.PeerIPsForMAC(clientIP) {
				if norm := normalizeIPString(peer); norm != "" {
					set[norm] = struct{}{}
				}
			}
		}
		return set
	}

	ipToMAC := map[string]string{}
	macToIPs := map[string][]string{}
	addEntry := func(ipRaw, macRaw string) {
		normIP := normalizeIPString(ipRaw)
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
				llIdx := slices.Index(fields, "lladdr")
				if llIdx >= 0 && llIdx+1 < len(fields) {
					addEntry(fields[0], fields[llIdx+1])
				}
			}
		}
	}

	for _, baseIP := range collectMapKeys(set) {
		mac := ipToMAC[baseIP]
		if mac == "" {
			continue
		}
		for _, sib := range macToIPs[mac] {
			set[sib] = struct{}{}
		}
	}
	return set
}

func (s *Server) fetchClashConnectionsForDoH(ctx context.Context) ([]BrowserDoHClashConn, error) {
	if s.opts.BrowserDoHForTest != nil {
		if s.opts.BrowserDoHForTest.ClashConnections != nil {
			return s.opts.BrowserDoHForTest.ClashConnections(ctx)
		}
		return nil, nil
	}
	sbRunning := daemon.IsSingBoxRunning()
	if !sbRunning {
		return nil, errClashUnreachable
	}
	cCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(cCtx)
	if err != nil {
		return nil, err
	}
	code, raw, err := doClashRequest(cCtx, sharedClashHTTPClient, http.MethodGet, base+"/connections", secret, nil)
	if err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("Clash API /connections HTTP %d", code)
	}
	var payload struct {
		Connections []struct {
			ID       string   `json:"id"`
			Upload   int64    `json:"upload"`
			Download int64    `json:"download"`
			Start    string   `json:"start"`
			Chains   []string `json:"chains"`
			Rule     string   `json:"rule"`
			Metadata struct {
				Network         string `json:"network"`
				SourceIP        string `json:"sourceIP"`
				DestinationIP   string `json:"destinationIP"`
				DestinationPort string `json:"destinationPort"`
				Host            string `json:"host"`
				SniffHost       string `json:"sniffHost"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}
	out := make([]BrowserDoHClashConn, 0, len(payload.Connections))
	for _, c := range payload.Connections {
		out = append(out, BrowserDoHClashConn{
			ID:        c.ID,
			Upload:    c.Upload,
			Download:  c.Download,
			Start:     c.Start,
			SourceIP:  c.Metadata.SourceIP,
			DestIP:    c.Metadata.DestinationIP,
			DestPort:  c.Metadata.DestinationPort,
			Host:      c.Metadata.Host,
			SniffHost: c.Metadata.SniffHost,
			Network:   c.Metadata.Network,
			Rule:      c.Rule,
			Chains:    c.Chains,
		})
	}
	return out, nil
}

func (s *Server) probeCachedGatewayEDNS(ctx context.Context) *netdiag.DNSResolverProfile {
	if s.opts.BrowserDoHForTest != nil {
		if s.opts.BrowserDoHForTest.GatewayEDNSProber != nil {
			p, err := s.opts.BrowserDoHForTest.GatewayEDNSProber(ctx)
			if err == nil {
				return p
			}
		}
		return nil
	}

	s.gwEDNSMu.Lock()
	if s.gwEDNSProfile != nil && time.Since(s.gwEDNSCachedAt) < gatewayEDNSCacheTTL {
		cached := *s.gwEDNSProfile
		s.gwEDNSMu.Unlock()
		return &cached
	}
	s.gwEDNSMu.Unlock()

	prof, err := netdiag.ProbeGatewayEDNSOnce(ctx)
	if err != nil || prof == nil {
		return nil
	}

	s.gwEDNSMu.Lock()
	s.gwEDNSProfile = prof
	s.gwEDNSCachedAt = time.Now()
	s.gwEDNSMu.Unlock()

	copyProf := *prof
	return &copyProf
}

func (s *Server) saveDoHProbeSnapshot(clientIP string, conns map[string]dohConnCounter) string {
	var raw [16]byte
	_, _ = rand.Read(raw[:])
	probeID := hex.EncodeToString(raw[:])

	now := time.Now()
	s.dohProbeMu.Lock()
	defer s.dohProbeMu.Unlock()
	if s.dohProbeSnapshots == nil {
		s.dohProbeSnapshots = map[string]dohProbeSnapshot{}
	}
	for id, snap := range s.dohProbeSnapshots {
		if now.Sub(snap.CreatedAt) > dohProbeSnapshotTTL {
			delete(s.dohProbeSnapshots, id)
		}
	}
	s.dohProbeSnapshots[probeID] = dohProbeSnapshot{
		ClientIP:  clientIP,
		CreatedAt: now,
		Conns:     conns,
	}
	return probeID
}

func (s *Server) popDoHProbeSnapshot(probeID, clientIP string) (dohProbeSnapshot, bool) {
	id := strings.TrimSpace(probeID)
	if id == "" {
		return dohProbeSnapshot{}, false
	}
	now := time.Now()
	s.dohProbeMu.Lock()
	defer s.dohProbeMu.Unlock()
	snap, ok := s.dohProbeSnapshots[id]
	if ok {
		delete(s.dohProbeSnapshots, id)
	}
	if !ok || snap.ClientIP != clientIP || now.Sub(snap.CreatedAt) > dohProbeSnapshotTTL {
		return dohProbeSnapshot{}, false
	}
	return snap, true
}

func (s *Server) handleBrowserDoHCheckPost(w http.ResponseWriter, r *http.Request) {
	var body browserDoHCheckRequest
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
		if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "无效的浏览器 DoH 检测请求参数: "+err.Error())
			return
		}
	}

	checkedAt := time.Now().UTC().Format(time.RFC3339)
	clientIP := s.resolveRequestClientIP(r)
	viaTS := isTailscaleAddr(clientIP)
	if !viaTS && s.opts.BrowserDoHForTest == nil {
		viaTS = isTailscaleRequest(r)
	}

	if viaTS {
		writeJSON(w, http.StatusOK, browserDoHCheckResponse{
			Status:       "skipped_remote",
			Confidence:   "none",
			ClientIP:     clientIP,
			IsLANClient:  false,
			ViaTailscale: true,
			Summary:      "当前正经由 Tailscale 异地隧道管理路由器，已自动跳过本地浏览器 DoH 旁路检测（请在局域网直连环境下检测本机浏览器）。",
			CheckedAt:    checkedAt,
		})
		return
	}

	if !isPrivateLANAddr(clientIP) {
		writeJSON(w, http.StatusOK, browserDoHCheckResponse{
			Status:      "skipped_remote",
			Confidence:  "none",
			ClientIP:    clientIP,
			IsLANClient: false,
			Summary:     "当前请求来源非局域网终端（例如本机回环或公网地址），已跳过本机浏览器 DoH 旁路归因。",
			CheckedAt:   checkedAt,
		})
		return
	}

	phase := strings.ToLower(strings.TrimSpace(body.Phase))
	if phase == "begin" {
		bCtx, bCancel := context.WithTimeout(r.Context(), 2500*time.Millisecond)
		defer bCancel()

		clientIPSet := s.collectClientIPSet(bCtx, clientIP)
		baseline := map[string]dohConnCounter{}
		if conns, err := s.fetchClashConnectionsForDoH(bCtx); err == nil {
			for _, c := range conns {
				if m, ok := matchPublicDoHConn(c, clientIPSet); ok {
					baseline[m.Key] = dohConnCounter{Upload: c.Upload, Download: c.Download}
				}
			}
		}
		probeID := s.saveDoHProbeSnapshot(clientIP, baseline)
		writeJSON(w, http.StatusOK, browserDoHCheckResponse{
			Status:      "pending",
			Confidence:  "none",
			ProbeID:     probeID,
			ClientIP:    clientIP,
			IsLANClient: true,
			Summary:     "已记录 DoH 检测前置流量基线快照。",
			CheckedAt:   checkedAt,
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5500*time.Millisecond)
	defer cancel()

	clientIPSet := s.collectClientIPSet(ctx, clientIP)
	browserResolvers := dedupBrowserSamples(body.BrowserSamples)
	baselineSnap, hasBaseline := s.popDoHProbeSnapshot(body.ProbeID, clientIP)

	conns, clashErr := s.fetchClashConnectionsForDoH(ctx)
	gwResolver := s.probeCachedGatewayEDNS(ctx)

	var matched []browserDoHEndpointMatch
	seenMatch := map[string]struct{}{}
	var matchedProviders []string
	var hasRejectedDoH bool
	idleLeftoverCount := 0

	for _, c := range conns {
		m, ok := matchPublicDoHConn(c, clientIPSet)
		if !ok {
			continue
		}

		if hasBaseline {
			if prev, existed := baselineSnap.Conns[m.Key]; existed {
				deltaUp := c.Upload - prev.Upload
				deltaDown := c.Download - prev.Download
				if deltaUp >= 0 && deltaDown >= 0 {
					activeTraffic := (deltaUp >= 64 && deltaDown >= 64) || (deltaUp+deltaDown) >= 128
					if !activeTraffic {
						idleLeftoverCount++
						continue
					}
				}
			}
		}

		if m.IsRejected {
			hasRejectedDoH = true
		}

		dedupKey := fmt.Sprintf("%s|%s|%s|%s", m.Endpoint.Provider, m.Endpoint.Host, m.Endpoint.DestIP, m.Endpoint.DestPort)
		if _, exists := seenMatch[dedupKey]; exists {
			continue
		}
		seenMatch[dedupKey] = struct{}{}
		matched = append(matched, m.Endpoint)
		if !slices.Contains(matchedProviders, m.Endpoint.Provider) {
			matchedProviders = append(matchedProviders, m.Endpoint.Provider)
		}
	}

	signals := make([]string, 0, 3)
	if len(matched) > 0 {
		epDesc := make([]string, 0, len(matched))
		for _, m := range matched {
			target := cmp.Or(m.Host, m.DestIP)
			if m.DestPort != "" {
				target += ":" + m.DestPort
			}
			epDesc = append(epDesc, fmt.Sprintf("%s (%s)", m.Provider, target))
		}
		if hasRejectedDoH {
			signals = append(signals, "网关活动连接实时捕捉到当前设备直连公共 DoH/DoT 并触发防泄漏拦截规则: "+strings.Join(epDesc, "、"))
		} else {
			signals = append(signals, "网关活动连接实时捕捉到当前设备正在直连外部 DoH/DoT 端点: "+strings.Join(epDesc, "、"))
		}
	}

	strictConflict := body.BrowserProbeAttempted > 0 &&
		len(browserResolvers) == 0 &&
		body.BrowserProbeFailed >= body.BrowserProbeAttempted &&
		gwResolver != nil

	if strictConflict {
		signals = append(signals, fmt.Sprintf(
			"路由器网关随机域名探测正常（出口 %s），但浏览器侧 %d 次独立解析请求全部失败（典型严格模式 DoH 被网关规则阻断特征）",
			cmp.Or(gwResolver.ISP, gwResolver.IP),
			body.BrowserProbeAttempted,
		))
	}

	var cnLeakProvider string
	var mismatchProvider string
	if gwResolver != nil && len(browserResolvers) > 0 {
		gwIsCN := strings.EqualFold(gwResolver.CountryCode, "CN")
		gwFam := normalizeDNSOrgFamily(gwResolver.ISP, gwResolver.IP)

		allHaveFamily := gwFam != ""
		anySameFamily := false
		for _, br := range browserResolvers {
			if strings.EqualFold(br.CountryCode, "CN") && !gwIsCN {
				cnLeakProvider = cmp.Or(br.ISP, br.Country, br.DNSIP)
			}
			brFam := normalizeDNSOrgFamily(br.ISP, br.DNSIP)
			if brFam == "" {
				allHaveFamily = false
			} else if brFam == gwFam {
				anySameFamily = true
			} else if mismatchProvider == "" {
				mismatchProvider = cmp.Or(br.ISP, br.DNSIP)
			}
		}

		if cnLeakProvider != "" {
			signals = append(signals, fmt.Sprintf(
				"网关 DNS 正常走海外解析（%s），但浏览器请求直接落回国内 DNS 出口（%s）",
				cmp.Or(gwResolver.ISP, gwResolver.CountryCode, gwResolver.IP),
				cnLeakProvider,
			))
		} else if allHaveFamily && !anySameFamily && mismatchProvider != "" {
			signals = append(signals, fmt.Sprintf(
				"网关与浏览器递归 DNS 归属完全分歧：网关经 %s，浏览器经 %s",
				cmp.Or(gwResolver.ISP, gwResolver.IP),
				mismatchProvider,
			))
		}
	}

	recommendation := "建议在当前浏览器隐私/安全设置中关闭「使用安全 DNS（DoH）」，让所有域名解析由路由器 AdGuard Home 与 sing-box 统一接管分流与防泄漏（若本机同时开启了第三方代理软件或手动固定外部 DNS，也请一并关闭并恢复自动获取 DNS）。"

	resp := browserDoHCheckResponse{
		IdleLeftoverCount: idleLeftoverCount,
		ClientIP:          clientIP,
		IsLANClient:       true,
		ViaTailscale:      false,
		MatchedEndpoints:  matched,
		GatewayResolver:   gwResolver,
		BrowserResolvers:  browserResolvers,
		Signals:           signals,
		CheckedAt:         checkedAt,
	}

	switch {
	case len(matched) > 0:
		resp.Status = "detected"
		resp.Confidence = "high"
		resp.DetectedProvider = strings.Join(matchedProviders, " / ")
		resp.Summary = fmt.Sprintf(
			"检测到当前设备正在绕过网关直接使用浏览器或系统安全 DNS（%s），会导致国内外分流失效、AdGuard 过滤失效甚至与网关防泄漏规则冲突断网。",
			resp.DetectedProvider,
		)
		resp.Recommendation = recommendation
	case strictConflict:
		resp.Status = "detected"
		resp.Confidence = "medium"
		resp.DetectedProvider = "浏览器严格安全 DNS（与网关防泄漏规则冲突）"
		resp.Summary = "浏览器侧随机域名探测全部失败而网关侧解析正常，高度符合「浏览器开启国内安全 DNS / 自定义 DoH 被网关防泄漏规则拦截」导致的网页打不开特征。"
		resp.Recommendation = recommendation
	case cnLeakProvider != "" || mismatchProvider != "":
		resp.Status = "suspected"
		resp.Confidence = "medium"
		resp.DetectedProvider = cmp.Or(cnLeakProvider, mismatchProvider)
		resp.Summary = fmt.Sprintf(
			"检测到当前浏览器的 DNS 解析出口（%s）与路由器网关出口不一致，怀疑浏览器开启了安全 DNS（DoH）或本机单独固定了 DNS / 代理软件。",
			resp.DetectedProvider,
		)
		resp.Recommendation = recommendation
	case gwResolver == nil && len(browserResolvers) == 0 && clashErr != nil:
		resp.Status = "unavailable"
		resp.Confidence = "none"
		resp.Summary = "暂无法访问网关 Clash 连接表及外部 EDNS 探测节点，请确认 sing-box 正在运行且网络连通后重试。"
	default:
		resp.Status = "clean"
		resp.Confidence = "none"
		if idleLeftoverCount > 0 {
			resp.Summary = fmt.Sprintf(
				"未检测到当前浏览器使用自身安全 DNS（DoH），域名解析正正常经由路由器统一接管（已忽略 %d 条先前遗留的零流量空闲 DoH 长连接，无需等待浏览器回收连接池）。",
				idleLeftoverCount,
			)
		} else {
			resp.Summary = "未检测到当前浏览器绕过网关使用独立安全 DNS（DoH），域名解析正正常经由路由器统一接管。"
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
