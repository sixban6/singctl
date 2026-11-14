package adguard

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// UpstreamPreset 描述经过网关防回环与 IP 证书实测的加密 DNS 上游预设。
type UpstreamPreset struct {
	Address     string `json:"address"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Recommended bool   `json:"recommended"`
}

// UpstreamServerInfo 描述一条当前生效的上游 DNS 服务器及其识别元信息。
type UpstreamServerInfo struct {
	Address  string `json:"address"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

// UpstreamProbeItem 描述单条加密上游 DNS 的真实并发探测结果。
type UpstreamProbeItem struct {
	Address   string `json:"address"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Healthy   bool   `json:"healthy"`
	LatencyMs int64  `json:"latencyMs"`
	Resolved  string `json:"resolved,omitempty"`
	Fastest   bool   `json:"fastest,omitempty"`
	Error     string `json:"error,omitempty"`
}

// ProbeReport 汇总本地引擎端到端解析与全部加密上游逐条竞速实测结果。
type ProbeReport struct {
	Healthy           bool                `json:"healthy"`
	DNSAddr           string              `json:"dnsAddr"`
	Domain            string              `json:"domain"`
	Resolved          string              `json:"resolved,omitempty"`
	LatencyMs         int64               `json:"latencyMs"`
	UpstreamMode      string              `json:"upstreamMode"`
	UpstreamModeLabel string              `json:"upstreamModeLabel"`
	FastestUpstream   string              `json:"fastestUpstream,omitempty"`
	FastestName       string              `json:"fastestName,omitempty"`
	FastestLatencyMs  int64               `json:"fastestLatencyMs,omitempty"`
	Upstreams         []UpstreamProbeItem `json:"upstreams"`
	Error             string              `json:"error,omitempty"`
}

var builtinBypassIPv4Set = map[string]struct{}{
	"223.5.5.5":     {},
	"223.6.6.6":     {},
	"1.12.12.12":    {},
	"120.53.53.53":  {},
}

var validIPv4LiteralRe = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)

// DefaultUpstreams 返回网关默认推荐的纯 IP 加密 DoH/DoT 上游列表。
func DefaultUpstreams() []string {
	return []string{
		"https://223.5.5.5/dns-query",
		"https://223.6.6.6/dns-query",
		"https://1.12.12.12/dns-query",
		"tls://223.5.5.5",
		"tls://1.12.12.12",
	}
}

// CuratedUpstreamPresets 返回国内宽带实测具备合法 IP SAN 证书的纯 IP 加密 DNS 预设列表。
func CuratedUpstreamPresets() []UpstreamPreset {
	return []UpstreamPreset{
		{
			Address:     "https://223.5.5.5/dns-query",
			Name:        "阿里云公共 DNS · 主 DoH",
			Protocol:    "DoH",
			Recommended: true,
		},
		{
			Address:     "https://223.6.6.6/dns-query",
			Name:        "阿里云公共 DNS · 备 DoH",
			Protocol:    "DoH",
			Recommended: true,
		},
		{
			Address:     "https://1.12.12.12/dns-query",
			Name:        "腾讯云 DNSPod · 主 DoH",
			Protocol:    "DoH",
			Recommended: true,
		},
		{
			Address:     "https://120.53.53.53/dns-query",
			Name:        "腾讯云 DNSPod · 备 DoH",
			Protocol:    "DoH",
			Recommended: false,
		},
		{
			Address:     "tls://223.5.5.5",
			Name:        "阿里云公共 DNS · 主 DoT",
			Protocol:    "DoT",
			Recommended: true,
		},
		{
			Address:     "tls://223.6.6.6",
			Name:        "阿里云公共 DNS · 备 DoT",
			Protocol:    "DoT",
			Recommended: false,
		},
		{
			Address:     "tls://1.12.12.12",
			Name:        "腾讯云 DNSPod · 主 DoT",
			Protocol:    "DoT",
			Recommended: true,
		},
		{
			Address:     "tls://120.53.53.53",
			Name:        "腾讯云 DNSPod · 备 DoT",
			Protocol:    "DoT",
			Recommended: false,
		},
	}
}

// UpstreamModeDescription 返回上游查询策略模式的中文可读说明。
func UpstreamModeDescription(mode string) string {
	switch NormalizeUpstreamMode(mode) {
	case "fastest_addr":
		return "最快 IP 优选（并发查询并探测优选延迟最低的目标 IP）"
	case "load_balance":
		return "负载均衡（按权重在多条加密上游之间动态分摊查询）"
	default:
		return "并行竞速（同时请求全部加密上游，每次自动采用最快返回的结果）"
	}
}

// NormalizeUpstreamMode 归一化 AdGuard Home 上游调度策略。
func NormalizeUpstreamMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "fastest_addr":
		return "fastest_addr"
	case "load_balance", "":
		if strings.TrimSpace(raw) == "" {
			return "parallel"
		}
		return "load_balance"
	case "parallel":
		return "parallel"
	default:
		return "parallel"
	}
}

// DescribeUpstream 识别上游 DNS 的服务商名称与加密协议类型。
func DescribeUpstream(addr string) UpstreamServerInfo {
	clean := strings.TrimSpace(addr)
	for _, p := range CuratedUpstreamPresets() {
		if strings.EqualFold(p.Address, clean) {
			return UpstreamServerInfo{
				Address:  p.Address,
				Name:     p.Name,
				Protocol: p.Protocol,
			}
		}
	}

	proto := "DNS"
	lower := strings.ToLower(clean)
	switch {
	case strings.HasPrefix(lower, "https://"):
		proto = "DoH"
	case strings.HasPrefix(lower, "tls://"):
		proto = "DoT"
	case strings.HasPrefix(lower, "quic://"):
		proto = "DoQ"
	}

	u, err := url.Parse(clean)
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	provider := "自定义加密上游"
	switch host {
	case "223.5.5.5", "223.6.6.6", "dns.alidns.com":
		provider = "阿里云公共 DNS"
	case "1.12.12.12", "120.53.53.53", "doh.pub", "dot.pub":
		provider = "腾讯云 DNSPod"
	case "1.1.1.1", "1.0.0.1":
		provider = "Cloudflare DNS"
	case "8.8.8.8", "8.8.4.4":
		provider = "Google DNS"
	case "9.9.9.9", "149.112.112.112":
		provider = "Quad9 DNS"
	}

	return UpstreamServerInfo{
		Address:  clean,
		Name:     fmt.Sprintf("%s · %s", provider, proto),
		Protocol: proto,
	}
}

var knownDomainToPureIP = map[string]string{
	"dns.alidns.com": "223.5.5.5",
	"alidns.com":     "223.5.5.5",
	"doh.pub":        "1.12.12.12",
	"dot.pub":        "1.12.12.12",
}

// NormalizeAndValidateUpstream 校验并归一化单条上游 DNS 地址。
// 为彻底避免透明代理网关 TProxy :53 引导死锁与运营商明文抢答，强制要求纯 IP 的 https:// (DoH) 或 tls:// (DoT)。
func NormalizeAndValidateUpstream(raw string) (normalized string, ipLiteral string, convertedNote string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", "", errors.New("上游地址不能为空")
	}
	if !strings.Contains(s, "://") {
		if ip := net.ParseIP(strings.Split(s, ":")[0]); ip != nil {
			return "", "", "", fmt.Errorf("不支持明文 DNS (%s)，请改用加密格式如 https://%s/dns-query 或 tls://%s", s, ip.String(), ip.String())
		}
		return "", "", "", fmt.Errorf("上游地址 %q 缺少加密协议前缀（请使用 https://<IP>/dns-query 或 tls://<IP>）", s)
	}

	u, parseErr := url.Parse(s)
	if parseErr != nil || u.Host == "" {
		return "", "", "", fmt.Errorf("上游地址 %q 格式无效", s)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "tls" {
		return "", "", "", fmt.Errorf("仅支持纯 IP 的 https:// (DoH) 或 tls:// (DoT) 加密上游（当前: %s://）", scheme)
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	port := u.Port()
	if port != "" {
		pNum, pErr := strconv.Atoi(port)
		if pErr != nil || pNum <= 0 || pNum > 65535 {
			return "", "", "", fmt.Errorf("上游端口 %q 不合法", port)
		}
		if pNum == 53 {
			return "", "", "", errors.New("禁止使用 53 明文端口作为上游，避免透明代理网关回环死锁")
		}
	}

	if mappedIP, ok := knownDomainToPureIP[host]; ok {
		convertedNote = fmt.Sprintf("%s 已自动转换为防死锁纯 IP (%s)", host, mappedIP)
		host = mappedIP
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "", "", "", fmt.Errorf("为防止网关冷启动时触发 53 端口引导死锁，请填写纯 IP 加密上游（如 https://223.5.5.5/dns-query，而非域名 %s）", host)
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return "", "", "", fmt.Errorf("禁止将本机回环或保留地址 (%s) 设为上游，否则会造成 DNS 自环死锁", ip.String())
	}
	if ip.IsPrivate() {
		return "", "", "", fmt.Errorf("禁止将局域网私网地址 (%s) 设为防劫持加密上游，请使用公网纯 IP DoH/DoT", ip.String())
	}

	hostWithPort := ip.String()
	if ip.To4() == nil {
		hostWithPort = "[" + ip.String() + "]"
	}
	if port != "" {
		hostWithPort = net.JoinHostPort(ip.String(), port)
	}

	if scheme == "https" {
		path := u.EscapedPath()
		if path == "" || path == "/" {
			path = "/dns-query"
		}
		normalized = "https://" + hostWithPort + path
		if u.RawQuery != "" {
			normalized += "?" + u.RawQuery
		}
	} else {
		normalized = "tls://" + hostWithPort
	}

	return normalized, ip.String(), convertedNote, nil
}

// GetConfiguredUpstreams 读取当前生效的加密上游列表与查询策略（优先读取在线 API，回退读取 AdGuardHome.yaml）。
func (m *Manager) GetConfiguredUpstreams(ctx context.Context) ([]string, string) {
	if st := m.Status(); st.WebHealthy && st.Password != "" {
		var dnsInfo struct {
			UpstreamDNS  []string `json:"upstream_dns"`
			UpstreamMode string   `json:"upstream_mode"`
		}
		if _, err := m.controlRequest(ctx, http.MethodGet, "/control/dns_info", nil, &dnsInfo); err == nil {
			cleaned := filterNonCommentUpstreams(dnsInfo.UpstreamDNS)
			if len(cleaned) > 0 {
				return cleaned, NormalizeUpstreamMode(dnsInfo.UpstreamMode)
			}
		}
	}

	if list, mode := readUpstreamsFromYAML(m.aghConfigFile); len(list) > 0 {
		return list, mode
	}
	return DefaultUpstreams(), "parallel"
}

func filterNonCommentUpstreams(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func readUpstreamsFromYAML(configPath string) ([]string, string) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, "parallel"
	}
	var doc struct {
		DNS struct {
			UpstreamDNS  []string `yaml:"upstream_dns"`
			UpstreamMode string   `yaml:"upstream_mode"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return nil, "parallel"
	}
	return filterNonCommentUpstreams(doc.DNS.UpstreamDNS), NormalizeUpstreamMode(doc.DNS.UpstreamMode)
}

// SetDNSUpstreams 校验、探测并零中断热更新 AdGuard Home 加密上游 DNS 与调度策略。
func (m *Manager) SetDNSUpstreams(ctx context.Context, rawUpstreams []string, rawMode string, skipProbe bool) ([]UpstreamServerInfo, string, []string, error) {
	mode := NormalizeUpstreamMode(rawMode)
	if len(rawUpstreams) == 0 {
		return nil, mode, nil, errors.New("至少需要保留 1 条加密上游 DNS 服务器")
	}

	seen := make(map[string]struct{}, len(rawUpstreams))
	cleaned := make([]string, 0, len(rawUpstreams))
	ips := make([]string, 0, len(rawUpstreams))
	var notes []string

	for _, item := range rawUpstreams {
		if strings.TrimSpace(item) == "" {
			continue
		}
		norm, ipStr, note, err := NormalizeAndValidateUpstream(item)
		if err != nil {
			return nil, mode, nil, err
		}
		key := strings.ToLower(norm)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, norm)
		ips = append(ips, ipStr)
		if note != "" {
			notes = append(notes, note)
		}
	}

	if len(cleaned) == 0 {
		return nil, mode, nil, errors.New("至少需要保留 1 条有效的加密上游 DNS 服务器")
	}
	if len(cleaned) > 12 {
		return nil, mode, nil, errors.New("上游 DNS 服务器数量请勿超过 12 条")
	}

	// 保存前先为新增的纯 IPv4 注入透明代理防火墙直连豁免，防止实测与热切后在 Global 模式下回环
	ensureRuntimeFirewallBypass(ips)

	if !skipProbe {
		items := ProbeUpstreamList(ctx, cleaned, "qq.com", 2800*time.Millisecond)
		anyHealthy := false
		var firstErr string
		for _, it := range items {
			if it.Healthy {
				anyHealthy = true
				break
			}
			if firstErr == "" && it.Error != "" {
				firstErr = fmt.Sprintf("%s (%s)", it.Address, it.Error)
			}
		}
		if !anyHealthy {
			return nil, mode, nil, fmt.Errorf("所选上游均无法完成加密解析验证，已拦截保存以防断网：%s", cmp.Or(firstErr, "连接超时"))
		}
	}

	// 1. 若 AdGuard Web Control API 在线，优先热更新内存配置（0ms 零重启生效）
	apiUpdated := false
	if st := m.Status(); st.WebHealthy && st.Password != "" {
		payload := map[string]any{
			"upstream_dns":  cleaned,
			"upstream_mode": mode,
		}
		if _, err := m.controlRequest(ctx, http.MethodPost, "/control/dns_config", payload, nil); err == nil {
			apiUpdated = true
		} else {
			return nil, mode, nil, fmt.Errorf("热更新 AdGuard 上游配置失败: %w", err)
		}
	}

	// 2. 同步持久化至磁盘 AdGuardHome.yaml (0600 原子写入)，确保服务重启或系统重启后配置不丢失
	if _, statErr := os.Stat(m.aghConfigFile); statErr == nil {
		if yamlErr := writeUpstreamsToYAML(m.aghConfigFile, cleaned, mode); yamlErr != nil && !apiUpdated {
			return nil, mode, nil, fmt.Errorf("写入 AdGuardHome.yaml 失败: %w", yamlErr)
		}
	}

	infos := make([]UpstreamServerInfo, 0, len(cleaned))
	for _, u := range cleaned {
		infos = append(infos, DescribeUpstream(u))
	}
	return infos, mode, notes, nil
}

func writeUpstreamsToYAML(configPath string, upstreams []string, mode string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return err
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return errors.New("invalid AdGuardHome.yaml")
	}
	dnsMap := ensureYAMLSubMap(root.Content[0], "dns")
	changedUp := setYAMLStringSlice(dnsMap, "upstream_dns", upstreams)
	changedMode := setYAMLScalar(dnsMap, "upstream_mode", mode, "!!str")
	if !changedUp && !changedMode {
		return nil
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	return WriteConfigAtomically(configPath, out)
}

// ProbeAllUpstreams 并发实测本地防劫持引擎端到端延迟及每条已配置加密上游的独立响应耗时，自动标记最快上游。
func (m *Manager) ProbeAllUpstreams(ctx context.Context, domain string) *ProbeReport {
	targetDomain := cmp.Or(strings.TrimSpace(domain), "qq.com")
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	upstreams, mode := m.GetConfiguredUpstreams(ctx)

	report := &ProbeReport{
		DNSAddr:           dnsAddr,
		Domain:            targetDomain,
		UpstreamMode:      mode,
		UpstreamModeLabel: UpstreamModeDescription(mode),
		Upstreams:         []UpstreamProbeItem{},
	}

	var (
		wg        sync.WaitGroup
		localErr  error
		localIPs  []string
		localCost time.Duration
		items     []UpstreamProbeItem
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := ProbeDNS(dnsAddr, 1200*time.Millisecond); err != nil {
			localErr = fmt.Errorf("本地引擎 %s 未响应: %v", dnsAddr, err)
			return
		}
		localIPs, localCost, localErr = ProbeUpstreamResolution(dnsAddr, targetDomain, 3500*time.Millisecond)
	}()

	go func() {
		defer wg.Done()
		items = ProbeUpstreamList(ctx, upstreams, targetDomain, 3200*time.Millisecond)
	}()
	wg.Wait()

	// 标记最快健康上游
	bestIdx := -1
	for i := range items {
		if !items[i].Healthy {
			continue
		}
		if bestIdx == -1 || items[i].LatencyMs < items[bestIdx].LatencyMs {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		items[bestIdx].Fastest = true
		report.FastestUpstream = items[bestIdx].Address
		report.FastestName = items[bestIdx].Name
		report.FastestLatencyMs = items[bestIdx].LatencyMs
	}
	report.Upstreams = items

	if localErr != nil || len(localIPs) == 0 {
		report.Healthy = false
		if localErr != nil {
			report.Error = localErr.Error()
		} else {
			report.Error = "本地引擎未返回有效解析记录"
		}
		return report
	}

	report.Healthy = true
	report.Resolved = localIPs[0]
	report.LatencyMs = max(int64(1), localCost.Milliseconds())
	return report
}

// ProbeUpstreamList 并发直连实测一组 DoH / DoT 上游服务器的真实加密解析 RTT（绕过本地缓存）。
func ProbeUpstreamList(ctx context.Context, upstreams []string, domain string, timeout time.Duration) []UpstreamProbeItem {
	if len(upstreams) == 0 {
		return []UpstreamProbeItem{}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	out := make([]UpstreamProbeItem, len(upstreams))
	var wg sync.WaitGroup
	for i, raw := range upstreams {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			out[idx] = ProbeSingleUpstream(ctx, addr, domain, timeout)
		}(i, raw)
	}
	wg.Wait()
	return out
}

// ProbeSingleUpstream 对单条加密上游 (https:// DoH 或 tls:// DoT) 执行标准 RFC 1035 Wireformat 查询并精确计时。
func ProbeSingleUpstream(ctx context.Context, upstream, domain string, timeout time.Duration) UpstreamProbeItem {
	meta := DescribeUpstream(upstream)
	item := UpstreamProbeItem{
		Address:  meta.Address,
		Name:     meta.Name,
		Protocol: meta.Protocol,
	}

	queryWire, txid, err := buildDNSQueryPacket(domain)
	if err != nil {
		item.Error = err.Error()
		return item
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u, parseErr := url.Parse(strings.TrimSpace(upstream))
	if parseErr != nil || u.Host == "" {
		item.Error = "无效的上游 URL"
		return item
	}

	start := time.Now()
	var respWire []byte

	switch strings.ToLower(u.Scheme) {
	case "https":
		respWire, err = queryDoHWireformat(probeCtx, strings.TrimSpace(upstream), queryWire, timeout)
	case "tls":
		respWire, err = queryDoTWireformat(probeCtx, u, queryWire, timeout)
	default:
		err = fmt.Errorf("暂不支持直接探测协议 %s", u.Scheme)
	}
	elapsed := time.Since(start)

	if err != nil {
		item.Error = simplifyProbeError(err)
		return item
	}

	resolvedIP, parseRespErr := parseDNSFirstARecord(respWire, txid)
	if parseRespErr != nil {
		item.Error = parseRespErr.Error()
		return item
	}

	item.Healthy = true
	item.LatencyMs = max(int64(1), elapsed.Milliseconds())
	item.Resolved = resolvedIP
	return item
}

func queryDoHWireformat(ctx context.Context, endpoint string, query []byte, timeout time.Duration) ([]byte, error) {
	tr := &http.Transport{
		Proxy:             nil, // 强制直连测试上游本身，不经过环境变量 HTTP_PROXY
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func queryDoTWireformat(ctx context.Context, u *url.URL, query []byte, timeout time.Duration) ([]byte, error) {
	host := u.Hostname()
	port := cmp.Or(u.Port(), "853")
	addr := net.JoinHostPort(host, port)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	// RFC 7858: TCP/TLS DNS 消息带 2 字节大端长度前缀
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DoT response length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func buildDNSQueryPacket(domain string) ([]byte, [2]byte, error) {
	var txid [2]byte
	_, _ = rand.Read(txid[:])

	clean := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if clean == "" {
		return nil, txid, errors.New("探测域名不能为空")
	}

	var buf bytes.Buffer
	buf.Write(txid[:])
	buf.Write([]byte{
		0x01, 0x00, // Standard query, RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	})
	for label := range strings.SplitSeq(clean, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, txid, fmt.Errorf("invalid domain label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE=A, QCLASS=IN
	return buf.Bytes(), txid, nil
}

func parseDNSFirstARecord(msg []byte, expectedTxID [2]byte) (string, error) {
	if len(msg) < 12 {
		return "", errors.New("DNS 响应报文过短")
	}
	if msg[0] != expectedTxID[0] || msg[1] != expectedTxID[1] {
		return "", errors.New("DNS 事务 ID 不匹配")
	}
	rcode := msg[3] & 0x0F
	if rcode != 0 {
		return "", fmt.Errorf("DNS 响应错误码 RCODE=%d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return "", errors.New("未返回任何解析记录")
	}

	offset := 12
	for range qdCount {
		next, err := skipDNSName(msg, offset)
		if err != nil {
			return "", err
		}
		if next+4 > len(msg) {
			return "", errors.New("DNS Question 字段截断")
		}
		offset = next + 4
	}

	var firstCNAME bool
	for range anCount {
		next, err := skipDNSName(msg, offset)
		if err != nil {
			return "", err
		}
		if next+10 > len(msg) {
			return "", errors.New("DNS Answer 头部截断")
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(msg) {
			return "", errors.New("DNS Answer 数据截断")
		}
		if rrType == 1 && rdLen == 4 { // Type A
			ip := net.IPv4(msg[rdataStart], msg[rdataStart+1], msg[rdataStart+2], msg[rdataStart+3])
			return ip.String(), nil
		}
		if rrType == 5 {
			firstCNAME = true
		}
		offset = rdataStart + rdLen
	}
	if firstCNAME {
		return "CNAME", nil
	}
	return "", errors.New("响应中未包含 IPv4 A 记录")
}

func skipDNSName(msg []byte, offset int) (int, error) {
	cur := offset
	for range 128 {
		if cur >= len(msg) {
			return 0, errors.New("DNS 域名越界")
		}
		b := msg[cur]
		if b == 0 {
			return cur + 1, nil
		}
		// 压缩指针 11xxxxxx
		if b&0xC0 == 0xC0 {
			if cur+1 >= len(msg) {
				return 0, errors.New("DNS 压缩指针截断")
			}
			return cur + 2, nil
		}
		cur += 1 + int(b)
	}
	return 0, errors.New("DNS 域名层级过深")
}

func simplifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "i/o timeout"):
		return "连接超时"
	case strings.Contains(s, "x509:"):
		return "TLS 证书不含该纯 IP 签名"
	case strings.Contains(s, "connection refused"):
		return "目标端口拒绝连接"
	default:
		return s
	}
}

// ensureRuntimeFirewallBypass 在 Linux 透明代理网关运行期间，为新增的自定义纯 IPv4 加密上游动态补齐 output 直连豁免，
// 避免用户在未重启 sing-box 的情况下添加新上游并在 Global 模式下发生死锁。
func ensureRuntimeFirewallBypass(ips []string) {
	if runtime.GOOS != "linux" {
		return
	}
	var customIPv4s []string
	for _, raw := range ips {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil {
			continue
		}
		v4 := ip.To4().String()
		if !validIPv4LiteralRe.MatchString(v4) {
			continue
		}
		if _, builtin := builtinBypassIPv4Set[v4]; builtin {
			continue
		}
		if !slices.Contains(customIPv4s, v4) {
			customIPv4s = append(customIPv4s, v4)
		}
	}
	if len(customIPv4s) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 1. nftables: 若存在 inet sing-box output 链且尚未包含该 IP，则在链首插入直连放行规则
	if nftPath, err := exec.LookPath("nft"); err == nil {
		out, listErr := exec.CommandContext(ctx, nftPath, "list", "chain", "inet", "sing-box", "output").Output()
		if listErr == nil {
			existingRules := string(out)
			for _, v4 := range customIPv4s {
				if strings.Contains(existingRules, v4) {
					continue
				}
				_ = exec.CommandContext(ctx, nftPath, "insert", "rule", "inet", "sing-box", "output",
					"ip", "daddr", v4, "tcp", "dport", "{", "443,", "853", "}", "accept").Run()
			}
			return
		}
	}

	// 2. iptables 兼容兜底 (Debian SINGBOX_OUTPUT 或 OpenWrt OUTPUT)
	if iptPath, err := exec.LookPath("iptables"); err == nil {
		targetChain := ""
		if exec.CommandContext(ctx, iptPath, "-t", "mangle", "-L", "SINGBOX_OUTPUT", "-n").Run() == nil {
			targetChain = "SINGBOX_OUTPUT"
		} else if exec.CommandContext(ctx, iptPath, "-t", "mangle", "-L", "SING_BOX", "-n").Run() == nil {
			targetChain = "OUTPUT"
		}
		if targetChain != "" {
			for _, v4 := range customIPv4s {
				for _, port := range []string{"443", "853"} {
					if exec.CommandContext(ctx, iptPath, "-t", "mangle", "-C", targetChain, "-d", v4, "-p", "tcp", "--dport", port, "-j", "RETURN").Run() != nil {
						_ = exec.CommandContext(ctx, iptPath, "-t", "mangle", "-I", targetChain, "1", "-d", v4, "-p", "tcp", "--dport", port, "-j", "RETURN").Run()
					}
				}
			}
		}
	}
}
