// 文件职责：负责 AdGuard Home 加密 DNS 上游预设目录、纯 IP 防死锁校验归一化以及在线/YAML 配置读写同步。
package adguard

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
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
	"223.5.5.5":    {},
	"223.6.6.6":    {},
	"1.12.12.12":   {},
	"120.53.53.53": {},
}

var validIPv4LiteralRe = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)

// DefaultUpstreams 返回网关默认推荐的纯 IP DoQ (QUIC) + DoH 黄金组合加密上游列表。
func DefaultUpstreams() []string {
	return []string{
		"quic://223.5.5.5:853",
		"quic://223.6.6.6:853",
		"https://223.5.5.5/dns-query",
		"https://223.6.6.6/dns-query",
		"https://1.12.12.12/dns-query",
	}
}

// CuratedUpstreamPresets 返回国内宽带实测具备合法 IP SAN 证书的纯 IP 加密 DNS 预设列表。
func CuratedUpstreamPresets() []UpstreamPreset {
	return []UpstreamPreset{
		{
			Address:     "quic://223.5.5.5:853",
			Name:        "阿里云公共 DNS · 主 DoQ",
			Protocol:    "DoQ",
			Recommended: true,
		},
		{
			Address:     "quic://223.6.6.6:853",
			Name:        "阿里云公共 DNS · 备 DoQ",
			Protocol:    "DoQ",
			Recommended: true,
		},
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
			Recommended: false,
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
			Recommended: false,
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
	case strings.HasPrefix(lower, "h3://"):
		proto = "DoH3"
	case strings.HasPrefix(lower, "tls://"):
		proto = "DoT"
	case strings.HasPrefix(lower, "quic://"):
		proto = "DoQ"
	case strings.HasPrefix(lower, "udp://"):
		proto = "Gateway"
	}

	u, err := url.Parse(clean)
	host := ""
	if err == nil {
		host = u.Hostname()
	}
	if proto == "Gateway" {
		return UpstreamServerInfo{
			Address:  clean,
			Name:     "上级主路由网关 DNS",
			Protocol: "Gateway",
		}
	}
	provider := "自定义加密上游"
	hostLower := strings.ToLower(strings.TrimSuffix(host, "."))
	switch {
	case hostLower == "223.5.5.5" || hostLower == "223.6.6.6" || hostLower == "dns.alidns.com" || strings.HasSuffix(hostLower, ".alidns.com"):
		provider = "阿里云公共 DNS"
	case hostLower == "1.12.12.12" || hostLower == "120.53.53.53" || hostLower == "doh.pub" || hostLower == "dot.pub":
		provider = "腾讯云 DNSPod"
	case hostLower == "onedns.net" || strings.HasSuffix(hostLower, ".onedns.net"):
		provider = "OneDNS"
	case hostLower == "360.cn" || strings.HasSuffix(hostLower, ".360.cn"):
		provider = "360 安全 DNS"
	case hostLower == "1.1.1.1" || hostLower == "1.0.0.1" || hostLower == "one.one.one.one" || hostLower == "cloudflare-dns.com" || strings.HasSuffix(hostLower, ".cloudflare-dns.com"):
		provider = "Cloudflare DNS"
	case hostLower == "8.8.8.8" || hostLower == "8.8.4.4" || hostLower == "dns.google":
		provider = "Google DNS"
	case hostLower == "9.9.9.9" || hostLower == "149.112.112.112" || hostLower == "quad9.net" || strings.HasSuffix(hostLower, ".quad9.net"):
		provider = "Quad9 DNS"
	}

	return UpstreamServerInfo{
		Address:  clean,
		Name:     fmt.Sprintf("%s · %s", provider, proto),
		Protocol: proto,
	}
}

var disallowedLocalDomainSuffixes = []string{
	".local",
	".localhost",
	".lan",
	".home.arpa",
	".internal",
	".arpa",
}

func containsControlOrWhitespace(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// ValidateUpstreamDomain 校验加密 DNS 上游使用的公网 FQDN 域名，严禁单标签、本地域名、纯数字 TLD 与注入字符。
func ValidateUpstreamDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if d == "" || len(d) > 253 {
		return "", fmt.Errorf("上游域名 %q 长度无效", raw)
	}
	if !strings.Contains(d, ".") {
		return "", fmt.Errorf("上游域名 %q 必须是完整的公网域名（不支持本机或单标签主机名）", raw)
	}
	for _, suffix := range disallowedLocalDomainSuffixes {
		if strings.HasSuffix(d, suffix) {
			return "", fmt.Errorf("禁止将局域网或本地域名 (%s) 设为加密上游，避免 DNS 回环死锁", d)
		}
	}
	labels := strings.Split(d, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("上游域名 %q 包含非法标签", raw)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("上游域名 %q 标签首尾不能为连字符", raw)
		}
		for i := range len(label) {
			ch := label[i]
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return "", fmt.Errorf("上游域名 %q 包含非法字符 %q", raw, ch)
			}
		}
	}
	tld := labels[len(labels)-1]
	allDigits := true
	for i := range len(tld) {
		if tld[i] < '0' || tld[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", fmt.Errorf("上游主机 %q 不是有效的公网 IP 或域名", raw)
	}
	return d, nil
}

// IsPureIPUpstream 判断单条加密上游的主机部分是否为纯 IP 字面量（无需引导解析）。
func IsPureIPUpstream(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	return net.ParseIP(strings.TrimSpace(u.Hostname())) != nil
}

// ValidatePureIPFallbackInvariant 守卫上游防死锁底线：当列表中包含域名型上游时，至少须保留 1 条纯 IP 加密上游兜底。
func ValidatePureIPFallbackInvariant(upstreams []string) error {
	if len(upstreams) == 0 {
		return errors.New("至少需要保留 1 条加密上游 DNS 服务器")
	}
	for _, raw := range upstreams {
		if IsPureIPUpstream(raw) {
			return nil
		}
	}
	return errors.New("为防止软路由冷启动 DNS 引导死锁，使用域名上游时列表中至少须保留 1 条纯 IP 加密上游（如 https://223.5.5.5/dns-query）")
}

// SameUpstreamSet 判断两组加密上游列表（忽略大小写与首尾空白）是否包含完全相同的地址集合。
func SameUpstreamSet(a, b []string) bool {
	setA := make(map[string]struct{}, len(a))
	for _, item := range a {
		if k := strings.ToLower(strings.TrimSpace(item)); k != "" {
			setA[k] = struct{}{}
		}
	}
	setB := make(map[string]struct{}, len(b))
	for _, item := range b {
		if k := strings.ToLower(strings.TrimSpace(item)); k != "" {
			setB[k] = struct{}{}
		}
	}
	if len(setA) != len(setB) {
		return false
	}
	for k := range setA {
		if _, ok := setB[k]; !ok {
			return false
		}
	}
	return true
}

// NormalizeAndValidateUpstream 校验并归一化单条加密上游 DNS 地址（支持纯 IP 与合法公网 FQDN 域名，原样保留域名不强转 IP）。
// 若主机为纯 IP，返回非空 ipLiteral；若为域名上游，返回 ipLiteral=""。
func NormalizeAndValidateUpstream(raw string) (normalized string, ipLiteral string, convertedNote string, err error) {
	if containsControlOrWhitespace(strings.TrimSpace(raw)) {
		return "", "", "", fmt.Errorf("上游地址 %q 包含非法空白或控制字符", raw)
	}
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", "", errors.New("上游地址不能为空")
	}
	if strings.ContainsAny(s, ";#`'\"\\") {
		return "", "", "", fmt.Errorf("上游地址 %q 包含非法字符", s)
	}
	if !strings.Contains(s, "://") {
		if ip := net.ParseIP(strings.Split(s, ":")[0]); ip != nil {
			return "", "", "", fmt.Errorf("不支持明文 DNS (%s)，请改用加密格式如 https://%s/dns-query 或 tls://%s", s, ip.String(), ip.String())
		}
		if cleanDom, domErr := ValidateUpstreamDomain(s); domErr == nil {
			return "", "", "", fmt.Errorf("上游地址 %q 缺少加密协议前缀，请改用如 tls://%s 或 https://%s/dns-query", s, cleanDom, cleanDom)
		}
		return "", "", "", fmt.Errorf("上游地址 %q 缺少加密协议前缀（请使用 https:// 或 tls://）", s)
	}

	u, parseErr := url.Parse(s)
	if parseErr != nil || u.Host == "" {
		return "", "", "", fmt.Errorf("上游地址 %q 格式无效", s)
	}
	if u.User != nil || u.Fragment != "" {
		return "", "", "", fmt.Errorf("上游地址 %q 不允许包含认证信息或锚点片段", s)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https", "tls", "quic", "h3":
	default:
		return "", "", "", fmt.Errorf("仅支持 https:// (DoH)、tls:// (DoT)、quic:// (DoQ) 或 h3:// (DoH3) 加密上游（当前: %s://）", scheme)
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
	if scheme == "quic" && port == "" {
		port = "853"
	}

	var hostWithPort string
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return "", "", "", fmt.Errorf("禁止将本机回环或保留地址 (%s) 设为上游，否则会造成 DNS 自环死锁", ip.String())
		}
		if ip.IsPrivate() {
			return "", "", "", fmt.Errorf("禁止将局域网私网地址 (%s) 设为防劫持加密上游，请使用公网加密 DoH/DoT", ip.String())
		}
		ipLiteral = ip.String()
		hostWithPort = ip.String()
		if ip.To4() == nil {
			hostWithPort = "[" + ip.String() + "]"
		}
		if port != "" {
			hostWithPort = net.JoinHostPort(ip.String(), port)
		}
	} else {
		cleanDomain, domErr := ValidateUpstreamDomain(host)
		if domErr != nil {
			return "", "", "", domErr
		}
		hostWithPort = cleanDomain
		if port != "" {
			hostWithPort = net.JoinHostPort(cleanDomain, port)
		}
	}

	switch scheme {
	case "https", "h3":
		path := u.EscapedPath()
		if path == "" || path == "/" {
			path = "/dns-query"
		}
		normalized = scheme + "://" + hostWithPort + path
		if u.RawQuery != "" {
			normalized += "?" + u.RawQuery
		}
	case "quic":
		normalized = "quic://" + hostWithPort
	default:
		normalized = "tls://" + hostWithPort
	}

	return normalized, ipLiteral, convertedNote, nil
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
	var duplicates []string
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
			duplicates = append(duplicates, norm)
			continue
		}
		seen[key] = struct{}{}
		cleaned = append(cleaned, norm)
		if ipStr != "" {
			ips = append(ips, ipStr)
		}
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
	if err := ValidatePureIPFallbackInvariant(cleaned); err != nil {
		return nil, mode, nil, err
	}

	prevSet := make(map[string]struct{})
	var prevList []string
	prevMode := ""
	if !skipProbe {
		prevList, prevMode = m.GetConfiguredUpstreams(ctx)
		for _, prev := range prevList {
			prevSet[strings.ToLower(strings.TrimSpace(prev))] = struct{}{}
		}
		if len(duplicates) > 0 && mode == prevMode && SameUpstreamSet(cleaned, prevList) {
			return nil, mode, nil, fmt.Errorf("上游 %s 已在当前列表中，无需重复添加", strings.Join(duplicates, "、"))
		}
	}
	if len(duplicates) > 0 {
		notes = append(notes, fmt.Sprintf("已自动跳过重复上游（%s）", strings.Join(duplicates, "、")))
	}

	bypassIPs := ips
	if !skipProbe || m.lookupIPFn != nil {
		bypassIPs = ResolveUpstreamBypassIPs(ctx, cleaned, m.lookupIPFn)
	}
	if m.bypassFirewallFn != nil {
		m.bypassFirewallFn(bypassIPs)
	} else {
		EnsureRuntimeFirewallBypass(bypassIPs)
	}

	if !skipProbe {
		probeTargets := make([]string, 0, len(cleaned))
		for _, addr := range cleaned {
			lower := strings.ToLower(addr)
			if strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "tls://") {
				probeTargets = append(probeTargets, addr)
			} else if _, existed := prevSet[lower]; !existed {
				notes = append(notes, fmt.Sprintf("%s 已交由引擎接管（跳过直连探测）", addr))
			}
		}
		if len(probeTargets) > 0 {
			probeFn := m.probeUpstreamListFn
			if probeFn == nil {
				probeFn = ProbeUpstreamList
			}
			items := probeFn(ctx, probeTargets, "qq.com", 2800*time.Millisecond)
			anyHealthy := false
			var firstErr string
			for _, it := range items {
				key := strings.ToLower(strings.TrimSpace(it.Address))
				if _, existed := prevSet[key]; !existed && len(prevSet) > 0 && !it.Healthy {
					return nil, mode, nil, fmt.Errorf("新增上游 %s 探测失败，已拦截添加：%s", it.Address, cmp.Or(it.Error, "连接超时"))
				}
				if it.Healthy {
					anyHealthy = true
				} else if firstErr == "" && it.Error != "" {
					firstErr = fmt.Sprintf("%s (%s)", it.Address, it.Error)
				}
			}
			if !anyHealthy {
				return nil, mode, nil, fmt.Errorf("所选上游均无法完成加密解析验证，已拦截保存以防断网：%s", cmp.Or(firstErr, "连接超时"))
			}
		}
	}

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
