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
