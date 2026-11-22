// 文件职责：负责 SmartDNS 零污染隔离主配置生成、加密上游指令校验格式化与 0600 原子落盘。
package smartdns

import (
	"cmp"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"singctl/internal/common/fsx"
)

// DefaultUpstreams 返回网关默认推荐的纯 IP 加密 DoH/DoT 上游列表（与 TProxy 放行清单一致）。
func DefaultUpstreams() []string {
	return []string{
		"https://223.5.5.5/dns-query",
		"https://1.12.12.12/dns-query",
		"tls://223.6.6.6:853",
		"tls://120.53.53.53:853",
	}
}

// NormalizeUpstreamMode 归一化 SmartDNS 上游测速与调度策略（fastest_ip / parallel / load_balance）。
func NormalizeUpstreamMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "parallel":
		return "parallel"
	case "load_balance":
		return "load_balance"
	case "fastest_ip", "fastest_addr", "":
		return "fastest_ip"
	default:
		return "fastest_ip"
	}
}

func containsControlOrNewline(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// FormatUpstreamDirective 严格校验加密上游 URL（阻断空白/换行/控制字符/明文与保留 IP），转换为 SmartDNS server-* 配置行。
func FormatUpstreamDirective(raw string) (string, error) {
	if containsControlOrNewline(raw) {
		return "", fmt.Errorf("上游地址包含非法换行或控制字符")
	}
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", errors.New("上游地址不能为空")
	}
	if strings.ContainsAny(s, " \t\r\n;#`'\"\\") {
		return "", fmt.Errorf("上游地址 %q 包含非法空白或注入字符", s)
	}
	if !strings.Contains(s, "://") {
		return "", fmt.Errorf("上游地址 %q 缺少加密协议前缀（仅支持 https://、tls://、quic://、h3://）", s)
	}

	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("上游地址 %q 格式无效", s)
	}
	if u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("上游地址 %q 不允许包含认证信息或锚点片段", s)
	}

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https", "tls", "quic", "h3":
	default:
		return "", fmt.Errorf("不支持的 DNS 上游协议 %q（仅支持 https://、tls://、quic://、h3://）", scheme)
	}

	host := strings.TrimSpace(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("上游地址 %q 缺少主机地址", s)
	}

	port := u.Port()
	if port != "" {
		pNum, pErr := strconv.Atoi(port)
		if pErr != nil || pNum <= 0 || pNum > 65535 {
			return "", fmt.Errorf("上游端口 %q 不合法", port)
		}
		if pNum == 53 {
			return "", errors.New("禁止使用 53 明文端口作为加密上游，避免透明代理网关回环死锁")
		}
	}

	var hostLiteral string
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return "", fmt.Errorf("禁止将本机回环或保留地址 (%s) 设为上游", ip.String())
		}
		if ip.IsPrivate() {
			return "", fmt.Errorf("禁止将局域网私网地址 (%s) 设为防劫持加密上游", ip.String())
		}
		if ip.To4() != nil {
			hostLiteral = ip.To4().String()
		} else {
			hostLiteral = "[" + ip.String() + "]"
		}
	} else {
		cleanDomain, domErr := ValidateDomain(host)
		if domErr != nil || !strings.Contains(cleanDomain, ".") {
			return "", fmt.Errorf("上游主机 %q 不合法", host)
		}
		hostLiteral = cleanDomain
	}

	switch scheme {
	case "https", "h3":
		hostPort := hostLiteral
		if port != "" {
			hostPort = hostLiteral + ":" + port
		}
		path := u.EscapedPath()
		if path == "" || path == "/" {
			path = "/dns-query"
		}
		endpoint := "https://" + hostPort + path
		if u.RawQuery != "" {
			endpoint += "?" + u.RawQuery
		}
		return "server-https " + endpoint, nil

	case "tls":
		p := cmp.Or(port, "853")
		return "server-tls " + hostLiteral + ":" + p, nil

	case "quic":
		p := cmp.Or(port, "853")
		return "server-quic " + hostLiteral + ":" + p, nil

	default:
		return "", fmt.Errorf("不支持的协议 %q", scheme)
	}
}

func validateSafePath(label, p string) (string, error) {
	if containsControlOrNewline(p) {
		return "", fmt.Errorf("%s 路径包含非法控制或换行字符", label)
	}
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return "", fmt.Errorf("%s 路径不能为空", label)
	}
	if strings.ContainsAny(trimmed, ";#`'\"") {
		return "", fmt.Errorf("%s 路径 %q 包含非法字符", label, trimmed)
	}
	return trimmed, nil
}

// BuildConfig 生成零污染隔离监听 127.0.0.1 与零闪存磨损参数的 smartdns.conf 文本。
func BuildConfig(input ConfigInput, rulesDir, auditLogPath, logFilePath string) (string, error) {
	dnsPort := input.DNSPort
	if dnsPort == 0 {
		dnsPort = DefaultDNSPort
	}
	if dnsPort == 53 {
		return "", errors.New("SmartDNS 禁止监听 53 端口，以免与 OpenWrt dnsmasq 冲突")
	}
	if dnsPort < 1 || dnsPort > 65535 {
		return "", fmt.Errorf("SmartDNS DNS 监听端口不合法: %d", dnsPort)
	}

	cleanRulesDir, err := validateSafePath("rulesDir", cmp.Or(rulesDir, DefaultRulesDir))
	if err != nil {
		return "", err
	}
	cleanAuditLog, err := validateSafePath("auditLogPath", cmp.Or(auditLogPath, DefaultAuditLogPath))
	if err != nil {
		return "", err
	}
	cleanLogFile, err := validateSafePath("logFilePath", cmp.Or(logFilePath, DefaultLogFilePath))
	if err != nil {
		return "", err
	}

	rawUpstreams := input.Upstreams
	if len(rawUpstreams) == 0 {
		rawUpstreams = DefaultUpstreams()
	}

	seen := make(map[string]struct{}, len(rawUpstreams))
	directives := make([]string, 0, len(rawUpstreams))
	for _, raw := range rawUpstreams {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		dir, err := FormatUpstreamDirective(raw)
		if err != nil {
			return "", err
		}
		key := strings.ToLower(dir)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		directives = append(directives, dir)
	}
	if len(directives) == 0 {
		return "", errors.New("至少需要配置 1 条合法的加密上游 DNS")
	}

	mode := NormalizeUpstreamMode(input.UpstreamMode)
	speedCheckMode := "ping,tcp:80,tcp:443"
	responseMode := "fastest-ip"
	switch mode {
	case "parallel":
		speedCheckMode = "ping,tcp:80,tcp:443"
		responseMode = "first-ping"
	case "load_balance":
		speedCheckMode = "none"
		responseMode = "fastest-response"
	}

	cacheSize := 8192
	if input.IsLowMemory {
		cacheSize = 2048
	}

	var b strings.Builder
	b.WriteString("# SmartDNS configuration managed by singctl (isolated loopback mode)\n")
	fmt.Fprintf(&b, "bind 127.0.0.1:%d\n\n", dnsPort)

	b.WriteString("# Encrypted upstreams\n")
	for _, dir := range directives {
		b.WriteString(dir)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')

	b.WriteString("# Speed check and response strategy\n")
	fmt.Fprintf(&b, "speed-check-mode %s\n", speedCheckMode)
	fmt.Fprintf(&b, "response-mode %s\n\n", responseMode)

	b.WriteString("# Memory & flash protection\n")
	fmt.Fprintf(&b, "cache-size %d\n", cacheSize)
	b.WriteString("cache-persist no\n")
	b.WriteString("serve-expired yes\n")
	b.WriteString("prefetch-domain yes\n")
	b.WriteString("log-level warn\n")
	fmt.Fprintf(&b, "log-file %s\n", cleanLogFile)
	b.WriteString("log-size 64k\n")
	b.WriteString("log-num 1\n\n")

	b.WriteString("# Lightweight tmpfs audit log for 24h stats\n")
	b.WriteString("audit-enable yes\n")
	b.WriteString("audit-SOA yes\n")
	fmt.Fprintf(&b, "audit-file %s\n", cleanAuditLog)
	b.WriteString("audit-size 128k\n")
	b.WriteString("audit-num 1\n")

	b.WriteString("\n# Local health-probe loopback resolution (zero upstream traffic)\n")
	b.WriteString("address /localhost/127.0.0.1\n")

	if input.BlockAAAA {
		b.WriteString("\n# IPv6 AAAA suppression\n")
		b.WriteString("force-AAAA-SOA yes\n")
	}

	b.WriteString("\n# Managed rule files\n")
	if !input.ProtectionPaused && len(input.EnabledFilters) > 0 {
		fmt.Fprintf(&b, "conf-file %s\n", filepath.Join(cleanRulesDir, "adblock.conf"))
	}
	fmt.Fprintf(&b, "conf-file %s\n", filepath.Join(cleanRulesDir, "audit_block.conf"))
	fmt.Fprintf(&b, "conf-file %s\n", filepath.Join(cleanRulesDir, "rewrites.conf"))
	fmt.Fprintf(&b, "conf-file %s\n", filepath.Join(cleanRulesDir, "whitelist.conf"))

	return b.String(), nil
}

// WriteConfig 以 0700 目录与 0600 文件权限原子写入 smartdns.conf。
func WriteConfig(configPath string, content string) error {
	cleanPath := strings.TrimSpace(configPath)
	if cleanPath == "" {
		return errors.New("configPath must not be empty")
	}
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	_ = os.Chmod(dir, 0700)
	return fsx.WriteAtomic0600(cleanPath, []byte(content))
}
