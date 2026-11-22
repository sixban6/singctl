// 文件职责：负责 SmartDNS 白名单、局域网重写、审计封禁与轻量去广告过滤规则校验、规范化及 0600 原子落盘。
package smartdns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"singctl/internal/common/fsx"
)

// MaxFilterFileBytes 限制单个远程去广告规则文件下载上限（4 MiB），防止撑爆软路由闪存。
const MaxFilterFileBytes = 4 * 1024 * 1024

var (
	validDomainRe = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*$`)

	ignoredHostnames = map[string]struct{}{
		"localhost":             {},
		"localhost.localdomain": {},
		"local":                 {},
		"broadcasthost":         {},
		"ip6-localhost":         {},
		"ip6-loopback":          {},
		"ip6-localnet":          {},
		"ip6-mcastprefix":       {},
		"ip6-allnodes":          {},
		"ip6-allrouters":        {},
		"ip6-allhosts":          {},
	}
)

// RuleSetInput 描述受管规则目录的白名单、自定义重写与审计封禁输入。
type RuleSetInput struct {
	Whitelist           []string
	Rewrites            []RewriteEntry
	AuditBlockedDomains []string
}

// FilterPreset 描述内置精选的 SmartDNS 轻量去广告预设。
type FilterPreset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Desc        string `json:"desc"`
	URL         string `json:"url"`
	Recommended bool   `json:"recommended"`
}

// ValidateDomain 严格校验域名格式并阻断换行、空白与配置指令注入。
func ValidateDomain(raw string) (string, error) {
	if containsControlOrNewline(raw) {
		return "", errors.New("域名包含非法换行或控制字符")
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("域名不能为空")
	}
	if strings.ContainsAny(s, " \t\r\n/\\#;*'\"`") {
		return "", fmt.Errorf("域名 %q 包含非法字符", s)
	}
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	if s == "" || len(s) > 253 || strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
		return "", fmt.Errorf("域名格式不合法: %q", raw)
	}
	if !validDomainRe.MatchString(s) {
		return "", fmt.Errorf("域名格式不合法: %q", raw)
	}
	return s, nil
}

// ValidateRewriteAnswer 严格校验重写目标（仅允许合法 IPv4/IPv6 或 # 屏蔽）。
func ValidateRewriteAnswer(raw string) (string, error) {
	if containsControlOrNewline(raw) {
		return "", errors.New("重写目标包含非法换行或控制字符")
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("重写目标不能为空")
	}
	if strings.ContainsAny(s, " \t\r\n;'\"`\\") {
		return "", fmt.Errorf("重写目标 %q 包含非法空白或注入字符", s)
	}
	if s == "#" {
		return "#", nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("重写目标 %q 必须为合法 IPv4/IPv6 地址或 #", s)
	}
	return ip.String(), nil
}

// ValidateFilterURL 校验远程过滤规则集订阅地址为合法的 http/https URL。
func ValidateFilterURL(raw string) (string, error) {
	if containsControlOrNewline(raw) {
		return "", errors.New("规则订阅 URL 包含非法控制或换行字符")
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsAny(trimmed, " \t\r\n") {
		return "", errors.New("规则订阅地址必须为有效的 http:// 或 https:// URL")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u == nil {
		return "", errors.New("规则订阅地址必须为有效的 http:// 或 https:// URL")
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || strings.TrimSpace(u.Hostname()) == "" {
		return "", errors.New("规则订阅地址必须为有效的 http:// 或 https:// URL")
	}
	return trimmed, nil
}

// CuratedFilterPresets 返回 SmartDNS 专用轻量去广告规则集预设（首次安装默认关闭，用户按需开启）。
func CuratedFilterPresets() []FilterPreset {
	return []FilterPreset{
		{
			ID:          "anti-ad-smartdns",
			Name:        "Anti-AD SmartDNS 轻量版",
			Desc:        "面向国内视频贴片与常见 App 追踪的 SmartDNS 原生精简规则集（默认关闭，按需开启）",
			URL:         "https://anti-ad.net/anti-ad-for-smartdns.conf",
			Recommended: true,
		},
		{
			ID:          "hagezi-light-smartdns",
			Name:        "HaGeZi Light 轻量安全精选",
			Desc:        "低内存软路由友好，下载后自动规范化转写为 SmartDNS 屏蔽规则（单文件上限 4 MiB）",
			URL:         "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/light.txt",
			Recommended: false,
		},
	}
}

func ensureRulesDir0700(rulesDir string) error {
	cleanDir := strings.TrimSpace(rulesDir)
	if cleanDir == "" {
		return errors.New("rulesDir must not be empty")
	}
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return fmt.Errorf("mkdir rulesDir %s: %w", cleanDir, err)
	}
	_ = os.Chmod(cleanDir, 0700)
	return nil
}

// WriteManagedRules 校验全部条目后以 0600 原子写入 whitelist.conf、rewrites.conf 与 audit_block.conf。
func WriteManagedRules(rulesDir string, input RuleSetInput) error {
	// 先全量校验，确保任一非法载荷都不会造成部分文件落盘。
	whitelist, err := normalizeUniqueDomains(input.Whitelist)
	if err != nil {
		return fmt.Errorf("白名单域名校验失败: %w", err)
	}
	auditBlocked, err := normalizeUniqueDomains(input.AuditBlockedDomains)
	if err != nil {
		return fmt.Errorf("审计封禁域名校验失败: %w", err)
	}

	seenRewrite := make(map[string]struct{}, len(input.Rewrites))
	rewrites := make([]RewriteEntry, 0, len(input.Rewrites))
	for _, rw := range input.Rewrites {
		if strings.TrimSpace(rw.Domain) == "" && strings.TrimSpace(rw.Answer) == "" {
			continue
		}
		dom, err := ValidateDomain(rw.Domain)
		if err != nil {
			return fmt.Errorf("重写域名校验失败: %w", err)
		}
		ans, err := ValidateRewriteAnswer(rw.Answer)
		if err != nil {
			return fmt.Errorf("重写目标校验失败 (%s): %w", dom, err)
		}
		key := dom + "|" + ans
		if _, dup := seenRewrite[key]; dup {
			continue
		}
		seenRewrite[key] = struct{}{}
		rewrites = append(rewrites, RewriteEntry{Domain: dom, Answer: ans})
	}

	if err := ensureRulesDir0700(rulesDir); err != nil {
		return err
	}

	var wlBuf strings.Builder
	wlBuf.WriteString("# singctl managed smartdns whitelist\n")
	for _, dom := range whitelist {
		fmt.Fprintf(&wlBuf, "domain-rules /%s/ -address -\n", dom)
	}
	if err := fsx.WriteAtomic0600(filepath.Join(rulesDir, "whitelist.conf"), []byte(wlBuf.String())); err != nil {
		return err
	}

	var rwBuf strings.Builder
	rwBuf.WriteString("# singctl managed smartdns rewrites\n")
	for _, rw := range rewrites {
		fmt.Fprintf(&rwBuf, "address /%s/%s\n", rw.Domain, rw.Answer)
	}
	if err := fsx.WriteAtomic0600(filepath.Join(rulesDir, "rewrites.conf"), []byte(rwBuf.String())); err != nil {
		return err
	}

	var abBuf strings.Builder
	abBuf.WriteString("# singctl managed smartdns audit blocklist\n")
	for _, dom := range auditBlocked {
		fmt.Fprintf(&abBuf, "address /%s/#\n", dom)
	}
	return fsx.WriteAtomic0600(filepath.Join(rulesDir, "audit_block.conf"), []byte(abBuf.String()))
}

func normalizeUniqueDomains(raw []string) ([]string, error) {
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if strings.TrimSpace(item) == "" {
			continue
		}
		dom, err := ValidateDomain(item)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[dom]; dup {
			continue
		}
		seen[dom] = struct{}{}
		out = append(out, dom)
	}
	return out, nil
}

// EnsureRulePlaceholders 确保受管规则目录下所有可能被 conf-file 引用的文件均存在（不覆盖已有文件）。
func EnsureRulePlaceholders(rulesDir string) error {
	if err := ensureRulesDir0700(rulesDir); err != nil {
		return err
	}
	placeholders := []string{
		"whitelist.conf",
		"rewrites.conf",
		"audit_block.conf",
		"adblock.conf",
	}
	for _, name := range placeholders {
		p := filepath.Join(rulesDir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			content := fmt.Sprintf("# singctl managed smartdns %s (placeholder)\n", name)
			if writeErr := fsx.WriteAtomic0600(p, []byte(content)); writeErr != nil {
				return writeErr
			}
		}
	}
	return nil
}

// NormalizeAdblockLine 将单行远程规则（SmartDNS address、hosts、ABP ||domain^ 或纯域名）安全规范化为 `address /<domain>/#`。
// 任何非屏蔽型指令（如 bind / server / conf-file / 任意 IP 重定向）或含注入字符的行一律丢弃。
func NormalizeAdblockLine(line string) (string, bool) {
	if containsControlOrNewline(line) {
		return "", false
	}
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, "!") || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "//") {
		return "", false
	}

	// 1. SmartDNS 原生拦截行: address /<domain>/# (仅放行屏蔽动作 #/#4/#6/0.0.0.0/::，绝不允许任意 IP 重定向或附加参数)
	if rest, ok := strings.CutPrefix(strings.ToLower(s), "address "); ok {
		fields := strings.Fields(rest)
		if len(fields) != 1 {
			return "", false
		}
		spec := fields[0]
		if !strings.HasPrefix(spec, "/") {
			return "", false
		}
		inner := spec[1:]
		domPart, action, found := strings.Cut(inner, "/")
		if !found || strings.Contains(action, "/") {
			return "", false
		}
		switch action {
		case "#", "#4", "#6", "0.0.0.0", "::":
		default:
			return "", false
		}
		dom, err := ValidateDomain(domPart)
		if err != nil || !strings.Contains(dom, ".") {
			return "", false
		}
		return "address /" + dom + "/#", true
	}

	// 去除行尾 # 注释（非 SmartDNS address 行不会有合法 # 后缀）
	if before, _, hasComment := strings.Cut(s, "#"); hasComment {
		s = strings.TrimSpace(before)
		if s == "" {
			return "", false
		}
	}

	// 2. ABP 简易域名行: ||example.com^
	if strings.HasPrefix(s, "||") && strings.HasSuffix(s, "^") && !strings.ContainsAny(s, " \t$/") {
		candidate := strings.TrimSuffix(strings.TrimPrefix(s, "||"), "^")
		dom, err := ValidateDomain(candidate)
		if err != nil || !strings.Contains(dom, ".") {
			return "", false
		}
		return "address /" + dom + "/#", true
	}

	// 3. Hosts 格式: 0.0.0.0 domain / 127.0.0.1 domain / :: domain
	fields := strings.Fields(s)
	if len(fields) == 2 {
		switch fields[0] {
		case "0.0.0.0", "127.0.0.1", "::", "::0":
			dom, err := ValidateDomain(fields[1])
			if err != nil || !strings.Contains(dom, ".") {
				return "", false
			}
			if _, skip := ignoredHostnames[dom]; skip {
				return "", false
			}
			return "address /" + dom + "/#", true
		default:
			return "", false
		}
	}

	// 4. 纯域名行（如 HaGeZi domains/light.txt），必须包含至少一个点，防误把单词配置指令当域名
	if len(fields) == 1 {
		dom, err := ValidateDomain(fields[0])
		if err != nil || !strings.Contains(dom, ".") {
			return "", false
		}
		if _, skip := ignoredHostnames[dom]; skip {
			return "", false
		}
		return "address /" + dom + "/#", true
	}

	return "", false
}

// SyncAdblockFilters 拉取、校验并规范化远程轻量去广告规则集写入 adblock.conf（单源硬上限 4 MiB）。
func SyncAdblockFilters(ctx context.Context, rulesDir string, urls []string, paused bool) (int, error) {
	return syncAdblockFiltersWithClient(ctx, nil, rulesDir, urls, paused)
}

func syncAdblockFiltersWithClient(ctx context.Context, client *http.Client, rulesDir string, urls []string, paused bool) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ensureRulesDir0700(rulesDir); err != nil {
		return 0, err
	}
	targetFile := filepath.Join(rulesDir, "adblock.conf")

	if paused || len(urls) == 0 {
		placeholder := "# singctl managed smartdns adblock (disabled or paused)\n"
		if err := fsx.WriteAtomic0600(targetFile, []byte(placeholder)); err != nil {
			return 0, err
		}
		return 0, nil
	}

	cleanURLs := make([]string, 0, len(urls))
	seenURL := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		u, err := ValidateFilterURL(raw)
		if err != nil {
			return 0, err
		}
		if _, dup := seenURL[u]; dup {
			continue
		}
		seenURL[u] = struct{}{}
		cleanURLs = append(cleanURLs, u)
	}
	if len(cleanURLs) == 0 {
		placeholder := "# singctl managed smartdns adblock (empty)\n"
		if err := fsx.WriteAtomic0600(targetFile, []byte(placeholder)); err != nil {
			return 0, err
		}
		return 0, nil
	}

	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	seenRules := make(map[string]struct{}, 1024)
	rules := make([]string, 0, 1024)

	for _, filterURL := range cleanURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, filterURL, nil)
		if err != nil {
			return 0, fmt.Errorf("构造规则请求失败 (%s): %w", filterURL, err)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, fmt.Errorf("下载去广告规则失败 (%s): %w", filterURL, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxFilterFileBytes+1))
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("下载去广告规则失败 (%s): HTTP %d", filterURL, resp.StatusCode)
		}
		if readErr != nil {
			return 0, fmt.Errorf("读取去广告规则失败 (%s): %w", filterURL, readErr)
		}
		if len(body) > MaxFilterFileBytes {
			return 0, fmt.Errorf("去广告规则文件超过 %d MiB 安全上限 (%s)，已拒绝写入以保护闪存", MaxFilterFileBytes/(1024*1024), filterURL)
		}

		for line := range strings.SplitSeq(string(body), "\n") {
			normalized, ok := NormalizeAdblockLine(line)
			if !ok {
				continue
			}
			if _, dup := seenRules[normalized]; dup {
				continue
			}
			seenRules[normalized] = struct{}{}
			rules = append(rules, normalized)
		}
	}

	var out strings.Builder
	out.WriteString("# singctl managed smartdns adblock rules\n")
	for _, r := range rules {
		out.WriteString(r)
		out.WriteByte('\n')
	}
	if err := fsx.WriteAtomic0600(targetFile, []byte(out.String())); err != nil {
		return 0, err
	}
	return len(rules), nil
}
