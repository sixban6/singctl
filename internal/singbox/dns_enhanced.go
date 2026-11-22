// 文件职责：实现 sing-box 加强版防劫持 DNS 加密上游编译、内网重写与白名单校验、在线原子同步、缓存清理与脱敏配置预览。
package singbox

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

const (
	dnsBootstrapServerTag = "dns_bootstrap"
	managedRewriteTTLStr  = "60"
)

var managedAdRuleSetTags = []string{
	"geosite-ad1",
	"geosite-ad2",
	BuiltinPCDNRuleSetTag,
}

// ManagedAdRuleSetTags 返回 sing-box 加强版引擎受管去广告与 PCDN 规则集 tag 列表副本。
func ManagedAdRuleSetTags() []string {
	return slices.Clone(managedAdRuleSetTags)
}

func defaultEncryptedLocalDNSServer() sboption.DNSServer {
	return sboption.DNSServer{
		Tag:        "dns_local",
		Type:       "https",
		Server:     defaultFallbackDoHServer,
		ServerPort: 443,
		Path:       defaultFallbackDoHPath,
	}
}

func hasControlOrWhitespace(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func isValidHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// ParseEncryptedDNSServer 解析并严格校验加密 DNS 上游 URL（https/tls/quic/h3），拒绝明文 UDP/TCP/HTTP 及注入载荷。
func ParseEncryptedDNSServer(rawURL string) (sboption.DNSServer, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游不能为空")
	}
	if hasControlOrWhitespace(trimmed) {
		return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游包含非法空白或控制字符")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return sboption.DNSServer{}, fmt.Errorf("解析加密 DNS 上游失败: %w", err)
	}
	if u.User != nil || u.Fragment != "" {
		return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游不允许携带凭据或锚点")
	}

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	var defaultPort int
	var needsPath bool
	switch scheme {
	case "https", "h3":
		defaultPort = 443
		needsPath = true
	case "tls", "quic":
		defaultPort = 853
	default:
		return sboption.DNSServer{}, fmt.Errorf("不支持的 DNS 协议 %q（仅允许 https/tls/quic/h3 加密上游）", u.Scheme)
	}

	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
	if host == "" {
		return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游缺少主机地址")
	}
	if addr, ipErr := netip.ParseAddr(host); ipErr == nil {
		if addr.Zone() != "" {
			return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游不允许包含链路作用域 IP")
		}
		host = addr.String()
	} else if !isValidHostname(host) {
		return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游主机名 %q 非法", host)
	}

	port := defaultPort
	if rawPort := u.Port(); rawPort != "" {
		p, pErr := strconv.Atoi(rawPort)
		if pErr != nil || p <= 0 || p > 65535 {
			return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游端口 %q 超出合法范围 (1-65535)", rawPort)
		}
		port = p
	}

	path := ""
	if needsPath {
		if u.Path == "" || u.Path == "/" {
			path = defaultFallbackDoHPath
		} else {
			if !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "..") {
				return sboption.DNSServer{}, fmt.Errorf("加密 DNS 上游路径 %q 非法", u.Path)
			}
			path = u.Path
		}
		if u.RawQuery != "" {
			path += "?" + u.RawQuery
		}
	} else if u.Path != "" && u.Path != "/" {
		return sboption.DNSServer{}, fmt.Errorf("%s 协议上游不支持路径 %q", scheme, u.Path)
	}

	return sboption.DNSServer{
		Tag:        "dns_local",
		Type:       scheme,
		Server:     host,
		ServerPort: port,
		Path:       path,
	}, nil
}

func parseDNSRewriteRule(rule config.DNSRewriteRule) (domain string, isWildcard bool, rrType string, ipStr string, err error) {
	rawDomain := strings.TrimSpace(rule.Domain)
	rawAnswer := strings.TrimSpace(rule.Answer)
	if rawDomain == "" || rawAnswer == "" {
		return "", false, "", "", fmt.Errorf("DNS 重写规则域名与应答 IP 均不能为空")
	}
	if hasControlOrWhitespace(rawDomain) || hasControlOrWhitespace(rawAnswer) {
		return "", false, "", "", fmt.Errorf("DNS 重写规则包含非法空白或控制字符")
	}

	d := strings.ToLower(strings.TrimSuffix(rawDomain, "."))
	if rest, ok := strings.CutPrefix(d, "*."); ok {
		isWildcard = true
		d = rest
	}
	if strings.Contains(d, "*") || !isValidHostname(d) {
		return "", false, "", "", fmt.Errorf("DNS 重写域名 %q 非法", rule.Domain)
	}

	addr, parseErr := netip.ParseAddr(rawAnswer)
	if parseErr != nil || addr.Zone() != "" {
		return "", false, "", "", fmt.Errorf("DNS 重写目标 %q 不是合法 IPv4/IPv6 地址", rule.Answer)
	}
	addr = addr.Unmap()
	if addr.Is4() {
		rrType = "A"
	} else {
		rrType = "AAAA"
	}
	return d, isWildcard, rrType, addr.String(), nil
}

// ValidateDNSRewriteRule 严格校验内网自定义 DNS 重写规则（防换行/RR/命令注入）。
func ValidateDNSRewriteRule(rule config.DNSRewriteRule) error {
	_, _, _, _, err := parseDNSRewriteRule(rule)
	return err
}

func normalizeWhitelistDomain(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || hasControlOrWhitespace(s) {
		return "", false
	}
	s = strings.ToLower(s)
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimSuffix(s, ".")
	if !isValidHostname(s) {
		return "", false
	}
	return s, true
}

// ExtractSubscriptionDomains 从客户端订阅列表中提取去重后的合法域名集合（用于防广告/PCDN 误杀）。
func ExtractSubscriptionDomains(cfg *config.Config) []string {
	if cfg == nil || len(cfg.Subs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.Subs))
	for _, sub := range cfg.Subs {
		rawURL := strings.TrimSpace(sub.URL)
		if rawURL == "" {
			continue
		}
		u, err := url.Parse(rawURL)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(u.Hostname()), "."))
		if host == "" || host == "localhost" {
			continue
		}
		if !isValidHostname(host) {
			continue
		}
		if !slices.Contains(out, host) {
			out = append(out, host)
		}
	}
	return out
}

func collectAllowList(whitelist, subDomains []string) []string {
	out := make([]string, 0, len(whitelist)+len(subDomains))
	for _, raw := range whitelist {
		if d, ok := normalizeWhitelistDomain(raw); ok && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	for _, raw := range subDomains {
		if d, ok := normalizeWhitelistDomain(raw); ok && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
}

// ApplyEnhancedSingBoxDNSInDoc 在 *sboption.Document 上幂等应用 sing-box 加强版防劫持 DNS 配置：
//   - 将 dns_local 升级为加密 DoH/DoT/DoQ/H3（默认纯 IP https://223.5.5.5/dns-query）+ 缓存/乐观解析/store_dns；
//   - 注入私网 PTR NXDOMAIN、内网自定义 Rewrites、白名单+订阅域名逻辑反选放行；
//   - 支持去广告临时/手动暂停与单规则集开关（不丢 route.rule_set 定义，恢复时自动还原）；
//   - 支持独立屏蔽 AAAA 开关且不误伤 ipv6_mode=cn_only 海外规则。
func ApplyEnhancedSingBoxDNSInDoc(doc *sboption.Document, dnsCfg config.ClientDNSConfig, subDomains []string, now time.Time) (bool, error) {
	if doc == nil || doc.DNS == nil {
		return false, nil
	}
	beforeSig, err := sboption.CanonicalJSON(doc)
	if err != nil {
		return false, err
	}

	applyEncryptedLocalDNSServerInDoc(doc, dnsCfg.Upstreams)
	ensurePrivatePTRBlockRulesInDoc(doc)

	disabledTags := computeDisabledAdRuleSetTags(dnsCfg, now)
	allowList := collectAllowList(dnsCfg.Whitelist, subDomains)
	definedRuleSets := collectDefinedRuleSetTags(doc.Route)

	reconcileManagedRewritesInDoc(doc, dnsCfg.Rewrites)
	reconcileManagedAdDNSRulesInDoc(doc, definedRuleSets, disabledTags, allowList)
	reconcileManagedAdRouteRulesInDoc(doc, definedRuleSets, disabledTags, allowList)
	reconcileBlockAAAADNSRuleInDoc(doc, dnsCfg.BlockAAAA)

	afterSig, err := sboption.CanonicalJSON(doc)
	if err != nil {
		return false, err
	}
	return beforeSig != afterSig, nil
}

// ApplyEnhancedSingBoxDNSJSON 在 JSON 文本上幂等应用 sing-box 加强版防劫持 DNS 配置。
func ApplyEnhancedSingBoxDNSJSON(rawJSON string, dnsCfg config.ClientDNSConfig, subDomains []string, now time.Time) (string, bool, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, false, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", false, fmt.Errorf("enhanced dns: parse config JSON: %w", err)
	}
	changed, err := ApplyEnhancedSingBoxDNSInDoc(doc, dnsCfg, subDomains, now)
	if err != nil {
		return "", false, err
	}
	if !changed {
		return rawJSON, false, nil
	}
	formatted, err := doc.MarshalPretty()
	if err != nil {
		return "", false, err
	}
	return formatted + "\n", true, nil
}

func applyEncryptedLocalDNSServerInDoc(doc *sboption.Document, upstreams []string) {
	localIdx := slices.IndexFunc(doc.DNS.Servers, func(s sboption.DNSServer) bool {
		return s.Tag == "dns_local"
	})

	desired := defaultEncryptedLocalDNSServer()
	for _, raw := range upstreams {
		if parsed, err := ParseEncryptedDNSServer(raw); err == nil {
			desired = parsed
			break
		}
	}

	needsBootstrap := false
	if _, ipErr := netip.ParseAddr(desired.Server); ipErr != nil {
		needsBootstrap = true
		desired.Extra = map[string]json.RawMessage{
			"domain_resolver": json.RawMessage(`"` + dnsBootstrapServerTag + `"`),
		}
	}

	if localIdx >= 0 {
		doc.DNS.Servers[localIdx] = desired
	}

	bootstrapIdx := slices.IndexFunc(doc.DNS.Servers, func(s sboption.DNSServer) bool {
		return s.Tag == dnsBootstrapServerTag
	})
	if needsBootstrap {
		bootstrapSrv := sboption.DNSServer{
			Tag:        dnsBootstrapServerTag,
			Type:       "https",
			Server:     defaultFallbackDoHServer,
			ServerPort: 443,
			Path:       defaultFallbackDoHPath,
		}
		if bootstrapIdx >= 0 {
			doc.DNS.Servers[bootstrapIdx] = bootstrapSrv
		} else {
			doc.DNS.Servers = append(doc.DNS.Servers, bootstrapSrv)
		}
	} else if bootstrapIdx >= 0 && !anyOtherServerReferencesTag(doc.DNS.Servers, dnsBootstrapServerTag) {
		doc.DNS.Servers = slices.Delete(doc.DNS.Servers, bootstrapIdx, bootstrapIdx+1)
	}

	doc.DNS.DisableCache = new(false)
	doc.DNS.Optimistic = new(true)
	if doc.Experimental != nil && doc.Experimental.CacheFile != nil {
		doc.Experimental.CacheFile.StoreDNS = new(true)
	}
}

func anyOtherServerReferencesTag(servers []sboption.DNSServer, tag string) bool {
	quoted := `"` + tag + `"`
	for _, s := range servers {
		if s.Tag == tag {
			continue
		}
		if raw, ok := s.Extra["domain_resolver"]; ok && strings.Contains(string(raw), quoted) {
			return true
		}
	}
	return false
}

func resolveSingBoxConfigPaths(sbCfgPath, workPath string) (cfgPath, wPath string) {
	explicitCfg := strings.TrimSpace(sbCfgPath)
	cfgPath = cmp.Or(explicitCfg, constant.SingBoxConfigFile)
	wPath = strings.TrimSpace(workPath)
	if wPath == "" && (explicitCfg == "" || cfgPath == constant.SingBoxConfigFile) {
		wPath = constant.SingBoxWorkConfigFile
	}
	return cfgPath, wPath
}

func recoverMissingManagedRuleSetsFromBase(doc *sboption.Document, baseJSON string, disabledTags map[string]bool) {
	if doc == nil || doc.Route == nil || strings.TrimSpace(baseJSON) == "" {
		return
	}
	baseDoc, err := sboption.ParseDocument([]byte(baseJSON))
	if err != nil || baseDoc.Route == nil || len(baseDoc.Route.RuleSet) == 0 {
		return
	}
	defined := collectDefinedRuleSetTags(doc.Route)
	for _, rs := range baseDoc.Route.RuleSet {
		tag := strings.TrimSpace(rs.Tag)
		if slices.Contains(managedAdRuleSetTags, tag) && !disabledTags[tag] && !defined[tag] {
			doc.Route.RuleSet = append(doc.Route.RuleSet, rs.Clone())
			defined[tag] = true
		}
	}
}

// SyncLiveSingBoxEnhancedDNS 以规则 02 两阶段原子校验替换与 SIGHUP 热重载在线同步 sing-box 加强版 DNS 配置。
func SyncLiveSingBoxEnhancedDNS(ctx context.Context, sbCfgPath, workPath string, dnsCfg config.ClientDNSConfig, subDomains []string, now time.Time) (bool, error) {
	cfgPath, wPath := resolveSingBoxConfigPaths(sbCfgPath, workPath)
	if cfgPath == "" {
		return false, nil
	}
	rawBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	EnsureInitialBaseSnapshot(cfgPath)

	doc, err := sboption.ParseDocument(rawBytes)
	if err != nil {
		return false, fmt.Errorf("sync enhanced dns: parse config.json: %w", err)
	}
	if baseJSON, bErr := LoadBaseSnapshot(cfgPath); bErr == nil && baseJSON != "" {
		recoverMissingManagedRuleSetsFromBase(doc, baseJSON, computeDisabledAdRuleSetTags(dnsCfg, now))
	}

	changed, err := ApplyEnhancedSingBoxDNSInDoc(doc, dnsCfg, subDomains, now)
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}

	formatted, err := doc.MarshalPretty()
	if err != nil {
		return false, err
	}
	if err := ApplyLiveSingBoxConfig(ctx, cfgPath, wPath, formatted+"\n", "dnsenhanced"); err != nil {
		return false, err
	}
	log.Success("已平滑热重载 sing-box 加强版防劫持 DNS 配置")
	return true, nil
}

// ClearSingBoxDNSCache 清理 sing-box DNS 持久化缓存文件（cache.db）并触发进程无感热重载以刷新内存缓存。
func ClearSingBoxDNSCache(ctx context.Context, sbCfgPath, workPath string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	cfgPath, wPath := resolveSingBoxConfigPaths(sbCfgPath, workPath)

	var candidates []string
	addCandidate := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasSuffix(strings.ToLower(filepath.Base(p)), ".db") {
			return
		}
		if !slices.Contains(candidates, p) {
			candidates = append(candidates, p)
		}
	}

	inspectCacheFilePath := func(path string) {
		if path == "" {
			return
		}
		addCandidate(filepath.Join(filepath.Dir(path), "cache.db"))
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		doc, err := sboption.ParseDocument(raw)
		if err != nil || doc.Experimental == nil || doc.Experimental.CacheFile == nil {
			return
		}
		if customPath := strings.TrimSpace(doc.Experimental.CacheFile.Path); customPath != "" {
			if !filepath.IsAbs(customPath) {
				customPath = filepath.Join(filepath.Dir(path), customPath)
			}
			addCandidate(customPath)
		}
	}

	inspectCacheFilePath(cfgPath)
	inspectCacheFilePath(wPath)

	for _, cachePath := range candidates {
		if err := os.Remove(cachePath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove sing-box cache %s: %w", cachePath, err)
		}
	}
	ReloadSingBoxProcess()
	return nil
}

func maskURLQueryAndUserInfo(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return s
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if u.User != nil {
				u.User = url.User("******")
			}
			if u.RawQuery != "" {
				u.RawQuery = "******"
			}
			return u.String()
		}
	}
	if idx := strings.IndexByte(s, '?'); idx >= 0 {
		return s[:idx+1] + "******"
	}
	return s
}

func sanitizeDNSServerForPreview(s sboption.DNSServer) sboption.DNSServer {
	cp := s
	cp.Path = maskURLQueryAndUserInfo(s.Path)
	cp.Address = maskURLQueryAndUserInfo(s.Address)
	cp.Extra = sboption.CloneRawMap(s.Extra)
	if len(cp.Extra) == 0 {
		return cp
	}
	if rawHeaders, ok := cp.Extra["headers"]; ok {
		var hdrs map[string]any
		if err := json.Unmarshal(rawHeaders, &hdrs); err == nil {
			masked := make(map[string]string, len(hdrs))
			for k := range hdrs {
				masked[k] = "******"
			}
			if b, err := json.Marshal(masked); err == nil {
				cp.Extra["headers"] = b
			}
		} else {
			cp.Extra["headers"] = json.RawMessage(`"******"`)
		}
	}
	for k := range cp.Extra {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") || strings.Contains(lower, "key") ||
			strings.Contains(lower, "auth") {
			cp.Extra[k] = json.RawMessage(`"******"`)
		}
	}
	return cp
}

// ExtractSingBoxDNSSectionPretty 从磁盘 sing-box 配置中提取仅包含 dns 段的脱敏缩进 JSON 片段（供前端配置抽屉预览）。
func ExtractSingBoxDNSSectionPretty(sbCfgPath string) (string, error) {
	cfgPath := cmp.Or(strings.TrimSpace(sbCfgPath), constant.SingBoxConfigFile)
	if cfgPath == "" {
		return "", fmt.Errorf("sing-box 配置文件路径为空")
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		return "", fmt.Errorf("读取 sing-box 配置失败: %w", err)
	}
	doc, err := sboption.ParseDocument(raw)
	if err != nil {
		return "", fmt.Errorf("解析 sing-box 配置失败: %w", err)
	}
	if doc.DNS == nil {
		return "{}", nil
	}

	sanitizedDNS := *doc.DNS
	sanitizedDNS.Extra = sboption.CloneRawMap(doc.DNS.Extra)
	if len(doc.DNS.Servers) > 0 {
		sanitizedDNS.Servers = make([]sboption.DNSServer, len(doc.DNS.Servers))
		for i, srv := range doc.DNS.Servers {
			sanitizedDNS.Servers[i] = sanitizeDNSServerForPreview(srv)
		}
	}
	if len(doc.DNS.Rules) > 0 {
		sanitizedDNS.Rules = make([]sboption.DNSRule, len(doc.DNS.Rules))
		for i := range doc.DNS.Rules {
			sanitizedDNS.Rules[i] = doc.DNS.Rules[i].Clone()
		}
	}

	payload := struct {
		DNS *sboption.DNSOptions `json:"dns"`
	}{
		DNS: &sanitizedDNS,
	}
	compact, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return sboption.PrettyBytes(compact)
}
