// 文件职责：三位一体审计封禁编排器（Enforcer），协同持久化 singctl.yaml 黑名单、同步 AdGuard Home DNS、
// 原子热更新 sing-box config.json，并联动 ruleset_import.go 执行规则集整包导入与 Clash 存量连接秒级掐断。
//
// 架构设计原则：
//   - 命令式薄外壳：安全防自锁校验、规则集下载编译与 HTTP 连接遍历均委派给纯函数及共享方法，
//     本文件专注于黑名单/白名单状态机与双层原子提交回滚闭环。
package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	"singctl/internal/util/netinfo"
)

// ProtectedBootstrapIPs 禁止被误拉黑的核心公共 DNS 与本机回环地址（防软路由自锁断网）。
var ProtectedBootstrapIPs = []string{
	"127.0.0.1", "::1", "0.0.0.0",
	"223.5.5.5", "223.6.6.6", "119.29.29.29", "1.12.12.12", "120.53.53.53",
	"1.1.1.1", "8.8.8.8",
}

// ProtectedBootstrapDomains 禁止被误拉黑的核心加密握手 (TLS ECH) 与公共 DoH 基础设施域名（防断网与降级攻击）。
var ProtectedBootstrapDomains = []string{
	"cloudflare-ech.com",
	"cloudflare-dns.com",
	"one.one.one.one",
	"dns.google",
	"dns.alidns.com",
	"doh.pub",
	"dot.pub",
}

// IsProtectedBootstrapDomain 判断目标域名是否属于核心加密握手或公共 DNS 基础设施域名。
func IsProtectedBootstrapDomain(raw string) bool {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return false
	}
	for _, p := range ProtectedBootstrapDomains {
		if d == p || strings.HasSuffix(d, "."+p) {
			return true
		}
	}
	return false
}

// Enforcer 负责执行“Sing-Box 路由阻断 + 自建 AdGuard Home DNS 黑名单 + 存量活跃连接秒级掐断”三位一体联动封禁。
type Enforcer struct {
	cfg               *config.Config
	configPath        string
	sbConfigPath      string
	sbWorkConfigPath  string
	aghConfigPath     string
	clashEndpoints    []string
	clashSecret       string
	httpClient        *http.Client  // 可选 HTTP 客户端注入（nil 时默认 12 秒超时，单测用于拦截外部请求）
	resolveSingBoxBin func() string // 可选 sing-box 二进制查找器注入（nil 时默认 singbox.FindSingBoxBin）
}

// NewEnforcer 创建默认三位一体封禁执行器。
func NewEnforcer(cfg *config.Config, singctlConfigPath string) *Enforcer {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &Enforcer{
		cfg:              cfg,
		configPath:       singctlConfigPath,
		sbConfigPath:     constant.SingBoxConfigFile,
		sbWorkConfigPath: constant.SingBoxWorkConfigFile,
		aghConfigPath:    constant.AdGuardConfigFile,
		clashEndpoints:   singbox.ClashAPIEndpoints(),
		clashSecret:      singbox.ClashAPISecret(),
	}
}

// SetPathsForTest 供单元测试注入临时配置文件路径与模拟 Clash API 端点。
func (e *Enforcer) SetPathsForTest(sbConfigPath, aghConfigPath string, clashEndpoints []string, secret string) {
	e.sbConfigPath = sbConfigPath
	e.sbWorkConfigPath = ""
	e.aghConfigPath = aghConfigPath
	e.clashEndpoints = clashEndpoints
	e.clashSecret = secret
}

// SetWorkConfigPathForTest 供单元测试注入临时沙盒运行时配置路径（例如模拟 /tmp/sing-box-work/config.json）。
func (e *Enforcer) SetWorkConfigPathForTest(sbWorkConfigPath string) {
	e.sbWorkConfigPath = sbWorkConfigPath
}

// SetStoragePaths 按需覆写 Enforcer 使用的 sing-box / AdGuard 配置路径（保留 Clash API 端点与鉴权密钥不变）。
func (e *Enforcer) SetStoragePaths(sbConfigPath, sbWorkConfigPath, aghConfigPath string) {
	if strings.TrimSpace(sbConfigPath) != "" {
		e.sbConfigPath = strings.TrimSpace(sbConfigPath)
		e.sbWorkConfigPath = strings.TrimSpace(sbWorkConfigPath)
	} else if strings.TrimSpace(sbWorkConfigPath) != "" {
		e.sbWorkConfigPath = strings.TrimSpace(sbWorkConfigPath)
	}
	if strings.TrimSpace(aghConfigPath) != "" {
		e.aghConfigPath = strings.TrimSpace(aghConfigPath)
	}
}

// ValidateTargetSafety 严格校验待拉黑目标是否安全（遵循规则 02 防自锁断网红线，拒绝拉黑网关自身、Tailscale 及机场订阅节点域名）。
func ValidateTargetSafety(cfg *config.Config, rawTarget string) (normalized string, isIP bool, err error) {
	return validateTargetSafety(cfg, rawTarget, true)
}

// protectedReservedPrefixes 禁止拉黑的回环、局域网私网、Tailscale CGNAT、FakeIP 及保留地址段。
var protectedReservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// parseAuditIPPrefix 解析单个 IP 或 CIDR 为规范化后的 netip.Prefix（自动 unmap IPv4-in-IPv6）。
func parseAuditIPPrefix(raw string) (netip.Prefix, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Prefix{}, false
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		addr := p.Addr()
		if addr.Is4In6() {
			bits := p.Bits()
			if bits >= 96 {
				return netip.PrefixFrom(addr.Unmap(), bits-96).Masked(), true
			}
		}
		return p.Masked(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}

func validateTargetSafety(cfg *config.Config, rawTarget string, strictMask bool) (normalized string, isIP bool, err error) {
	normalized, isIP = singbox.NormalizeBlockTarget(rawTarget)
	if normalized == "" {
		return "", false, fmt.Errorf("无效的拉黑目标: %q", rawTarget)
	}
	if strings.ContainsAny(normalized, " \t\r\n;|&$`\"'<>") {
		return "", false, fmt.Errorf("目标包含非法字符: %q", rawTarget)
	}

	plain := strings.TrimSuffix(strings.TrimSuffix(normalized, "/32"), "/128")
	if plain == "localhost" || plain == "lan" || plain == "local" {
		return "", false, fmt.Errorf("安全拦截: 禁止拉黑本机主机名 (%s)，防止网关断网", plain)
	}

	var parsedPrefix netip.Prefix
	if isIP {
		var ok bool
		parsedPrefix, ok = parseAuditIPPrefix(normalized)
		if !ok {
			return "", false, fmt.Errorf("无效的 IP 或 CIDR 目标格式: %q", rawTarget)
		}
		if !parsedPrefix.IsSingleIP() {
			bits := parsedPrefix.Bits()
			if parsedPrefix.Addr().Is4() {
				minBits := 8
				if strictMask {
					minBits = 16
				}
				if bits < minBits {
					return "", false, fmt.Errorf("安全拦截: 为防止大面积误伤断网，IPv4 网段掩码长度须在 /%d 至 /32 之间 (%s)", minBits, parsedPrefix)
				}
			} else {
				minBits := 16
				if strictMask {
					minBits = 32
				}
				if bits < minBits {
					return "", false, fmt.Errorf("安全拦截: 为防止大面积误伤断网，IPv6 网段掩码长度须在 /%d 至 /128 之间 (%s)", minBits, parsedPrefix)
				}
			}
		}
		for _, rp := range protectedReservedPrefixes {
			if parsedPrefix.Overlaps(rp) {
				if parsedPrefix.IsSingleIP() {
					return "", false, fmt.Errorf("安全拦截: 禁止拉黑本机回环、局域网私网、Tailscale 或 FakeIP 保留地址 (%s)", plain)
				}
				return "", false, fmt.Errorf("安全拦截: 目标网段 (%s) 与本机回环、私网、Tailscale 或 FakeIP 保留网段重叠，已拒绝", parsedPrefix)
			}
		}
		for _, bIP := range ProtectedBootstrapIPs {
			if bAddr, parseErr := netip.ParseAddr(bIP); parseErr == nil && parsedPrefix.Contains(bAddr.Unmap()) {
				return "", false, fmt.Errorf("安全拦截: 目标 (%s) 包含核心基础 DNS 服务器 (%s)，禁止拉黑以防解析瘫痪", parsedPrefix, bIP)
			}
		}
		if lanIP := netinfo.GetPrimaryLANIPv4(); lanIP != "" {
			if lanAddr, parseErr := netip.ParseAddr(lanIP); parseErr == nil && parsedPrefix.Contains(lanAddr.Unmap()) {
				return "", false, fmt.Errorf("安全拦截: 目标 (%s) 包含本机局域网网关 IP (%s)，已拒绝", parsedPrefix, lanIP)
			}
		}
		normalized = parsedPrefix.String()
	} else if IsProtectedBootstrapDomain(plain) {
		return "", false, fmt.Errorf("安全拦截: 禁止拉黑核心加密握手/公共 DNS 基础设施域名 (%s)，防止连接中断或隐私降级", plain)
	}

	// 检查是否误伤用户自身的订阅域名、代理 IP 或自建节点
	checkProtectedHostOrIP := func(rawHost, kind string) error {
		host := strings.ToLower(strings.TrimSpace(rawHost))
		if host == "" {
			return nil
		}
		if isIP {
			if hAddr, parseErr := netip.ParseAddr(host); parseErr == nil && parsedPrefix.Contains(hAddr.Unmap()) {
				return fmt.Errorf("安全拦截: 目标 (%s) 包含您正在使用的%s (%s)，禁止拉黑以防断网", parsedPrefix, kind, host)
			}
			return nil
		}
		if plain == host || strings.HasSuffix(host, "."+plain) {
			return fmt.Errorf("安全拦截: 目标 %q 命中您正在使用的%s (%s)，禁止拉黑以防断网", plain, kind, host)
		}
		return nil
	}
	if cfg != nil {
		for _, sub := range cfg.Subs {
			u, parseErr := url.Parse(strings.TrimSpace(sub.URL))
			if parseErr == nil && u.Hostname() != "" {
				if err := checkProtectedHostOrIP(u.Hostname(), "订阅节点"); err != nil {
					return "", false, err
				}
			}
		}
		for _, srvDom := range []string{cfg.Server.GetNodeDomain(), cfg.Server.GetSubstoreDomain(), strings.TrimSpace(cfg.Server.ServerIP)} {
			if strings.EqualFold(strings.TrimSpace(srvDom), "node.example.com") {
				continue
			}
			if err := checkProtectedHostOrIP(srvDom, "自建代理节点"); err != nil {
				return "", false, err
			}
		}
	}

	return normalized, isIP, nil
}

// isRuleSetImportInput 判断用户输入是否为远程规则集 URL (.srs / .json) 或 ruleset:<tag> 标识。
func isRuleSetImportInput(raw string) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if strings.HasPrefix(s, "ruleset:") {
		return true
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if u, err := url.Parse(s); err == nil && u.Path != "" {
			p := strings.ToLower(u.Path)
			if strings.HasSuffix(p, ".srs") || strings.HasSuffix(p, ".json") {
				return true
			}
		}
	}
	return false
}

// Block 执行一键双层拉黑（写入 singctl.yaml -> 同步 AdGuard Home -> 原子热更新 sing-box config.json -> 立即斩断存量连接）。
// 若传入的是 sing-box 规则集 URL (.srs / .json) 或 ruleset:<tag>，自动执行整包导入与单行聚合封禁（不展开刷屏）。
func (e *Enforcer) Block(ctx context.Context, rawTarget, rawSourceIP, reason string) (*BlockActionResult, error) {
	if isRuleSetImportInput(rawTarget) {
		return e.ImportAndBlockRuleSet(ctx, rawTarget, "", rawSourceIP, reason)
	}

	normTarget, _, err := ValidateTargetSafety(e.cfg, rawTarget)
	if err != nil {
		return nil, err
	}

	normSource := ""
	if strings.TrimSpace(rawSourceIP) != "" {
		normSource = singbox.NormalizeSourceIPCIDR(rawSourceIP)
		if normSource == "" {
			return nil, fmt.Errorf("无效的源设备 IP 格式: %q", rawSourceIP)
		}
	}

	displayTarget := strings.TrimSuffix(strings.TrimSuffix(normTarget, "/32"), "/128")
	displaySource := strings.TrimSuffix(strings.TrimSuffix(normSource, "/32"), "/128")
	reason = cmp.Or(strings.TrimSpace(reason), "设备行为审计手动拉黑")

	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
	oldEffective := singbox.EffectiveBlockRules(e.cfg)

	// 幂等检查：若已存在相同 (Target, SourceIP) 则更新原因与时间，否则追加
	found := false
	for i := range e.cfg.CustomRules.Block {
		t, _ := singbox.NormalizeBlockTarget(e.cfg.CustomRules.Block[i].Target)
		s := singbox.NormalizeSourceIPCIDR(e.cfg.CustomRules.Block[i].SourceIP)
		if t == normTarget && s == normSource {
			e.cfg.CustomRules.Block[i].Target = displayTarget
			e.cfg.CustomRules.Block[i].SourceIP = displaySource
			e.cfg.CustomRules.Block[i].Reason = reason
			found = true
			break
		}
	}
	if !found {
		e.cfg.CustomRules.Block = append(e.cfg.CustomRules.Block, config.BlockRule{
			Target:    displayTarget,
			SourceIP:  displaySource,
			Reason:    reason,
			CreatedAt: time.Now().Format(time.RFC3339),
		})
	}

	res := &BlockActionResult{
		Target:   displayTarget,
		SourceIP: displaySource,
	}

	// 1. 持久化至 singctl.yaml (0600 权限)
	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.CustomRules.Block = oldBlocks
			return nil, fmt.Errorf("保存黑名单至 %s 失败: %w", e.configPath, err)
		}
		res.ConfigSaved = true
	}

	newEffective := singbox.EffectiveBlockRules(e.cfg)

	// 2. 同步至自建 DNS (AdGuard Home)
	dnsApplied, dnsMode, _ := e.syncDNSLayer(ctx, newEffective)
	res.DNSBlocked = dnsApplied
	res.DNSMode = dnsMode

	// 3. 两阶段原子热更新 sing-box config.json
	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldEffective, newEffective); sbErr == nil && sbApplied {
		res.SingBoxSynced = true
	}

	// 4. 实时斩断该目标的所有存量活跃连接
	res.KilledConnections = e.killMatchingConnections(ctx, displayTarget, displaySource)

	res.Message = fmt.Sprintf("已将 %s 加入双层黑名单 (Sing-Box 路由阻断=%v, DNS 黑名单=%v, 斩断活跃连接=%d 条)",
		displayTarget, res.SingBoxSynced, res.DNSBlocked, res.KilledConnections)
	return res, nil
}

// Unblock 从 Sing-Box 与自建 AdGuard Home DNS 黑名单中移除指定目标。
func (e *Enforcer) Unblock(ctx context.Context, rawTarget, rawSourceIP string) (*BlockActionResult, error) {
	normTarget, _ := singbox.NormalizeBlockTarget(rawTarget)
	if normTarget == "" {
		return nil, fmt.Errorf("无效的解封目标: %q", rawTarget)
	}
	normSource := singbox.NormalizeSourceIPCIDR(rawSourceIP)
	if normSource == "" && singbox.IsBuiltinPCDNTarget(normTarget) {
		return e.SetPCDNBlock(ctx, false)
	}
	displayTarget := strings.TrimSuffix(strings.TrimSuffix(normTarget, "/32"), "/128")
	displaySource := strings.TrimSuffix(strings.TrimSuffix(normSource, "/32"), "/128")

	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
	oldEffective := singbox.EffectiveBlockRules(e.cfg)
	kept := make([]config.BlockRule, 0, len(oldBlocks))
	removed := 0
	for _, b := range oldBlocks {
		t, _ := singbox.NormalizeBlockTarget(b.Target)
		s := singbox.NormalizeSourceIPCIDR(b.SourceIP)
		// 当未指定 sourceIP 时，移除该目标下的所有全局及按设备规则；指定时仅精确移除
		if t == normTarget && (normSource == "" || s == normSource) {
			removed++
			continue
		}
		kept = append(kept, b)
	}
	if removed == 0 {
		return nil, fmt.Errorf("未在黑名单中找到目标: %s", displayTarget)
	}

	e.cfg.CustomRules.Block = kept
	res := &BlockActionResult{
		Target:   displayTarget,
		SourceIP: displaySource,
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.CustomRules.Block = oldBlocks
			return nil, fmt.Errorf("更新配置文件 %s 失败: %w", e.configPath, err)
		}
		res.ConfigSaved = true
	}

	newEffective := singbox.EffectiveBlockRules(e.cfg)

	dnsApplied, dnsMode, _ := e.syncDNSLayer(ctx, newEffective)
	res.DNSBlocked = dnsApplied
	res.DNSMode = dnsMode

	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldEffective, newEffective); sbErr == nil && sbApplied {
		res.SingBoxSynced = true
	}

	res.Message = fmt.Sprintf("已将 %s 从双层黑名单解封 (移除 %d 条规则)", displayTarget, removed)
	return res, nil
}

// WhitelistAdd 将指定域名或 IP/CIDR 加入客户端审计信任白名单（持久化至 singctl.yaml，权限 0600）。
func (e *Enforcer) WhitelistAdd(rawTarget string) (string, error) {
	normTarget, isIP := singbox.NormalizeBlockTarget(rawTarget)
	if normTarget == "" {
		return "", fmt.Errorf("无效的白名单目标: %q", rawTarget)
	}
	if strings.ContainsAny(normTarget, " \t\r\n;|&$`\"'<>") {
		return "", fmt.Errorf("目标包含非法字符: %q", rawTarget)
	}
	if !isIP && !isValidAuditDomain(normTarget) {
		return "", fmt.Errorf("无效的白名单域名或 IP/CIDR: %q", rawTarget)
	}
	displayTarget := strings.TrimSuffix(strings.TrimSuffix(normTarget, "/32"), "/128")

	oldList := slices.Clone(e.cfg.Audit.Whitelist)
	exists := slices.ContainsFunc(e.cfg.Audit.Whitelist, func(item string) bool {
		t, _ := singbox.NormalizeBlockTarget(item)
		return t == normTarget || strings.EqualFold(strings.TrimSpace(item), displayTarget)
	})
	if !exists {
		e.cfg.Audit.Whitelist = append(e.cfg.Audit.Whitelist, displayTarget)
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.Audit.Whitelist = oldList
			return "", fmt.Errorf("保存信任白名单至 %s 失败: %w", e.configPath, err)
		}
	}
	return displayTarget, nil
}

// WhitelistRemove 从客户端审计信任白名单中移除指定域名或 IP/CIDR（持久化至 singctl.yaml，权限 0600）。
func (e *Enforcer) WhitelistRemove(rawTarget string) (string, error) {
	normTarget, _ := singbox.NormalizeBlockTarget(rawTarget)
	trimmed := strings.ToLower(strings.TrimSpace(rawTarget))
	if normTarget == "" && trimmed == "" {
		return "", fmt.Errorf("无效的白名单目标: %q", rawTarget)
	}
	displayTarget := cmp.Or(strings.TrimSuffix(strings.TrimSuffix(normTarget, "/32"), "/128"), trimmed)

	oldList := slices.Clone(e.cfg.Audit.Whitelist)
	kept := make([]string, 0, len(oldList))
	removed := 0
	for _, item := range oldList {
		t, _ := singbox.NormalizeBlockTarget(item)
		if (normTarget != "" && t == normTarget) || strings.EqualFold(strings.TrimSpace(item), displayTarget) {
			removed++
			continue
		}
		kept = append(kept, item)
	}
	if removed == 0 {
		return "", fmt.Errorf("未在信任白名单中找到目标: %s", displayTarget)
	}

	e.cfg.Audit.Whitelist = kept
	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.Audit.Whitelist = oldList
			return "", fmt.Errorf("更新配置文件 %s 失败: %w", e.configPath, err)
		}
	}
	return displayTarget, nil
}

func blockedRuleSetSummaryPath(tag string) string {
	return filepath.Join(os.TempDir(), "singctl-block-rs-"+singbox.SanitizeRuleSetTag(tag)+".json")
}

// ImportAndBlockRuleSet 从远程 URL (.srs 二进制或 .json 源码) 或本地预设规则集导入并整包封禁。
// 在黑名单列表中仅生成 1 条 "ruleset:<tag>" 聚合记录，绝不展开刷屏。
func (e *Enforcer) ImportAndBlockRuleSet(ctx context.Context, rawInput, customTag, rawSourceIP, reason string) (*BlockActionResult, error) {
	spec, err := parseRuleSetImportSpec(rawInput, customTag, rawSourceIP)
	if err != nil {
		return nil, err
	}
	if spec.tag == singbox.BuiltinPCDNRuleSetTag && spec.normSource == "" {
		return e.SetPCDNBlock(ctx, true)
	}

	ruleSetDir := e.ruleSetDir()
	_ = os.MkdirAll(ruleSetDir, 0755)
	dstSRSPath := filepath.Join(ruleSetDir, spec.tag+".srs")

	rawData, err := e.fetchRuleSetPayload(ctx, spec, dstSRSPath)
	if err != nil {
		return nil, err
	}
	srsBytes, parsed, isJSON, err := compileOrDecompileRuleSet(ctx, rawData, e.activeSingBoxBin())
	if err != nil {
		return nil, err
	}
	ruleCount, samples, err := validateDecompiledRuleSetSafety(e.cfg, spec.tag, &parsed)
	if err != nil {
		return nil, err
	}
	if err := persistImportedRuleSetFiles(ruleSetDir, dstSRSPath, spec, srsBytes, isJSON, &parsed); err != nil {
		return nil, err
	}

	displayTarget := "ruleset:" + spec.tag
	preview := strings.Join(samples, ", ")
	if ruleCount > len(samples) && preview != "" {
		preview += fmt.Sprintf(" 等共 %d 条", ruleCount)
	}
	if strings.TrimSpace(reason) == "" || reason == "WebUI 手动拉黑" {
		if appLabel, ok := ruleSetAppDisplayNames[spec.tag]; ok {
			reason = "规则集整包封禁: " + appLabel
		} else {
			reason = "规则集整包封禁 (" + spec.tag + ")"
		}
	}

	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
	oldEffective := singbox.EffectiveBlockRules(e.cfg)
	found := false
	for i := range e.cfg.CustomRules.Block {
		t, _ := singbox.NormalizeBlockTarget(e.cfg.CustomRules.Block[i].Target)
		s := singbox.NormalizeSourceIPCIDR(e.cfg.CustomRules.Block[i].SourceIP)
		if t == displayTarget && s == spec.normSource {
			e.cfg.CustomRules.Block[i].Target = displayTarget
			e.cfg.CustomRules.Block[i].SourceIP = spec.displaySource
			e.cfg.CustomRules.Block[i].Reason = reason
			e.cfg.CustomRules.Block[i].RuleSetURL = spec.sourceURL
			e.cfg.CustomRules.Block[i].RuleCount = ruleCount
			e.cfg.CustomRules.Block[i].Preview = preview
			found = true
			break
		}
	}
	if !found {
		e.cfg.CustomRules.Block = append(e.cfg.CustomRules.Block, config.BlockRule{
			Target:     displayTarget,
			SourceIP:   spec.displaySource,
			Reason:     reason,
			RuleSetURL: spec.sourceURL,
			RuleCount:  ruleCount,
			Preview:    preview,
			CreatedAt:  time.Now().Format(time.RFC3339),
		})
	}

	res := &BlockActionResult{
		Target:   displayTarget,
		SourceIP: spec.displaySource,
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.CustomRules.Block = oldBlocks
			return nil, fmt.Errorf("保存黑名单至 %s 失败: %w", e.configPath, err)
		}
		res.ConfigSaved = true
	}

	newEffective := singbox.EffectiveBlockRules(e.cfg)
	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldEffective, newEffective); sbErr == nil && sbApplied {
		res.SingBoxSynced = true
	}

	res.KilledConnections = e.killMatchingRuleSetConnections(ctx, &parsed, spec.displaySource)
	res.Message = fmt.Sprintf("已导入并封禁规则集 %s (含 %d 条规则, Sing-Box 原生阻断=%v, 斩断活跃连接=%d 条)",
		spec.tag, ruleCount, res.SingBoxSynced, res.KilledConnections)
	return res, nil
}

func (e *Enforcer) ruleSetDir() string {
	dir := filepath.Dir(e.sbConfigPath)
	if dir == "" || dir == "." {
		dir = constant.SingBoxConfigDir
	}
	return filepath.Join(dir, "rule_sets")
}

// SetPCDNBlock 一键开启或关闭内置默认防 PCDN 规则集（持久化至 singctl.yaml 并热重载 sing-box）。
func (e *Enforcer) SetPCDNBlock(ctx context.Context, enabled bool) (*BlockActionResult, error) {
	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
	oldPCDN := e.cfg.Audit.PCDNBlock
	oldEffective := singbox.EffectiveBlockRules(e.cfg)

	e.cfg.Audit.SetPCDNBlock(enabled)
	if !enabled && len(e.cfg.CustomRules.Block) > 0 {
		kept := make([]config.BlockRule, 0, len(e.cfg.CustomRules.Block))
		for _, b := range e.cfg.CustomRules.Block {
			norm, _ := singbox.NormalizeBlockTarget(b.Target)
			if singbox.IsBuiltinPCDNTarget(norm) && strings.TrimSpace(b.SourceIP) == "" {
				continue
			}
			kept = append(kept, b)
		}
		e.cfg.CustomRules.Block = kept
	}
	if enabled && e.sbConfigPath != "" {
		_, _, _ = singbox.EnsureBuiltinPCDNRuleSetFile(ctx, e.ruleSetDir())
	}

	res := &BlockActionResult{
		Target: singbox.BuiltinPCDNRuleSetTarget,
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.CustomRules.Block = oldBlocks
			e.cfg.Audit.PCDNBlock = oldPCDN
			return nil, fmt.Errorf("保存防 PCDN 开关至 %s 失败: %w", e.configPath, err)
		}
		res.ConfigSaved = true
	}

	newEffective := singbox.EffectiveBlockRules(e.cfg)
	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldEffective, newEffective); sbErr == nil && sbApplied {
		res.SingBoxSynced = true
	} else if sbErr != nil && e.sbConfigPath != "" {
		// 配置已保存，sing-box 同步失败时不静默吞掉
		res.Message = fmt.Sprintf("防 PCDN 状态已保存，但 sing-box 同步异常: %v", sbErr)
		return res, sbErr
	}

	if enabled {
		res.KilledConnections = e.killMatchingBuiltinPCDNConnections(ctx)
		res.Message = fmt.Sprintf("已开启内置防 PCDN 拦截 (%d 组调度与拉流域名, Sing-Box 原生阻断=%v, 斩断存量连接=%d 条)",
			len(singbox.BuiltinPCDNDomainSuffixes), res.SingBoxSynced, res.KilledConnections)
	} else {
		res.Message = fmt.Sprintf("已关闭内置防 PCDN 拦截 (Sing-Box 已移除规则=%v)", res.SingBoxSynced)
	}
	return res, nil
}

// EnsureDefaultPCDNBlock 在守护进程或 WebUI 启动后幂等检查并将默认开启的防 PCDN 规则集同步到现有 sing-box 配置。
func (e *Enforcer) EnsureDefaultPCDNBlock(ctx context.Context) (bool, error) {
	if e == nil || e.cfg == nil || !e.cfg.Audit.IsPCDNBlockEnabled() || e.sbConfigPath == "" {
		return false, nil
	}
	rawBytes, err := os.ReadFile(e.sbConfigPath)
	if err != nil {
		return false, nil
	}
	if hasActiveBuiltinPCDNRuleSet(rawBytes) {
		return false, nil
	}

	_, _, _ = singbox.EnsureBuiltinPCDNRuleSetFile(ctx, e.ruleSetDir())
	oldWithoutBuiltin := make([]config.BlockRule, 0, len(e.cfg.CustomRules.Block)+1)
	oldWithoutBuiltin = append(oldWithoutBuiltin, singbox.BuiltinPCDNBlockRule())
	for _, b := range e.cfg.CustomRules.Block {
		norm, _ := singbox.NormalizeBlockTarget(b.Target)
		if singbox.IsBuiltinPCDNTarget(norm) && strings.TrimSpace(b.SourceIP) == "" {
			continue
		}
		oldWithoutBuiltin = append(oldWithoutBuiltin, b)
	}
	newWithBuiltin := singbox.EffectiveBlockRules(e.cfg)
	sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldWithoutBuiltin, newWithBuiltin)
	if sbErr != nil {
		return false, sbErr
	}
	if sbApplied {
		_ = e.killMatchingBuiltinPCDNConnections(ctx)
	}
	return sbApplied, nil
}

func (e *Enforcer) killMatchingBuiltinPCDNConnections(ctx context.Context) int {
	var parsed decompiledSRS
	if err := json.Unmarshal(singbox.BuiltinPCDNRuleSetJSON(), &parsed); err != nil {
		return 0
	}
	return e.killMatchingRuleSetConnections(ctx, &parsed, "")
}

func hasActiveBuiltinPCDNRuleSet(rawBytes []byte) bool {
	var root struct {
		DNS *struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
		Route struct {
			RuleSet []map[string]any `json:"rule_set"`
			Rules   []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(rawBytes, &root); err != nil {
		return false
	}

	hasDef := false
	for _, rs := range root.Route.RuleSet {
		tag, _ := rs["tag"].(string)
		if tag != singbox.BuiltinPCDNRuleSetTag {
			continue
		}
		typ, _ := rs["type"].(string)
		switch typ {
		case "local":
			pathStr, _ := rs["path"].(string)
			if pathStr != "" && singbox.IsBuiltinPCDNRuleSetFileCurrent(pathStr) {
				hasDef = true
			}
		case "inline":
			if rulesArr, ok := rs["rules"].([]any); ok && len(rulesArr) > 0 {
				if firstRule, ok := rulesArr[0].(map[string]any); ok {
					if ds, ok := firstRule["domain_suffix"].([]any); ok && len(ds) == len(singbox.BuiltinPCDNDomainSuffixes) {
						hasDef = true
					}
				}
			}
		}
	}
	if !hasDef {
		return false
	}

	ruleMatchesBuiltin := func(rules []map[string]any) bool {
		for _, r := range rules {
			act, _ := r["action"].(string)
			if act != "reject" {
				continue
			}
			if _, hasSrc := r["source_ip_cidr"]; hasSrc {
				continue
			}
			switch rs := r["rule_set"].(type) {
			case string:
				if rs == singbox.BuiltinPCDNRuleSetTag {
					return true
				}
			case []any:
				for _, item := range rs {
					if s, ok := item.(string); ok && s == singbox.BuiltinPCDNRuleSetTag {
						return true
					}
				}
			}
		}
		return false
	}

	if !ruleMatchesBuiltin(root.Route.Rules) {
		return false
	}
	if root.DNS != nil && !ruleMatchesBuiltin(root.DNS.Rules) {
		return false
	}
	return true
}

func (e *Enforcer) syncDNSLayer(ctx context.Context, blocks []config.BlockRule) (bool, string, error) {
	if e.aghConfigPath != "" && e.aghConfigPath != constant.AdGuardConfigFile {
		// 测试指定了自定义 AdGuardHome.yaml 路径时直接同步该 YAML 文件
		if _, err := os.Stat(e.aghConfigPath); err == nil {
			_, syncErr := adguard.SyncUserBlockRulesYAML(e.aghConfigPath, blocks)
			return syncErr == nil, "yaml_file", syncErr
		}
		return false, "not_installed", nil
	}
	mgr := adguard.NewManager(e.cfg, e.configPath)
	return mgr.SyncBlockRules(ctx, blocks)
}

// syncSingBoxLayer 遵循规则 02（两阶段原子切换 + 预校验 + 自动回滚）：
// 在校验通过后原子替换主配置（及存在时的沙盒运行时配置）并发送 SIGHUP 热重载。
func (e *Enforcer) syncSingBoxLayer(ctx context.Context, oldBlocks, newBlocks []config.BlockRule) (bool, error) {
	if e.sbConfigPath == "" {
		return false, nil
	}
	rawBytes, err := os.ReadFile(e.sbConfigPath)
	if err != nil {
		return false, err
	}

	updatedJSON, err := singbox.SyncBlockRulesInConfigJSON(string(rawBytes), oldBlocks, newBlocks)
	if err != nil {
		return false, err
	}

	if err := singbox.ApplyLiveSingBoxConfig(ctx, e.sbConfigPath, e.sbWorkConfigPath, updatedJSON, "audit"); err != nil {
		return false, err
	}
	if baseRaw, bErr := singbox.LoadBaseSnapshot(e.sbConfigPath); bErr == nil && strings.TrimSpace(baseRaw) != "" {
		if updatedBase, uErr := singbox.SyncBlockRulesInConfigJSON(baseRaw, oldBlocks, newBlocks); uErr == nil {
			_ = singbox.SaveBaseSnapshot(e.sbConfigPath, updatedBase)
		}
	}
	return true, nil
}

// killMatchingConnections 遍历 Clash API /connections，将所有命中被拉黑目标的存量活跃连接立即调用 DELETE /connections/{id} 斩断。
func (e *Enforcer) killMatchingConnections(ctx context.Context, targetPlain, sourcePlain string) int {
	targetPrefix, targetIsIPPrefix := parseAuditIPPrefix(targetPlain)
	return e.killConnectionsMatching(ctx, sourcePlain, func(host, destIP string) bool {
		if destIP == targetPlain || host == targetPlain || strings.HasSuffix(host, "."+targetPlain) {
			return true
		}
		if targetIsIPPrefix {
			if addr, parseErr := netip.ParseAddr(destIP); parseErr == nil {
				return targetPrefix.Contains(addr.Unmap())
			}
			if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
				return targetPrefix.Contains(addr.Unmap())
			}
		}
		return false
	})
}

func matchDecompiledRuleSet(parsed *decompiledSRS, host, destIP string) bool {
	if parsed == nil {
		return false
	}
	host = strings.ToLower(strings.TrimSpace(host))
	destIP = strings.TrimSpace(destIP)
	parsedIP := net.ParseIP(destIP)
	if parsedIP == nil && net.ParseIP(host) != nil {
		parsedIP = net.ParseIP(host)
	}

	for _, r := range parsed.Rules {
		if host != "" {
			for _, d := range r.Domain {
				if strings.EqualFold(host, strings.TrimSpace(d)) {
					return true
				}
			}
			for _, ds := range r.DomainSuffix {
				s := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ds), "."))
				if s != "" && (host == s || strings.HasSuffix(host, "."+s)) {
					return true
				}
			}
			for _, kw := range r.DomainKeyword {
				k := strings.ToLower(strings.TrimSpace(kw))
				if k != "" && strings.Contains(host, k) {
					return true
				}
			}
		}
		if parsedIP != nil {
			for _, cidr := range r.IPCIDR {
				if _, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr)); err == nil && ipNet != nil && ipNet.Contains(parsedIP) {
					return true
				}
			}
		}
	}
	return false
}

func loadBlockedRuleSetSummary(tag string) *decompiledSRS {
	data, err := os.ReadFile(blockedRuleSetSummaryPath(tag))
	if err != nil || len(data) == 0 {
		return nil
	}
	var parsed decompiledSRS
	if json.Unmarshal(data, &parsed) != nil {
		return nil
	}
	return &parsed
}

func (e *Enforcer) killMatchingRuleSetConnections(ctx context.Context, parsed *decompiledSRS, sourcePlain string) int {
	if parsed == nil || len(parsed.Rules) == 0 {
		return 0
	}
	return e.killConnectionsMatching(ctx, sourcePlain, func(host, destIP string) bool {
		return matchDecompiledRuleSet(parsed, host, destIP)
	})
}
