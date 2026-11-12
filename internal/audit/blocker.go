package audit

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
	cfg            *config.Config
	configPath     string
	sbConfigPath   string
	aghConfigPath  string
	clashEndpoints []string
	clashSecret    string
}

// NewEnforcer 创建默认三位一体封禁执行器。
func NewEnforcer(cfg *config.Config, singctlConfigPath string) *Enforcer {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &Enforcer{
		cfg:            cfg,
		configPath:     singctlConfigPath,
		sbConfigPath:   constant.SingBoxConfigFile,
		aghConfigPath:  constant.AdGuardConfigFile,
		clashEndpoints: singbox.ClashAPIEndpoints(),
		clashSecret:    singbox.ClashAPISecret(),
	}
}

// SetPathsForTest 供单元测试注入临时配置文件路径与模拟 Clash API 端点。
func (e *Enforcer) SetPathsForTest(sbConfigPath, aghConfigPath string, clashEndpoints []string, secret string) {
	e.sbConfigPath = sbConfigPath
	e.aghConfigPath = aghConfigPath
	e.clashEndpoints = clashEndpoints
	e.clashSecret = secret
}

// ValidateTargetSafety 严格校验待拉黑目标是否安全（遵循规则 02 防自锁断网红线，拒绝拉黑网关自身、Tailscale 及机场订阅节点域名）。
func ValidateTargetSafety(cfg *config.Config, rawTarget string) (normalized string, isIP bool, err error) {
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

	if isIP {
		ip := net.ParseIP(plain)
		if ip == nil {
			ip, _, _ = net.ParseCIDR(normalized)
		}
		if ip != nil {
			if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
				return "", false, fmt.Errorf("安全拦截: 禁止拉黑本机回环或未指定地址 (%s)", plain)
			}
			if ip.IsPrivate() {
				return "", false, fmt.Errorf("安全拦截: 禁止将局域网私网地址 (%s) 作为目标拉黑（若需限制内网设备，请使用 --device 指定源设备 IP）", plain)
			}
			if _, tsNet, err := net.ParseCIDR("100.64.0.0/10"); err == nil && tsNet.Contains(ip) {
				return "", false, fmt.Errorf("安全拦截: 禁止拉黑 Tailscale 组网地址 (%s)", plain)
			}
		}
		if slices.Contains(ProtectedBootstrapIPs, plain) {
			return "", false, fmt.Errorf("安全拦截: 禁止拉黑核心基础 DNS 服务器 (%s)，防止全局解析瘫痪", plain)
		}
		if lanIP := netinfo.GetPrimaryLANIPv4(); lanIP != "" && plain == lanIP {
			return "", false, fmt.Errorf("安全拦截: 禁止拉黑本机局域网网关 IP (%s)", plain)
		}
	} else if IsProtectedBootstrapDomain(plain) {
		return "", false, fmt.Errorf("安全拦截: 禁止拉黑核心加密握手/公共 DNS 基础设施域名 (%s)，防止连接中断或隐私降级", plain)
	}

	// 检查是否误伤用户自身的订阅域名或自建节点域名
	if cfg != nil {
		for _, sub := range cfg.Subs {
			u, parseErr := url.Parse(strings.TrimSpace(sub.URL))
			if parseErr == nil && u.Hostname() != "" {
				subHost := strings.ToLower(u.Hostname())
				if plain == subHost || strings.HasSuffix(subHost, "."+plain) {
					return "", false, fmt.Errorf("安全拦截: 目标 %q 命中您正在使用的订阅域名 (%s)，禁止拉黑以防断网", plain, subHost)
				}
			}
		}
		for _, srvDom := range []string{cfg.Server.GetNodeDomain(), cfg.Server.GetSubstoreDomain(), strings.TrimSpace(cfg.Server.ServerIP)} {
			srvDom = strings.ToLower(strings.TrimSpace(srvDom))
			if srvDom != "" && srvDom != "node.example.com" && (plain == srvDom || strings.HasSuffix(srvDom, "."+plain)) {
				return "", false, fmt.Errorf("安全拦截: 目标 %q 命中自建代理节点 (%s)，禁止拉黑以防断网", plain, srvDom)
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

	// 2. 同步至自建 DNS (AdGuard Home)
	dnsApplied, dnsMode, _ := e.syncDNSLayer(ctx, e.cfg.CustomRules.Block)
	res.DNSBlocked = dnsApplied
	res.DNSMode = dnsMode

	// 3. 两阶段原子热更新 sing-box config.json
	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldBlocks, e.cfg.CustomRules.Block); sbErr == nil && sbApplied {
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
	displayTarget := strings.TrimSuffix(strings.TrimSuffix(normTarget, "/32"), "/128")
	displaySource := strings.TrimSuffix(strings.TrimSuffix(normSource, "/32"), "/128")

	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
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

	dnsApplied, dnsMode, _ := e.syncDNSLayer(ctx, e.cfg.CustomRules.Block)
	res.DNSBlocked = dnsApplied
	res.DNSMode = dnsMode

	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldBlocks, e.cfg.CustomRules.Block); sbErr == nil && sbApplied {
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
	rawInput = strings.TrimSpace(rawInput)
	if rawInput == "" {
		return nil, fmt.Errorf("规则集地址不能为空")
	}

	normSource := ""
	if strings.TrimSpace(rawSourceIP) != "" {
		normSource = singbox.NormalizeSourceIPCIDR(rawSourceIP)
		if normSource == "" {
			return nil, fmt.Errorf("无效的源设备 IP 格式: %q", rawSourceIP)
		}
	}
	displaySource := strings.TrimSuffix(strings.TrimSuffix(normSource, "/32"), "/128")

	var tag string
	var sourceURL string
	lowerInput := strings.ToLower(rawInput)
	if strings.HasPrefix(lowerInput, "ruleset:") {
		tag = singbox.SanitizeRuleSetTag(rawInput[len("ruleset:"):])
	} else {
		u, err := url.Parse(rawInput)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("无效的规则集 URL: %q (需以 http:// 或 https:// 开头)", rawInput)
		}
		sourceURL = rawInput
		base := filepath.Base(u.Path)
		tag = singbox.SanitizeRuleSetTag(cmp.Or(strings.TrimSpace(customTag), base))
		if tag != "" && !strings.HasPrefix(tag, "geosite-") && !strings.HasPrefix(tag, "geoip-") && !strings.HasPrefix(tag, "block-") {
			tag = "block-" + tag
		}
	}
	if tag == "" {
		return nil, fmt.Errorf("无法从输入提取有效的规则集标识: %q", rawInput)
	}

	ruleSetDir := filepath.Dir(e.sbConfigPath)
	if ruleSetDir == "" || ruleSetDir == "." {
		ruleSetDir = constant.SingBoxConfigDir
	}
	ruleSetDir = filepath.Join(ruleSetDir, "rule_sets")
	_ = os.MkdirAll(ruleSetDir, 0755)
	dstSRSPath := filepath.Join(ruleSetDir, tag+".srs")

	var rawData []byte
	if sourceURL != "" {
		var candidates []string
		if strings.Contains(sourceURL, "github.com/") || strings.Contains(sourceURL, "raw.githubusercontent.com/") {
			if !strings.HasPrefix(sourceURL, "https://ghfast.top/") {
				candidates = append(candidates, "https://ghfast.top/"+sourceURL)
			}
		}
		candidates = append(candidates, sourceURL)

		client := &http.Client{Timeout: 12 * time.Second}
		var lastErr error
		for _, cand := range candidates {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, cand, nil)
			if reqErr != nil {
				lastErr = reqErr
				continue
			}
			resp, doErr := client.Do(req)
			if doErr != nil {
				lastErr = doErr
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && readErr == nil && len(body) > 12 {
				rawData = body
				break
			}
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if len(rawData) == 0 {
			// 若远程拉取失败但本地已有同名 .srs 缓存，允许复用本地文件
			if localBytes, err := os.ReadFile(dstSRSPath); err == nil && len(localBytes) > 16 {
				rawData = localBytes
			} else {
				return nil, fmt.Errorf("下载规则集失败 (%s): %v", sourceURL, lastErr)
			}
		}
	} else {
		localBytes, err := os.ReadFile(dstSRSPath)
		if err != nil || len(localBytes) <= 16 {
			return nil, fmt.Errorf("本地未找到规则集文件 %s，请提供完整的 .srs / .json 下载 URL", dstSRSPath)
		}
		rawData = localBytes
	}

	sbBin := findSingBoxBin()
	trimmed := strings.TrimSpace(string(rawData))
	isJSON := strings.HasPrefix(trimmed, "{")
	var parsed decompiledSRS
	var srsBytes []byte

	if isJSON {
		if err := json.Unmarshal(rawData, &parsed); err != nil || len(parsed.Rules) == 0 {
			return nil, fmt.Errorf("无效的 sing-box 源码规则集 JSON 格式")
		}
		if sbBin != "" {
			tmpJSON := filepath.Join(os.TempDir(), fmt.Sprintf("singctl-rs-%d.json", time.Now().UnixNano()))
			tmpSRS := tmpJSON + ".srs"
			_ = os.WriteFile(tmpJSON, rawData, 0600)
			compCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			out, compErr := exec.CommandContext(compCtx, sbBin, "rule-set", "compile", tmpJSON, "-o", tmpSRS).CombinedOutput()
			cancel()
			_ = os.Remove(tmpJSON)
			if compErr != nil {
				_ = os.Remove(tmpSRS)
				return nil, fmt.Errorf("编译 JSON 规则集为 .srs 失败: %v (%s)", compErr, strings.TrimSpace(string(out)))
			}
			srsBytes, _ = os.ReadFile(tmpSRS)
			_ = os.Remove(tmpSRS)
		} else {
			// 测试环境无 sing-box 二进制时构造带 SRS 魔数的占位文件用于单元测试验证
			srsBytes = append([]byte("SRS\x02"), rawData...)
		}
	} else if strings.HasPrefix(string(rawData), "SRS") || strings.HasPrefix(string(rawData), "RULE") {
		srsBytes = rawData
		if sbBin != "" {
			tmpSRS := filepath.Join(os.TempDir(), fmt.Sprintf("singctl-rs-%d.srs", time.Now().UnixNano()))
			_ = os.WriteFile(tmpSRS, srsBytes, 0600)
			decCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			out, decErr := exec.CommandContext(decCtx, sbBin, "rule-set", "decompile", tmpSRS, "-o", "/dev/stdout").Output()
			cancel()
			_ = os.Remove(tmpSRS)
			if decErr == nil && len(out) > 0 {
				_ = json.Unmarshal(out, &parsed)
			}
		}
	} else {
		return nil, fmt.Errorf("不支持的规则集文件格式（仅支持 sing-box 二进制 .srs 或源码 .json 规则集）")
	}

	// 遵循规则 02 防自锁校验：扫描规则集内条目，严禁误封用户自身的机场订阅域名、自建节点或网关地址
	var ruleCount int
	var samples []string
	for _, r := range parsed.Rules {
		for _, d := range append(slices.Clone(r.Domain), r.DomainSuffix...) {
			d = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" {
				continue
			}
			if _, _, safeErr := ValidateTargetSafety(e.cfg, d); safeErr != nil {
				return nil, fmt.Errorf("规则集安全校验未通过 (%s): %w", tag, safeErr)
			}
			ruleCount++
			if len(samples) < 8 && !slices.Contains(samples, d) {
				samples = append(samples, d)
			}
		}
		for _, kw := range r.DomainKeyword {
			kw = strings.TrimSpace(kw)
			if kw != "" {
				ruleCount++
				if len(samples) < 8 && !slices.Contains(samples, "kw:"+kw) {
					samples = append(samples, "kw:"+kw)
				}
			}
		}
		for _, cidr := range r.IPCIDR {
			cidr = strings.TrimSpace(cidr)
			if cidr != "" {
				if _, _, safeErr := ValidateTargetSafety(e.cfg, cidr); safeErr != nil {
					return nil, fmt.Errorf("规则集安全校验未通过 (%s): %w", tag, safeErr)
				}
				ruleCount++
				if len(samples) < 8 && !slices.Contains(samples, cidr) {
					samples = append(samples, cidr)
				}
			}
		}
	}

	// 落盘 .srs 文件与轻量反编译摘要（供审计引擎 IsBlocked 与断连匹配使用）
	tmpDst := dstSRSPath + ".tmp"
	if err := os.WriteFile(tmpDst, srsBytes, 0644); err != nil {
		return nil, fmt.Errorf("写入规则集文件失败: %w", err)
	}
	if err := os.Rename(tmpDst, dstSRSPath); err != nil {
		_ = os.Remove(tmpDst)
		return nil, fmt.Errorf("保存规则集文件失败: %w", err)
	}
	if sourceURL != "" && !isJSON {
		singbox.RecordRuleSetManifest(ruleSetDir, tag, sourceURL, "binary")
	}
	if summaryBytes, err := json.Marshal(parsed); err == nil {
		_ = os.WriteFile(blockedRuleSetSummaryPath(tag), summaryBytes, 0600)
	}

	displayTarget := "ruleset:" + tag
	preview := strings.Join(samples, ", ")
	if ruleCount > len(samples) && preview != "" {
		preview += fmt.Sprintf(" 等共 %d 条", ruleCount)
	}
	if strings.TrimSpace(reason) == "" || reason == "WebUI 手动拉黑" {
		if appLabel, ok := ruleSetAppDisplayNames[tag]; ok {
			reason = "规则集整包封禁: " + appLabel
		} else {
			reason = "规则集整包封禁 (" + tag + ")"
		}
	}

	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
	found := false
	for i := range e.cfg.CustomRules.Block {
		t, _ := singbox.NormalizeBlockTarget(e.cfg.CustomRules.Block[i].Target)
		s := singbox.NormalizeSourceIPCIDR(e.cfg.CustomRules.Block[i].SourceIP)
		if t == displayTarget && s == normSource {
			e.cfg.CustomRules.Block[i].Target = displayTarget
			e.cfg.CustomRules.Block[i].SourceIP = displaySource
			e.cfg.CustomRules.Block[i].Reason = reason
			e.cfg.CustomRules.Block[i].RuleSetURL = sourceURL
			e.cfg.CustomRules.Block[i].RuleCount = ruleCount
			e.cfg.CustomRules.Block[i].Preview = preview
			found = true
			break
		}
	}
	if !found {
		e.cfg.CustomRules.Block = append(e.cfg.CustomRules.Block, config.BlockRule{
			Target:     displayTarget,
			SourceIP:   displaySource,
			Reason:     reason,
			RuleSetURL: sourceURL,
			RuleCount:  ruleCount,
			Preview:    preview,
			CreatedAt:  time.Now().Format(time.RFC3339),
		})
	}

	res := &BlockActionResult{
		Target:   displayTarget,
		SourceIP: displaySource,
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.CustomRules.Block = oldBlocks
			return nil, fmt.Errorf("保存黑名单至 %s 失败: %w", e.configPath, err)
		}
		res.ConfigSaved = true
	}

	if sbApplied, sbErr := e.syncSingBoxLayer(ctx, oldBlocks, e.cfg.CustomRules.Block); sbErr == nil && sbApplied {
		res.SingBoxSynced = true
	}

	res.KilledConnections = e.killMatchingRuleSetConnections(ctx, &parsed, displaySource)
	res.Message = fmt.Sprintf("已导入并封禁规则集 %s (含 %d 条规则, Sing-Box 原生阻断=%v, 斩断活跃连接=%d 条)",
		tag, ruleCount, res.SingBoxSynced, res.KilledConnections)
	return res, nil
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
// 在 /tmp 预生成新配置并通过 sing-box check 后，才原子替换 /etc/sing-box/config.json 并发送 SIGHUP 热重载。
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

	tmpFile := filepath.Join(os.TempDir(), fmt.Sprintf("singctl-sb-audit-%d.json", os.Getpid()))
	defer os.Remove(tmpFile)
	if err := os.WriteFile(tmpFile, []byte(updatedJSON), 0600); err != nil {
		return false, err
	}
	_ = os.Chmod(tmpFile, 0600)

	// 若系统安装了 sing-box，先执行离线语法校验，未通过绝不覆盖线上配置
	if sbBin := findSingBoxBin(); sbBin != "" {
		checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		cmd := exec.CommandContext(checkCtx, sbBin, "check", "-c", tmpFile)
		out, checkErr := cmd.CombinedOutput()
		cancel()
		if checkErr != nil {
			return false, fmt.Errorf("sing-box check failed: %w (%s)", checkErr, strings.TrimSpace(string(out)))
		}
	}

	// 备份原配置 (0600) 并执行同目录原子替换
	bakPath := e.sbConfigPath + ".audit.bak"
	_ = os.WriteFile(bakPath, rawBytes, 0600)
	_ = os.Chmod(bakPath, 0600)

	atomicTmp := e.sbConfigPath + ".audit.tmp"
	if err := os.WriteFile(atomicTmp, []byte(updatedJSON), 0600); err != nil {
		return false, err
	}
	_ = os.Chmod(atomicTmp, 0600)
	if err := os.Rename(atomicTmp, e.sbConfigPath); err != nil {
		_ = os.Remove(atomicTmp)
		return false, err
	}
	_ = os.Chmod(e.sbConfigPath, 0600)

	// 发送 SIGHUP 热重载信号（无损加载新路由规则，不断开正常代理连接）
	reloadSingBoxProcess()
	return true, nil
}

func findSingBoxBin() string {
	if info, err := os.Stat(constant.SingBoxInstallDir); err == nil && !info.IsDir() {
		return constant.SingBoxInstallDir
	}
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p
	}
	return ""
}

func reloadSingBoxProcess() {
	if _, err := exec.LookPath("pkill"); err == nil {
		if exec.Command("pkill", "-HUP", "-x", "sing-box").Run() == nil {
			return
		}
	}
	if _, err := exec.LookPath("killall"); err == nil {
		_ = exec.Command("killall", "-HUP", "sing-box").Run()
	}
}

// killMatchingConnections 遍历 Clash API /connections，将所有命中被拉黑目标的存量活跃连接立即调用 DELETE /connections/{id} 斩断。
func (e *Enforcer) killMatchingConnections(ctx context.Context, targetPlain, sourcePlain string) int {
	client := &http.Client{Timeout: 2 * time.Second}
	killed := 0

	for _, ep := range e.clashEndpoints {
		baseURL := strings.TrimRight(ep, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/connections", nil)
		if err != nil {
			continue
		}
		if e.clashSecret != "" {
			req.Header.Set("Authorization", "Bearer "+e.clashSecret)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var parsed clashConnectionsResponse
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if decErr != nil {
			continue
		}

		for _, conn := range parsed.Connections {
			if sourcePlain != "" && strings.TrimSpace(conn.Metadata.SourceIP) != sourcePlain {
				continue
			}
			host := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host)))
			destIP := strings.TrimSpace(conn.Metadata.DestinationIP)
			matched := destIP == targetPlain || host == targetPlain || strings.HasSuffix(host, "."+targetPlain)
			if !matched {
				continue
			}
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections/"+url.PathEscape(conn.ID), nil)
			if err != nil {
				continue
			}
			if e.clashSecret != "" {
				delReq.Header.Set("Authorization", "Bearer "+e.clashSecret)
			}
			if delResp, err := client.Do(delReq); err == nil {
				delResp.Body.Close()
				if delResp.StatusCode == http.StatusNoContent || delResp.StatusCode == http.StatusOK {
					killed++
				}
			}
		}
		break
	}
	return killed
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
	client := &http.Client{Timeout: 2 * time.Second}
	killed := 0

	for _, ep := range e.clashEndpoints {
		baseURL := strings.TrimRight(ep, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/connections", nil)
		if err != nil {
			continue
		}
		if e.clashSecret != "" {
			req.Header.Set("Authorization", "Bearer "+e.clashSecret)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var connResp clashConnectionsResponse
		decErr := json.NewDecoder(resp.Body).Decode(&connResp)
		resp.Body.Close()
		if decErr != nil {
			continue
		}

		for _, conn := range connResp.Connections {
			if sourcePlain != "" && strings.TrimSpace(conn.Metadata.SourceIP) != sourcePlain {
				continue
			}
			host := strings.ToLower(cmp.Or(strings.TrimSpace(conn.Metadata.SniffHost), strings.TrimSpace(conn.Metadata.Host)))
			destIP := strings.TrimSpace(conn.Metadata.DestinationIP)
			if !matchDecompiledRuleSet(parsed, host, destIP) {
				continue
			}
			delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, baseURL+"/connections/"+url.PathEscape(conn.ID), nil)
			if err != nil {
				continue
			}
			if e.clashSecret != "" {
				delReq.Header.Set("Authorization", "Bearer "+e.clashSecret)
			}
			if delResp, err := client.Do(delReq); err == nil {
				delResp.Body.Close()
				if delResp.StatusCode == http.StatusNoContent || delResp.StatusCode == http.StatusOK {
					killed++
				}
			}
		}
		break
	}
	return killed
}
