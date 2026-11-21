// 文件职责：负责自定义规则与审计黑名单向 sing-box 配置树（custom_rules、rule_set、DNS/Route 规则）的编译与原地注入。
//
// 架构设计原则：
//   - 函数式内核（Functional Core）：目标规范化（NormalizeBlockTarget）、规则组编译（CompileBlockRules）
//     等纯变换与磁盘配置同步完全隔离，便于快速单元测试。
//   - 优先级防绕过设计：审计黑名单阻断规则始终挂载在 clash_mode / sniff / hijack-dns 之后、
//     GeoSite/业务分流规则之前，确保恶意站点无法通过分流规则逃逸。
package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"singctl/internal/config"
	log "singctl/internal/logger"
)

func hasAnyCustomRules(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	blocks := EffectiveBlockRules(cfg)
	return len(blocks) > 0 ||
		len(cfg.CustomRules.Outbounds) > 0 ||
		len(cfg.CustomRules.DNS) > 0 ||
		len(cfg.CustomRules.Route) > 0
}

// InjectCustomRules 将 singctl.yaml 中声明的 custom_rules（出站组定制、DNS 规则、路由规则）
// 注入到生成的 sing-box 配置中，从而在不污染通用 singgen 模板的前提下实现高可维护性的策略扩展。
func (g *ConfigGenerator) InjectCustomRules(rawJSON string) (string, error) {
	return g.InjectCustomRulesForPlatform(rawJSON, "")
}

// InjectCustomRulesForPlatform 按目标平台注入 custom_rules。
// 针对 iOS 平台：跳过局域网设备限定黑名单（SourceIP != ""）与本地物理磁盘规则集（allowLocal = false），
// 防止引入 iPhone 沙盒不可读路径或无效规则引用。
func (g *ConfigGenerator) InjectCustomRulesForPlatform(rawJSON, platform string) (string, error) {
	if g == nil || !hasAnyCustomRules(g.config) {
		return rawJSON, nil
	}

	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config JSON for custom rules: %w", err)
	}
	if err := applyCustomRulesToRoot(g.config, root, platform); err != nil {
		return "", err
	}
	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON with custom rules: %w", err)
	}
	return string(data), nil
}

// applyCustomRulesToRoot 直接在已解析的 JSON 树上注入 custom_rules 与生效黑名单（供单树编译流水线复用）。
func applyCustomRulesToRoot(cfg *config.Config, root map[string]any, platform string) error {
	if cfg == nil || root == nil {
		return nil
	}
	blocks := EffectiveBlockRules(cfg)

	// 1. 注入出站策略组定制与过滤 (custom_rules.outbounds)
	if len(cfg.CustomRules.Outbounds) > 0 {
		if err := applyCustomOutboundRules(root, cfg.CustomRules.Outbounds); err != nil {
			return err
		}
	}

	isIOS := strings.EqualFold(strings.TrimSpace(platform), PlatformIOS)
	if !isIOS {
		for _, b := range blocks {
			if IsBuiltinPCDNTarget(b.Target) {
				_, _, _ = EnsureBuiltinPCDNRuleSetFile(context.Background(), RuleSetCacheDir())
				break
			}
		}
	} else if len(blocks) > 0 {
		// iOS 沙盒没有局域网源 IP 控制语义，且无法访问本地文件系统路径，需要安全过滤
		filtered := make([]config.BlockRule, 0, len(blocks))
		for _, b := range blocks {
			if strings.TrimSpace(b.SourceIP) != "" {
				continue
			}
			norm, _ := NormalizeBlockTarget(b.Target)
			if strings.HasPrefix(norm, "ruleset:") && strings.TrimSpace(b.RuleSetURL) == "" && !IsBuiltinPCDNTarget(norm) {
				continue
			}
			filtered = append(filtered, b)
		}
		blocks = filtered
	}

	// 2. 编译设备审计黑名单规则 (custom_rules.block)，作为最高优先级阻断规则注入
	syncBlockRuleSetDefinitions(root, nil, blocks, !isIOS)
	blockDNS, blockRoute := CompileBlockRules(blocks)

	// 3. 注入 DNS 规则 (custom_rules.block + custom_rules.dns)
	allDNS := append(blockDNS, cfg.CustomRules.DNS...)
	if len(allDNS) > 0 {
		applyCustomDNSRules(root, allDNS)
	}

	// 4. 注入路由规则 (先按标准位置注入 custom_rules.route，再将黑名单阻断规则挂在最前确保最高拦截优先级)
	if len(cfg.CustomRules.Route) > 0 {
		applyCustomRouteRules(root, cfg.CustomRules.Route)
	}
	if len(blockRoute) > 0 {
		applyBlockRouteRules(root, blockRoute)
	}
	return nil
}

// NormalizeBlockTarget 规范化拉黑目标（去除协议头、端口、首尾通配符与空格），并判定其是否为 IP/CIDR。
// 若以 "ruleset:<tag>" 开头，规范化为 "ruleset:<sanitized_tag>"。
func NormalizeBlockTarget(raw string) (cleaned string, isIPOrCIDR bool) {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(s), "ruleset:") {
		tag := SanitizeRuleSetTag(s[len("ruleset:"):])
		if tag == "" {
			return "", false
		}
		if IsBuiltinPCDNTag(tag) {
			tag = BuiltinPCDNRuleSetTag
		}
		return "ruleset:" + tag, false
	}
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		// 保留合法 CIDR（规范化为网络地址），剥离 URL 路径
		if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
			return ipNet.String(), true
		}
		s = s[:idx]
	}
	// 若包含端口 (host:port) 则剥离端口
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	s = strings.Trim(s, "[]")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", false
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + "/32", true
		}
		return ip.String() + "/128", true
	}
	if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
		return ipNet.String(), true
	}
	return s, false
}

// NormalizeSourceIPCIDR 将可选的内网源设备 IP 规范化为 CIDR 表达式（如 192.0.2.55 -> 192.0.2.55/32）。
func NormalizeSourceIPCIDR(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
		return ipNet.String()
	}
	if h, _, err := net.SplitHostPort(s); err == nil && h != "" {
		s = h
	}
	if ip := net.ParseIP(s); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String() + "/32"
		}
		return ip.String() + "/128"
	}
	return ""
}

// SanitizeRuleSetTag 过滤规则集 tag 仅保留字母、数字、连字符与下划线，防路径穿越或命令注入。
func SanitizeRuleSetTag(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimSuffix(raw, ".srs")
	raw = strings.TrimSuffix(raw, ".json")
	var b strings.Builder
	for _, r := range raw {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == '.' || r == ' ' {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

// CompileBlockRules 将语义化 BlockRule 列表编译为 sing-box 原生 DNS 阻断规则与路由阻断规则。
// 按 source_ip_cidr 分组聚合，保证生成的 JSON 紧凑、高效且完全符合 sing-box v1.12+/v1.14 规范。
func CompileBlockRules(blocks []config.BlockRule) (dnsRules []map[string]any, routeRules []map[string]any) {
	if len(blocks) == 0 {
		return nil, nil
	}

	type groupBucket struct {
		sourceCIDR string
		ruleSets   []string
		domains    []string
		ipCIDRs    []string
	}
	var groups []*groupBucket
	bySource := make(map[string]*groupBucket)

	for _, b := range blocks {
		target, isIP := NormalizeBlockTarget(b.Target)
		if target == "" {
			continue
		}
		srcCIDR := NormalizeSourceIPCIDR(b.SourceIP)
		bucket, ok := bySource[srcCIDR]
		if !ok {
			bucket = &groupBucket{sourceCIDR: srcCIDR}
			bySource[srcCIDR] = bucket
			groups = append(groups, bucket)
		}
		if strings.HasPrefix(target, "ruleset:") {
			tag := strings.TrimPrefix(target, "ruleset:")
			if tag != "" && !slices.Contains(bucket.ruleSets, tag) {
				bucket.ruleSets = append(bucket.ruleSets, tag)
			}
		} else if isIP {
			if !slices.Contains(bucket.ipCIDRs, target) {
				bucket.ipCIDRs = append(bucket.ipCIDRs, target)
			}
		} else {
			if !slices.Contains(bucket.domains, target) {
				bucket.domains = append(bucket.domains, target)
			}
		}
	}

	for _, g := range groups {
		if len(g.ruleSets) > 0 {
			dr := map[string]any{"action": "reject", "rule_set": g.ruleSets}
			rr := map[string]any{"action": "reject", "rule_set": g.ruleSets}
			if g.sourceCIDR != "" {
				dr["source_ip_cidr"] = []string{g.sourceCIDR}
				rr["source_ip_cidr"] = []string{g.sourceCIDR}
			}
			dnsRules = append(dnsRules, dr)
			routeRules = append(routeRules, rr)
		}
		if len(g.domains) > 0 {
			dr := map[string]any{"action": "reject", "domain_suffix": g.domains}
			rr := map[string]any{"action": "reject", "domain_suffix": g.domains}
			if g.sourceCIDR != "" {
				dr["source_ip_cidr"] = []string{g.sourceCIDR}
				rr["source_ip_cidr"] = []string{g.sourceCIDR}
			}
			dnsRules = append(dnsRules, dr)
			routeRules = append(routeRules, rr)
		}
		if len(g.ipCIDRs) > 0 {
			rr := map[string]any{"action": "reject", "ip_cidr": g.ipCIDRs}
			if g.sourceCIDR != "" {
				rr["source_ip_cidr"] = []string{g.sourceCIDR}
			}
			routeRules = append(routeRules, rr)
		}
	}
	return dnsRules, routeRules
}

// SyncBlockRulesInConfigJSON 在不重新拉取远程订阅的前提下，对现有 sing-box config.json 原地幂等同步黑名单阻断规则。
func SyncBlockRulesInConfigJSON(rawJSON string, oldBlocks, newBlocks []config.BlockRule) (string, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("failed to parse config.json: %w", err)
	}

	syncBlockRuleSetDefinitions(root, oldBlocks, newBlocks, true)

	oldDNS, oldRoute := CompileBlockRules(oldBlocks)
	newDNS, newRoute := CompileBlockRules(newBlocks)

	// 先从现有规则集中剔除旧的或重复的受管 block 规则
	removeMatchingRules(root, "dns", append(oldDNS, newDNS...))
	removeMatchingRules(root, "route", append(oldRoute, newRoute...))

	// 再注入最新的受管 block 规则
	if len(newDNS) > 0 {
		applyCustomDNSRules(root, newDNS)
	}
	if len(newRoute) > 0 {
		applyBlockRouteRules(root, newRoute)
	}

	data, err := json.Marshal(root)
	if err != nil {
		return "", err
	}
	return PrettyJSON(string(data))
}

func syncBlockRuleSetDefinitions(root map[string]any, oldBlocks, newBlocks []config.BlockRule, allowLocal bool) {
	routeMap, ok := root["route"].(map[string]any)
	if !ok {
		routeMap = make(map[string]any)
		root["route"] = routeMap
	}

	activeTags := make(map[string]config.BlockRule)
	for _, b := range newBlocks {
		norm, _ := NormalizeBlockTarget(b.Target)
		if strings.HasPrefix(norm, "ruleset:") {
			tag := strings.TrimPrefix(norm, "ruleset:")
			if tag != "" {
				activeTags[tag] = b
			}
		}
	}

	removedBlockTags := make(map[string]bool)
	for _, b := range oldBlocks {
		norm, _ := NormalizeBlockTarget(b.Target)
		if strings.HasPrefix(norm, "ruleset:") {
			tag := strings.TrimPrefix(norm, "ruleset:")
			if strings.HasPrefix(tag, "block-") {
				if _, stillActive := activeTags[tag]; !stillActive {
					removedBlockTags[tag] = true
				}
			}
		}
	}

	existingList, _ := routeMap["rule_set"].([]any)
	kept := make([]any, 0, len(existingList)+len(activeTags))
	presentTags := make(map[string]bool)

	for _, item := range existingList {
		m, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		tag, _ := m["tag"].(string)
		if removedBlockTags[tag] {
			continue
		}
		if tag == BuiltinPCDNRuleSetTag {
			if _, stillActive := activeTags[tag]; stillActive {
				continue
			}
		}
		presentTags[tag] = true
		kept = append(kept, item)
	}

	for tag, b := range activeTags {
		if presentTags[tag] {
			continue
		}
		if allowLocal {
			localPath := filepath.Join(RuleSetCacheDir(), tag+".srs")
			if info, err := os.Stat(localPath); err == nil && info.Size() > 16 {
				kept = append(kept, map[string]any{
					"tag":    tag,
					"type":   "local",
					"format": "binary",
					"path":   localPath,
				})
				continue
			}
		}
		if tag == BuiltinPCDNRuleSetTag {
			kept = append(kept, BuiltinPCDNInlineRuleSet())
			continue
		}
		if strings.TrimSpace(b.RuleSetURL) != "" {
			kept = append(kept, map[string]any{
				"tag":    tag,
				"type":   "remote",
				"format": "binary",
				"url":    strings.TrimSpace(b.RuleSetURL),
			})
		}
	}

	if len(kept) > 0 {
		routeMap["rule_set"] = kept
	} else if len(removedBlockTags) > 0 {
		delete(routeMap, "rule_set")
	}
}

func removeMatchingRules(root map[string]any, section string, toRemove []map[string]any) {
	if len(toRemove) == 0 {
		return
	}
	secMap, ok := root[section].(map[string]any)
	if !ok {
		return
	}
	existing, ok := secMap["rules"].([]any)
	if !ok || len(existing) == 0 {
		return
	}
	signatures := make(map[string]struct{}, len(toRemove))
	for _, r := range toRemove {
		if b, err := json.Marshal(r); err == nil {
			signatures[string(b)] = struct{}{}
		}
	}
	kept := make([]any, 0, len(existing))
	for _, item := range existing {
		if b, err := json.Marshal(item); err == nil {
			if _, hit := signatures[string(b)]; hit {
				continue
			}
		}
		kept = append(kept, item)
	}
	secMap["rules"] = kept
}

func applyCustomOutboundRules(root map[string]any, rules []config.OutboundRule) error {
	rawOutbounds, ok := root["outbounds"].([]any)
	if !ok || len(rawOutbounds) == 0 {
		return nil
	}

	// 收集所有底层代理节点 tag，供 custom_rules.outbounds 中使用 "{all}" 展开
	var allLeafTags []string
	for _, item := range rawOutbounds {
		obMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := obMap["tag"].(string)
		obType, _ := obMap["type"].(string)
		if tag == "" {
			continue
		}
		switch obType {
		case "selector", "urltest", "direct", "block", "dns":
			continue
		default:
			allLeafTags = append(allLeafTags, tag)
		}
	}

	for idx, rule := range rules {
		targetTag := strings.TrimSpace(rule.Tag)
		if targetTag == "" {
			return fmt.Errorf("custom_rules.outbounds[%d]: tag is required", idx)
		}

		var includeRe, excludeRe *regexp.Regexp
		var err error
		if rule.Include != "" {
			includeRe, err = regexp.Compile(rule.Include)
			if err != nil {
				return fmt.Errorf("custom_rules.outbounds[%d] (%s): invalid include regex %q: %w", idx, targetTag, rule.Include, err)
			}
		}
		if rule.Exclude != "" {
			excludeRe, err = regexp.Compile(rule.Exclude)
			if err != nil {
				return fmt.Errorf("custom_rules.outbounds[%d] (%s): invalid exclude regex %q: %w", idx, targetTag, rule.Exclude, err)
			}
		}

		var targetMap map[string]any
		for _, item := range rawOutbounds {
			obMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if tag, _ := obMap["tag"].(string); tag == targetTag {
				targetMap = obMap
				break
			}
		}
		if targetMap == nil {
			log.Warn("custom_rules.outbounds: 未找到目标出站组 [%s]，已跳过", targetTag)
			continue
		}

		// 确定基础候选节点列表
		var candidates []string
		if len(rule.Outbounds) > 0 {
			for _, o := range rule.Outbounds {
				if o == "{all}" {
					candidates = append(candidates, allLeafTags...)
				} else if o != "" {
					candidates = append(candidates, o)
				}
			}
		} else if existing, ok := targetMap["outbounds"].([]any); ok {
			for _, item := range existing {
				if s, ok := item.(string); ok && s != "" {
					candidates = append(candidates, s)
				}
			}
		} else if existingStrs, ok := targetMap["outbounds"].([]string); ok {
			candidates = append(candidates, existingStrs...)
		}

		// 执行 include / exclude 正则过滤（带零节点防断网回退保护：若误配全被筛空则保留原池）
		finalMembers := candidates
		if (includeRe != nil || excludeRe != nil) && len(candidates) > 0 {
			filtered := make([]string, 0, len(candidates))
			for _, name := range candidates {
				if excludeRe != nil && excludeRe.MatchString(name) {
					continue
				}
				if includeRe != nil && !includeRe.MatchString(name) {
					continue
				}
				filtered = append(filtered, name)
			}
			if len(filtered) > 0 {
				finalMembers = filtered
				log.Info("自定义出站组 [%s] 节点过滤已生效: 保留 %d 个，剔除 %d 个", targetTag, len(filtered), len(candidates)-len(filtered))
			} else {
				log.Warn("⚠️ 自定义出站组 [%s] 过滤规则未匹配到任何节点，已自动回退保留原节点池 (%d 个)", targetTag, len(candidates))
			}
		}

		if len(rule.Outbounds) > 0 || includeRe != nil || excludeRe != nil {
			memberAny := make([]any, len(finalMembers))
			for i, m := range finalMembers {
				memberAny[i] = m
			}
			targetMap["outbounds"] = memberAny

			// 若原 default 节点被过滤剔除，自动修正避免 sing-box 启动校验失败
			if defTag, ok := targetMap["default"].(string); ok && defTag != "" && len(finalMembers) > 0 {
				if !slices.Contains(finalMembers, defTag) {
					targetMap["default"] = finalMembers[0]
				}
			}
		}

		if rule.URL != "" {
			targetMap["url"] = rule.URL
		}
		if rule.Interval != "" {
			targetMap["interval"] = rule.Interval
		}
		if rule.Tolerance > 0 {
			targetMap["tolerance"] = rule.Tolerance
		}
		if rule.InterruptExistConnections != nil {
			targetMap["interrupt_exist_connections"] = *rule.InterruptExistConnections
		}
		if rule.Default != "" {
			if slices.Contains(finalMembers, rule.Default) || len(finalMembers) == 0 {
				targetMap["default"] = rule.Default
			} else {
				log.Warn("custom_rules.outbounds [%s]: 指定的 default=%q 不在候选节点池中，已忽略", targetTag, rule.Default)
			}
		}
	}

	return nil
}

func applyCustomDNSRules(root map[string]any, customDNS []map[string]any) {
	dnsMap, ok := root["dns"].(map[string]any)
	if !ok {
		return
	}
	var existingRules []any
	if r, ok := dnsMap["rules"].([]any); ok {
		existingRules = r
	}

	// 插入在 clash_mode 与 dns_tailscale 基础规则之后、所有业务/GeoSite 规则之前
	insertIdx := 0
	for i, r := range existingRules {
		rMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		_, hasClashMode := rMap["clash_mode"]
		srv, _ := rMap["server"].(string)
		if hasClashMode || srv == "dns_tailscale" {
			insertIdx = i + 1
		}
	}

	newRules := make([]any, 0, len(existingRules)+len(customDNS))
	newRules = append(newRules, existingRules[:insertIdx]...)
	for _, r := range customDNS {
		newRules = append(newRules, r)
	}
	newRules = append(newRules, existingRules[insertIdx:]...)
	dnsMap["rules"] = newRules
}

// applyBlockRouteRules 将黑名单阻断规则挂载在 route.rules 最前面（紧随 sniff / hijack-dns / ip_is_private / clash_mode 之后，
// 排在所有业务域名与 geosite-hok 等规则集之前），确保黑名单拥有最高拦截优先级。
func applyBlockRouteRules(root map[string]any, blockRoute []map[string]any) {
	routeMap, ok := root["route"].(map[string]any)
	if !ok {
		return
	}
	var existingRules []any
	if r, ok := routeMap["rules"].([]any); ok {
		existingRules = r
	}

	insertIdx := 0
	for i, r := range existingRules {
		rMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		act, _ := rMap["action"].(string)
		_, hasPrivate := rMap["ip_is_private"]
		_, hasClashMode := rMap["clash_mode"]
		if act == "sniff" || act == "hijack-dns" || hasPrivate || hasClashMode {
			insertIdx = i + 1
		}
	}

	newRules := make([]any, 0, len(existingRules)+len(blockRoute))
	newRules = append(newRules, existingRules[:insertIdx]...)
	for _, r := range blockRoute {
		newRules = append(newRules, r)
	}
	newRules = append(newRules, existingRules[insertIdx:]...)
	routeMap["rules"] = newRules
}

func applyCustomRouteRules(root map[string]any, customRoute []map[string]any) {
	routeMap, ok := root["route"].(map[string]any)
	if !ok {
		return
	}
	var existingRules []any
	if r, ok := routeMap["rules"].([]any); ok {
		existingRules = r
	}

	// 优先定位在广告拦截规则 (geosite-ad1) 之前插入（即处于私网/SSH/ClashMode/geosite-hok 之后，
	// 广告拦截与所有 GeoIP/GeoSite 大集合规则之前）；若无 geosite-ad1 则回退到 ip_is_private 之后。
	insertIdx := -1
	privateIdx := -1
	for i, r := range existingRules {
		rMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if _, hasPrivate := rMap["ip_is_private"]; hasPrivate && privateIdx < 0 {
			privateIdx = i + 1
		}
		if ruleSetContains(rMap["rule_set"], "geosite-ad1") {
			insertIdx = i
			break
		}
	}
	if insertIdx < 0 {
		if privateIdx >= 0 {
			insertIdx = privateIdx
		} else {
			insertIdx = len(existingRules)
		}
	}

	newRules := make([]any, 0, len(existingRules)+len(customRoute))
	newRules = append(newRules, existingRules[:insertIdx]...)
	for _, r := range customRoute {
		newRules = append(newRules, r)
	}
	newRules = append(newRules, existingRules[insertIdx:]...)
	routeMap["rules"] = newRules
}

func ruleSetContains(raw any, target string) bool {
	switch v := raw.(type) {
	case string:
		return v == target
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == target {
				return true
			}
		}
	case []string:
		return slices.Contains(v, target)
	}
	return false
}
