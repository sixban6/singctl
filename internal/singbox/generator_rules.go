// 文件职责：负责自定义规则与审计黑名单向 sing-box 强类型配置树（*sboption.Document）的编译、锚点注入与在线幂等同步。
//
// 架构设计原则：
//   - 函数式内核（Functional Core）：目标规范化（NormalizeBlockTarget）、规则组编译（compileTypedBlockRules）
//     等纯变换与磁盘配置同步完全隔离。
//   - 类型化锚点定位：统一复用 sboption/rule_anchors.go 定位 DNS 与路由插入点，杜绝手写下标扫描分叉。
package singbox

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

func hasAnyCustomRules(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	blocks := EffectiveBlockRules(cfg)
	return len(blocks) > 0 ||
		len(cfg.Audit.DirectDevices) > 0 ||
		len(cfg.CustomRules.Outbounds) > 0 ||
		len(cfg.CustomRules.DNS) > 0 ||
		len(cfg.CustomRules.Route) > 0
}

// InjectCustomRules 将 singctl.yaml 中声明的 custom_rules 注入到生成的 sing-box 配置中。
func (g *ConfigGenerator) InjectCustomRules(rawJSON string) (string, error) {
	return g.InjectCustomRulesForPlatform(rawJSON, "")
}

// InjectCustomRulesForPlatform 按目标平台注入 custom_rules。
func (g *ConfigGenerator) InjectCustomRulesForPlatform(rawJSON, platform string) (string, error) {
	if g == nil || !hasAnyCustomRules(g.config) {
		return rawJSON, nil
	}

	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse config JSON for custom rules: %w", err)
	}
	if err := applyCustomRulesToDoc(g.config, doc, platform); err != nil {
		return "", err
	}
	out, err := doc.MarshalCompact()
	if err != nil {
		return "", fmt.Errorf("failed to marshal config JSON with custom rules: %w", err)
	}
	return out, nil
}

// applyCustomRulesToDoc 直接在 *sboption.Document 上注入 custom_rules 与生效黑名单（供单树编译流水线复用）。
func applyCustomRulesToDoc(cfg *config.Config, doc *sboption.Document, platform string) error {
	if cfg == nil || doc == nil {
		return nil
	}
	blocks := EffectiveBlockRules(cfg)

	if len(cfg.CustomRules.Outbounds) > 0 {
		if err := applyCustomOutboundRulesInDoc(doc, cfg.CustomRules.Outbounds); err != nil {
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

	syncBlockRuleSetDefinitionsInDoc(doc, nil, blocks, !isIOS)
	blockDNS, blockRoute := compileTypedBlockRules(blocks)

	customDNS, err := parseCustomDNSRuleMaps(cfg.CustomRules.DNS)
	if err != nil {
		return err
	}
	allDNS := append(blockDNS, customDNS...)
	if len(allDNS) > 0 && doc.DNS != nil {
		idx := sboption.CustomDNSInsertIndex(doc.DNS.Rules)
		doc.DNS.Rules = slices.Insert(doc.DNS.Rules, idx, allDNS...)
	}

	if len(cfg.CustomRules.Route) > 0 && doc.Route != nil {
		customRoute, rErr := parseCustomRouteRuleMaps(cfg.CustomRules.Route)
		if rErr != nil {
			return rErr
		}
		idx := sboption.CustomRouteInsertIndex(doc.Route.Rules)
		doc.Route.Rules = slices.Insert(doc.Route.Rules, idx, customRoute...)
	}
	if len(blockRoute) > 0 && doc.Route != nil {
		idx := sboption.BlockRouteInsertIndex(doc.Route.Rules)
		doc.Route.Rules = slices.Insert(doc.Route.Rules, idx, blockRoute...)
	}
	ApplyDirectDevicesToDoc(doc, cfg.Audit.DirectDevices, platform)
	return nil
}

func parseCustomDNSRuleMaps(items []map[string]any) ([]sboption.DNSRule, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]sboption.DNSRule, 0, len(items))
	for i, m := range items {
		r, err := sboption.ParseDNSRuleMap(m)
		if err != nil {
			return nil, fmt.Errorf("custom_rules.dns[%d]: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parseCustomRouteRuleMaps(items []map[string]any) ([]sboption.RouteRule, error) {
	if len(items) == 0 {
		return nil, nil
	}
	out := make([]sboption.RouteRule, 0, len(items))
	for i, m := range items {
		r, err := sboption.ParseRouteRuleMap(m)
		if err != nil {
			return nil, fmt.Errorf("custom_rules.route[%d]: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// NormalizeBlockTarget 规范化拉黑目标（去除协议头、端口、首尾通配符与空格），并判定其是否为 IP/CIDR。
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
		if _, ipNet, err := net.ParseCIDR(s); err == nil && ipNet != nil {
			return ipNet.String(), true
		}
		s = s[:idx]
	}
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

func compileTypedBlockRules(blocks []config.BlockRule) (dnsRules []sboption.DNSRule, routeRules []sboption.RouteRule) {
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
		var srcList sboption.Listable[string]
		if g.sourceCIDR != "" {
			srcList = sboption.ListOf(g.sourceCIDR)
		}
		if len(g.ruleSets) > 0 {
			dnsRules = append(dnsRules, sboption.DNSRule{
				Action:       "reject",
				RuleSet:      sboption.ListOf(g.ruleSets...),
				SourceIPCIDR: srcList.Clone(),
			})
			routeRules = append(routeRules, sboption.RouteRule{
				Action:       "reject",
				RuleSet:      sboption.ListOf(g.ruleSets...),
				SourceIPCIDR: srcList.Clone(),
			})
		}
		if len(g.domains) > 0 {
			dnsRules = append(dnsRules, sboption.DNSRule{
				Action:       "reject",
				DomainSuffix: sboption.ListOf(g.domains...),
				SourceIPCIDR: srcList.Clone(),
			})
			routeRules = append(routeRules, sboption.RouteRule{
				Action:       "reject",
				DomainSuffix: sboption.ListOf(g.domains...),
				SourceIPCIDR: srcList.Clone(),
			})
		}
		if len(g.ipCIDRs) > 0 {
			routeRules = append(routeRules, sboption.RouteRule{
				Action:       "reject",
				IPCIDR:       sboption.ListOf(g.ipCIDRs...),
				SourceIPCIDR: srcList.Clone(),
			})
		}
	}
	return dnsRules, routeRules
}

// SyncBlockRulesInConfigJSON 在不重新拉取远程订阅的前提下，对现有 sing-box config.json 原地幂等同步黑名单阻断规则。
func SyncBlockRulesInConfigJSON(rawJSON string, oldBlocks, newBlocks []config.BlockRule) (string, error) {
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse config.json: %w", err)
	}

	syncBlockRuleSetDefinitionsInDoc(doc, oldBlocks, newBlocks, true)

	oldDNS, oldRoute := compileTypedBlockRules(oldBlocks)
	newDNS, newRoute := compileTypedBlockRules(newBlocks)

	if doc.DNS != nil {
		doc.DNS.Rules = removeMatchingDNSRules(doc.DNS.Rules, append(oldDNS, newDNS...))
		if len(newDNS) > 0 {
			idx := sboption.CustomDNSInsertIndex(doc.DNS.Rules)
			doc.DNS.Rules = slices.Insert(doc.DNS.Rules, idx, newDNS...)
		}
	}
	if doc.Route != nil {
		doc.Route.Rules = removeMatchingRouteRules(doc.Route.Rules, append(oldRoute, newRoute...))
		if len(newRoute) > 0 {
			idx := sboption.BlockRouteInsertIndex(doc.Route.Rules)
			doc.Route.Rules = slices.Insert(doc.Route.Rules, idx, newRoute...)
		}
	}

	return doc.MarshalPretty()
}

func syncBlockRuleSetDefinitionsInDoc(doc *sboption.Document, oldBlocks, newBlocks []config.BlockRule, allowLocal bool) {
	if doc.Route == nil {
		doc.Route = &sboption.RouteOptions{}
	}

	activeTags := make(map[string]config.BlockRule)
	var activeOrder []string
	for _, b := range newBlocks {
		norm, _ := NormalizeBlockTarget(b.Target)
		if tag, ok := strings.CutPrefix(norm, "ruleset:"); ok && tag != "" {
			if _, exists := activeTags[tag]; !exists {
				activeOrder = append(activeOrder, tag)
			}
			activeTags[tag] = b
		}
	}

	removedBlockTags := make(map[string]bool)
	for _, b := range oldBlocks {
		norm, _ := NormalizeBlockTarget(b.Target)
		if tag, ok := strings.CutPrefix(norm, "ruleset:"); ok && strings.HasPrefix(tag, "block-") {
			if _, stillActive := activeTags[tag]; !stillActive {
				removedBlockTags[tag] = true
			}
		}
	}

	kept := make([]sboption.RuleSet, 0, len(doc.Route.RuleSet)+len(activeTags))
	presentTags := make(map[string]bool)
	for _, item := range doc.Route.RuleSet {
		if removedBlockTags[item.Tag] {
			continue
		}
		if item.Tag == BuiltinPCDNRuleSetTag {
			if _, stillActive := activeTags[item.Tag]; stillActive {
				continue
			}
		}
		presentTags[item.Tag] = true
		kept = append(kept, item)
	}

	for _, tag := range activeOrder {
		if presentTags[tag] {
			continue
		}
		b := activeTags[tag]
		if allowLocal {
			localPath := filepath.Join(RuleSetCacheDir(), tag+".srs")
			if info, err := os.Stat(localPath); err == nil && info.Size() > 16 {
				kept = append(kept, sboption.RuleSet{
					Tag:    tag,
					Type:   "local",
					Format: "binary",
					Path:   localPath,
				})
				continue
			}
		}
		if tag == BuiltinPCDNRuleSetTag {
			kept = append(kept, BuiltinPCDNInlineRuleSet())
			continue
		}
		if u := strings.TrimSpace(b.RuleSetURL); u != "" {
			kept = append(kept, sboption.RuleSet{
				Tag:    tag,
				Type:   "remote",
				Format: "binary",
				URL:    u,
			})
		}
	}

	if len(kept) > 0 {
		doc.Route.RuleSet = kept
	} else if len(removedBlockTags) > 0 {
		doc.Route.RuleSet = nil
	} else if doc.Route.RuleSet != nil {
		doc.Route.RuleSet = kept
	}
}

func removeMatchingDNSRules(existing, toRemove []sboption.DNSRule) []sboption.DNSRule {
	if len(toRemove) == 0 || len(existing) == 0 {
		return existing
	}
	signatures := make(map[string]bool, len(toRemove))
	for _, r := range toRemove {
		if sig, err := sboption.CanonicalJSON(r); err == nil {
			signatures[sig] = true
		}
	}
	kept := make([]sboption.DNSRule, 0, len(existing))
	for _, r := range existing {
		if sig, err := sboption.CanonicalJSON(r); err == nil && signatures[sig] {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

func removeMatchingRouteRules(existing, toRemove []sboption.RouteRule) []sboption.RouteRule {
	if len(toRemove) == 0 || len(existing) == 0 {
		return existing
	}
	signatures := make(map[string]bool, len(toRemove))
	for _, r := range toRemove {
		if sig, err := sboption.CanonicalJSON(r); err == nil {
			signatures[sig] = true
		}
	}
	kept := make([]sboption.RouteRule, 0, len(existing))
	for _, r := range existing {
		if sig, err := sboption.CanonicalJSON(r); err == nil && signatures[sig] {
			continue
		}
		kept = append(kept, r)
	}
	return kept
}

func applyCustomOutboundRulesInDoc(doc *sboption.Document, rules []config.OutboundRule) error {
	if doc == nil || len(doc.Outbounds) == 0 {
		return nil
	}

	var allLeafTags []string
	for _, ob := range doc.Outbounds {
		if ob.Tag != "" && !isNonLeafOutboundType(ob.Type) {
			allLeafTags = append(allLeafTags, ob.Tag)
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

		obIdx := slices.IndexFunc(doc.Outbounds, func(ob sboption.Outbound) bool { return ob.Tag == targetTag })
		if obIdx < 0 {
			log.Warn("custom_rules.outbounds: 未找到目标出站组 [%s]，已跳过", targetTag)
			continue
		}
		targetOb := &doc.Outbounds[obIdx]

		var candidates []string
		if len(rule.Outbounds) > 0 {
			for _, o := range rule.Outbounds {
				if o == "{all}" {
					candidates = append(candidates, allLeafTags...)
				} else if o != "" {
					candidates = append(candidates, o)
				}
			}
		} else {
			for _, s := range targetOb.Outbounds {
				if s != "" {
					candidates = append(candidates, s)
				}
			}
		}

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
			targetOb.Outbounds = slices.Clone(finalMembers)
			if targetOb.Default != "" && len(finalMembers) > 0 && !slices.Contains(finalMembers, targetOb.Default) {
				targetOb.Default = finalMembers[0]
			}
		}

		if rule.URL != "" {
			targetOb.URL = rule.URL
		}
		if rule.Interval != "" {
			targetOb.Interval = rule.Interval
		}
		if rule.Tolerance > 0 {
			targetOb.Tolerance = rule.Tolerance
		}
		if rule.InterruptExistConnections != nil {
			targetOb.InterruptExistConnections = new(*rule.InterruptExistConnections)
		}
		if rule.Default != "" {
			if slices.Contains(finalMembers, rule.Default) || len(finalMembers) == 0 {
				targetOb.Default = rule.Default
			} else {
				log.Warn("custom_rules.outbounds [%s]: 指定的 default=%q 不在候选节点池中，已忽略", targetTag, rule.Default)
			}
		}
	}

	return nil
}
