// 文件职责：负责审计黑名单对 AdGuard Home DNS 层与 sing-box 路由层的原子同步，以及 Clash 存量活跃连接匹配掐断。
package audit

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"strings"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
)

func (e *Enforcer) killMatchingBuiltinPCDNConnections(ctx context.Context) int {
	var parsed DecompiledSRS
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

func matchDecompiledRuleSet(parsed *DecompiledSRS, host, destIP string) bool {
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

func loadBlockedRuleSetSummary(tag string) *DecompiledSRS {
	data, err := os.ReadFile(blockedRuleSetSummaryPath(tag))
	if err != nil || len(data) == 0 {
		return nil
	}
	var parsed DecompiledSRS
	if json.Unmarshal(data, &parsed) != nil {
		return nil
	}
	return &parsed
}

func (e *Enforcer) killMatchingRuleSetConnections(ctx context.Context, parsed *DecompiledSRS, sourcePlain string) int {
	if parsed == nil || len(parsed.Rules) == 0 {
		return 0
	}
	return e.killConnectionsMatching(ctx, sourcePlain, func(host, destIP string) bool {
		return matchDecompiledRuleSet(parsed, host, destIP)
	})
}
