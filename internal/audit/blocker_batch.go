// 文件职责：提供审计黑名单原子批量封禁（单次落盘、单次 sing-box/DNS 热重载与存量活跃连接批量斩断）。
package audit

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
)

// BlockBatchItem 描述批量拉黑请求中的单条目标项。
type BlockBatchItem struct {
	Target   string `json:"target"`
	SourceIP string `json:"sourceIp,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// BlockBatchResult 汇总批量拉黑执行结果与各层同步反馈。
type BlockBatchResult struct {
	OK                bool             `json:"ok"`
	Added             int              `json:"added"`
	Skipped           int              `json:"skipped"`
	Failed            int              `json:"failed"`
	ConfigSaved       bool             `json:"configSaved"`
	SingBoxSynced     bool             `json:"singboxSynced"`
	DNSBlocked        bool             `json:"dnsBlocked"`
	DNSMode           string           `json:"dnsMode,omitempty"`
	KilledConnections int              `json:"killedConnections"`
	Applied           []BlockBatchItem `json:"applied,omitempty"`
	Errors            []string         `json:"errors,omitempty"`
	Message           string           `json:"message"`
}

// BlockBatch 一次性原子拉黑多条目标并仅执行一次配置落盘、DNS 同步与 sing-box 热重载。
func (e *Enforcer) BlockBatch(ctx context.Context, items []BlockBatchItem) (*BlockBatchResult, error) {
	if len(items) == 0 {
		return nil, errors.New("批量拉黑列表不能为空")
	}

	oldBlocks := slices.Clone(e.cfg.CustomRules.Block)
	oldEffective := singbox.EffectiveBlockRules(e.cfg)

	type pendingRule struct {
		normTarget    string
		normSource    string
		displayTarget string
		displaySource string
		reason        string
	}

	seenInBatch := make(map[string]struct{}, len(items))
	var validRules []pendingRule
	var errs []string
	skipped := 0

	for _, item := range items {
		rawTarget := strings.TrimSpace(item.Target)
		if rawTarget == "" || isRuleSetImportInput(rawTarget) {
			errs = append(errs, fmt.Sprintf("不支持批量导入规则集或空目标: %q", item.Target))
			continue
		}
		normTarget, _, err := ValidateTargetSafety(e.cfg, rawTarget)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rawTarget, err))
			continue
		}
		normSource := ""
		if strings.TrimSpace(item.SourceIP) != "" {
			normSource = singbox.NormalizeSourceIPCIDR(item.SourceIP)
			if normSource == "" {
				errs = append(errs, fmt.Sprintf("%s: 无效源设备 IP %q", rawTarget, item.SourceIP))
				continue
			}
		}
		dedupKey := normTarget + "|" + normSource
		if _, dup := seenInBatch[dedupKey]; dup {
			skipped++
			continue
		}
		seenInBatch[dedupKey] = struct{}{}
		validRules = append(validRules, pendingRule{
			normTarget:    normTarget,
			normSource:    normSource,
			displayTarget: strings.TrimSuffix(strings.TrimSuffix(normTarget, "/32"), "/128"),
			displaySource: strings.TrimSuffix(strings.TrimSuffix(normSource, "/32"), "/128"),
			reason:        cmp.Or(strings.TrimSpace(item.Reason), "设备行为审计批量拉黑"),
		})
	}

	if len(validRules) == 0 {
		return nil, fmt.Errorf("未通过安全校验，无法执行批量拉黑: %s", strings.Join(errs, "; "))
	}

	nowStr := time.Now().Format(time.RFC3339)
	applied := make([]BlockBatchItem, 0, len(validRules))
	for _, r := range validRules {
		found := false
		for i := range e.cfg.CustomRules.Block {
			t, _ := singbox.NormalizeBlockTarget(e.cfg.CustomRules.Block[i].Target)
			s := singbox.NormalizeSourceIPCIDR(e.cfg.CustomRules.Block[i].SourceIP)
			if t == r.normTarget && s == r.normSource {
				e.cfg.CustomRules.Block[i].Target = r.displayTarget
				e.cfg.CustomRules.Block[i].SourceIP = r.displaySource
				e.cfg.CustomRules.Block[i].Reason = r.reason
				found = true
				break
			}
		}
		if !found {
			e.cfg.CustomRules.Block = append(e.cfg.CustomRules.Block, config.BlockRule{
				Target:    r.displayTarget,
				SourceIP:  r.displaySource,
				Reason:    r.reason,
				CreatedAt: nowStr,
			})
		}
		applied = append(applied, BlockBatchItem{
			Target:   r.displayTarget,
			SourceIP: r.displaySource,
			Reason:   r.reason,
		})
	}

	res := &BlockBatchResult{
		OK:      true,
		Added:   len(applied),
		Skipped: skipped,
		Failed:  len(errs),
		Applied: applied,
		Errors:  errs,
	}

	if e.configPath != "" {
		if err := config.Save(e.configPath, e.cfg); err != nil {
			e.cfg.CustomRules.Block = oldBlocks
			return nil, fmt.Errorf("批量保存黑名单至 %s 失败: %w", e.configPath, err)
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

	killed := 0
	for _, r := range applied {
		killed += e.killMatchingConnections(ctx, r.Target, r.SourceIP)
	}
	res.KilledConnections = killed

	res.Message = fmt.Sprintf("已批量拉黑 %d 条目标（跳过重复 %d、受保护拒绝 %d，斩断活跃连接 %d 条）",
		res.Added, res.Skipped, res.Failed, res.KilledConnections)
	return res, nil
}
