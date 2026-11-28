// 文件职责：提供审计页一键切换连接出口规则的增删改、热重载与存量连接即时踢断接口。
package webui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
)

type auditRouteRuleUpsertRequest struct {
	Target           string `json:"target"`
	MatchType        string `json:"matchType,omitempty"`
	Outbound         string `json:"outbound"`
	SourceIP         string `json:"sourceIp,omitempty"`
	Note             string `json:"note,omitempty"`
	ConnTarget       string `json:"connTarget,omitempty"`
	CloseConnections *bool  `json:"closeConnections,omitempty"`
}

type auditRouteRuleDeleteRequest struct {
	Target           string `json:"target"`
	MatchType        string `json:"matchType,omitempty"`
	SourceIP         string `json:"sourceIp,omitempty"`
	CloseConnections *bool  `json:"closeConnections,omitempty"`
}

var (
	tsRouteCGNAT = netip.MustParsePrefix("100.64.0.0/10")
	tsRouteULA6  = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

func validateRouteRuleSafety(rule config.TrafficCustomRule) error {
	if audit.IsProtectedBootstrapDomain(rule.Target) {
		return errors.New("受核心防断网基础设施保护，禁止修改此域名出口")
	}
	if rule.MatchType == config.TrafficMatchIPCIDR {
		pfx, err := netip.ParsePrefix(rule.Target)
		if err != nil {
			return errors.New("无效的 IP/CIDR 目标")
		}
		addr := pfx.Addr().Unmap()
		if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
			addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() ||
			tsRouteCGNAT.Overlaps(pfx) || tsRouteULA6.Overlaps(pfx) {
			return errors.New("禁止对内网、环回、组网隧道或保留地址段覆盖分流出口")
		}
		for _, protIP := range audit.ProtectedBootstrapIPs {
			if pAddr, pErr := netip.ParseAddr(protIP); pErr == nil && pfx.Contains(pAddr.Unmap()) {
				return errors.New("受核心引导 DNS 基础设施保护，禁止修改 " + protIP + " 出口")
			}
		}
	}
	return nil
}

func (s *Server) validateRouteOutboundAgainstLiveSB(outbound string) (canonicalOutbound string, err error) {
	rawSBBytes, sbErr := os.ReadFile(s.sbConfigPath())
	rawSB := string(rawSBBytes)
	hasLiveSB := sbErr == nil && strings.TrimSpace(rawSB) != ""
	if !hasLiveSB {
		return outbound, nil
	}
	groups, directTag := singbox.InspectClientRoutingOutbounds(rawSB)
	if strings.EqualFold(outbound, config.TrafficOutboundDirect) || (directTag != "" && strings.EqualFold(outbound, directTag)) {
		return config.TrafficOutboundDirect, nil
	}
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}
	if !slices.Contains(groupTags, outbound) {
		return "", errors.New("当前 sing-box 配置中不存在策略组: " + outbound)
	}
	return outbound, nil
}

func (s *Server) closeSwitchedConnections(
	ctx context.Context,
	cfg *config.Config,
	target, matchType, sourceIP, connTarget string,
	closeFlag *bool,
) int {
	if closeFlag != nil && !*closeFlag {
		return 0
	}
	collector := s.auditCollector
	if collector == nil {
		collector = audit.NewCollector(cfg)
	}
	matchSuffix := matchType == config.TrafficMatchDomainSuffix
	closedTotal := 0
	if res, err := collector.CloseConnections(ctx, audit.CloseConnectionsRequest{
		Target:      target,
		MatchSuffix: matchSuffix,
		DeviceIP:    sourceIP,
	}); err == nil {
		closedTotal += res.Closed
	}
	ct := strings.TrimSpace(connTarget)
	if ct != "" && !strings.EqualFold(ct, target) && !(matchSuffix && strings.HasSuffix(strings.ToLower(strings.TrimSuffix(ct, ".")), "."+strings.ToLower(target))) {
		if res2, err := collector.CloseConnections(ctx, audit.CloseConnectionsRequest{
			Target:   ct,
			DeviceIP: sourceIP,
		}); err == nil {
			closedTotal += res2.Closed
		}
	}
	return closedTotal
}

// handleAuditRouteRuleUpsert 一键新增或原地更新单条审计连接定向出口规则，并立即热重载与踢断存量连接。
func (s *Server) handleAuditRouteRuleUpsert(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditRouteRuleUpsertRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	cand, err := config.NormalizeTrafficCustomRule(config.TrafficCustomRule{
		Target:    req.Target,
		MatchType: req.MatchType,
		Outbound:  req.Outbound,
		SourceIP:  req.SourceIP,
		Note:      req.Note,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateRouteRuleSafety(cand); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		prevRules []config.TrafficCustomRule
		savedRule config.TrafficCustomRule
		applied   bool
		liveJSON  string
	)
	cfg, txErr := s.updateConfigTx(configTxOptions{
		InvalidateIOS: true,
		SaveErrPrefix: "保存自定义分流规则失败: ",
		LiveApply: func(cfg *config.Config) error {
			var applyErr error
			applied, liveJSON, applyErr = s.compileAndApplyTrafficRouting(r.Context(), prevRules, cfg)
			return applyErr
		},
	}, func(cfg *config.Config) error {
		canonOut, obErr := s.validateRouteOutboundAgainstLiveSB(cand.Outbound)
		if obErr != nil {
			return &apiStatusError{status: http.StatusBadRequest, msg: obErr.Error()}
		}
		cand.Outbound = canonOut
		prevRules = slices.Clone(cfg.TrafficRouting.Rules)
		var uErr error
		savedRule, uErr = cfg.TrafficRouting.UpsertRule(cand)
		if uErr != nil {
			return &apiStatusError{status: http.StatusBadRequest, msg: uErr.Error()}
		}
		cfg.TrafficRouting = cfg.TrafficRouting.Normalized()
		return nil
	})
	if txErr != nil {
		writePartialSaveError(w, txErr)
		return
	}

	closedCount := s.closeSwitchedConnections(
		r.Context(), cfg, savedRule.Target, savedRule.MatchType, savedRule.SourceIP, req.ConnTarget, req.CloseConnections,
	)
	s.invalidateAuditCache()
	_ = daemon.NotifyReload()

	report := singbox.BuildClientRoutingReport(cfg, liveJSON)
	destLabel := savedRule.Outbound
	if destLabel == config.TrafficOutboundDirect && report.DirectTag != "" {
		destLabel = "直连 (" + report.DirectTag + ")"
	}
	msg := "已固定 " + savedRule.Target + " → " + destLabel
	if applied {
		msg += "，并已热重载生效"
	} else {
		msg += "，已保存（将在下次生成配置时生效）"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"applied":           applied,
		"closedConnections": closedCount,
		"rule":              savedRule,
		"rules":             report.CustomRules,
		"report":            report,
		"message":           msg,
	})
}

// handleAuditRouteRuleDelete 删除指定审计快捷定向出口规则，剥离编译态 Route/DNS 规则并断开存量连接。
func (s *Server) handleAuditRouteRuleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditRouteRuleDeleteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	normCand, err := config.NormalizeTrafficCustomRule(config.TrafficCustomRule{
		Target:    req.Target,
		MatchType: req.MatchType,
		Outbound:  config.TrafficOutboundDirect,
		SourceIP:  req.SourceIP,
	})
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		prevRules []config.TrafficCustomRule
		removed   bool
		applied   bool
		liveJSON  string
	)
	cfg, txErr := s.updateConfigTx(configTxOptions{
		InvalidateIOS: true,
		SaveErrPrefix: "删除自定义分流规则失败: ",
		LiveApply: func(cfg *config.Config) error {
			if !removed {
				rawSBBytes, _ := os.ReadFile(s.sbConfigPath())
				liveJSON = string(rawSBBytes)
				return nil
			}
			var applyErr error
			applied, liveJSON, applyErr = s.compileAndApplyTrafficRouting(r.Context(), prevRules, cfg)
			return applyErr
		},
	}, func(cfg *config.Config) error {
		prevRules = slices.Clone(cfg.TrafficRouting.Rules)
		removed = cfg.TrafficRouting.RemoveRule(normCand.Target, normCand.MatchType, normCand.SourceIP)
		cfg.TrafficRouting = cfg.TrafficRouting.Normalized()
		return nil
	})
	if txErr != nil {
		writePartialSaveError(w, txErr)
		return
	}

	closedCount := 0
	if removed {
		closedCount = s.closeSwitchedConnections(
			r.Context(), cfg, normCand.Target, normCand.MatchType, normCand.SourceIP, "", req.CloseConnections,
		)
		s.invalidateAuditCache()
		_ = daemon.NotifyReload()
	}

	report := singbox.BuildClientRoutingReport(cfg, liveJSON)
	msg := "已恢复 " + normCand.Target + " 默认分流"
	if !removed {
		msg = "未找到匹配的自定义出口规则"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"removed":           removed,
		"applied":           applied,
		"closedConnections": closedCount,
		"rules":             report.CustomRules,
		"report":            report,
		"message":           msg,
	})
}
