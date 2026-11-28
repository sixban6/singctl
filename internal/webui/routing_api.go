// 文件职责：提供客户端智能分流预设查询、热编译校验与失败自动回滚接口。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
)

func (s *Server) sbConfigPath() string {
	return cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
}

func (s *Server) sbWorkConfigPath() string {
	if strings.TrimSpace(s.opts.SingBoxWorkConfigPath) != "" {
		return strings.TrimSpace(s.opts.SingBoxWorkConfigPath)
	}
	// 单测通过 Options.SingBoxConfigPath 隔离测试文件时，不触碰宿主真实 /tmp/sing-box-work/config.json
	if strings.TrimSpace(s.opts.SingBoxConfigPath) != "" {
		return ""
	}
	return constant.SingBoxWorkConfigFile
}

func (s *Server) invalidateIOSCache() {
	s.iosMu.Lock()
	s.iosCacheKey = ""
	s.iosCacheVal = ""
	s.iosMu.Unlock()
}

type trafficRoutingPutRequest struct {
	Reset   bool                                  `json:"reset,omitempty"`
	Replace bool                                  `json:"replace,omitempty"`
	Presets map[string]config.TrafficRuleOverride `json:"presets,omitempty"`
}

func (s *Server) handleTrafficRoutingGet(w http.ResponseWriter, _ *http.Request) {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.readConfigOrEmpty()

	rawSB, _ := os.ReadFile(s.sbConfigPath())
	report := singbox.BuildClientRoutingReport(cfg, string(rawSB))
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) compileAndApplyTrafficRouting(
	ctx context.Context,
	prevRules []config.TrafficCustomRule,
	cfg *config.Config,
) (applied bool, liveJSON string, err error) {
	sbPath := s.sbConfigPath()
	rawSBBytes, sbErr := os.ReadFile(sbPath)
	rawSB := string(rawSBBytes)
	liveJSON = rawSB
	if sbErr != nil || strings.TrimSpace(rawSB) == "" {
		return false, liveJSON, nil
	}
	updatedJSON, convErr := singbox.ApplyTrafficRoutingWithPrevRules(rawSB, prevRules, cfg.TrafficRouting, cfg.CustomRules)
	if convErr != nil {
		return false, liveJSON, &apiStatusError{status: http.StatusInternalServerError, msg: "编译分流规则失败: " + convErr.Error()}
	}
	if applyErr := singbox.ApplyLiveSingBoxConfig(ctx, sbPath, s.sbWorkConfigPath(), updatedJSON, "routing"); applyErr != nil {
		return false, liveJSON, &apiStatusError{status: http.StatusBadRequest, msg: "应用配置或 sing-box 校验失败: " + applyErr.Error()}
	}
	if baseRaw, bErr := singbox.LoadBaseSnapshot(sbPath); bErr == nil && strings.TrimSpace(baseRaw) != "" {
		if updatedBase, uErr := singbox.ApplyTrafficRoutingWithPrevRules(baseRaw, prevRules, cfg.TrafficRouting, cfg.CustomRules); uErr == nil {
			_ = singbox.SaveBaseSnapshot(sbPath, updatedBase)
		}
	}
	return true, updatedJSON, nil
}

func (s *Server) handleTrafficRoutingPut(w http.ResponseWriter, r *http.Request) {
	var body trafficRoutingPutRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	sbPath := s.sbConfigPath()
	var (
		applied   bool
		liveJSON  string
		prevRules []config.TrafficCustomRule
	)
	cfg, err := s.updateConfigTx(configTxOptions{
		InvalidateIOS: true,
		SaveErrPrefix: "保存 singctl.yaml 失败: ",
		LiveApply: func(cfg *config.Config) error {
			var applyErr error
			applied, liveJSON, applyErr = s.compileAndApplyTrafficRouting(r.Context(), prevRules, cfg)
			return applyErr
		},
	}, func(cfg *config.Config) error {
		prevRules = slices.Clone(cfg.TrafficRouting.Rules)
		rawSBBytes, sbErr := os.ReadFile(sbPath)
		rawSB := string(rawSBBytes)
		hasLiveSB := sbErr == nil && strings.TrimSpace(rawSB) != ""

		groups, _ := singbox.InspectClientRoutingOutbounds(rawSB)
		groupTags := make([]string, len(groups))
		for i, g := range groups {
			groupTags[i] = g.Tag
		}

		nextPresets, valErr := mergeTrafficRoutingPresets(cfg, body, hasLiveSB, groupTags)
		if valErr != nil {
			return valErr
		}
		cfg.TrafficRouting = config.TrafficRoutingConfig{
			Presets: nextPresets,
			Rules:   slices.Clone(prevRules),
		}.Normalized()
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}

	msg := "分流策略已保存并触发热重载生效"
	if body.Reset {
		msg = "已恢复默认推荐分流策略并热重载生效"
	} else if !applied {
		msg = "分流策略已保存，将在下次生成 sing-box 配置时生效"
	}

	report := singbox.BuildClientRoutingReport(cfg, liveJSON)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"applied": applied,
		"message": msg,
		"report":  report,
	})
}

func mergeTrafficRoutingPresets(
	cfg *config.Config,
	body trafficRoutingPutRequest,
	hasLiveSB bool,
	groupTags []string,
) (map[string]config.TrafficRuleOverride, error) {
	nextPresets := make(map[string]config.TrafficRuleOverride)
	if body.Reset {
		return nextPresets, nil
	}
	if !body.Replace {
		for k, v := range cfg.TrafficRouting.Normalized().Presets {
			nextPresets[k] = v
		}
	}
	for rawID, ov := range body.Presets {
		id := strings.ToLower(strings.TrimSpace(rawID))
		preset, ok := singbox.LookupClientRoutingPreset(id)
		if !ok {
			return nil, &apiStatusError{status: http.StatusBadRequest, msg: "未知的分流预设项: " + rawID}
		}
		cleanOutbound, err := config.CleanTrafficOutboundName(ov.Outbound)
		if err != nil {
			return nil, &apiStatusError{status: http.StatusBadRequest, msg: err.Error()}
		}
		if cleanOutbound != "" && hasLiveSB && !slices.Contains(groupTags, cleanOutbound) {
			return nil, &apiStatusError{status: http.StatusBadRequest, msg: "当前 sing-box 配置中不存在策略组: " + cleanOutbound}
		}

		defOutbound := singbox.ResolvePresetDefaultOutbound(preset.PreferVPS, preset.PreferAuto, groupTags)
		prev := nextPresets[id]
		mergedEnabled := preset.DefaultOn
		if prev.Enabled != nil {
			mergedEnabled = *prev.Enabled
		}
		if ov.Enabled != nil {
			mergedEnabled = *ov.Enabled
		}
		mergedOutbound := prev.Outbound
		if cleanOutbound != "" {
			mergedOutbound = cleanOutbound
		}
		isDefaultEnabled := mergedEnabled == preset.DefaultOn
		isDefaultOutbound := mergedOutbound == "" || mergedOutbound == defOutbound
		if isDefaultEnabled && isDefaultOutbound {
			delete(nextPresets, id)
			continue
		}
		enabledCopy := mergedEnabled
		outCopy := mergedOutbound
		if isDefaultOutbound {
			outCopy = ""
		}
		nextPresets[id] = config.TrafficRuleOverride{
			Enabled:  &enabledCopy,
			Outbound: outCopy,
		}
	}
	return nextPresets, nil
}
