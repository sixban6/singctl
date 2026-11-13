package webui

import (
	"cmp"
	"encoding/json"
	"net/http"
	"os"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
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
	s.routingMu.Lock()
	defer s.routingMu.Unlock()

	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	rawSB, _ := os.ReadFile(s.sbConfigPath())
	report := singbox.BuildClientRoutingReport(cfg, string(rawSB))
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleTrafficRoutingPut(w http.ResponseWriter, r *http.Request) {
	var body trafficRoutingPutRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.routingMu.Lock()
	defer s.routingMu.Unlock()

	cfgPath := configPathFor(s)
	origCfgBytes, origReadErr := os.ReadFile(cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	sbPath := s.sbConfigPath()
	rawSBBytes, sbErr := os.ReadFile(sbPath)
	rawSB := string(rawSBBytes)
	hasLiveSB := sbErr == nil && strings.TrimSpace(rawSB) != ""

	groups, _ := singbox.InspectClientRoutingOutbounds(rawSB)
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}

	nextPresets := make(map[string]config.TrafficRuleOverride)
	if !body.Reset {
		if !body.Replace {
			for k, v := range cfg.TrafficRouting.Normalized().Presets {
				nextPresets[k] = v
			}
		}
		for rawID, ov := range body.Presets {
			id := strings.ToLower(strings.TrimSpace(rawID))
			preset, ok := singbox.LookupClientRoutingPreset(id)
			if !ok {
				writeJSONError(w, http.StatusBadRequest, "未知的分流预设项: "+rawID)
				return
			}
			cleanOutbound, err := config.CleanTrafficOutboundName(ov.Outbound)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
			if cleanOutbound != "" && hasLiveSB && !slices.Contains(groupTags, cleanOutbound) {
				writeJSONError(w, http.StatusBadRequest, "当前 sing-box 配置中不存在策略组: "+cleanOutbound)
				return
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
			// 若与默认推荐值完全一致，则不冗余写入 singctl.yaml
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
	}

	cfg.TrafficRouting = config.TrafficRoutingConfig{Presets: nextPresets}.Normalized()

	if err := backupConfig(cfgPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存 singctl.yaml 失败: "+err.Error())
		return
	}
	s.invalidateIOSCache()

	applied := false
	liveJSON := rawSB
	if hasLiveSB {
		updatedJSON, err := singbox.ApplyTrafficRoutingToConfigJSON(rawSB, cfg.TrafficRouting, cfg.CustomRules)
		if err != nil {
			if origReadErr == nil {
				_ = os.WriteFile(cfgPath, origCfgBytes, 0600)
			}
			writeJSONError(w, http.StatusInternalServerError, "编译分流规则失败: "+err.Error())
			return
		}
		if err := singbox.ApplyLiveSingBoxConfig(r.Context(), sbPath, s.sbWorkConfigPath(), updatedJSON, "routing"); err != nil {
			if origReadErr == nil {
				_ = os.WriteFile(cfgPath, origCfgBytes, 0600)
			}
			writeJSONError(w, http.StatusBadRequest, "应用配置或 sing-box 校验失败: "+err.Error())
			return
		}
		applied = true
		liveJSON = updatedJSON
	}

	_ = daemon.NotifyReload()

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
