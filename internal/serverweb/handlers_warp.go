package serverweb

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/telemetry"
)

// WarpDaemonStatus 描述本地 Cloudflare WARP (wireproxy) 运行与隧道状态
type WarpDaemonStatus struct {
	Installed     bool   `json:"installed"`
	Running       bool   `json:"running"`
	TunnelHealthy bool   `json:"tunnelHealthy"`
	SocksPort     int    `json:"socksPort"`
	WarpIP        string `json:"warpIp,omitempty"`
	WarpLoc       string `json:"warpLoc,omitempty"`
	Error         string `json:"error,omitempty"`
}

// WarpRoutingStatusResponse 返回服务端 WARP 分流中心总览数据
type WarpRoutingStatusResponse struct {
	Daemon        WarpDaemonStatus         `json:"daemon"`
	Routing       config.WarpRoutingConfig `json:"routing"`
	Presets       []deploy.WarpPresetState `json:"presets"`
	DCConnCount   int                      `json:"dcConnCount"`
	WarpConnCount int                      `json:"warpConnCount"`
}

func (s *Server) probeWarpDaemon(forceRefresh bool) WarpDaemonStatus {
	if s.warpDaemonProbe != nil {
		return s.warpDaemonProbe(forceRefresh)
	}

	_, errBin := exec.LookPath("wireproxy")
	_, errConf := os.Stat("/etc/wireproxy/wireproxy.conf")
	installed := errBin == nil || os.IsExist(errConf) || errConf == nil
	if !installed {
		if _, stErr := os.Stat("/usr/local/bin/wireproxy"); stErr == nil {
			installed = true
		}
	}

	running := checkServiceRunning("wireproxy") || checkServiceRunning("warp-svc")
	portOpen := deploy.CheckWarpSocksPort()
	if portOpen {
		running = true
		installed = true
	}

	status := WarpDaemonStatus{
		Installed:     installed,
		Running:       running,
		TunnelHealthy: portOpen,
		SocksPort:     40000,
	}

	if !portOpen {
		if !installed {
			status.Error = "尚未安装 wireproxy (WARP) 服务"
		} else if !running {
			status.Error = "wireproxy 服务未运行，127.0.0.1:40000 未监听"
		} else {
			status.Error = "wireproxy 已启动但 127.0.0.1:40000 尚未就绪"
		}
		return status
	}

	// 读取 30 秒短期缓存的出口 IP，避免频繁请求 cloudflare trace 拖慢页面首屏
	s.warpCacheMu.Lock()
	cachedIP := s.warpCachedIP
	cachedLoc := s.warpCachedLoc
	cacheFresh := !forceRefresh && cachedIP != "" && time.Since(s.warpCachedAt) < 30*time.Second
	s.warpCacheMu.Unlock()

	if cacheFresh {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
		return status
	}

	if ip, loc, _, ok := deploy.FetchWarpExitInfo(2500 * time.Millisecond); ok && ip != "" {
		status.WarpIP = ip
		status.WarpLoc = loc
		s.warpCacheMu.Lock()
		s.warpCachedIP = ip
		s.warpCachedLoc = loc
		s.warpCachedAt = time.Now()
		s.warpCacheMu.Unlock()
	} else if cachedIP != "" {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
	}
	return status
}

func (s *Server) buildWarpRoutingStatus(r *http.Request, cfg *config.Config, forceRefresh bool) WarpRoutingStatusResponse {
	var wr config.WarpRoutingConfig
	if cfg != nil {
		if normalized, err := config.NormalizeWarpRouting(cfg.Server.WarpRouting); err == nil {
			wr = normalized
		} else {
			wr = cfg.Server.WarpRouting
		}
	} else {
		wr = config.WarpRoutingConfig{
			Mode:          config.WarpModeSplit,
			WarpDomains:   []string{},
			WarpCIDRs:     []string{},
			DirectDomains: []string{},
			DirectCIDRs:   []string{},
		}
	}

	var dcCount, warpCount int
	if s.telemetry != nil {
		snap := s.telemetry.Collect(r.Context())
		dcCount = snap.Outbounds.DirectConnections
		warpCount = snap.Outbounds.WarpConnections
	}

	return WarpRoutingStatusResponse{
		Daemon:        s.probeWarpDaemon(forceRefresh),
		Routing:       wr,
		Presets:       deploy.BuildPresetStateList(wr),
		DCConnCount:   dcCount,
		WarpConnCount: warpCount,
	}
}

func (s *Server) handleGetWarpRouting(w http.ResponseWriter, r *http.Request) {
	forceRefresh := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	cfg, _ := config.Load(s.opts.ConfigPath)
	resp := s.buildWarpRoutingStatus(r, cfg, forceRefresh)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) applyWarpRoutingConfig(r *http.Request, targetWR config.WarpRoutingConfig) (WarpRoutingStatusResponse, int, int, error) {
	normalized, err := config.NormalizeWarpRouting(targetWR)
	if err != nil {
		return WarpRoutingStatusResponse{}, http.StatusBadRequest, 0, err
	}

	s.warpMu.Lock()
	defer s.warpMu.Unlock()

	cfg, loadErr := config.Load(s.opts.ConfigPath)
	if loadErr != nil || cfg == nil {
		return WarpRoutingStatusResponse{}, http.StatusInternalServerError, 0, fmt.Errorf("加载配置文件失败: %w", loadErr)
	}

	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	if _, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, normalized, s.warpDeps); applyErr != nil {
		if errors.Is(applyErr, deploy.ErrWarpTunnelUnavailable) {
			return WarpRoutingStatusResponse{}, http.StatusConflict, 0, applyErr
		}
		if !errors.Is(applyErr, os.ErrNotExist) {
			return WarpRoutingStatusResponse{}, http.StatusInternalServerError, 0, applyErr
		}
	}

	cfg.Server.WarpRouting = normalized
	if saveErr := config.Save(s.opts.ConfigPath, cfg); saveErr != nil {
		return WarpRoutingStatusResponse{}, http.StatusInternalServerError, 0, fmt.Errorf("持久化 singctl.yaml 失败: %w", saveErr)
	}

	evicted := 0
	if s.telemetry != nil {
		n, _ := s.telemetry.EvictMismatchedConnections(r.Context(), func(host, dstIP, ruleTag, currentOutbound string) bool {
			expected := deploy.ExpectedTargetOutbound(normalized, host, dstIP, ruleTag)
			return expected != currentOutbound
		})
		evicted = n
	}

	return s.buildWarpRoutingStatus(r, cfg, false), http.StatusOK, evicted, nil
}

func (s *Server) handleUpdateWarpRouting(w http.ResponseWriter, r *http.Request) {
	var body config.WarpRoutingConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求格式")
		return
	}

	statusResp, httpCode, evicted, err := s.applyWarpRoutingConfig(r, body)
	if err != nil {
		writeJSONError(w, httpCode, err.Error())
		return
	}

	enabledCount := 0
	for _, p := range statusResp.Presets {
		if p.Enabled {
			enabledCount++
		}
	}
	s.recordAudit(r, fmt.Sprintf("更新 WARP 智能分流策略 [模式:%s, 启用预设:%d, 自定义WARP:%d, 白名单:%d, 踢流:%d]",
		statusResp.Routing.Mode, enabledCount,
		len(statusResp.Routing.WarpDomains)+len(statusResp.Routing.WarpCIDRs),
		len(statusResp.Routing.DirectDomains)+len(statusResp.Routing.DirectCIDRs),
		evicted,
	))

	msg := "WARP 分流策略已安全通过校验并零断流热更新"
	if evicted > 0 {
		msg = fmt.Sprintf("已热更新分流路由并平滑切换 %d 条存量连接", evicted)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":            msg,
		"evictedConnections": evicted,
		"daemon":             statusResp.Daemon,
		"routing":            statusResp.Routing,
		"presets":            statusResp.Presets,
		"dcConnCount":        statusResp.DCConnCount,
		"warpConnCount":      statusResp.WarpConnCount,
	})
}

func (s *Server) handleQuickSwitchWarp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target   string `json:"target"`
		Outbound string `json:"outbound"` // "WARP" | "DC" | "Direct"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供要切换的目标域名或 IP/CIDR")
		return
	}

	targetOut := strings.ToUpper(strings.TrimSpace(body.Outbound))
	switch targetOut {
	case "WARP":
	case "DC", "DIRECT":
		targetOut = "DC"
	default:
		writeJSONError(w, http.StatusBadRequest, "outbound 必须为 WARP 或 DC")
		return
	}

	rawTarget := strings.TrimSpace(body.Target)
	isCIDR := false
	cleanTarget := ""
	if cidr, err := config.CleanWarpCIDRRule(rawTarget); err == nil {
		isCIDR = true
		cleanTarget = cidr
	} else {
		domainRule, dErr := config.CleanWarpDomainRule(rawTarget)
		if dErr != nil {
			writeJSONError(w, http.StatusBadRequest, dErr.Error())
			return
		}
		cleanTarget = domainRule
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置文件失败")
		return
	}
	nextWR := cfg.Server.WarpRouting.Clone()
	nextWR, err = config.NormalizeWarpRouting(nextWR)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if nextWR.NormalizedMode() == config.WarpModeBypass {
		writeJSONError(w, http.StatusConflict, "当前处于「紧急全直出旁路」模式，请先切换回「原生优先·按需分流」或「全局 WARP」后再调整单项目标")
		return
	}

	matchedPresetName := ""
	if isCIDR {
		if targetOut == "WARP" {
			nextWR.DirectCIDRs = removeStringFold(nextWR.DirectCIDRs, cleanTarget)
			if nextWR.NormalizedMode() != config.WarpModeGlobalWarp && !slices.Contains(nextWR.WarpCIDRs, cleanTarget) {
				nextWR.WarpCIDRs = append(nextWR.WarpCIDRs, cleanTarget)
			}
		} else {
			nextWR.WarpCIDRs = removeStringFold(nextWR.WarpCIDRs, cleanTarget)
			if nextWR.NormalizedMode() == config.WarpModeGlobalWarp && !slices.Contains(nextWR.DirectCIDRs, cleanTarget) {
				nextWR.DirectCIDRs = append(nextWR.DirectCIDRs, cleanTarget)
			}
		}
	} else {
		bareHost := strings.TrimPrefix(strings.TrimPrefix(cleanTarget, "full:"), "keyword:")
		isModifierRule := strings.HasPrefix(cleanTarget, "full:") || strings.HasPrefix(cleanTarget, "keyword:")
		presetDef, hasPreset := deploy.FindPresetByHost(bareHost)

		if targetOut == "WARP" {
			nextWR.DirectDomains = removeStringFold(nextWR.DirectDomains, cleanTarget)
			if !isModifierRule && hasPreset && !nextWR.IsPresetEnabled(presetDef.ID, presetDef.DefaultEnabled) {
				if nextWR.Presets == nil {
					nextWR.Presets = make(map[string]bool)
				}
				nextWR.Presets[presetDef.ID] = true
				matchedPresetName = presetDef.Name
			} else if nextWR.NormalizedMode() != config.WarpModeGlobalWarp && !slices.Contains(nextWR.WarpDomains, cleanTarget) {
				// 避免被高优先级 Direct 命中或默认 DC 拦截时也补入自定义 WARP 名单
				if !hasPreset || isModifierRule {
					nextWR.WarpDomains = append(nextWR.WarpDomains, cleanTarget)
				}
			}
		} else {
			nextWR.WarpDomains = removeStringFold(nextWR.WarpDomains, cleanTarget)
			if !isModifierRule && hasPreset && nextWR.IsPresetEnabled(presetDef.ID, presetDef.DefaultEnabled) {
				if nextWR.Presets == nil {
					nextWR.Presets = make(map[string]bool)
				}
				nextWR.Presets[presetDef.ID] = false
				matchedPresetName = presetDef.Name
			}
			// 若处于全局 WARP 模式，必须明确加入直出白名单才能切回 DC
			if nextWR.NormalizedMode() == config.WarpModeGlobalWarp && !slices.Contains(nextWR.DirectDomains, cleanTarget) {
				nextWR.DirectDomains = append(nextWR.DirectDomains, cleanTarget)
			}
		}
	}

	statusResp, httpCode, evicted, applyErr := s.applyWarpRoutingConfig(r, nextWR)
	if applyErr != nil {
		writeJSONError(w, httpCode, applyErr.Error())
		return
	}

	actionLabel := "切换至 WARP 出口"
	if targetOut == "DC" {
		actionLabel = "切回原生直出 (DC)"
	}
	s.recordAudit(r, fmt.Sprintf("一键秒切目标 [%s] -> %s (踢断旧流:%d)", cleanTarget, targetOut, evicted))

	msg := fmt.Sprintf("已将 %s %s", cleanTarget, actionLabel)
	if matchedPresetName != "" {
		msg = fmt.Sprintf("已联动预设「%s」将 %s %s", matchedPresetName, cleanTarget, actionLabel)
	}
	if evicted > 0 {
		msg += fmt.Sprintf("，并立即切换 %d 条活跃连接", evicted)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":            msg,
		"target":             cleanTarget,
		"outbound":           targetOut,
		"matchedPreset":      matchedPresetName,
		"evictedConnections": evicted,
		"daemon":             statusResp.Daemon,
		"routing":            statusResp.Routing,
		"presets":            statusResp.Presets,
		"dcConnCount":        statusResp.DCConnCount,
		"warpConnCount":      statusResp.WarpConnCount,
	})
}

func (s *Server) handleGetWarpConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	outbound := r.URL.Query().Get("outbound")

	if s.telemetry == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      "遥测采集器未初始化",
		})
		return
	}

	items, err := s.telemetry.GetActiveDestinations(r.Context(), q, outbound)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      true,
		"destinations": items,
		"total":        len(items),
	})
}

func (s *Server) handleWarpAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"` // "rekey" | "ensure"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	action := strings.ToLower(strings.TrimSpace(body.Action))
	s.warpMu.Lock()
	defer s.warpMu.Unlock()

	switch action {
	case "rekey":
		newIP, newLoc, err := deploy.RotateWarpIdentity()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.warpCacheMu.Lock()
		s.warpCachedIP = newIP
		s.warpCachedLoc = newLoc
		s.warpCachedAt = time.Now()
		s.warpCacheMu.Unlock()

		s.recordAudit(r, fmt.Sprintf("重新注册并切换 WARP 出口 IP [%s (%s)]", newIP, cmp.Or(newLoc, "Unknown")))
		writeJSON(w, http.StatusOK, map[string]any{
			"message": fmt.Sprintf("已更换全新 WARP 出口 IP：%s (%s)", newIP, cmp.Or(newLoc, "Anycast")),
			"warpIp":  newIP,
			"warpLoc": newLoc,
			"daemon":  s.probeWarpDaemon(false),
		})

	case "ensure":
		cfg, _ := config.Load(s.opts.ConfigPath)
		if err := deploy.DeployWarpWithConfig(cfg); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "一键部署/修复 WARP 失败: "+err.Error())
			return
		}
		daemon := s.probeWarpDaemon(true)
		s.recordAudit(r, "一键部署并修复本地 WARP (wireproxy) 隧道")
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "WARP (wireproxy) 本地隧道已就绪，现可自由切换任意分流规则",
			"daemon":  daemon,
		})

	default:
		writeJSONError(w, http.StatusBadRequest, "不支持的操作: "+action)
	}
}

func removeStringFold(items []string, target string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(target)) {
			out = append(out, item)
		}
	}
	return out
}
