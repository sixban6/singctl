package serverweb

import (
	"cmp"
	"context"
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
	Installed        bool   `json:"installed"`
	Running          bool   `json:"running"`
	TunnelHealthy    bool   `json:"tunnelHealthy"`
	SocksPort        int    `json:"socksPort"`
	WarpIP           string `json:"warpIp,omitempty"`
	WarpLoc          string `json:"warpLoc,omitempty"`
	Error            string `json:"error,omitempty"`
	DegradedFallback bool   `json:"degradedFallback,omitempty"`
	AutoHealStatus   string `json:"autoHealStatus,omitempty"`
	LastHealedAt     string `json:"lastHealedAt,omitempty"`
}

// WarpRoutingStatusResponse 返回服务端 WARP 分流中心总览数据（支持单机与全集群多节点透视）
type WarpRoutingStatusResponse struct {
	SelectedNode  string                   `json:"selectedNode,omitempty"`
	Nodes         []WarpNodeSummary        `json:"nodes,omitempty"`
	Daemon        WarpDaemonStatus         `json:"daemon"`
	Routing       config.WarpRoutingConfig `json:"routing"`
	Presets       []deploy.WarpPresetState `json:"presets"`
	DCConnCount   int                      `json:"dcConnCount"`
	WarpConnCount int                      `json:"warpConnCount"`
}

func (s *Server) applyWatchdogFieldsToDaemonStatus(status *WarpDaemonStatus) {
	if status == nil {
		return
	}
	s.warpWatchdogMu.Lock()
	degraded := s.warpDegraded
	healMsg := s.warpAutoHealStatus
	healedAt := s.warpLastHealedAt
	s.warpWatchdogMu.Unlock()

	if !status.DegradedFallback {
		status.DegradedFallback = degraded
	}
	if status.AutoHealStatus == "" {
		status.AutoHealStatus = healMsg
	}
	if status.LastHealedAt == "" {
		status.LastHealedAt = healedAt
	}
}

func (s *Server) probeWarpDaemon(forceRefresh bool) WarpDaemonStatus {
	if s.warpDaemonProbe != nil {
		st := s.warpDaemonProbe(forceRefresh)
		s.applyWatchdogFieldsToDaemonStatus(&st)
		return st
	}

	_, errBin := exec.LookPath("wireproxy")
	_, _, hasConf := deploy.ResolveWireproxyConfigPaths()
	installed := errBin == nil || hasConf || deploy.IsWindtfWireproxyBinary(deploy.DefaultWireproxyBin)

	running := checkServiceRunning("wireproxy")
	portCheck := s.warpPortChecker
	if portCheck == nil {
		portCheck = deploy.CheckWarpSocksPort
	}
	portOpen := portCheck()
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
			status.Error = "尚未安装内置纯 Go wireproxy (WARP) 服务"
		} else if !running {
			status.Error = "wireproxy 服务未运行，127.0.0.1:40000 未监听"
		} else {
			status.Error = "wireproxy 已启动但 127.0.0.1:40000 尚未就绪"
		}
		s.applyWatchdogFieldsToDaemonStatus(&status)
		return status
	}

	const warpExitCacheTTL = 5 * time.Minute
	s.warpCacheMu.Lock()
	cachedIP := s.warpCachedIP
	cachedLoc := s.warpCachedLoc
	cacheFresh := !forceRefresh && cachedIP != "" && time.Since(s.warpCachedAt) < warpExitCacheTTL
	s.warpCacheMu.Unlock()

	if cacheFresh {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
		s.applyWatchdogFieldsToDaemonStatus(&status)
		return status
	}

	refreshWarpExit := func() (string, string, bool) {
		exitFetch := s.warpExitFetcher
		if exitFetch == nil {
			exitFetch = deploy.FetchWarpExitInfo
		}
		ip, loc, _, ok := exitFetch(2500 * time.Millisecond)
		if ok && ip != "" {
			s.warpCacheMu.Lock()
			s.warpCachedIP = ip
			s.warpCachedLoc = loc
			s.warpCachedAt = time.Now()
			s.warpCacheMu.Unlock()
		}
		return ip, loc, ok && ip != ""
	}

	// SWR: 已有历史出口 IP 且非强制刷新时，0ms 秒回缓存并单飞后台更新，消除 2.5s 外网阻塞
	if !forceRefresh && cachedIP != "" {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
		tryRunSingleFlight(&s.warpExitRefreshing, 4*time.Second, func(context.Context) {
			refreshWarpExit()
		})
		s.applyWatchdogFieldsToDaemonStatus(&status)
		return status
	}

	if ip, loc, ok := refreshWarpExit(); ok {
		status.WarpIP = ip
		status.WarpLoc = loc
	} else if cachedIP != "" {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
	}
	s.applyWatchdogFieldsToDaemonStatus(&status)
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
	selectedNode := cmp.Or(strings.TrimSpace(r.URL.Query().Get("node")), "local")
	cfg, _ := config.Load(s.opts.ConfigPath)
	resp, err := s.buildClusterWarpStatus(r, cfg, selectedNode, forceRefresh)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) liveWarpDepsForConfig(cfg *config.Config) *deploy.LiveWarpApplyDeps {
	var deps deploy.LiveWarpApplyDeps
	if s.warpDeps != nil {
		deps = *s.warpDeps
	}
	protected := slices.Clone(deps.ProtectedDomains)
	for _, dom := range deploy.CollectServerProtectedDomains(cfg) {
		if !slices.Contains(protected, dom) {
			protected = append(protected, dom)
		}
	}
	deps.ProtectedDomains = protected
	return &deps
}

func (s *Server) evictAllWarpConnections(ctx context.Context) int {
	if s.telemetry == nil {
		return 0
	}
	n, _ := s.telemetry.EvictMismatchedConnections(ctx, func(_, _, _, currentOutbound string) bool {
		return currentOutbound == "WARP"
	})
	return n
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
	liveDeps := s.liveWarpDepsForConfig(cfg)
	if _, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, normalized, liveDeps); applyErr != nil {
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
	s.updateConfigCache(cfg)

	s.warpWatchdogMu.Lock()
	s.warpDegraded = false
	s.warpFailStreak = 0
	s.warpBootSynced = true
	s.warpWatchdogMu.Unlock()

	evicted := 0
	if s.telemetry != nil {
		protected := deploy.CollectServerProtectedDomains(cfg)
		n, _ := s.telemetry.EvictMismatchedConnections(r.Context(), func(host, dstIP, ruleTag, currentOutbound string) bool {
			expected := deploy.ExpectedTargetOutbound(normalized, host, dstIP, ruleTag, protected...)
			return expected != currentOutbound
		})
		evicted = n
	}

	return s.buildWarpRoutingStatus(r, cfg, false), http.StatusOK, evicted, nil
}

func (s *Server) handleUpdateWarpRouting(w http.ResponseWriter, r *http.Request) {
	var body struct {
		config.WarpRoutingConfig
		Node        string `json:"node"`
		ViewNode    string `json:"viewNode"`
		SyncCluster bool   `json:"syncCluster"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求格式")
		return
	}

	targetNode := cmp.Or(strings.TrimSpace(body.Node), "local")
	viewNode := cmp.Or(strings.TrimSpace(body.ViewNode), targetNode)

	// 1. 全集群广播模式（选中了 all 或显式开启了 syncCluster）
	if targetNode == "all" || body.SyncCluster {
		normalized, err := config.NormalizeWarpRouting(body.WarpRoutingConfig)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		statusResp, httpCode, evicted, results, msg, applyErr := s.broadcastWarpRoutingCluster(r, normalized, viewNode)
		if applyErr != nil {
			writeJSONError(w, httpCode, applyErr.Error())
			return
		}
		s.recordAudit(r, fmt.Sprintf("全集群同步更新 WARP 智能分流策略 [模式:%s, 节点数:%d, 踢流:%d]",
			normalized.Mode, len(results), evicted))
		writeJSON(w, http.StatusOK, map[string]any{
			"message":            msg,
			"evictedConnections": evicted,
			"results":            results,
			"selectedNode":       statusResp.SelectedNode,
			"nodes":              statusResp.Nodes,
			"daemon":             statusResp.Daemon,
			"routing":            statusResp.Routing,
			"presets":            statusResp.Presets,
			"dcConnCount":        statusResp.DCConnCount,
			"warpConnCount":      statusResp.WarpConnCount,
		})
		return
	}

	// 2. 指定远端单台子节点独立更新
	if targetNode != "local" {
		fn, ok := s.findEnabledFleetNode(targetNode)
		if !ok {
			writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
			return
		}
		normalized, err := config.NormalizeWarpRouting(body.WarpRoutingConfig)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, applyErr := s.applyWarpRoutingRemoteNode(r.Context(), fn, normalized)
		if applyErr != nil {
			code := http.StatusInternalServerError
			if isTunnelUnavailableErr(applyErr) {
				code = http.StatusConflict
			}
			writeJSONError(w, code, fmt.Sprintf("[%s] %v", cmp.Or(fn.Name, fn.ID), applyErr))
			return
		}
		cfg, _ := config.Load(s.opts.ConfigPath)
		statusResp, _ := s.buildClusterWarpStatus(r, cfg, viewNode, false)
		s.recordAudit(r, fmt.Sprintf("更新子节点 [%s] WARP 分流策略 [模式:%s, 踢流:%d]",
			cmp.Or(fn.Name, fn.ID), res.Status.Routing.Mode, res.EvictedConnections))
		writeJSON(w, http.StatusOK, map[string]any{
			"message":            fmt.Sprintf("[%s] %s", cmp.Or(fn.Name, fn.ID), res.Message),
			"evictedConnections": res.EvictedConnections,
			"selectedNode":       statusResp.SelectedNode,
			"nodes":              statusResp.Nodes,
			"daemon":             statusResp.Daemon,
			"routing":            statusResp.Routing,
			"presets":            statusResp.Presets,
			"dcConnCount":        statusResp.DCConnCount,
			"warpConnCount":      statusResp.WarpConnCount,
		})
		return
	}

	// 3. 本机主控更新（默认行为）
	statusResp, httpCode, evicted, err := s.applyWarpRoutingConfig(r, body.WarpRoutingConfig)
	if err != nil {
		writeJSONError(w, httpCode, err.Error())
		return
	}
	cfg, _ := config.Load(s.opts.ConfigPath)
	if clusterResp, cErr := s.buildClusterWarpStatus(r, cfg, "local", false); cErr == nil {
		statusResp = clusterResp
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
		"selectedNode":       statusResp.SelectedNode,
		"nodes":              statusResp.Nodes,
		"daemon":             statusResp.Daemon,
		"routing":            statusResp.Routing,
		"presets":            statusResp.Presets,
		"dcConnCount":        statusResp.DCConnCount,
		"warpConnCount":      statusResp.WarpConnCount,
	})
}

func (s *Server) handleQuickSwitchWarp(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target      string `json:"target"`
		Outbound    string `json:"outbound"` // "WARP" | "DC" | "Direct"
		Node        string `json:"node"`
		ViewNode    string `json:"viewNode"`
		SyncCluster bool   `json:"syncCluster"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供要切换的目标域名或 IP/CIDR")
		return
	}

	targetNode := cmp.Or(strings.TrimSpace(body.Node), "local")
	viewNode := cmp.Or(strings.TrimSpace(body.ViewNode), targetNode)

	if targetNode == "all" || body.SyncCluster {
		s.handleClusterQuickSwitch(w, r, body.Target, body.Outbound, viewNode)
		return
	}

	if targetNode != "local" {
		fn, ok := s.findEnabledFleetNode(targetNode)
		if !ok {
			writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
			return
		}
		res, err := s.quickSwitchRemoteNode(r.Context(), fn, body.Target, body.Outbound)
		if err != nil {
			code := http.StatusInternalServerError
			if strings.Contains(err.Error(), "紧急全直出旁路") || isTunnelUnavailableErr(err) {
				code = http.StatusConflict
			}
			writeJSONError(w, code, fmt.Sprintf("[%s] %v", cmp.Or(fn.Name, fn.ID), err))
			return
		}
		cfg, _ := config.Load(s.opts.ConfigPath)
		statusResp, _ := s.buildClusterWarpStatus(r, cfg, viewNode, false)
		s.recordAudit(r, fmt.Sprintf("子节点 [%s] 一键秒切目标 [%s] -> %s (踢断旧流:%d)",
			cmp.Or(fn.Name, fn.ID), res.Target, res.Outbound, res.EvictedConnections))
		writeJSON(w, http.StatusOK, map[string]any{
			"message":            fmt.Sprintf("[%s] %s", cmp.Or(fn.Name, fn.ID), res.Message),
			"target":             res.Target,
			"outbound":           res.Outbound,
			"matchedPreset":      res.MatchedPreset,
			"evictedConnections": res.EvictedConnections,
			"selectedNode":       statusResp.SelectedNode,
			"nodes":              statusResp.Nodes,
			"daemon":             statusResp.Daemon,
			"routing":            statusResp.Routing,
			"presets":            statusResp.Presets,
			"dcConnCount":        statusResp.DCConnCount,
			"warpConnCount":      statusResp.WarpConnCount,
		})
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置文件失败")
		return
	}
	nextWR, cleanTarget, targetOut, matchedPresetName, qErr := computeQuickSwitchRouting(cfg.Server.WarpRouting, body.Target, body.Outbound)
	if qErr != nil {
		if errors.Is(qErr, ErrWarpQuickSwitchInBypass) {
			writeJSONError(w, http.StatusConflict, qErr.Error())
		} else {
			writeJSONError(w, http.StatusBadRequest, qErr.Error())
		}
		return
	}

	statusResp, httpCode, evicted, applyErr := s.applyWarpRoutingConfig(r, nextWR)
	if applyErr != nil {
		writeJSONError(w, httpCode, applyErr.Error())
		return
	}
	if clusterResp, cErr := s.buildClusterWarpStatus(r, cfg, "local", false); cErr == nil {
		statusResp.SelectedNode = clusterResp.SelectedNode
		statusResp.Nodes = clusterResp.Nodes
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
		"selectedNode":       statusResp.SelectedNode,
		"nodes":              statusResp.Nodes,
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
	targetNode := cmp.Or(strings.TrimSpace(r.URL.Query().Get("node")), "local")

	if targetNode == "all" {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      true,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      "请选择具体节点胶囊透视该主机的实时出站连接",
		})
		return
	}
	if targetNode != "local" {
		s.handleRemoteWarpConnections(w, r, targetNode, q, outbound)
		return
	}

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
		Action string `json:"action"` // "rekey" | "ensure" | "enable_telemetry"
		Node   string `json:"node"`   // "local" | "<id>" | "all"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	action := strings.ToLower(strings.TrimSpace(body.Action))
	targetNode := cmp.Or(strings.TrimSpace(body.Node), "local")
	if targetNode != "local" || action == "enable_telemetry" {
		s.handleClusterOrRemoteWarpAction(w, r, action, targetNode)
		return
	}

	s.warpMu.Lock()
	defer s.warpMu.Unlock()

	switch action {
	case "rekey":
		s.warpCacheMu.Lock()
		prevIP := strings.TrimSpace(s.warpCachedIP)
		s.warpCacheMu.Unlock()
		if prevIP == "" {
			if ip, _, _, ok := deploy.FetchWarpExitInfo(1200 * time.Millisecond); ok && ip != "" {
				prevIP = strings.TrimSpace(ip)
			}
		}

		rotateFn := s.warpRotateIdentity
		if rotateFn == nil {
			rotateFn = deploy.RotateWarpIdentityFrom
		}
		newIP, newLoc, err := rotateFn(prevIP)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.warpCacheMu.Lock()
		s.warpCachedIP = newIP
		s.warpCachedLoc = newLoc
		s.warpCachedAt = time.Now()
		s.warpCacheMu.Unlock()

		restoredFromDegraded := s.restoreSavedWarpRoutingIfDegraded()
		if !restoredFromDegraded {
			s.warpWatchdogMu.Lock()
			if !s.warpDegraded {
				s.warpAutoHealStatus = ""
				s.warpLastHealedAt = ""
			}
			s.warpWatchdogMu.Unlock()
		}
		evicted := s.evictAllWarpConnections(r.Context())
		s.invalidateStatusCaches()

		s.recordAudit(r, fmt.Sprintf("重新注册并切换 WARP 出口 IP [%s (%s)] (踢断旧流:%d)", newIP, cmp.Or(newLoc, "Unknown"), evicted))
		var msg string
		switch {
		case prevIP != "" && prevIP != newIP:
			msg = fmt.Sprintf("已更换全新 WARP 出口 IP：%s → %s (%s)", prevIP, newIP, cmp.Or(newLoc, "Anycast"))
		case prevIP != "" && prevIP == newIP:
			msg = fmt.Sprintf("已重新注册 WARP 密钥，当前出口 IP 为 %s (%s)", newIP, cmp.Or(newLoc, "Anycast"))
		default:
			msg = fmt.Sprintf("已更换全新 WARP 出口 IP：%s (%s)", newIP, cmp.Or(newLoc, "Anycast"))
		}
		if restoredFromDegraded {
			msg += "，并已自动解除直出降级恢复原有分流策略"
		}
		if evicted > 0 {
			msg += fmt.Sprintf("（已立即切换 %d 条存量连接）", evicted)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":            msg,
			"warpIp":             newIP,
			"warpLoc":            newLoc,
			"evictedConnections": evicted,
			"daemon":             s.probeWarpDaemon(false),
		})

	case "ensure":
		cfg, _ := config.Load(s.opts.ConfigPath)
		if err := deploy.DeployWarpWithConfig(cfg); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "一键部署/修复 WARP 失败: "+err.Error())
			return
		}
		restoredFromDegraded := s.restoreSavedWarpRoutingIfDegraded()
		evicted := s.evictAllWarpConnections(r.Context())
		s.invalidateStatusCaches()
		daemon := s.probeWarpDaemon(true)
		s.recordAudit(r, fmt.Sprintf("一键部署并修复内置纯 Go WARP 隧道 (踢断旧流:%d)", evicted))
		msg := "WARP (纯 Go wireproxy) 本地隧道已就绪，现可自由切换任意分流规则"
		if restoredFromDegraded {
			msg = "WARP 本地隧道已修复，并已自动恢复原有分流策略"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"message":            msg,
			"evictedConnections": evicted,
			"daemon":             daemon,
		})

	default:
		writeJSONError(w, http.StatusBadRequest, "不支持的操作: "+action)
	}
}

func (s *Server) restoreSavedWarpRoutingIfDegraded() bool {
	s.warpWatchdogMu.Lock()
	degraded := s.warpDegraded
	s.warpFailStreak = 0
	s.warpWatchdogMu.Unlock()
	if !degraded {
		return false
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		return false
	}
	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	if _, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, cfg.Server.WarpRouting, s.liveWarpDepsForConfig(cfg)); applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		return false
	}

	s.warpWatchdogMu.Lock()
	s.warpDegraded = false
	s.warpAutoHealStatus = "已手动恢复 WARP 隧道并切回原有分流策略"
	s.warpLastHealedAt = time.Now().Format("2006-01-02 15:04:05")
	s.warpWatchdogMu.Unlock()
	return true
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
