// 文件职责：提供多节点 Fleet 集群 WARP 状态聚合、并发巡检缓存、批量分流同步广播与远端单节点代理操作接口。
package serverweb

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/fleet"
	"singctl/internal/telemetry"
	"strings"
	"sync"
	"time"
)

func (s *Server) listEnabledFleetNodes() []fleet.Node {
	if s.fleet == nil || s.fleet.Store == nil {
		return nil
	}
	all, err := s.fleet.Store.List()
	if err != nil {
		return nil
	}
	out := make([]fleet.Node, 0, len(all))
	for _, n := range all {
		if n.Enabled {
			out = append(out, n)
		}
	}
	return out
}

func (s *Server) findEnabledFleetNode(id string) (fleet.Node, bool) {
	for _, n := range s.listEnabledFleetNodes() {
		if n.ID == id {
			return n, true
		}
	}
	return fleet.Node{}, false
}

func (s *Server) fleetRunner() fleet.RunnerFunc {
	if s.fleet != nil && s.fleet.Runner != nil {
		return s.fleet.Runner
	}
	return fleet.DefaultSSHRunner
}

func (s *Server) putRemoteWarpCache(nodeID string, resp WarpRoutingStatusResponse, online bool, errMsg string) {
	s.warpClusterMu.Lock()
	if s.warpNodeCache == nil {
		s.warpNodeCache = make(map[string]warpNodeCacheEntry)
	}
	s.warpNodeCache[nodeID] = warpNodeCacheEntry{
		resp:      resp,
		online:    online,
		errMsg:    errMsg,
		fetchedAt: time.Now(),
	}
	s.warpClusterMu.Unlock()
}

func (s *Server) getRemoteWarpCache(nodeID string) (warpNodeCacheEntry, bool) {
	s.warpClusterMu.Lock()
	defer s.warpClusterMu.Unlock()
	if s.warpNodeCache == nil {
		return warpNodeCacheEntry{}, false
	}
	ent, ok := s.warpNodeCache[nodeID]
	return ent, ok
}

func (s *Server) fetchRemoteNodeWarpStatus(ctx context.Context, node fleet.Node, forceRefresh bool) (WarpRoutingStatusResponse, error) {
	script, err := buildRemoteWarpCtlScript("status", warpCLIStatusArgs{Refresh: forceRefresh})
	if err != nil {
		return WarpRoutingStatusResponse{}, err
	}
	rCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _, runErr := s.fleetRunner()(rCtx, node, script)
	if runErr != nil {
		s.putRemoteWarpCache(node.ID, WarpRoutingStatusResponse{}, false, runErr.Error())
		return WarpRoutingStatusResponse{}, runErr
	}
	var resp WarpRoutingStatusResponse
	if uErr := json.Unmarshal(extractJSONObjectBytes(out), &resp); uErr != nil {
		errMsg := fmt.Sprintf("解析子节点 %s WARP 状态失败: %v", node.Name, uErr)
		s.putRemoteWarpCache(node.ID, WarpRoutingStatusResponse{}, false, errMsg)
		return WarpRoutingStatusResponse{}, errors.New(errMsg)
	}
	s.putRemoteWarpCache(node.ID, resp, true, "")
	return resp, nil
}

func (s *Server) refreshAllFleetWarpAsync(forceRefresh bool) {
	nodes := s.listEnabledFleetNodes()
	if len(nodes) == 0 {
		return
	}
	tryRunSingleFlight(&s.warpClusterRefreshing, 18*time.Second, func(ctx context.Context) {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 6)
		for _, n := range nodes {
			node := n
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				_, _ = s.fetchRemoteNodeWarpStatus(ctx, node, forceRefresh)
			})
		}
		wg.Wait()
	})
}

func (s *Server) refreshAllFleetWarpSync(ctx context.Context, forceRefresh bool) {
	nodes := s.listEnabledFleetNodes()
	if len(nodes) == 0 {
		return
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for _, n := range nodes {
		node := n
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			_, _ = s.fetchRemoteNodeWarpStatus(ctx, node, forceRefresh)
		})
	}
	wg.Wait()
}

func (s *Server) buildNodeSummaries(localStatus WarpRoutingStatusResponse, fleetNodes []fleet.Node) ([]WarpNodeSummary, bool) {
	summaries := make([]WarpNodeSummary, 0, 1+len(fleetNodes))
	summaries = append(summaries, WarpNodeSummary{
		ID:            "local",
		Name:          "主控本机",
		IsLocal:       true,
		Online:        true,
		Mode:          string(localStatus.Routing.NormalizedMode()),
		Daemon:        localStatus.Daemon,
		DCConnCount:   localStatus.DCConnCount,
		WarpConnCount: localStatus.WarpConnCount,
		UpdatedAt:     time.Now().Format("15:04:05"),
	})

	anyStale := false
	for _, fn := range fleetNodes {
		cached, ok := s.getRemoteWarpCache(fn.ID)
		if !ok || time.Since(cached.fetchedAt) > warpNodeCacheTTL {
			anyStale = true
		}
		if ok && cached.online {
			summaries = append(summaries, WarpNodeSummary{
				ID:            fn.ID,
				Name:          cmp.Or(fn.Name, fn.ID),
				Host:          fn.Domain,
				IsLocal:       false,
				Online:        true,
				Mode:          string(cached.resp.Routing.NormalizedMode()),
				Daemon:        cached.resp.Daemon,
				DCConnCount:   cached.resp.DCConnCount,
				WarpConnCount: cached.resp.WarpConnCount,
				UpdatedAt:     cached.fetchedAt.Format("15:04:05"),
			})
		} else {
			errText := ""
			if ok {
				errText = cached.errMsg
			}
			summaries = append(summaries, WarpNodeSummary{
				ID:      fn.ID,
				Name:    cmp.Or(fn.Name, fn.ID),
				Host:    fn.Domain,
				IsLocal: false,
				Online:  fn.Online && errText == "",
				Mode:    string(config.WarpModeSplit),
				Daemon: WarpDaemonStatus{
					SocksPort: 40000,
					Error:     cmp.Or(errText, "正在同步子节点状态..."),
				},
				Error: errText,
			})
		}
	}
	return summaries, anyStale
}

func (s *Server) buildClusterWarpStatus(r *http.Request, cfg *config.Config, selectedNode string, forceRefresh bool) (WarpRoutingStatusResponse, error) {
	selectedNode = cmp.Or(strings.TrimSpace(selectedNode), "local")
	fleetNodes := s.listEnabledFleetNodes()
	localResp := s.buildWarpRoutingStatus(r, cfg, forceRefresh && (selectedNode == "local" || selectedNode == "all"))

	if len(fleetNodes) == 0 {
		localResp.SelectedNode = "local"
		return localResp, nil
	}

	if selectedNode == "all" {
		if forceRefresh {
			s.refreshAllFleetWarpSync(r.Context(), true)
		}
		summaries, anyStale := s.buildNodeSummaries(localResp, fleetNodes)
		if !forceRefresh && anyStale {
			s.refreshAllFleetWarpAsync(false)
		}
		totalDC := 0
		totalWarp := 0
		healthyNodes := 0
		installedNodes := 0
		for _, ns := range summaries {
			totalDC += ns.DCConnCount
			totalWarp += ns.WarpConnCount
			if ns.Daemon.TunnelHealthy {
				healthyNodes++
			}
			if ns.Daemon.Installed {
				installedNodes++
			}
		}
		aggDaemon := WarpDaemonStatus{
			Installed:     installedNodes > 0,
			Running:       healthyNodes > 0,
			TunnelHealthy: healthyNodes > 0,
			SocksPort:     40000,
			WarpIP:        fmt.Sprintf("%d/%d 节点就绪", healthyNodes, len(summaries)),
			WarpLoc:       "全集群",
		}
		if healthyNodes == 0 {
			aggDaemon.Error = "集群内暂无就绪的 WARP 隧道节点"
		}
		return WarpRoutingStatusResponse{
			SelectedNode:  "all",
			Nodes:         summaries,
			Daemon:        aggDaemon,
			Routing:       localResp.Routing,
			Presets:       localResp.Presets,
			DCConnCount:   totalDC,
			WarpConnCount: totalWarp,
		}, nil
	}

	if selectedNode == "local" {
		summaries, anyStale := s.buildNodeSummaries(localResp, fleetNodes)
		if anyStale {
			s.refreshAllFleetWarpAsync(false)
		}
		localResp.SelectedNode = "local"
		localResp.Nodes = summaries
		return localResp, nil
	}

	targetNode, ok := s.findEnabledFleetNode(selectedNode)
	if !ok {
		return WarpRoutingStatusResponse{}, fmt.Errorf("未找到集群子节点: %s", selectedNode)
	}

	var remoteResp WarpRoutingStatusResponse
	cached, hasCache := s.getRemoteWarpCache(selectedNode)
	if !forceRefresh && hasCache && cached.online {
		remoteResp = cached.resp
		if time.Since(cached.fetchedAt) > warpNodeCacheTTL {
			s.refreshAllFleetWarpAsync(false)
		}
	} else {
		fetched, err := s.fetchRemoteNodeWarpStatus(r.Context(), targetNode, forceRefresh)
		if err != nil {
			return WarpRoutingStatusResponse{}, fmt.Errorf("连接子节点 [%s] 获取 WARP 状态失败: %w", cmp.Or(targetNode.Name, targetNode.ID), err)
		}
		remoteResp = fetched
	}

	summaries, anyStale := s.buildNodeSummaries(localResp, fleetNodes)
	if !forceRefresh && anyStale {
		s.refreshAllFleetWarpAsync(false)
	}
	remoteResp.SelectedNode = selectedNode
	remoteResp.Nodes = summaries
	return remoteResp, nil
}

func isTunnelUnavailableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, deploy.ErrWarpTunnelUnavailable) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "40000") || strings.Contains(msg, "未就绪") || strings.Contains(msg, "wireproxy")
}

func (s *Server) applyWarpRoutingRemoteNode(ctx context.Context, node fleet.Node, targetWR config.WarpRoutingConfig) (warpCLIApplyResult, error) {
	script, err := buildRemoteWarpCtlScript("apply", targetWR)
	if err != nil {
		return warpCLIApplyResult{}, err
	}
	rCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _, runErr := s.fleetRunner()(rCtx, node, script)
	if runErr != nil {
		return warpCLIApplyResult{}, runErr
	}
	var res warpCLIApplyResult
	if uErr := json.Unmarshal(extractJSONObjectBytes(out), &res); uErr != nil {
		return warpCLIApplyResult{}, fmt.Errorf("解析子节点响应失败: %w", uErr)
	}
	s.putRemoteWarpCache(node.ID, res.Status, true, "")
	return res, nil
}

func (s *Server) quickSwitchRemoteNode(ctx context.Context, node fleet.Node, target, outbound string) (warpCLIApplyResult, error) {
	script, err := buildRemoteWarpCtlScript("quick-switch", warpCLIQuickSwitchArgs{Target: target, Outbound: outbound})
	if err != nil {
		return warpCLIApplyResult{}, err
	}
	rCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _, runErr := s.fleetRunner()(rCtx, node, script)
	if runErr != nil {
		return warpCLIApplyResult{}, runErr
	}
	var res warpCLIApplyResult
	if uErr := json.Unmarshal(extractJSONObjectBytes(out), &res); uErr != nil {
		return warpCLIApplyResult{}, fmt.Errorf("解析子节点响应失败: %w", uErr)
	}
	s.putRemoteWarpCache(node.ID, res.Status, true, "")
	return res, nil
}

func formatClusterSummaryMessage(actionTitle string, items []WarpClusterOpItem, totalEvicted int) string {
	okCount := 0
	skipCount := 0
	var failedNames []string
	for _, it := range items {
		switch {
		case it.Success:
			okCount++
		case it.Skipped:
			skipCount++
		default:
			failedNames = append(failedNames, it.Name)
		}
	}
	msg := fmt.Sprintf("%s：全集群 %d/%d 台节点已零断流同步生效", actionTitle, okCount, len(items))
	if skipCount > 0 {
		msg += fmt.Sprintf("（%d 台未装/未就绪已自动跳过）", skipCount)
	}
	if len(failedNames) > 0 {
		msg += fmt.Sprintf("（失败：%s）", strings.Join(failedNames, "、"))
	}
	if totalEvicted > 0 {
		msg += fmt.Sprintf("，共平滑切换 %d 条连接", totalEvicted)
	}
	return msg
}

func (s *Server) broadcastWarpRoutingCluster(r *http.Request, normalized config.WarpRoutingConfig, viewNode string) (WarpRoutingStatusResponse, int, int, []WarpClusterOpItem, string, error) {
	fleetNodes := s.listEnabledFleetNodes()
	items := make([]WarpClusterOpItem, 1+len(fleetNodes))
	var totalEvicted int
	var evictMu sync.Mutex

	var wg sync.WaitGroup
	// 1. 本机主控节点
	wg.Go(func() {
		_, _, evicted, err := s.applyWarpRoutingConfig(r, normalized)
		if err == nil {
			evictMu.Lock()
			totalEvicted += evicted
			evictMu.Unlock()
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: true, Message: "已热更新"}
		} else if isTunnelUnavailableErr(err) && normalized.NormalizedMode() != config.WarpModeBypass {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Skipped: true, Message: "本地 WARP 隧道未就绪，已跳过"}
		} else {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: err.Error()}
		}
	})

	// 2. 并发下发所有 Fleet 子节点
	sem := make(chan struct{}, 6)
	for i, fn := range fleetNodes {
		idx := i + 1
		node := fn
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := s.applyWarpRoutingRemoteNode(r.Context(), node, normalized)
			name := cmp.Or(node.Name, node.ID)
			if err == nil {
				evictMu.Lock()
				totalEvicted += res.EvictedConnections
				evictMu.Unlock()
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: true, Message: "已热更新"}
			} else if isTunnelUnavailableErr(err) && normalized.NormalizedMode() != config.WarpModeBypass {
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Skipped: true, Message: "WARP 隧道未就绪，已跳过防断流"}
			} else {
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: false, Message: err.Error()}
			}
		})
	}
	wg.Wait()

	anyOK := false
	for _, it := range items {
		if it.Success {
			anyOK = true
			break
		}
	}
	if !anyOK {
		return WarpRoutingStatusResponse{}, http.StatusConflict, 0, items, "", fmt.Errorf("集群内暂无可应用 WARP 策略的就绪节点：%s", items[0].Message)
	}

	cfg := s.readConfigOrNil()
	effectiveView := cmp.Or(strings.TrimSpace(viewNode), "all")
	statusResp, err := s.buildClusterWarpStatus(r, cfg, effectiveView, false)
	if err != nil {
		statusResp, _ = s.buildClusterWarpStatus(r, cfg, "local", false)
	}
	msg := formatClusterSummaryMessage("WARP 分流策略同步完成", items, totalEvicted)
	return statusResp, http.StatusOK, totalEvicted, items, msg, nil
}

func (s *Server) handleClusterQuickSwitch(w http.ResponseWriter, r *http.Request, rawTarget, rawOutbound, viewNode string) {
	// 先在内存中校验目标格式合法性
	_, cleanTarget, targetOut, matchedPreset, vErr := computeQuickSwitchRouting(config.WarpRoutingConfig{Mode: config.WarpModeSplit}, rawTarget, rawOutbound)
	if vErr != nil {
		writeJSONError(w, http.StatusBadRequest, vErr.Error())
		return
	}

	fleetNodes := s.listEnabledFleetNodes()
	items := make([]WarpClusterOpItem, 1+len(fleetNodes))
	var totalEvicted int
	var evictMu sync.Mutex
	var wg sync.WaitGroup

	// 1. 本机快速切换（基于本机自身当前配置独立计算）
	wg.Go(func() {
		cfg, err := s.loadConfigSnapshot()
		if err != nil || cfg == nil {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: "读取配置失败"}
			return
		}
		nextWR, _, _, _, qErr := computeQuickSwitchRouting(cfg.Server.WarpRouting, rawTarget, rawOutbound)
		if qErr != nil {
			if errors.Is(qErr, ErrWarpQuickSwitchInBypass) {
				items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Skipped: true, Message: "处于紧急旁路模式，已跳过"}
			} else {
				items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: qErr.Error()}
			}
			return
		}
		_, _, evicted, applyErr := s.applyWarpRoutingConfig(r, nextWR)
		if applyErr == nil {
			evictMu.Lock()
			totalEvicted += evicted
			evictMu.Unlock()
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: true, Message: "已秒切"}
		} else if isTunnelUnavailableErr(applyErr) {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Skipped: true, Message: "WARP 隧道未就绪，已跳过"}
		} else {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: applyErr.Error()}
		}
	})

	// 2. 并发对各子节点按各自当前配置独立叠加切换
	sem := make(chan struct{}, 6)
	for i, fn := range fleetNodes {
		idx := i + 1
		node := fn
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			name := cmp.Or(node.Name, node.ID)
			res, err := s.quickSwitchRemoteNode(r.Context(), node, rawTarget, rawOutbound)
			if err == nil {
				evictMu.Lock()
				totalEvicted += res.EvictedConnections
				evictMu.Unlock()
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: true, Message: "已秒切"}
			} else if isTunnelUnavailableErr(err) || strings.Contains(err.Error(), "紧急全直出旁路") {
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Skipped: true, Message: "隧道未就绪或处于旁路，已跳过"}
			} else {
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: false, Message: err.Error()}
			}
		})
	}
	wg.Wait()

	anyOK := false
	for _, it := range items {
		if it.Success {
			anyOK = true
			break
		}
	}
	if !anyOK {
		writeJSONError(w, http.StatusConflict, "集群内暂无可执行秒切的就绪节点")
		return
	}

	cfg := s.readConfigOrNil()
	effectiveView := cmp.Or(strings.TrimSpace(viewNode), "all")
	statusResp, err := s.buildClusterWarpStatus(r, cfg, effectiveView, false)
	if err != nil {
		statusResp, _ = s.buildClusterWarpStatus(r, cfg, "local", false)
	}

	actionLabel := "切换至 WARP"
	if targetOut == "DC" {
		actionLabel = "切回直出 DC"
	}
	title := fmt.Sprintf("已将 %s %s", cleanTarget, actionLabel)
	msg := formatClusterSummaryMessage(title, items, totalEvicted)
	s.recordAudit(r, fmt.Sprintf("全集群一键秒切 [%s] -> %s (踢流:%d)", cleanTarget, targetOut, totalEvicted))

	writeJSON(w, http.StatusOK, map[string]any{
		"message":            msg,
		"target":             cleanTarget,
		"outbound":           targetOut,
		"matchedPreset":      matchedPreset,
		"evictedConnections": totalEvicted,
		"results":            items,
		"selectedNode":       statusResp.SelectedNode,
		"nodes":              statusResp.Nodes,
		"daemon":             statusResp.Daemon,
		"routing":            statusResp.Routing,
		"presets":            statusResp.Presets,
		"dcConnCount":        statusResp.DCConnCount,
		"warpConnCount":      statusResp.WarpConnCount,
	})
}

func (s *Server) handleRemoteWarpConnections(w http.ResponseWriter, r *http.Request, nodeID, query, outbound string) {
	fn, ok := s.findEnabledFleetNode(nodeID)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+nodeID)
		return
	}
	script, err := buildRemoteWarpCtlScript("connections", warpCLIConnectionsArgs{Query: query, Outbound: outbound})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, _, runErr := s.fleetRunner()(rCtx, fn, script)
	if runErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      fmt.Sprintf("连接子节点 [%s] 获取活跃流失败: %v", cmp.Or(fn.Name, fn.ID), runErr),
		})
		return
	}
	var payload map[string]any
	if uErr := json.Unmarshal(extractJSONObjectBytes(out), &payload); uErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      fmt.Sprintf("解析子节点 [%s] 活跃流数据失败: %v", cmp.Or(fn.Name, fn.ID), uErr),
		})
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func (s *Server) runRemoteWarpActionNode(ctx context.Context, node fleet.Node, action string) (map[string]any, error) {
	script, err := buildRemoteWarpCtlScript("action", warpCLIActionArgs{Action: action})
	if err != nil {
		return nil, err
	}
	timeout := 35 * time.Second
	if action == "ensure" {
		timeout = 75 * time.Second
	}
	rCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, _, runErr := s.fleetRunner()(rCtx, node, script)
	if runErr != nil {
		return nil, runErr
	}
	var res map[string]any
	if uErr := json.Unmarshal(extractJSONObjectBytes(out), &res); uErr != nil {
		return nil, fmt.Errorf("解析子节点响应失败: %w", uErr)
	}
	// Refresh cached status for this node in background/inline
	_, _ = s.fetchRemoteNodeWarpStatus(ctx, node, false)
	return res, nil
}

func (s *Server) handleClusterOrRemoteWarpAction(w http.ResponseWriter, r *http.Request, action, targetNode string) {
	switch action {
	case "rekey", "ensure", "enable_telemetry":
	default:
		writeJSONError(w, http.StatusBadRequest, "不支持的操作: "+action)
		return
	}

	if targetNode == "local" && action == "enable_telemetry" {
		s.handleEnableTelemetry(w, r)
		return
	}

	if targetNode == "all" {
		fleetNodes := s.listEnabledFleetNodes()
		items := make([]WarpClusterOpItem, 1+len(fleetNodes))
		var wg sync.WaitGroup

		// 1. 本机
		wg.Go(func() {
			out, err := ExecuteLocalWarpCLI(r.Context(), "action", mustJSON(warpCLIActionArgs{Action: action}), LocalWarpCLIOptions{
				ConfigPath:        s.opts.ConfigPath,
				SingBoxConfigPath: s.opts.SingBoxConfigPath,
				DaemonProbe:       s.warpDaemonProbe,
				RotateWarpFn:      s.warpRotateIdentity,
			})
			if err == nil {
				var m map[string]any
				_ = json.Unmarshal(out, &m)
				if ip, _ := m["warpIp"].(string); ip != "" {
					s.warpCacheMu.Lock()
					s.warpCachedIP = ip
					if loc, _ := m["warpLoc"].(string); loc != "" {
						s.warpCachedLoc = loc
					}
					s.warpCachedAt = time.Now()
					s.warpCacheMu.Unlock()
				}
				s.invalidateConfigCache()
				items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: true, Message: "执行成功"}
			} else {
				items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: err.Error()}
			}
		})

		// 2. 子节点并发执行
		sem := make(chan struct{}, 6)
		for i, fn := range fleetNodes {
			idx := i + 1
			node := fn
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				name := cmp.Or(node.Name, node.ID)
				_, err := s.runRemoteWarpActionNode(r.Context(), node, action)
				if err == nil {
					items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: true, Message: "执行成功"}
				} else {
					items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: false, Message: err.Error()}
				}
			})
		}
		wg.Wait()

		okCount := 0
		for _, it := range items {
			if it.Success {
				okCount++
			}
		}
		if okCount == 0 {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("全集群执行 %s 失败: %s", action, items[0].Message))
			return
		}
		label := "全集群批量更换 WARP IP"
		if action == "ensure" {
			label = "全集群一键部署/修复 WARP"
		} else if action == "enable_telemetry" {
			label = "全集群开启实时遥测"
		}
		s.recordAudit(r, fmt.Sprintf("%s (%d/%d 成功)", label, okCount, len(items)))
		cfg := s.readConfigOrNil()
		clusterStatus, _ := s.buildClusterWarpStatus(r, cfg, "all", false)
		writeJSON(w, http.StatusOK, map[string]any{
			"message": fmt.Sprintf("%s完成：%d/%d 台节点执行成功", label, okCount, len(items)),
			"results": items,
			"daemon":  clusterStatus.Daemon,
			"nodes":   clusterStatus.Nodes,
		})
		return
	}

	fn, ok := s.findEnabledFleetNode(targetNode)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
		return
	}
	res, err := s.runRemoteWarpActionNode(r.Context(), fn, action)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("[%s] %v", cmp.Or(fn.Name, fn.ID), err))
		return
	}
	rawMsg, _ := res["message"].(string)
	res["message"] = fmt.Sprintf("[%s] %s", cmp.Or(fn.Name, fn.ID), cmp.Or(rawMsg, "操作已完成"))
	s.recordAudit(r, fmt.Sprintf("子节点 [%s] 执行 WARP 操作 [%s]", cmp.Or(fn.Name, fn.ID), action))
	writeJSON(w, http.StatusOK, res)
}
