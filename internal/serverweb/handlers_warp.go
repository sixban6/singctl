// 文件职责：提供服务端 WARP 路由配置、单项目标秒切、活跃流查询与单机/全集群广播薄 HTTP 控制层（领域逻辑委托 deploy 与 fleet）。
package serverweb

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/httpx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/fleet"
	"singctl/internal/telemetry"
)

type warpRuntime struct {
	actionMu sync.Mutex
	prober   *deploy.WarpProber
	watchdog *deploy.WarpWatchdog
	cluster  *fleet.WarpClusterCoordinator
}

func newWarpRuntime(s *Server) *warpRuntime {
	rt := &warpRuntime{
		prober:  deploy.NewWarpProber(),
		cluster: fleet.NewWarpClusterCoordinator(s.fleet),
	}
	rt.watchdog = deploy.NewWarpWatchdog(deploy.WarpWatchdogRuntime{
		ActionMu:          &rt.actionMu,
		SingBoxConfigPath: s.opts.SingBoxConfigPath,
		LoadConfig:        s.loadConfigBounded,
		LiveDepsForConfig: s.liveWarpDepsForConfig,
		EvictAllWarpConns: s.evictAllWarpConnections,
		EvictMismatchedConns: func(ctx context.Context, cfg *config.Config) {
			if s.telemetry == nil || cfg == nil {
				return
			}
			protected := deploy.CollectServerProtectedDomains(cfg)
			_, _ = s.telemetry.EvictMismatchedConnections(ctx, func(host, dstIP, ruleTag, currentOutbound string) bool {
				return deploy.ExpectedTargetOutbound(cfg.Server.WarpRouting, host, dstIP, ruleTag, protected...) != currentOutbound
			})
		},
		OnAudit: func(action string) {
			if s.audit != nil {
				s.audit.Record("127.0.0.1", action)
			}
		},
		OnExitIPUpdated: func(ip, loc string) {
			rt.prober.SetCachedExit(ip, loc, time.Now())
		},
		OnWireproxyNormalized: func() {
			rt.prober.ClearCache()
		},
	})
	return rt
}

// ProbeWarpDaemon 探测本机 WARP 守护进程与隧道状态，并叠加看门狗熔断/自愈标记。
func (s *Server) ProbeWarpDaemon(forceRefresh bool) WarpDaemonStatus {
	st := s.warp.prober.Probe(forceRefresh)
	s.warp.watchdog.DecorateDaemonStatus(&st)
	return st
}

// RunWarpWatchdogTick 执行单次 WARP 健康巡检与三阶段自愈（供测试确定性驱动）。
func (s *Server) RunWarpWatchdogTick(ctx context.Context) {
	s.warp.watchdog.RunTick(ctx)
}

func (s *Server) buildWarpRoutingStatus(ctx context.Context, cfg *config.Config, forceRefresh bool) WarpRoutingStatusResponse {
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
		snap := s.telemetry.Collect(ctx)
		dcCount = snap.Outbounds.DirectConnections
		warpCount = snap.Outbounds.WarpConnections
	}

	return WarpRoutingStatusResponse{
		Daemon:        s.ProbeWarpDaemon(forceRefresh),
		Routing:       wr,
		Presets:       deploy.BuildPresetStateList(wr),
		DCConnCount:   dcCount,
		WarpConnCount: warpCount,
	}
}

func (s *Server) buildClusterWarpStatus(ctx context.Context, cfg *config.Config, selectedNode string, forceRefresh bool) (WarpRoutingStatusResponse, error) {
	localResp := s.buildWarpRoutingStatus(ctx, cfg, forceRefresh && (selectedNode == "" || selectedNode == "local"))
	return s.warp.cluster.BuildClusterStatus(ctx, localResp, selectedNode, forceRefresh)
}

func (s *Server) handleGetWarpRouting(w http.ResponseWriter, r *http.Request) {
	forceRefresh := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	selectedNode := cmp.Or(strings.TrimSpace(r.URL.Query().Get("node")), "local")
	cfg := s.readConfigOrNil()
	resp, err := s.buildClusterWarpStatus(r.Context(), cfg, selectedNode, forceRefresh)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) liveWarpDepsForConfig(cfg *config.Config) *deploy.LiveWarpApplyDeps {
	var deps deploy.LiveWarpApplyDeps
	if injected := s.snapshotDeps().WarpApplyDeps; injected != nil {
		deps = *injected
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

func (s *Server) applyWarpRoutingConfig(ctx context.Context, targetWR config.WarpRoutingConfig) (WarpRoutingStatusResponse, int, int, error) {
	normalized, err := config.NormalizeWarpRouting(targetWR)
	if err != nil {
		return WarpRoutingStatusResponse{}, http.StatusBadRequest, 0, err
	}

	s.warp.actionMu.Lock()
	defer s.warp.actionMu.Unlock()

	cfg, loadErr := s.loadMutableConfig()
	if loadErr != nil || cfg == nil {
		return WarpRoutingStatusResponse{}, http.StatusInternalServerError, 0, fmt.Errorf("加载配置文件失败: %w", loadErr)
	}

	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	if _, applyErr := deploy.ApplyLiveWarpRouting(sbCfgPath, normalized, s.liveWarpDepsForConfig(cfg)); applyErr != nil {
		if errors.Is(applyErr, deploy.ErrWarpTunnelUnavailable) {
			return WarpRoutingStatusResponse{}, http.StatusConflict, 0, applyErr
		}
		if !errors.Is(applyErr, os.ErrNotExist) {
			return WarpRoutingStatusResponse{}, http.StatusInternalServerError, 0, applyErr
		}
	}

	cfg.Server.WarpRouting = normalized
	if saveErr := s.saveConfig(cfg); saveErr != nil {
		return WarpRoutingStatusResponse{}, http.StatusInternalServerError, 0, fmt.Errorf("持久化 singctl.yaml 失败: %w", saveErr)
	}

	s.warp.watchdog.ResetOnManualApply()

	evicted := 0
	if s.telemetry != nil {
		protected := deploy.CollectServerProtectedDomains(cfg)
		n, _ := s.telemetry.EvictMismatchedConnections(ctx, func(host, dstIP, ruleTag, currentOutbound string) bool {
			return deploy.ExpectedTargetOutbound(normalized, host, dstIP, ruleTag, protected...) != currentOutbound
		})
		evicted = n
	}
	return s.buildWarpRoutingStatus(ctx, cfg, false), http.StatusOK, evicted, nil
}

func writeWarpRoutingMutationResponse(w http.ResponseWriter, msg string, evicted int, statusResp WarpRoutingStatusResponse, extra map[string]any) {
	out := map[string]any{
		"message":            msg,
		"evictedConnections": evicted,
		"selectedNode":       statusResp.SelectedNode,
		"nodes":              statusResp.Nodes,
		"daemon":             statusResp.Daemon,
		"routing":            statusResp.Routing,
		"presets":            statusResp.Presets,
		"dcConnCount":        statusResp.DCConnCount,
		"warpConnCount":      statusResp.WarpConnCount,
	}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUpdateWarpRouting(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		config.WarpRoutingConfig
		Node        string `json:"node"`
		ViewNode    string `json:"viewNode"`
		SyncCluster bool   `json:"syncCluster"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, false, "无效的 JSON 请求格式")
	if !ok {
		return
	}

	targetNode := cmp.Or(strings.TrimSpace(body.Node), "local")
	viewNode := cmp.Or(strings.TrimSpace(body.ViewNode), targetNode)

	if targetNode == "all" || body.SyncCluster {
		normalized, err := config.NormalizeWarpRouting(body.WarpRoutingConfig)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		evicted, results, msg, conflict, applyErr := s.warp.cluster.BroadcastRouting(r.Context(), normalized, func(ctx context.Context) (int, error) {
			_, _, ev, lErr := s.applyWarpRoutingConfig(ctx, normalized)
			return ev, lErr
		})
		if applyErr != nil {
			code := http.StatusInternalServerError
			if conflict {
				code = http.StatusConflict
			}
			writeJSONError(w, code, applyErr.Error())
			return
		}
		statusResp, _ := s.buildClusterWarpStatus(r.Context(), s.readConfigOrNil(), viewNode, false)
		s.recordAudit(r, fmt.Sprintf("全集群同步更新 WARP 智能分流策略 [模式:%s, 节点数:%d, 踢流:%d]",
			normalized.Mode, len(results), evicted))
		writeWarpRoutingMutationResponse(w, msg, evicted, statusResp, map[string]any{"results": results})
		return
	}

	if targetNode != "local" {
		fn, found := s.warp.cluster.FindEnabledNode(targetNode)
		if !found {
			writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
			return
		}
		normalized, err := config.NormalizeWarpRouting(body.WarpRoutingConfig)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, applyErr := s.warp.cluster.ApplyRemoteNode(r.Context(), fn, normalized)
		if applyErr != nil {
			code := http.StatusInternalServerError
			if fleet.IsTunnelUnavailableErr(applyErr) {
				code = http.StatusConflict
			}
			writeJSONError(w, code, fmt.Sprintf("[%s] %v", cmp.Or(fn.Name, fn.ID), applyErr))
			return
		}
		statusResp, _ := s.buildClusterWarpStatus(r.Context(), s.readConfigOrNil(), viewNode, false)
		s.recordAudit(r, fmt.Sprintf("更新子节点 [%s] WARP 分流策略 [模式:%s, 踢流:%d]",
			cmp.Or(fn.Name, fn.ID), res.Status.Routing.Mode, res.EvictedConnections))
		writeWarpRoutingMutationResponse(w, fmt.Sprintf("[%s] %s", cmp.Or(fn.Name, fn.ID), res.Message), res.EvictedConnections, statusResp, nil)
		return
	}

	statusResp, httpCode, evicted, err := s.applyWarpRoutingConfig(r.Context(), body.WarpRoutingConfig)
	if err != nil {
		writeJSONError(w, httpCode, err.Error())
		return
	}
	if clusterResp, cErr := s.buildClusterWarpStatus(r.Context(), s.readConfigOrNil(), "local", false); cErr == nil {
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
	writeWarpRoutingMutationResponse(w, msg, evicted, statusResp, nil)
}

func (s *Server) handleQuickSwitchWarp(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Target      string `json:"target"`
		Outbound    string `json:"outbound"`
		Node        string `json:"node"`
		ViewNode    string `json:"viewNode"`
		SyncCluster bool   `json:"syncCluster"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, false, "请提供要切换的目标域名或 IP/CIDR")
	if !ok {
		return
	}
	if strings.TrimSpace(body.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "请提供要切换的目标域名或 IP/CIDR")
		return
	}

	targetNode := cmp.Or(strings.TrimSpace(body.Node), "local")
	viewNode := cmp.Or(strings.TrimSpace(body.ViewNode), targetNode)

	if targetNode == "all" || body.SyncCluster {
		cleanTarget, targetOut, matchedPreset, totalEvicted, items, summaryMsg, conflict, badReqErr := s.warp.cluster.BroadcastQuickSwitch(
			r.Context(),
			body.Target,
			body.Outbound,
			func(ctx context.Context) (int, bool, string, error) {
				cfg, lErr := s.loadConfigSnapshot()
				if lErr != nil || cfg == nil {
					return 0, false, "", errors.New("加载配置失败")
				}
				nextWR, _, _, _, qErr := deploy.ComputeQuickSwitchRouting(cfg.Server.WarpRouting, body.Target, body.Outbound)
				if qErr != nil {
					if errors.Is(qErr, deploy.ErrWarpQuickSwitchInBypass) {
						return 0, true, "当前处于紧急旁路，已跳过", nil
					}
					return 0, false, "", qErr
				}
				_, _, evicted, aErr := s.applyWarpRoutingConfig(ctx, nextWR)
				return evicted, false, "", aErr
			},
		)
		if badReqErr != nil {
			writeJSONError(w, http.StatusBadRequest, badReqErr.Error())
			return
		}
		if conflict {
			firstMsg := "无可用节点"
			if len(items) > 0 {
				firstMsg = items[0].Message
			}
			writeJSONError(w, http.StatusConflict, "集群内暂无可执行快切的就绪节点："+firstMsg)
			return
		}
		statusResp, _ := s.buildClusterWarpStatus(r.Context(), s.readConfigOrNil(), viewNode, false)
		s.recordAudit(r, fmt.Sprintf("全集群秒切目标 [%s] -> %s (节点数:%d, 踢断旧流:%d)", cleanTarget, targetOut, len(items), totalEvicted))
		writeWarpRoutingMutationResponse(w, summaryMsg, totalEvicted, statusResp, map[string]any{
			"target":        cleanTarget,
			"outbound":      targetOut,
			"matchedPreset": matchedPreset,
			"results":       items,
		})
		return
	}

	if targetNode != "local" {
		fn, found := s.warp.cluster.FindEnabledNode(targetNode)
		if !found {
			writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
			return
		}
		res, err := s.warp.cluster.QuickSwitchRemoteNode(r.Context(), fn, body.Target, body.Outbound)
		if err != nil {
			code := http.StatusInternalServerError
			if strings.Contains(err.Error(), "紧急全直出旁路") || fleet.IsTunnelUnavailableErr(err) {
				code = http.StatusConflict
			}
			writeJSONError(w, code, fmt.Sprintf("[%s] %v", cmp.Or(fn.Name, fn.ID), err))
			return
		}
		statusResp, _ := s.buildClusterWarpStatus(r.Context(), s.readConfigOrNil(), viewNode, false)
		s.recordAudit(r, fmt.Sprintf("子节点 [%s] 一键秒切目标 [%s] -> %s (踢断旧流:%d)",
			cmp.Or(fn.Name, fn.ID), res.Target, res.Outbound, res.EvictedConnections))
		writeWarpRoutingMutationResponse(w, fmt.Sprintf("[%s] %s", cmp.Or(fn.Name, fn.ID), res.Message), res.EvictedConnections, statusResp, map[string]any{
			"target":        res.Target,
			"outbound":      res.Outbound,
			"matchedPreset": res.MatchedPreset,
		})
		return
	}

	cfg, err := s.loadConfigSnapshot()
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置文件失败")
		return
	}
	nextWR, cleanTarget, targetOut, matchedPresetName, qErr := deploy.ComputeQuickSwitchRouting(cfg.Server.WarpRouting, body.Target, body.Outbound)
	if qErr != nil {
		if errors.Is(qErr, deploy.ErrWarpQuickSwitchInBypass) {
			writeJSONError(w, http.StatusConflict, qErr.Error())
		} else {
			writeJSONError(w, http.StatusBadRequest, qErr.Error())
		}
		return
	}

	statusResp, httpCode, evicted, applyErr := s.applyWarpRoutingConfig(r.Context(), nextWR)
	if applyErr != nil {
		writeJSONError(w, httpCode, applyErr.Error())
		return
	}
	if clusterResp, cErr := s.buildClusterWarpStatus(r.Context(), s.readConfigOrNil(), "local", false); cErr == nil {
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
	writeWarpRoutingMutationResponse(w, msg, evicted, statusResp, map[string]any{
		"target":        cleanTarget,
		"outbound":      targetOut,
		"matchedPreset": matchedPresetName,
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
		fn, found := s.warp.cluster.FindEnabledNode(targetNode)
		if !found {
			writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
			return
		}
		writeJSON(w, http.StatusOK, s.warp.cluster.FetchRemoteConnections(r.Context(), fn, q, outbound))
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

func (s *Server) runLocalWarpActionForCluster(ctx context.Context, action string) error {
	switch action {
	case "rekey":
		s.warp.actionMu.Lock()
		defer s.warp.actionMu.Unlock()
		prevIP := strings.TrimSpace(s.warp.prober.CachedExitIP())
		rotateFn := s.snapshotDeps().WarpRotateIdentity
		if rotateFn == nil {
			rotateFn = deploy.RotateWarpIdentityFrom
		}
		newIP, newLoc, err := rotateFn(prevIP)
		if err != nil {
			return err
		}
		s.warp.prober.SetCachedExit(newIP, newLoc, time.Now())
		_ = s.warp.watchdog.RestoreSavedRoutingIfDegraded(s.readConfigOrNil())
		_ = s.evictAllWarpConnections(ctx)
		s.invalidateStatusCaches()
		return nil

	case "ensure":
		s.warp.actionMu.Lock()
		defer s.warp.actionMu.Unlock()
		if err := deploy.DeployWarpWithConfig(s.readConfigOrNil()); err != nil {
			return err
		}
		_ = s.warp.watchdog.RestoreSavedRoutingIfDegraded(s.readConfigOrNil())
		_ = s.evictAllWarpConnections(ctx)
		s.invalidateStatusCaches()
		return nil

	case "enable_telemetry":
		changed, _, _, err := telemetry.EnsureConfigTelemetry(s.opts.SingBoxConfigPath)
		if err != nil {
			return err
		}
		if changed {
			if runErr := s.serviceMgr().Restart(ctx, "sing-box"); runErr != nil {
				return runErr
			}
			time.Sleep(350 * time.Millisecond)
		}
		return nil

	default:
		return fmt.Errorf("不支持的操作: %s", action)
	}
}

func (s *Server) handleWarpAction(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		Action string `json:"action"`
		Node   string `json:"node"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, false, "无效的 JSON 请求")
	if !ok {
		return
	}

	action := strings.ToLower(strings.TrimSpace(body.Action))
	targetNode := cmp.Or(strings.TrimSpace(body.Node), "local")

	if targetNode == "all" {
		switch action {
		case "rekey", "ensure", "enable_telemetry":
		default:
			writeJSONError(w, http.StatusBadRequest, "不支持的操作: "+action)
			return
		}
		items, summaryMsg, auditMsg, err := s.warp.cluster.BroadcastAction(r.Context(), action, func(ctx context.Context) error {
			return s.runLocalWarpActionForCluster(ctx, action)
		})
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.recordAudit(r, auditMsg)
		writeJSON(w, http.StatusOK, map[string]any{
			"message": summaryMsg,
			"results": items,
			"daemon":  s.ProbeWarpDaemon(false),
		})
		return
	}

	if targetNode != "local" {
		switch action {
		case "rekey", "ensure", "enable_telemetry":
		default:
			writeJSONError(w, http.StatusBadRequest, "不支持的操作: "+action)
			return
		}
		fn, found := s.warp.cluster.FindEnabledNode(targetNode)
		if !found {
			writeJSONError(w, http.StatusNotFound, "未找到集群子节点: "+targetNode)
			return
		}
		res, err := s.warp.cluster.RunRemoteAction(r.Context(), fn, action)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("[%s] %v", cmp.Or(fn.Name, fn.ID), err))
			return
		}
		if rawMsg, _ := res["message"].(string); rawMsg != "" {
			res["message"] = fmt.Sprintf("[%s] %s", cmp.Or(fn.Name, fn.ID), rawMsg)
		}
		s.recordAudit(r, fmt.Sprintf("子节点 [%s] 执行 WARP 控制指令 [%s]", cmp.Or(fn.Name, fn.ID), action))
		writeJSON(w, http.StatusOK, res)
		return
	}

	if action == "enable_telemetry" {
		if err := s.runLocalWarpActionForCluster(r.Context(), action); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "启用实时流量遥测失败: "+err.Error())
			return
		}
		s.recordAudit(r, "在 WARP 分流中心一键开启本机实时流量遥测")
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "本机实时流量遥测已无损开启",
			"daemon":  s.ProbeWarpDaemon(false),
		})
		return
	}

	s.warp.actionMu.Lock()
	defer s.warp.actionMu.Unlock()

	switch action {
	case "rekey":
		prevIP := strings.TrimSpace(s.warp.prober.CachedExitIP())
		if prevIP == "" {
			if ip, _, _, fetched := deploy.FetchWarpExitInfo(1200 * time.Millisecond); fetched && ip != "" {
				prevIP = strings.TrimSpace(ip)
			}
		}

		rotateFn := s.snapshotDeps().WarpRotateIdentity
		if rotateFn == nil {
			rotateFn = deploy.RotateWarpIdentityFrom
		}
		newIP, newLoc, err := rotateFn(prevIP)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.warp.prober.SetCachedExit(newIP, newLoc, time.Now())

		restoredFromDegraded := s.warp.watchdog.RestoreSavedRoutingIfDegraded(s.readConfigOrNil())
		if !restoredFromDegraded {
			s.warp.watchdog.ClearHealBadgeIfHealthy()
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
			"daemon":             s.ProbeWarpDaemon(false),
		})

	case "ensure":
		if err := deploy.DeployWarpWithConfig(s.readConfigOrNil()); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "一键部署/修复 WARP 失败: "+err.Error())
			return
		}
		restoredFromDegraded := s.warp.watchdog.RestoreSavedRoutingIfDegraded(s.readConfigOrNil())
		evicted := s.evictAllWarpConnections(r.Context())
		s.invalidateStatusCaches()
		daemon := s.ProbeWarpDaemon(true)
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
