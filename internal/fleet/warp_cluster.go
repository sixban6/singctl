// 文件职责：负责 Fleet 多节点 WARP 状态并发巡检缓存、远端 warp-ctl Base64 安全管道调用与全集群分流广播编排。
package fleet

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/telemetry"
)

const warpNodeCacheTTL = 30 * time.Second

// WarpClusterOpItem 记录全集群批量编排时单台主机的执行明细。
type WarpClusterOpItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Skipped bool   `json:"skipped,omitempty"`
	Message string `json:"message"`
}

type warpNodeCacheEntry struct {
	resp      deploy.WarpRoutingStatusResponse
	online    bool
	errMsg    string
	fetchedAt time.Time
}

// WarpClusterCoordinator 协调主控本机与 Fleet 子节点的 WARP 状态聚合、SWR 巡检缓存及批量广播。
type WarpClusterCoordinator struct {
	mgr        *Manager
	mu         sync.Mutex
	nodeCache  map[string]warpNodeCacheEntry
	refreshing atomic.Bool
}

// NewWarpClusterCoordinator 创建 Fleet 集群 WARP 协调器。
func NewWarpClusterCoordinator(mgr *Manager) *WarpClusterCoordinator {
	return &WarpClusterCoordinator{
		mgr:       mgr,
		nodeCache: make(map[string]warpNodeCacheEntry),
	}
}

// BuildRemoteWarpCtlScript 构建经严格白名单校验与 Base64 管道传递载荷的远端 warp-ctl 执行脚本。
func BuildRemoteWarpCtlScript(subcommand string, payload any) (string, error) {
	switch subcommand {
	case "status", "apply", "quick-switch", "connections", "action":
	default:
		return "", fmt.Errorf("invalid warp-ctl subcommand: %q", subcommand)
	}
	var raw []byte
	if payload != nil {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			return "", err
		}
	}
	b64 := base64.StdEncoding.EncodeToString(raw)
	return fmt.Sprintf("set -e\nWARPCTL_B64='%s'\nprintf '%%s' \"$WARPCTL_B64\" | base64 -d | singctl --config /etc/singctl/singctl.yaml sr warp-ctl %s\n", b64, subcommand), nil
}

// ExtractJSONObjectBytes 从可能包含 SSH 登录横幅或警告行的远端标准输出中截取顶层 JSON 对象字节。
func ExtractJSONObjectBytes(raw string) []byte {
	s := strings.TrimSpace(raw)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start >= 0 && end > start {
		return []byte(s[start : end+1])
	}
	return []byte(s)
}

// IsTunnelUnavailableErr 判断错误是否表示远端或本地 WARP 隧道未安装/未就绪。
func IsTunnelUnavailableErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, deploy.ErrWarpTunnelUnavailable) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "40000") || strings.Contains(msg, "未就绪") || strings.Contains(msg, "wireproxy")
}

// ListEnabledNodes 返回当前已启用的 Fleet 子节点列表。
func (c *WarpClusterCoordinator) ListEnabledNodes() []Node {
	if c == nil || c.mgr == nil || c.mgr.Store == nil {
		return nil
	}
	all, err := c.mgr.Store.List()
	if err != nil {
		return nil
	}
	out := make([]Node, 0, len(all))
	for _, n := range all {
		if n.Enabled {
			out = append(out, n)
		}
	}
	return out
}

// FindEnabledNode 按 ID 查找已启用的 Fleet 子节点。
func (c *WarpClusterCoordinator) FindEnabledNode(id string) (Node, bool) {
	for _, n := range c.ListEnabledNodes() {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

func (c *WarpClusterCoordinator) runner() RunnerFunc {
	if c != nil && c.mgr != nil && c.mgr.Runner != nil {
		return c.mgr.Runner
	}
	return DefaultSSHRunner
}

func (c *WarpClusterCoordinator) putCache(nodeID string, resp deploy.WarpRoutingStatusResponse, online bool, errMsg string) {
	c.mu.Lock()
	if c.nodeCache == nil {
		c.nodeCache = make(map[string]warpNodeCacheEntry)
	}
	c.nodeCache[nodeID] = warpNodeCacheEntry{
		resp:      resp,
		online:    online,
		errMsg:    errMsg,
		fetchedAt: time.Now(),
	}
	c.mu.Unlock()
}

func (c *WarpClusterCoordinator) getCache(nodeID string) (warpNodeCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nodeCache == nil {
		return warpNodeCacheEntry{}, false
	}
	ent, ok := c.nodeCache[nodeID]
	return ent, ok
}

func (c *WarpClusterCoordinator) fetchRemoteStatus(ctx context.Context, node Node, forceRefresh bool) (deploy.WarpRoutingStatusResponse, error) {
	script, err := BuildRemoteWarpCtlScript("status", deploy.WarpCLIStatusArgs{Refresh: forceRefresh})
	if err != nil {
		return deploy.WarpRoutingStatusResponse{}, err
	}
	rCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _, runErr := c.runner()(rCtx, node, script)
	if runErr != nil {
		c.putCache(node.ID, deploy.WarpRoutingStatusResponse{}, false, runErr.Error())
		return deploy.WarpRoutingStatusResponse{}, runErr
	}
	var resp deploy.WarpRoutingStatusResponse
	if uErr := json.Unmarshal(ExtractJSONObjectBytes(out), &resp); uErr != nil {
		errMsg := fmt.Sprintf("解析子节点 %s WARP 状态失败: %v", node.Name, uErr)
		c.putCache(node.ID, deploy.WarpRoutingStatusResponse{}, false, errMsg)
		return deploy.WarpRoutingStatusResponse{}, errors.New(errMsg)
	}
	c.putCache(node.ID, resp, true, "")
	return resp, nil
}

func (c *WarpClusterCoordinator) refreshAllAsync(forceRefresh bool) {
	nodes := c.ListEnabledNodes()
	if len(nodes) == 0 {
		return
	}
	fsx.TrySingleFlight(&c.refreshing, 18*time.Second, func(ctx context.Context) {
		var wg sync.WaitGroup
		sem := make(chan struct{}, 6)
		for _, n := range nodes {
			node := n
			wg.Go(func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				_, _ = c.fetchRemoteStatus(ctx, node, forceRefresh)
			})
		}
		wg.Wait()
	})
}

func (c *WarpClusterCoordinator) refreshAllSync(ctx context.Context, forceRefresh bool) {
	nodes := c.ListEnabledNodes()
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
			_, _ = c.fetchRemoteStatus(ctx, node, forceRefresh)
		})
	}
	wg.Wait()
}

func (c *WarpClusterCoordinator) buildNodeSummaries(localStatus deploy.WarpRoutingStatusResponse, fleetNodes []Node) ([]deploy.WarpNodeSummary, bool) {
	summaries := make([]deploy.WarpNodeSummary, 0, 1+len(fleetNodes))
	summaries = append(summaries, deploy.WarpNodeSummary{
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
		cached, ok := c.getCache(fn.ID)
		if !ok || time.Since(cached.fetchedAt) > warpNodeCacheTTL {
			anyStale = true
		}
		if ok && cached.online {
			summaries = append(summaries, deploy.WarpNodeSummary{
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
			continue
		}
		errText := ""
		if ok {
			errText = cached.errMsg
		}
		summaries = append(summaries, deploy.WarpNodeSummary{
			ID:      fn.ID,
			Name:    cmp.Or(fn.Name, fn.ID),
			Host:    fn.Domain,
			IsLocal: false,
			Online:  fn.Online && errText == "",
			Mode:    string(config.WarpModeSplit),
			Daemon: deploy.WarpDaemonStatus{
				SocksPort: 40000,
				Error:     cmp.Or(errText, "正在同步子节点状态..."),
			},
			Error: errText,
		})
	}
	return summaries, anyStale
}

// BuildClusterStatus 汇总主控与全量启用子节点的 WARP 透视状态（支持 selectedNode = local | all | <nodeID>）。
func (c *WarpClusterCoordinator) BuildClusterStatus(ctx context.Context, localResp deploy.WarpRoutingStatusResponse, selectedNode string, forceRefresh bool) (deploy.WarpRoutingStatusResponse, error) {
	selectedNode = cmp.Or(strings.TrimSpace(selectedNode), "local")
	fleetNodes := c.ListEnabledNodes()
	if len(fleetNodes) == 0 {
		localResp.SelectedNode = "local"
		return localResp, nil
	}

	if selectedNode == "all" {
		if forceRefresh {
			c.refreshAllSync(ctx, true)
		}
		summaries, anyStale := c.buildNodeSummaries(localResp, fleetNodes)
		if !forceRefresh && anyStale {
			c.refreshAllAsync(false)
		}
		totalDC, totalWarp, healthyNodes, installedNodes := 0, 0, 0, 0
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
		aggDaemon := deploy.WarpDaemonStatus{
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
		return deploy.WarpRoutingStatusResponse{
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
		summaries, anyStale := c.buildNodeSummaries(localResp, fleetNodes)
		if anyStale {
			c.refreshAllAsync(false)
		}
		localResp.SelectedNode = "local"
		localResp.Nodes = summaries
		return localResp, nil
	}

	targetNode, ok := c.FindEnabledNode(selectedNode)
	if !ok {
		return deploy.WarpRoutingStatusResponse{}, fmt.Errorf("未找到集群子节点: %s", selectedNode)
	}

	var remoteResp deploy.WarpRoutingStatusResponse
	cached, hasCache := c.getCache(selectedNode)
	if !forceRefresh && hasCache && cached.online {
		remoteResp = cached.resp
		if time.Since(cached.fetchedAt) > warpNodeCacheTTL {
			c.refreshAllAsync(false)
		}
	} else {
		fetched, err := c.fetchRemoteStatus(ctx, targetNode, forceRefresh)
		if err != nil {
			return deploy.WarpRoutingStatusResponse{}, fmt.Errorf("连接子节点 [%s] 获取 WARP 状态失败: %w", cmp.Or(targetNode.Name, targetNode.ID), err)
		}
		remoteResp = fetched
	}

	summaries, anyStale := c.buildNodeSummaries(localResp, fleetNodes)
	if !forceRefresh && anyStale {
		c.refreshAllAsync(false)
	}
	remoteResp.SelectedNode = selectedNode
	remoteResp.Nodes = summaries
	return remoteResp, nil
}

// ApplyRemoteNode 向指定远端节点下发 WARP 分流配置并更新缓存。
func (c *WarpClusterCoordinator) ApplyRemoteNode(ctx context.Context, node Node, targetWR config.WarpRoutingConfig) (deploy.WarpCLIApplyResult, error) {
	script, err := BuildRemoteWarpCtlScript("apply", targetWR)
	if err != nil {
		return deploy.WarpCLIApplyResult{}, err
	}
	rCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _, runErr := c.runner()(rCtx, node, script)
	if runErr != nil {
		return deploy.WarpCLIApplyResult{}, runErr
	}
	var res deploy.WarpCLIApplyResult
	if uErr := json.Unmarshal(ExtractJSONObjectBytes(out), &res); uErr != nil {
		return deploy.WarpCLIApplyResult{}, fmt.Errorf("解析子节点响应失败: %w", uErr)
	}
	c.putCache(node.ID, res.Status, true, "")
	return res, nil
}

// QuickSwitchRemoteNode 在指定远端节点按其当前配置执行单项目标快切。
func (c *WarpClusterCoordinator) QuickSwitchRemoteNode(ctx context.Context, node Node, target, outbound string) (deploy.WarpCLIApplyResult, error) {
	script, err := BuildRemoteWarpCtlScript("quick-switch", deploy.WarpCLIQuickSwitchArgs{Target: target, Outbound: outbound})
	if err != nil {
		return deploy.WarpCLIApplyResult{}, err
	}
	rCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, _, runErr := c.runner()(rCtx, node, script)
	if runErr != nil {
		return deploy.WarpCLIApplyResult{}, runErr
	}
	var res deploy.WarpCLIApplyResult
	if uErr := json.Unmarshal(ExtractJSONObjectBytes(out), &res); uErr != nil {
		return deploy.WarpCLIApplyResult{}, fmt.Errorf("解析子节点响应失败: %w", uErr)
	}
	c.putCache(node.ID, res.Status, true, "")
	return res, nil
}

// FetchRemoteConnections 查询指定远端节点的活跃出站连接分组。
func (c *WarpClusterCoordinator) FetchRemoteConnections(ctx context.Context, node Node, query, outbound string) map[string]any {
	script, err := BuildRemoteWarpCtlScript("connections", deploy.WarpCLIConnectionsArgs{Query: query, Outbound: outbound})
	if err != nil {
		return map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      err.Error(),
		}
	}
	rCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, _, runErr := c.runner()(rCtx, node, script)
	if runErr != nil {
		return map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      fmt.Sprintf("连接子节点 [%s] 获取活跃流失败: %v", cmp.Or(node.Name, node.ID), runErr),
		}
	}
	var payload map[string]any
	if uErr := json.Unmarshal(ExtractJSONObjectBytes(out), &payload); uErr != nil {
		return map[string]any{
			"enabled":      false,
			"destinations": []telemetry.ActiveDestinationGroup{},
			"total":        0,
			"message":      fmt.Sprintf("解析子节点 [%s] 活跃流数据失败: %v", cmp.Or(node.Name, node.ID), uErr),
		}
	}
	return payload
}

// RunRemoteAction 在指定远端节点执行 rekey / ensure / enable_telemetry 控制动作。
func (c *WarpClusterCoordinator) RunRemoteAction(ctx context.Context, node Node, action string) (map[string]any, error) {
	script, err := BuildRemoteWarpCtlScript("action", deploy.WarpCLIActionArgs{Action: action})
	if err != nil {
		return nil, err
	}
	timeout := 35 * time.Second
	if action == "ensure" {
		timeout = 75 * time.Second
	}
	rCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, _, runErr := c.runner()(rCtx, node, script)
	if runErr != nil {
		return nil, runErr
	}
	var res map[string]any
	if uErr := json.Unmarshal(ExtractJSONObjectBytes(out), &res); uErr != nil {
		return nil, fmt.Errorf("解析子节点响应失败: %w", uErr)
	}
	_, _ = c.fetchRemoteStatus(ctx, node, false)
	return res, nil
}

func formatClusterSummaryMessage(actionTitle string, items []WarpClusterOpItem, totalEvicted int) string {
	okCount, skipCount := 0, 0
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

// BroadcastRouting 并发向主控本机与全部启用子节点广播应用 WARP 分流策略（自动跳过未就绪节点防断流）。
func (c *WarpClusterCoordinator) BroadcastRouting(ctx context.Context, normalized config.WarpRoutingConfig, applyLocal func(context.Context) (int, error)) (int, []WarpClusterOpItem, string, bool, error) {
	fleetNodes := c.ListEnabledNodes()
	items := make([]WarpClusterOpItem, 1+len(fleetNodes))
	var totalEvicted int
	var evictMu sync.Mutex
	var wg sync.WaitGroup

	wg.Go(func() {
		evicted, err := applyLocal(ctx)
		if err == nil {
			evictMu.Lock()
			totalEvicted += evicted
			evictMu.Unlock()
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: true, Message: "已热更新"}
		} else if IsTunnelUnavailableErr(err) && normalized.NormalizedMode() != config.WarpModeBypass {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Skipped: true, Message: "本地 WARP 隧道未就绪，已跳过"}
		} else {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: err.Error()}
		}
	})

	sem := make(chan struct{}, 6)
	for i, fn := range fleetNodes {
		idx := i + 1
		node := fn
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := c.ApplyRemoteNode(ctx, node, normalized)
			name := cmp.Or(node.Name, node.ID)
			if err == nil {
				evictMu.Lock()
				totalEvicted += res.EvictedConnections
				evictMu.Unlock()
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: true, Message: "已热更新"}
			} else if IsTunnelUnavailableErr(err) && normalized.NormalizedMode() != config.WarpModeBypass {
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
		return 0, items, "", true, fmt.Errorf("集群内暂无可应用 WARP 策略的就绪节点：%s", items[0].Message)
	}
	return totalEvicted, items, formatClusterSummaryMessage("WARP 分流策略同步完成", items, totalEvicted), false, nil
}

// BroadcastQuickSwitch 并发在主控与全部启用子节点执行单项目标快切。
func (c *WarpClusterCoordinator) BroadcastQuickSwitch(
	ctx context.Context,
	rawTarget, rawOutbound string,
	applyLocal func(context.Context) (evicted int, skipped bool, skipMsg string, err error),
) (cleanTarget, targetOut, matchedPreset string, totalEvicted int, items []WarpClusterOpItem, summaryMsg string, conflict bool, badReqErr error) {
	_, cleanTarget, targetOut, matchedPreset, vErr := deploy.ComputeQuickSwitchRouting(config.WarpRoutingConfig{Mode: config.WarpModeSplit}, rawTarget, rawOutbound)
	if vErr != nil {
		return "", "", "", 0, nil, "", false, vErr
	}

	fleetNodes := c.ListEnabledNodes()
	items = make([]WarpClusterOpItem, 1+len(fleetNodes))
	var evictMu sync.Mutex
	var wg sync.WaitGroup

	wg.Go(func() {
		evicted, skipped, skipMsg, err := applyLocal(ctx)
		switch {
		case skipped:
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Skipped: true, Message: skipMsg}
		case err == nil:
			evictMu.Lock()
			totalEvicted += evicted
			evictMu.Unlock()
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: true, Message: "已秒切"}
		case IsTunnelUnavailableErr(err):
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Skipped: true, Message: "WARP 隧道未就绪，已跳过"}
		default:
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: err.Error()}
		}
	})

	sem := make(chan struct{}, 6)
	for i, fn := range fleetNodes {
		idx := i + 1
		node := fn
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			name := cmp.Or(node.Name, node.ID)
			res, err := c.QuickSwitchRemoteNode(ctx, node, rawTarget, rawOutbound)
			if err == nil {
				evictMu.Lock()
				totalEvicted += res.EvictedConnections
				evictMu.Unlock()
				items[idx] = WarpClusterOpItem{ID: node.ID, Name: name, Success: true, Message: "已秒切"}
			} else if IsTunnelUnavailableErr(err) || strings.Contains(err.Error(), "紧急全直出旁路") {
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
		return cleanTarget, targetOut, matchedPreset, 0, items, "", true, nil
	}

	actionLabel := "切换至 WARP"
	if targetOut == "DC" {
		actionLabel = "切回直出 DC"
	}
	summaryMsg = formatClusterSummaryMessage(fmt.Sprintf("已将 %s %s", cleanTarget, actionLabel), items, totalEvicted)
	return cleanTarget, targetOut, matchedPreset, totalEvicted, items, summaryMsg, false, nil
}

// BroadcastAction 并发在主控与全部启用子节点执行 rekey / ensure / enable_telemetry 操作。
func (c *WarpClusterCoordinator) BroadcastAction(ctx context.Context, action string, runLocal func(context.Context) error) ([]WarpClusterOpItem, string, string, error) {
	fleetNodes := c.ListEnabledNodes()
	items := make([]WarpClusterOpItem, 1+len(fleetNodes))
	var wg sync.WaitGroup

	wg.Go(func() {
		if err := runLocal(ctx); err == nil {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: true, Message: "执行成功"}
		} else {
			items[0] = WarpClusterOpItem{ID: "local", Name: "主控本机", Success: false, Message: err.Error()}
		}
	})

	sem := make(chan struct{}, 6)
	for i, fn := range fleetNodes {
		idx := i + 1
		node := fn
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			name := cmp.Or(node.Name, node.ID)
			if _, err := c.RunRemoteAction(ctx, node, action); err == nil {
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
		return items, "", "", fmt.Errorf("全集群执行 %s 失败: %s", action, items[0].Message)
	}
	label := "全集群批量更换 WARP IP"
	switch action {
	case "ensure":
		label = "全集群一键部署/修复 WARP"
	case "enable_telemetry":
		label = "全集群开启实时遥测"
	}
	summaryMsg := fmt.Sprintf("%s完成：%d/%d 台节点执行成功", label, okCount, len(items))
	auditMsg := fmt.Sprintf("%s (%d/%d 成功)", label, okCount, len(items))
	return items, summaryMsg, auditMsg, nil
}
