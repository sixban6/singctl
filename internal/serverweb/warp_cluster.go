package serverweb

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/fleet"
	"singctl/internal/telemetry"
)

const warpNodeCacheTTL = 30 * time.Second

// WarpNodeSummary 描述集群中单台主机（主控本机或 Fleet 子节点）的 WARP 摘要状态
type WarpNodeSummary struct {
	ID            string           `json:"id"`
	Name          string           `json:"name"`
	Host          string           `json:"host,omitempty"`
	IsLocal       bool             `json:"isLocal"`
	Online        bool             `json:"online"`
	Mode          string           `json:"mode"`
	Daemon        WarpDaemonStatus `json:"daemon"`
	DCConnCount   int              `json:"dcConnCount"`
	WarpConnCount int              `json:"warpConnCount"`
	UpdatedAt     string           `json:"updatedAt,omitempty"`
	Error         string           `json:"error,omitempty"`
}

// WarpClusterOpItem 记录全集群批量编排时单台主机的执行明细
type WarpClusterOpItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Success bool   `json:"success"`
	Skipped bool   `json:"skipped,omitempty"`
	Message string `json:"message"`
}

type warpNodeCacheEntry struct {
	resp      WarpRoutingStatusResponse
	online    bool
	errMsg    string
	fetchedAt time.Time
}

// LocalWarpCLIOptions 允许在远程 CLI 子命令或单元测试中执行本机 WARP 原子控制操作
type LocalWarpCLIOptions struct {
	ConfigPath        string
	SingBoxConfigPath string
	ApplyDeps         *deploy.LiveWarpApplyDeps
	DaemonProbe       func(forceRefresh bool) WarpDaemonStatus
	RotateWarpFn      func(prevIP string) (string, string, error)
	EnsureWarpFn      func(cfg *config.Config) error
}

type warpCLIStatusArgs struct {
	Refresh bool `json:"refresh"`
}

type warpCLIQuickSwitchArgs struct {
	Target   string `json:"target"`
	Outbound string `json:"outbound"`
}

type warpCLIConnectionsArgs struct {
	Query    string `json:"q"`
	Outbound string `json:"outbound"`
}

type warpCLIActionArgs struct {
	Action string `json:"action"`
}

type warpCLIApplyResult struct {
	Message            string                    `json:"message"`
	EvictedConnections int                       `json:"evictedConnections"`
	MatchedPreset      string                    `json:"matchedPreset,omitempty"`
	Target             string                    `json:"target,omitempty"`
	Outbound           string                    `json:"outbound,omitempty"`
	Status             WarpRoutingStatusResponse `json:"status"`
}

// ExecuteLocalWarpCLI 在本机执行 WARP 控制动作并返回标准 JSON（供 `singctl sr warp-ctl` 与单测直接调用）。
func ExecuteLocalWarpCLI(ctx context.Context, subcommand string, payload []byte, opts LocalWarpCLIOptions) ([]byte, error) {
	cfgPath := cmp.Or(strings.TrimSpace(opts.ConfigPath), "/etc/singctl/singctl.yaml")
	sbPath := cmp.Or(strings.TrimSpace(opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	col := telemetry.NewCollector(sbPath)

	probeLocalDaemon := func(forceRefresh bool) WarpDaemonStatus {
		if opts.DaemonProbe != nil {
			return opts.DaemonProbe(forceRefresh)
		}
		_, errBin := exec.LookPath("wireproxy")
		_, _, hasConf := deploy.ResolveWireproxyConfigPaths()
		installed := errBin == nil || hasConf || deploy.IsWindtfWireproxyBinary(deploy.DefaultWireproxyBin)
		running := checkServiceRunning("wireproxy")
		portOpen := deploy.CheckWarpSocksPort()
		if portOpen {
			running = true
			installed = true
		}
		st := WarpDaemonStatus{
			Installed:     installed,
			Running:       running,
			TunnelHealthy: portOpen,
			SocksPort:     40000,
		}
		if !portOpen {
			if !installed {
				st.Error = "尚未安装内置纯 Go wireproxy (WARP) 服务"
			} else if !running {
				st.Error = "wireproxy 服务未运行，127.0.0.1:40000 未监听"
			} else {
				st.Error = "wireproxy 已启动但 127.0.0.1:40000 尚未就绪"
			}
			return st
		}
		if ip, loc, _, ok := deploy.FetchWarpExitInfo(2500 * time.Millisecond); ok && ip != "" {
			st.WarpIP = ip
			st.WarpLoc = loc
		}
		return st
	}

	buildLocalStatus := func(cfg *config.Config, forceRefresh bool) WarpRoutingStatusResponse {
		var wr config.WarpRoutingConfig
		if cfg != nil {
			if norm, err := config.NormalizeWarpRouting(cfg.Server.WarpRouting); err == nil {
				wr = norm
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
		snap := col.Collect(ctx)
		return WarpRoutingStatusResponse{
			Daemon:        probeLocalDaemon(forceRefresh),
			Routing:       wr,
			Presets:       deploy.BuildPresetStateList(wr),
			DCConnCount:   snap.Outbounds.DirectConnections,
			WarpConnCount: snap.Outbounds.WarpConnections,
		}
	}

	buildDeps := func(cfg *config.Config) *deploy.LiveWarpApplyDeps {
		var deps deploy.LiveWarpApplyDeps
		if opts.ApplyDeps != nil {
			deps = *opts.ApplyDeps
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

	applyRouting := func(targetWR config.WarpRoutingConfig) (WarpRoutingStatusResponse, int, error) {
		normalized, err := config.NormalizeWarpRouting(targetWR)
		if err != nil {
			return WarpRoutingStatusResponse{}, 0, err
		}
		cfg, loadErr := config.Load(cfgPath)
		if loadErr != nil || cfg == nil {
			return WarpRoutingStatusResponse{}, 0, fmt.Errorf("加载配置文件失败: %w", loadErr)
		}
		if _, applyErr := deploy.ApplyLiveWarpRouting(sbPath, normalized, buildDeps(cfg)); applyErr != nil {
			if !errors.Is(applyErr, os.ErrNotExist) {
				return WarpRoutingStatusResponse{}, 0, applyErr
			}
		}
		cfg.Server.WarpRouting = normalized
		if saveErr := config.Save(cfgPath, cfg); saveErr != nil {
			return WarpRoutingStatusResponse{}, 0, fmt.Errorf("持久化 singctl.yaml 失败: %w", saveErr)
		}
		protected := deploy.CollectServerProtectedDomains(cfg)
		evicted, _ := col.EvictMismatchedConnections(ctx, func(host, dstIP, ruleTag, currentOutbound string) bool {
			expected := deploy.ExpectedTargetOutbound(normalized, host, dstIP, ruleTag, protected...)
			return expected != currentOutbound
		})
		return buildLocalStatus(cfg, false), evicted, nil
	}

	switch subcommand {
	case "status":
		var args warpCLIStatusArgs
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &args)
		}
		cfg, _ := config.Load(cfgPath)
		return json.Marshal(buildLocalStatus(cfg, args.Refresh))

	case "apply":
		var targetWR config.WarpRoutingConfig
		if err := json.Unmarshal(payload, &targetWR); err != nil {
			return nil, fmt.Errorf("解析 WARP 分流配置失败: %w", err)
		}
		st, evicted, err := applyRouting(targetWR)
		if err != nil {
			return nil, err
		}
		msg := "WARP 分流策略已安全通过校验并零断流热更新"
		if evicted > 0 {
			msg = fmt.Sprintf("已热更新分流路由并平滑切换 %d 条存量连接", evicted)
		}
		return json.Marshal(warpCLIApplyResult{
			Message:            msg,
			EvictedConnections: evicted,
			Status:             st,
		})

	case "quick-switch":
		var args warpCLIQuickSwitchArgs
		if err := json.Unmarshal(payload, &args); err != nil {
			return nil, fmt.Errorf("解析 quick-switch 参数失败: %w", err)
		}
		cfg, err := config.Load(cfgPath)
		if err != nil || cfg == nil {
			return nil, fmt.Errorf("加载配置文件失败: %w", err)
		}
		nextWR, cleanTarget, targetOut, matchedPreset, err := computeQuickSwitchRouting(cfg.Server.WarpRouting, args.Target, args.Outbound)
		if err != nil {
			return nil, err
		}
		st, evicted, err := applyRouting(nextWR)
		if err != nil {
			return nil, err
		}
		actionLabel := "切换至 WARP 出口"
		if targetOut == "DC" {
			actionLabel = "切回原生直出 (DC)"
		}
		msg := fmt.Sprintf("已将 %s %s", cleanTarget, actionLabel)
		if matchedPreset != "" {
			msg = fmt.Sprintf("已联动预设「%s」将 %s %s", matchedPreset, cleanTarget, actionLabel)
		}
		if evicted > 0 {
			msg += fmt.Sprintf("，并立即切换 %d 条活跃连接", evicted)
		}
		return json.Marshal(warpCLIApplyResult{
			Message:            msg,
			EvictedConnections: evicted,
			MatchedPreset:      matchedPreset,
			Target:             cleanTarget,
			Outbound:           targetOut,
			Status:             st,
		})

	case "connections":
		var args warpCLIConnectionsArgs
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &args)
		}
		items, err := col.GetActiveDestinations(ctx, args.Query, args.Outbound)
		if err != nil {
			return json.Marshal(map[string]any{
				"enabled":      false,
				"destinations": []telemetry.ActiveDestinationGroup{},
				"total":        0,
				"message":      err.Error(),
			})
		}
		return json.Marshal(map[string]any{
			"enabled":      true,
			"destinations": items,
			"total":        len(items),
		})

	case "action":
		var args warpCLIActionArgs
		if err := json.Unmarshal(payload, &args); err != nil {
			return nil, fmt.Errorf("解析 action 参数失败: %w", err)
		}
		act := strings.ToLower(strings.TrimSpace(args.Action))
		switch act {
		case "rekey":
			prevIP := ""
			if opts.RotateWarpFn == nil {
				if ip, _, _, ok := deploy.FetchWarpExitInfo(1200 * time.Millisecond); ok && ip != "" {
					prevIP = strings.TrimSpace(ip)
				}
			}
			rotateFn := opts.RotateWarpFn
			if rotateFn == nil {
				rotateFn = deploy.RotateWarpIdentityFrom
			}
			newIP, newLoc, err := rotateFn(prevIP)
			if err != nil {
				return nil, err
			}
			evicted, _ := col.EvictMismatchedConnections(ctx, func(_, _, _, currentOutbound string) bool {
				return currentOutbound == "WARP"
			})
			daemon := probeLocalDaemon(false)
			if newIP != "" {
				daemon.WarpIP = newIP
			}
			if newLoc != "" {
				daemon.WarpLoc = newLoc
			}
			msg := fmt.Sprintf("已更换全新 WARP 出口 IP：%s (%s)", newIP, cmp.Or(newLoc, "Anycast"))
			if prevIP != "" && prevIP != newIP {
				msg = fmt.Sprintf("已更换全新 WARP 出口 IP：%s → %s (%s)", prevIP, newIP, cmp.Or(newLoc, "Anycast"))
			}
			return json.Marshal(map[string]any{
				"message":            msg,
				"warpIp":             newIP,
				"warpLoc":            newLoc,
				"evictedConnections": evicted,
				"daemon":             daemon,
			})

		case "ensure":
			cfg, _ := config.Load(cfgPath)
			ensureFn := opts.EnsureWarpFn
			if ensureFn == nil {
				ensureFn = deploy.DeployWarpWithConfig
			}
			if err := ensureFn(cfg); err != nil {
				return nil, fmt.Errorf("一键部署/修复 WARP 失败: %w", err)
			}
			evicted, _ := col.EvictMismatchedConnections(ctx, func(_, _, _, currentOutbound string) bool {
				return currentOutbound == "WARP"
			})
			return json.Marshal(map[string]any{
				"message":            "WARP (纯 Go wireproxy) 隧道已就绪，现可自由切换分流规则",
				"evictedConnections": evicted,
				"daemon":             probeLocalDaemon(true),
			})

		case "enable_telemetry":
			changed, _, _, err := telemetry.EnsureConfigTelemetry(sbPath)
			if err != nil {
				return nil, fmt.Errorf("启用实时流量遥测失败: %w", err)
			}
			if changed {
				if runErr := runSystemCmdTimeout(defaultServerActionTimeout, "systemctl", "restart", "sing-box"); runErr != nil {
					return nil, fmt.Errorf("已写入遥测配置，但重启 sing-box 失败: %w", runErr)
				}
				time.Sleep(350 * time.Millisecond)
			}
			return json.Marshal(map[string]any{
				"message": "实时流量与分流遥测已无损开启",
				"changed": changed,
				"daemon":  probeLocalDaemon(false),
			})

		default:
			return nil, fmt.Errorf("不支持的操作: %s", act)
		}

	default:
		return nil, fmt.Errorf("未知的 warp-ctl 子命令: %s", subcommand)
	}
}

func computeQuickSwitchRouting(current config.WarpRoutingConfig, rawTarget, rawOutbound string) (config.WarpRoutingConfig, string, string, string, error) {
	targetOut := strings.ToUpper(strings.TrimSpace(rawOutbound))
	switch targetOut {
	case "WARP":
	case "DC", "DIRECT":
		targetOut = "DC"
	default:
		return config.WarpRoutingConfig{}, "", "", "", errors.New("outbound 必须为 WARP 或 DC")
	}

	trimmed := strings.TrimSpace(rawTarget)
	if trimmed == "" {
		return config.WarpRoutingConfig{}, "", "", "", errors.New("请提供要切换的目标域名或 IP/CIDR")
	}
	isCIDR := false
	cleanTarget := ""
	if cidr, err := config.CleanWarpCIDRRule(trimmed); err == nil {
		isCIDR = true
		cleanTarget = cidr
	} else {
		domainRule, dErr := config.CleanWarpDomainRule(trimmed)
		if dErr != nil {
			return config.WarpRoutingConfig{}, "", "", "", dErr
		}
		cleanTarget = domainRule
	}

	nextWR, err := config.NormalizeWarpRouting(current.Clone())
	if err != nil {
		return config.WarpRoutingConfig{}, "", "", "", err
	}
	if nextWR.NormalizedMode() == config.WarpModeBypass {
		return config.WarpRoutingConfig{}, "", "", "", ErrWarpQuickSwitchInBypass
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
			if nextWR.NormalizedMode() == config.WarpModeGlobalWarp && !slices.Contains(nextWR.DirectDomains, cleanTarget) {
				nextWR.DirectDomains = append(nextWR.DirectDomains, cleanTarget)
			}
		}
	}

	return nextWR, cleanTarget, targetOut, matchedPresetName, nil
}

// ErrWarpQuickSwitchInBypass 标识目标节点当前处于紧急旁路模式
var ErrWarpQuickSwitchInBypass = errors.New("当前处于「紧急全直出旁路」模式，请先切换回「原生优先·按需分流」或「全局 WARP」后再调整单项目标")

func buildRemoteWarpCtlScript(subcommand string, payload any) (string, error) {
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

func extractJSONObjectBytes(raw string) []byte {
	s := strings.TrimSpace(raw)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start >= 0 && end > start {
		return []byte(s[start : end+1])
	}
	return []byte(s)
}

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

	cfg, _ := config.Load(s.opts.ConfigPath)
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
		cfg, err := config.Load(s.opts.ConfigPath)
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

	cfg, _ := config.Load(s.opts.ConfigPath)
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
		cfg, _ := config.Load(s.opts.ConfigPath)
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

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
