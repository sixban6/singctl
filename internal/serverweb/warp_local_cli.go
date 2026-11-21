// 文件职责：提供服务端本机非交互 warp-ctl CLI 执行引擎（状态/分流快切/连接查询）与单项目标计算纯函数。
package serverweb

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/telemetry"
	"slices"
	"strings"
	"time"
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
				if runErr := servicemgr.NewSystemd(defaultServiceCmdRunner{}).Restart(ctx, "sing-box"); runErr != nil {
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
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
