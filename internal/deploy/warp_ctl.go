// 文件职责：提供单机 WARP 状态模型、守护进程探针（WarpProber）、非交互 warp-ctl 控制引擎与快速分流计算纯函数。
package deploy

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/telemetry"
)

// ErrWarpQuickSwitchInBypass 标识目标节点当前处于紧急旁路模式。
var ErrWarpQuickSwitchInBypass = errors.New("当前处于「紧急全直出旁路」模式，请先切换回「原生优先·按需分流」或「全局 WARP」后再调整单项目标")

// WarpDaemonStatus 描述本地 Cloudflare WARP (wireproxy) 运行与隧道状态。
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

// WarpNodeSummary 描述集群中单台主机（主控本机或 Fleet 子节点）的 WARP 摘要状态。
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

// WarpRoutingStatusResponse 返回服务端 WARP 分流中心总览数据（支持单机与全集群多节点透视）。
type WarpRoutingStatusResponse struct {
	SelectedNode  string                   `json:"selectedNode,omitempty"`
	Nodes         []WarpNodeSummary        `json:"nodes,omitempty"`
	Daemon        WarpDaemonStatus         `json:"daemon"`
	Routing       config.WarpRoutingConfig `json:"routing"`
	Presets       []WarpPresetState        `json:"presets"`
	DCConnCount   int                      `json:"dcConnCount"`
	WarpConnCount int                      `json:"warpConnCount"`
}

// WarpCLIStatusArgs 定义 `warp-ctl status` 请求参数。
type WarpCLIStatusArgs struct {
	Refresh bool `json:"refresh"`
}

// WarpCLIQuickSwitchArgs 定义 `warp-ctl quick-switch` 请求参数。
type WarpCLIQuickSwitchArgs struct {
	Target   string `json:"target"`
	Outbound string `json:"outbound"`
}

// WarpCLIConnectionsArgs 定义 `warp-ctl connections` 请求参数。
type WarpCLIConnectionsArgs struct {
	Query    string `json:"q"`
	Outbound string `json:"outbound"`
}

// WarpCLIActionArgs 定义 `warp-ctl action` 请求参数。
type WarpCLIActionArgs struct {
	Action string `json:"action"`
}

// WarpCLIApplyResult 定义 `warp-ctl apply` / `quick-switch` 响应载荷。
type WarpCLIApplyResult struct {
	Message            string                    `json:"message"`
	EvictedConnections int                       `json:"evictedConnections"`
	MatchedPreset      string                    `json:"matchedPreset,omitempty"`
	Target             string                    `json:"target,omitempty"`
	Outbound           string                    `json:"outbound,omitempty"`
	Status             WarpRoutingStatusResponse `json:"status"`
}

// LocalWarpCLIOptions 允许在远程 CLI 子命令或单元测试中执行本机 WARP 原子控制操作。
type LocalWarpCLIOptions struct {
	ConfigPath        string
	SingBoxConfigPath string
	ApplyDeps         *LiveWarpApplyDeps
	DaemonProbe       func(forceRefresh bool) WarpDaemonStatus
	RotateWarpFn      func(prevIP string) (string, string, error)
	EnsureWarpFn      func(cfg *config.Config) error
}

const warpExitCacheTTL = 5 * time.Minute

// WarpProber 封装单机 WARP 守护进程状态探测与出口 IP SWR 缓存。
type WarpProber struct {
	DaemonProbe func(forceRefresh bool) WarpDaemonStatus
	PortChecker func() bool
	ExitFetcher func(timeout time.Duration) (ip, loc, traceRaw string, ok bool)

	mu         sync.Mutex
	cachedIP   string
	cachedLoc  string
	cachedAt   time.Time
	refreshing atomic.Bool
}

// NewWarpProber 创建单机 WARP 状态探针实例。
func NewWarpProber() *WarpProber {
	return &WarpProber{}
}

// SetCachedExit 更新探针缓存的 WARP 出口 IP 与地区标识。
func (p *WarpProber) SetCachedExit(ip, loc string, at time.Time) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.cachedIP = ip
	p.cachedLoc = loc
	p.cachedAt = at
	p.mu.Unlock()
}

// CachedExitIP 返回当前内存缓存的 WARP 出口 IP。
func (p *WarpProber) CachedExitIP() string {
	if p == nil {
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cachedIP
}

// ClearCache 清空缓存的出口 IP 信息。
func (p *WarpProber) ClearCache() {
	if p == nil {
		return
	}
	p.SetCachedExit("", "", time.Time{})
}

// Probe 执行本地 wireproxy 状态探测与 SWR 出口 IP 查询。
func (p *WarpProber) Probe(forceRefresh bool) WarpDaemonStatus {
	if p != nil && p.DaemonProbe != nil {
		return p.DaemonProbe(forceRefresh)
	}

	_, errBin := exec.LookPath("wireproxy")
	_, _, hasConf := ResolveWireproxyConfigPaths()
	installed := errBin == nil || hasConf || IsWindtfWireproxyBinary(DefaultWireproxyBin)

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	running := serviceMgr().IsActive(ctx, "wireproxy")
	cancel()

	portCheck := CheckWarpSocksPort
	if p != nil && p.PortChecker != nil {
		portCheck = p.PortChecker
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
		switch {
		case !installed:
			status.Error = "尚未安装内置纯 Go wireproxy (WARP) 服务"
		case !running:
			status.Error = "wireproxy 服务未运行，127.0.0.1:40000 未监听"
		default:
			status.Error = "wireproxy 已启动但 127.0.0.1:40000 尚未就绪"
		}
		return status
	}

	if p == nil {
		if ip, loc, _, ok := FetchWarpExitInfo(2500 * time.Millisecond); ok && ip != "" {
			status.WarpIP = ip
			status.WarpLoc = loc
		}
		return status
	}

	p.mu.Lock()
	cachedIP := p.cachedIP
	cachedLoc := p.cachedLoc
	cacheFresh := !forceRefresh && cachedIP != "" && time.Since(p.cachedAt) < warpExitCacheTTL
	p.mu.Unlock()

	if cacheFresh {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
		return status
	}

	refreshWarpExit := func() (string, string, bool) {
		exitFetch := p.ExitFetcher
		if exitFetch == nil {
			exitFetch = FetchWarpExitInfo
		}
		ip, loc, _, ok := exitFetch(2500 * time.Millisecond)
		if ok && ip != "" {
			p.SetCachedExit(ip, loc, time.Now())
		}
		return ip, loc, ok && ip != ""
	}

	if !forceRefresh && cachedIP != "" {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
		fsx.TrySingleFlight(&p.refreshing, 4*time.Second, func(context.Context) {
			refreshWarpExit()
		})
		return status
	}

	if ip, loc, ok := refreshWarpExit(); ok {
		status.WarpIP = ip
		status.WarpLoc = loc
	} else if cachedIP != "" {
		status.WarpIP = cachedIP
		status.WarpLoc = cachedLoc
	}
	return status
}

// DiagnoseWARP 通过本地 wireproxy SOCKS5 通道探测 Cloudflare trace 出口详情与往返延迟。
func DiagnoseWARP(traceURLOverride ...string) map[string]any {
	traceURL := "https://cloudflare.com/cdn-cgi/trace"
	if len(traceURLOverride) > 0 && strings.TrimSpace(traceURLOverride[0]) != "" {
		traceURL = strings.TrimSpace(traceURLOverride[0])
	}
	client, err := newWarpSocksHTTPClient(4 * time.Second)
	if err != nil {
		return map[string]any{"connected": false, "error": err.Error()}
	}
	defer client.CloseIdleConnections()

	start := time.Now()
	resp, err := client.Get(traceURL)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]any{"connected": false, "error": err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	res := map[string]any{
		"connected": true,
		"latencyMs": latency,
		"warp":      "off",
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "ip", "loc", "warp":
			res[k] = v
		}
	}
	return res
}

type warpController struct {
	cfgPath string
	sbPath  string
	col     *telemetry.Collector
	prober  *WarpProber
	opts    LocalWarpCLIOptions
}

func newWarpController(opts LocalWarpCLIOptions) *warpController {
	cfgPath := cmp.Or(strings.TrimSpace(opts.ConfigPath), "/etc/singctl/singctl.yaml")
	sbPath := cmp.Or(strings.TrimSpace(opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	prober := NewWarpProber()
	prober.DaemonProbe = opts.DaemonProbe
	return &warpController{
		cfgPath: cfgPath,
		sbPath:  sbPath,
		col:     telemetry.NewCollector(sbPath),
		prober:  prober,
		opts:    opts,
	}
}

func (c *warpController) buildStatus(ctx context.Context, cfg *config.Config, forceRefresh bool) WarpRoutingStatusResponse {
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
	snap := c.col.Collect(ctx)
	return WarpRoutingStatusResponse{
		Daemon:        c.prober.Probe(forceRefresh),
		Routing:       wr,
		Presets:       BuildPresetStateList(wr),
		DCConnCount:   snap.Outbounds.DirectConnections,
		WarpConnCount: snap.Outbounds.WarpConnections,
	}
}

func (c *warpController) liveDeps(cfg *config.Config) *LiveWarpApplyDeps {
	var deps LiveWarpApplyDeps
	if c.opts.ApplyDeps != nil {
		deps = *c.opts.ApplyDeps
	}
	protected := slices.Clone(deps.ProtectedDomains)
	for _, dom := range CollectServerProtectedDomains(cfg) {
		if !slices.Contains(protected, dom) {
			protected = append(protected, dom)
		}
	}
	deps.ProtectedDomains = protected
	return &deps
}

func (c *warpController) applyRouting(ctx context.Context, targetWR config.WarpRoutingConfig) (WarpRoutingStatusResponse, int, error) {
	normalized, err := config.NormalizeWarpRouting(targetWR)
	if err != nil {
		return WarpRoutingStatusResponse{}, 0, err
	}
	cfg, loadErr := config.Load(c.cfgPath)
	if loadErr != nil || cfg == nil {
		return WarpRoutingStatusResponse{}, 0, fmt.Errorf("加载配置文件失败: %w", loadErr)
	}
	if _, applyErr := ApplyLiveWarpRouting(c.sbPath, normalized, c.liveDeps(cfg)); applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		return WarpRoutingStatusResponse{}, 0, applyErr
	}
	cfg.Server.WarpRouting = normalized
	if saveErr := config.Save(c.cfgPath, cfg); saveErr != nil {
		return WarpRoutingStatusResponse{}, 0, fmt.Errorf("持久化 singctl.yaml 失败: %w", saveErr)
	}
	protected := CollectServerProtectedDomains(cfg)
	evicted, _ := c.col.EvictMismatchedConnections(ctx, func(host, dstIP, ruleTag, currentOutbound string) bool {
		return ExpectedTargetOutbound(normalized, host, dstIP, ruleTag, protected...) != currentOutbound
	})
	return c.buildStatus(ctx, cfg, false), evicted, nil
}

func (c *warpController) execAction(ctx context.Context, payload []byte) ([]byte, error) {
	var args WarpCLIActionArgs
	if err := json.Unmarshal(payload, &args); err != nil {
		return nil, fmt.Errorf("解析 action 参数失败: %w", err)
	}
	act := strings.ToLower(strings.TrimSpace(args.Action))
	switch act {
	case "rekey":
		prevIP := ""
		if c.opts.RotateWarpFn == nil {
			if ip, _, _, ok := FetchWarpExitInfo(1200 * time.Millisecond); ok && ip != "" {
				prevIP = strings.TrimSpace(ip)
			}
		}
		rotateFn := c.opts.RotateWarpFn
		if rotateFn == nil {
			rotateFn = RotateWarpIdentityFrom
		}
		newIP, newLoc, err := rotateFn(prevIP)
		if err != nil {
			return nil, err
		}
		evicted, _ := c.col.EvictMismatchedConnections(ctx, func(_, _, _, currentOutbound string) bool {
			return currentOutbound == "WARP"
		})
		daemon := c.prober.Probe(false)
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
		cfg, _ := config.Load(c.cfgPath)
		ensureFn := c.opts.EnsureWarpFn
		if ensureFn == nil {
			ensureFn = DeployWarpWithConfig
		}
		if err := ensureFn(cfg); err != nil {
			return nil, fmt.Errorf("一键部署/修复 WARP 失败: %w", err)
		}
		evicted, _ := c.col.EvictMismatchedConnections(ctx, func(_, _, _, currentOutbound string) bool {
			return currentOutbound == "WARP"
		})
		return json.Marshal(map[string]any{
			"message":            "WARP (纯 Go wireproxy) 隧道已就绪，现可自由切换分流规则",
			"evictedConnections": evicted,
			"daemon":             c.prober.Probe(true),
		})

	case "enable_telemetry":
		changed, _, _, err := telemetry.EnsureConfigTelemetry(c.sbPath)
		if err != nil {
			return nil, fmt.Errorf("启用实时流量遥测失败: %w", err)
		}
		if changed {
			if runErr := serviceMgr().Restart(ctx, "sing-box"); runErr != nil {
				return nil, fmt.Errorf("已写入遥测配置，但重启 sing-box 失败: %w", runErr)
			}
			time.Sleep(350 * time.Millisecond)
		}
		return json.Marshal(map[string]any{
			"message": "实时流量与分流遥测已无损开启",
			"changed": changed,
			"daemon":  c.prober.Probe(false),
		})

	default:
		return nil, fmt.Errorf("不支持的操作: %s", act)
	}
}

// ExecuteLocalWarpCLI 在本机执行 WARP 控制动作并返回标准 JSON（供 `singctl sr warp-ctl` 与单测直接调用）。
func ExecuteLocalWarpCLI(ctx context.Context, subcommand string, payload []byte, opts LocalWarpCLIOptions) ([]byte, error) {
	ctrl := newWarpController(opts)
	switch subcommand {
	case "status":
		var args WarpCLIStatusArgs
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &args)
		}
		cfg, _ := config.Load(ctrl.cfgPath)
		return json.Marshal(ctrl.buildStatus(ctx, cfg, args.Refresh))

	case "apply":
		var targetWR config.WarpRoutingConfig
		if err := json.Unmarshal(payload, &targetWR); err != nil {
			return nil, fmt.Errorf("解析 WARP 分流配置失败: %w", err)
		}
		st, evicted, err := ctrl.applyRouting(ctx, targetWR)
		if err != nil {
			return nil, err
		}
		msg := "WARP 分流策略已安全通过校验并零断流热更新"
		if evicted > 0 {
			msg = fmt.Sprintf("已热更新分流路由并平滑切换 %d 条存量连接", evicted)
		}
		return json.Marshal(WarpCLIApplyResult{Message: msg, EvictedConnections: evicted, Status: st})

	case "quick-switch":
		var args WarpCLIQuickSwitchArgs
		if err := json.Unmarshal(payload, &args); err != nil {
			return nil, fmt.Errorf("解析 quick-switch 参数失败: %w", err)
		}
		cfg, err := config.Load(ctrl.cfgPath)
		if err != nil || cfg == nil {
			return nil, fmt.Errorf("加载配置文件失败: %w", err)
		}
		nextWR, cleanTarget, targetOut, matchedPreset, err := ComputeQuickSwitchRouting(cfg.Server.WarpRouting, args.Target, args.Outbound)
		if err != nil {
			return nil, err
		}
		st, evicted, err := ctrl.applyRouting(ctx, nextWR)
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
		return json.Marshal(WarpCLIApplyResult{
			Message:            msg,
			EvictedConnections: evicted,
			MatchedPreset:      matchedPreset,
			Target:             cleanTarget,
			Outbound:           targetOut,
			Status:             st,
		})

	case "connections":
		var args WarpCLIConnectionsArgs
		if len(payload) > 0 {
			_ = json.Unmarshal(payload, &args)
		}
		items, err := ctrl.col.GetActiveDestinations(ctx, args.Query, args.Outbound)
		if err != nil {
			return json.Marshal(map[string]any{
				"enabled":      false,
				"destinations": []telemetry.ActiveDestinationGroup{},
				"total":        0,
				"message":      err.Error(),
			})
		}
		return json.Marshal(map[string]any{"enabled": true, "destinations": items, "total": len(items)})

	case "action":
		return ctrl.execAction(ctx, payload)

	default:
		return nil, fmt.Errorf("未知的 warp-ctl 子命令: %s", subcommand)
	}
}

// ComputeQuickSwitchRouting 基于当前分流配置纯函数计算单项目标（域名/预设/CIDR）切换后的新配置。
func ComputeQuickSwitchRouting(current config.WarpRoutingConfig, rawTarget, rawOutbound string) (config.WarpRoutingConfig, string, string, string, error) {
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
		return nextWR, cleanTarget, targetOut, "", nil
	}

	bareHost := strings.TrimPrefix(strings.TrimPrefix(cleanTarget, "full:"), "keyword:")
	isModifierRule := strings.HasPrefix(cleanTarget, "full:") || strings.HasPrefix(cleanTarget, "keyword:")
	presetDef, hasPreset := FindPresetByHost(bareHost)

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

	return nextWR, cleanTarget, targetOut, matchedPresetName, nil
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
