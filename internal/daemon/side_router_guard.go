// 文件职责：实现主路由旁路由离线自动回退救生艇（周期探活旁路由、连续失联自动摘除策略路由回退直连、恢复后自动重挂策略路由）。
package daemon

import (
	"cmp"
	"context"
	"runtime"
	"strings"
	"sync"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/gateway"
	"singctl/internal/logger"
	"singctl/internal/vlan"
)

const defaultSideRouterFailThreshold = 2

// SideRouterGuardDeps 显式注入旁路由故障逃生巡检依赖（nil 自动回退生产实现）。
type SideRouterGuardDeps struct {
	SideRoutesFile string
	FailThreshold  int
	ProbeOnline    func(ctx context.Context, sideIP string) bool
	SuspendRoutes  func(ctx context.Context) error
	ApplyRoutes    func(ctx context.Context, spec vlan.VLANSideRouteSpec) error
	OnEvent        func(action string, healthy bool, summary string)
}

// SideRouterFailoverGuard 管理主路由将托管 VLAN 流量切向旁路由时的自动容灾与回切状态机。
type SideRouterFailoverGuard struct {
	deps SideRouterGuardDeps

	mu               sync.Mutex
	consecutiveFails int
	suspended        bool
}

// NewSideRouterFailoverGuard 创建旁路由离线容灾救生艇状态机。
func NewSideRouterFailoverGuard(deps SideRouterGuardDeps) *SideRouterFailoverGuard {
	if deps.FailThreshold <= 0 {
		deps.FailThreshold = defaultSideRouterFailThreshold
	}
	return &SideRouterFailoverGuard{deps: deps}
}

func (g *SideRouterFailoverGuard) sideRoutesFile() string {
	return cmp.Or(strings.TrimSpace(g.deps.SideRoutesFile), constant.VLANSideRoutesFile)
}

func (g *SideRouterFailoverGuard) probeOnline(ctx context.Context, sideIP string) bool {
	if g.deps.ProbeOnline != nil {
		return g.deps.ProbeOnline(ctx, sideIP)
	}
	return gateway.ProbeSideRouterStatus(ctx, sideIP, gateway.SideRouterProbeDeps{}).Online
}

func (g *SideRouterFailoverGuard) suspendRoutes(ctx context.Context) error {
	if g.deps.SuspendRoutes != nil {
		return g.deps.SuspendRoutes(ctx)
	}
	return vlan.SuspendRuntimeSideRoutes(ctx, nil)
}

func (g *SideRouterFailoverGuard) applyRoutes(ctx context.Context, spec vlan.VLANSideRouteSpec) error {
	if g.deps.ApplyRoutes != nil {
		return g.deps.ApplyRoutes(ctx, spec)
	}
	return vlan.ApplyRuntimeSideRoutes(ctx, spec, nil)
}

func (g *SideRouterFailoverGuard) emitEvent(action string, healthy bool, summary string) {
	if g.deps.OnEvent != nil {
		g.deps.OnEvent(action, healthy, summary)
	}
}

// IsSuspended 返回当前是否因旁路由失联而处于主路由直连逃生状态。
func (g *SideRouterFailoverGuard) IsSuspended() bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.suspended
}

// EvaluateOnce 执行单轮旁路由在线探测，按防抖动阈值决定摘除或恢复托管 VLAN 策略路由。
func (g *SideRouterFailoverGuard) EvaluateOnce(ctx context.Context, cfg *config.Config) {
	if g == nil || cfg == nil {
		return
	}
	sideIP := strings.TrimSpace(cfg.Gateway.SideRouterIP)
	if cfg.Gateway.IsSideRouter() || sideIP == "" {
		g.mu.Lock()
		g.consecutiveFails = 0
		g.suspended = false
		g.mu.Unlock()
		return
	}

	spec := vlan.ReadSideRouteSpec(g.sideRoutesFile())
	if len(spec.CIDRs) == 0 {
		g.mu.Lock()
		g.consecutiveFails = 0
		g.suspended = false
		g.mu.Unlock()
		return
	}
	spec.SideRouterIP = sideIP

	if !cfg.Gateway.IsSideRouterFailoverEnabled() {
		g.mu.Lock()
		wasSuspended := g.suspended
		g.consecutiveFails = 0
		g.mu.Unlock()
		if wasSuspended && g.applyRoutes(ctx, spec) == nil {
			g.mu.Lock()
			g.suspended = false
			g.mu.Unlock()
		}
		return
	}

	if g.probeOnline(ctx, sideIP) {
		g.mu.Lock()
		wasSuspended := g.suspended
		g.consecutiveFails = 0
		g.mu.Unlock()
		if wasSuspended {
			if err := g.applyRoutes(ctx, spec); err != nil {
				logger.Warn("[SideRouterGuard] 旁路由 %s 恢复后重挂策略路由失败: %v", sideIP, err)
				return
			}
			g.mu.Lock()
			g.suspended = false
			g.mu.Unlock()
			msg := "旁路由 (" + sideIP + ") 已恢复在线，已重新接管托管子网策略分流"
			logger.Success("[SideRouterGuard] %s", msg)
			g.emitEvent("SIDE_ROUTER_RECOVERED", true, msg)
		}
		return
	}

	g.mu.Lock()
	g.consecutiveFails++
	shouldSuspend := !g.suspended && g.consecutiveFails >= g.deps.FailThreshold
	g.mu.Unlock()

	if !shouldSuspend {
		return
	}
	if err := g.suspendRoutes(ctx); err != nil {
		logger.Warn("[SideRouterGuard] 旁路由 %s 离线，摘除策略路由失败: %v", sideIP, err)
		return
	}
	g.mu.Lock()
	g.suspended = true
	g.mu.Unlock()
	msg := "旁路由 (" + sideIP + ") 连续失联，已自动摘除策略路由并切回主路由直连逃生"
	logger.Warn("[SideRouterGuard] %s", msg)
	g.emitEvent("SIDE_ROUTER_FAILOVER", false, msg)
}

func reconcileMainRouterVLANState(ctx context.Context, cfg *config.Config) {
	if runtime.GOOS != "linux" || (cfg != nil && cfg.Gateway.IsSideRouter()) {
		return
	}
	if proxyCIDRs := vlan.ReadProxyBypassList(constant.VLANProxyBypassFile); len(proxyCIDRs) > 0 {
		_ = vlan.SyncRuntimeProxyBypass(ctx, constant.VLANProxyBypassFile, proxyCIDRs)
	}
	if dnsRules := vlan.ReadDNSBypassRules(constant.VLANDNSBypassFile); len(dnsRules) > 0 {
		_ = vlan.SyncRuntimeDNSBypass(ctx, constant.VLANDNSBypassFile, dnsRules)
	}
	sideSpec := vlan.ReadSideRouteSpec(constant.VLANSideRoutesFile)
	if sideSpec.SideRouterIP == "" && cfg != nil && cfg.ConfiguredWorkMode() == config.WorkModeDelegated {
		sideSpec.SideRouterIP = strings.TrimSpace(cfg.Gateway.SideRouterIP)
	}
	if sideSpec.SideRouterIP != "" {
		_ = vlan.ApplyRuntimeSideRoutes(ctx, sideSpec, nil)
	}
}
