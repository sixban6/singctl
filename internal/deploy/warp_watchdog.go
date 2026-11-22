// 文件职责：提供单机 WARP 连通性三阶段自愈看门狗（切换 Endpoint → 换 IP → DC 直出熔断与恢复自动回切）。
package deploy

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
)

// DefaultWarpWatchdogInterval 定义 WARP 后台健康巡检周期。
const DefaultWarpWatchdogInterval = 45 * time.Second

// WarpWatchdogDeps 允许测试注入 WARP 后台巡检自愈与熔断逻辑的外部依赖。
type WarpWatchdogDeps struct {
	HasLegacyFscarmen func() bool
	PurgeAndDeploy    func(cfg *config.Config) error
	ProbeRealTargets  func(timeout time.Duration) (ip, loc string, err error)
	SwitchEndpoint    func() (endpoint, ip, loc string, err error)
	RotateIdentity    func() (ip, loc string, err error)
}

// WarpWatchdogRuntime 定义看门狗与控制面宿主交互的显式回调。
type WarpWatchdogRuntime struct {
	ActionMu              *sync.Mutex
	SingBoxConfigPath     string
	LoadConfig            func(maxWait time.Duration) (*config.Config, error)
	LiveDepsForConfig     func(cfg *config.Config) *LiveWarpApplyDeps
	EvictAllWarpConns     func(ctx context.Context) int
	EvictMismatchedConns  func(ctx context.Context, cfg *config.Config)
	OnAudit               func(action string)
	OnExitIPUpdated       func(ip, loc string)
	OnWireproxyNormalized func()
}

// WarpWatchdog 维护单机 WARP 巡检状态机（连续失败计数、老版迁移标记、熔断降级状态与最近自愈提示）。
type WarpWatchdog struct {
	rt        WarpWatchdogRuntime
	privateMu sync.Mutex

	mu             sync.Mutex
	deps           *WarpWatchdogDeps
	legacyChecked  bool
	bootSynced     bool
	degraded       bool
	failStreak     int
	autoHealStatus string
	lastHealedAt   string
}

// NewWarpWatchdog 创建单机 WARP 健康巡检看门狗实例。
func NewWarpWatchdog(rt WarpWatchdogRuntime) *WarpWatchdog {
	w := &WarpWatchdog{rt: rt}
	if w.rt.ActionMu == nil {
		w.rt.ActionMu = &w.privateMu
	}
	return w
}

// SetDeps 注入或覆盖测试替身。
func (w *WarpWatchdog) SetDeps(deps *WarpWatchdogDeps) {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.deps = deps
	w.mu.Unlock()
}

func (w *WarpWatchdog) resolveDeps() (WarpWatchdogDeps, bool) {
	d := WarpWatchdogDeps{
		HasLegacyFscarmen: HasLegacyFscarmenWarp,
		PurgeAndDeploy:    DeployWarpWithConfig,
		ProbeRealTargets:  ProbeWarpRealTargets,
		SwitchEndpoint:    SwitchWarpEndpoint,
		RotateIdentity:    RotateWarpIdentity,
	}
	w.mu.Lock()
	custom := w.deps
	w.mu.Unlock()
	if custom == nil {
		return d, false
	}
	if custom.HasLegacyFscarmen != nil {
		d.HasLegacyFscarmen = custom.HasLegacyFscarmen
	}
	if custom.PurgeAndDeploy != nil {
		d.PurgeAndDeploy = custom.PurgeAndDeploy
	}
	if custom.ProbeRealTargets != nil {
		d.ProbeRealTargets = custom.ProbeRealTargets
	}
	if custom.SwitchEndpoint != nil {
		d.SwitchEndpoint = custom.SwitchEndpoint
	}
	if custom.RotateIdentity != nil {
		d.RotateIdentity = custom.RotateIdentity
	}
	return d, true
}

func (w *WarpWatchdog) sbConfigPath() string {
	return cmp.Or(strings.TrimSpace(w.rt.SingBoxConfigPath), constant.SingBoxConfigFile)
}

func (w *WarpWatchdog) liveDeps(cfg *config.Config) *LiveWarpApplyDeps {
	if w.rt.LiveDepsForConfig != nil {
		if d := w.rt.LiveDepsForConfig(cfg); d != nil {
			return d
		}
	}
	return &LiveWarpApplyDeps{ProtectedDomains: CollectServerProtectedDomains(cfg)}
}

func (w *WarpWatchdog) evictAll(ctx context.Context) int {
	if w.rt.EvictAllWarpConns != nil {
		return w.rt.EvictAllWarpConns(ctx)
	}
	return 0
}

func (w *WarpWatchdog) recordAudit(action string) {
	if w.rt.OnAudit != nil {
		w.rt.OnAudit(action)
	}
}

// Start 在受控上下文内运行后台 WARP 健康巡检循环。
func (w *WarpWatchdog) Start(ctx context.Context, interval time.Duration) {
	if w == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultWarpWatchdogInterval
	}
	go func() {
		bootTimer := time.NewTimer(6 * time.Second)
		defer bootTimer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-bootTimer.C:
			w.RunTick(ctx)
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.RunTick(ctx)
			}
		}
	}()
}

// RunTick 执行单次 WARP 健康巡检、旧版 fscarmen 迁移及三阶段自动自愈。
func (w *WarpWatchdog) RunTick(ctx context.Context) {
	if w == nil || w.rt.LoadConfig == nil {
		return
	}
	cfg, err := w.rt.LoadConfig(200 * time.Millisecond)
	if err != nil || cfg == nil {
		return
	}

	d, hasCustomDeps := w.resolveDeps()
	w.syncBootAndPurgeLegacy(ctx, cfg, d, hasCustomDeps)

	w.mu.Lock()
	isDegraded := w.degraded
	w.mu.Unlock()

	if !NeedsWarpTunnel(cfg.Server.WarpRouting) && !isDegraded {
		w.mu.Lock()
		w.failStreak = 0
		w.mu.Unlock()
		return
	}

	if ip, loc, probeErr := d.ProbeRealTargets(4 * time.Second); probeErr == nil {
		w.handleHealthyTick(ctx, cfg, ip, loc)
		return
	}
	w.handleUnhealthyTick(ctx, cfg, d, isDegraded)
}

func (w *WarpWatchdog) syncBootAndPurgeLegacy(ctx context.Context, cfg *config.Config, d WarpWatchdogDeps, hasCustomDeps bool) {
	w.mu.Lock()
	legacyChecked := w.legacyChecked
	alreadySynced := w.bootSynced || w.degraded
	w.mu.Unlock()

	if !legacyChecked {
		if d.HasLegacyFscarmen() {
			w.rt.ActionMu.Lock()
			deployErr := d.PurgeAndDeploy(cfg)
			w.rt.ActionMu.Unlock()
			if deployErr == nil {
				_ = w.evictAll(ctx)
				w.recordAudit("检测到旧版 fscarmen WARP 残留，已自动清理并迁移至内置纯 Go wireproxy 引擎 (MTU=1280)")
				logger.Success("已自动清理旧版 fscarmen WARP 并迁移至纯 Go wireproxy")
			} else {
				logger.Warn("WARP Watchdog 迁移旧版 fscarmen 失败: %v", deployErr)
			}
		}

		if !hasCustomDeps {
			w.rt.ActionMu.Lock()
			normalizedWireproxy := false
			if raw, rErr := os.ReadFile(DefaultWireproxyConf); rErr == nil {
				if normalized, changed := NormalizeWireproxyConfigContent(string(raw)); changed {
					if wErr := fsx.WriteAtomic0600(DefaultWireproxyConf, []byte(normalized)); wErr == nil {
						_ = serviceMgr().Restart(context.Background(), "wireproxy")
						normalizedWireproxy = true
					}
				}
			}
			w.rt.ActionMu.Unlock()
			if normalizedWireproxy && w.rt.OnWireproxyNormalized != nil {
				w.rt.OnWireproxyNormalized()
			}
		}

		w.mu.Lock()
		w.legacyChecked = true
		alreadySynced = w.bootSynced || w.degraded
		w.mu.Unlock()
	}

	if alreadySynced {
		return
	}

	sbCfgPath := w.sbConfigPath()
	if _, stErr := os.Stat(sbCfgPath); stErr != nil {
		return
	}

	w.rt.ActionMu.Lock()
	liveDeps := w.liveDeps(cfg)
	checkPort := CheckWarpSocksPort
	if liveDeps.CheckWarpPort != nil {
		checkPort = liveDeps.CheckWarpPort
	}
	if NeedsWarpTunnel(cfg.Server.WarpRouting) && !checkPort() {
		w.rt.ActionMu.Unlock()
		return
	}
	_, applyErr := ApplyLiveWarpRouting(sbCfgPath, cfg.Server.WarpRouting, liveDeps)
	w.rt.ActionMu.Unlock()

	if applyErr == nil {
		w.mu.Lock()
		w.bootSynced = true
		w.mu.Unlock()
	}
}

func (w *WarpWatchdog) handleHealthyTick(ctx context.Context, cfg *config.Config, ip, loc string) {
	if ip != "" && w.rt.OnExitIPUpdated != nil {
		w.rt.OnExitIPUpdated(ip, loc)
	}

	w.mu.Lock()
	wasDegraded := w.degraded
	needBootSync := !w.bootSynced
	w.failStreak = 0
	w.mu.Unlock()

	if !wasDegraded && !needBootSync {
		return
	}

	w.rt.ActionMu.Lock()
	_, applyErr := ApplyLiveWarpRouting(w.sbConfigPath(), cfg.Server.WarpRouting, w.liveDeps(cfg))
	w.rt.ActionMu.Unlock()
	if applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		return
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	w.mu.Lock()
	w.bootSynced = true
	if wasDegraded {
		w.degraded = false
		w.autoHealStatus = fmt.Sprintf("WARP 隧道已恢复健康 (%s)，已自动切回原有分流策略", cmp.Or(ip, "Connected"))
		w.lastHealedAt = nowStr
	}
	w.mu.Unlock()

	if wasDegraded {
		if w.rt.EvictMismatchedConns != nil {
			w.rt.EvictMismatchedConns(ctx, cfg)
		}
		w.recordAudit(fmt.Sprintf("WARP 巡检确认隧道已恢复健康 [%s (%s)]，自动解除直出降级并恢复原有分流策略", cmp.Or(ip, "OK"), cmp.Or(loc, "Anycast")))
		logger.Success("WARP 隧道已恢复健康 (%s)，已自动恢复分流策略", ip)
	}
}

func (w *WarpWatchdog) handleUnhealthyTick(ctx context.Context, cfg *config.Config, d WarpWatchdogDeps, isDegraded bool) {
	w.mu.Lock()
	w.failStreak++
	streak := w.failStreak
	w.mu.Unlock()

	if isDegraded {
		if streak%4 == 0 {
			w.rt.ActionMu.Lock()
			if _, _, _, swErr := d.SwitchEndpoint(); swErr != nil {
				_, _, _ = d.RotateIdentity()
			}
			w.rt.ActionMu.Unlock()
		}
		return
	}
	if streak < 2 {
		return
	}

	w.rt.ActionMu.Lock()
	defer w.rt.ActionMu.Unlock()

	sbCfgPath := w.sbConfigPath()
	nowStr := time.Now().Format("2006-01-02 15:04:05")

	// 阶段 1：轮换 Cloudflare WARP Endpoint 节点恢复连通
	if ep, epIP, epLoc, swErr := d.SwitchEndpoint(); swErr == nil {
		w.markHealed(epIP, epLoc, fmt.Sprintf("自动自愈成功：已切换优选节点 %s 恢复连通", ep), nowStr)
		w.ensureHardExemptionsAfterHeal(sbCfgPath, cfg)
		evicted := w.evictAll(ctx)
		w.recordAudit(fmt.Sprintf("WARP 巡检自愈 [阶段1]：自动切换优选 Endpoint [%s] 恢复连通 (踢断旧流:%d)", ep, evicted))
		logger.Success("WARP 巡检自愈阶段 1 成功：Endpoint=%s", ep)
		return
	}

	// 阶段 2：重新注册 WireGuard 身份与出口 IP 并实测外网 HTTPS 连通
	if rotIP, rotLoc, rotErr := d.RotateIdentity(); rotErr == nil {
		if probeIP, probeLoc, pErr := d.ProbeRealTargets(4 * time.Second); pErr == nil {
			finalIP := cmp.Or(probeIP, rotIP)
			finalLoc := cmp.Or(probeLoc, rotLoc, "Anycast")
			w.markHealed(finalIP, finalLoc, fmt.Sprintf("自动自愈成功：已更换 WARP IP %s (%s)", finalIP, finalLoc), nowStr)
			w.ensureHardExemptionsAfterHeal(sbCfgPath, cfg)
			evicted := w.evictAll(ctx)
			w.recordAudit(fmt.Sprintf("WARP 巡检自愈 [阶段2]：自动更换全新 WARP 出口 IP [%s (%s)] 恢复连通 (踢断旧流:%d)", finalIP, finalLoc, evicted))
			logger.Success("WARP 巡检自愈阶段 2 成功：IP=%s (%s)", finalIP, finalLoc)
			return
		}
	}

	// 阶段 3：熔断保护 —— 仅对现网 sing-box config.json 临时写入旁路全直出 (DC)，绝不覆盖 singctl.yaml 用户原分流意向
	bypassWR := config.WarpRoutingConfig{Mode: config.WarpModeBypass}
	if _, applyErr := ApplyLiveWarpRouting(sbCfgPath, bypassWR, w.liveDeps(cfg)); applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		logger.Warn("WARP Watchdog 阶段 3 熔断降级写入失败: %v", applyErr)
		return
	}

	w.mu.Lock()
	w.degraded = true
	w.bootSynced = true
	w.failStreak = 0
	w.autoHealStatus = "WARP 出口异常，已自动熔断降级至原生直出 (DC) 保障不断网，后台正持续探测自动回切"
	w.lastHealedAt = nowStr
	w.mu.Unlock()

	evicted := w.evictAll(ctx)
	w.recordAudit(fmt.Sprintf("WARP 巡检自愈 [阶段3·熔断保护]：切换节点与换 IP 均未恢复，已临时降级至原生直出 (DC) 保障不断网，待恢复后自动回切 (踢断旧流:%d)", evicted))
	logger.Warn("WARP 多次自愈未恢复，已触发阶段 3 熔断降级至 DC 直出 (singctl.yaml 已完整保留)")
}

func (w *WarpWatchdog) markHealed(ip, loc, statusMsg, nowStr string) {
	if ip != "" && w.rt.OnExitIPUpdated != nil {
		w.rt.OnExitIPUpdated(ip, loc)
	}
	w.mu.Lock()
	w.degraded = false
	w.failStreak = 0
	w.autoHealStatus = statusMsg
	w.lastHealedAt = nowStr
	w.mu.Unlock()
}

func (w *WarpWatchdog) ensureHardExemptionsAfterHeal(sbCfgPath string, cfg *config.Config) {
	w.mu.Lock()
	synced := w.bootSynced
	w.mu.Unlock()
	if synced {
		return
	}
	if _, err := ApplyLiveWarpRouting(sbCfgPath, cfg.Server.WarpRouting, w.liveDeps(cfg)); err == nil {
		w.mu.Lock()
		w.bootSynced = true
		w.mu.Unlock()
	}
}

// ResetOnManualApply 在管理员手动下发 WARP 分流策略后重置熔断与失败计数。
func (w *WarpWatchdog) ResetOnManualApply() {
	if w == nil {
		return
	}
	w.mu.Lock()
	w.degraded = false
	w.failStreak = 0
	w.bootSynced = true
	w.mu.Unlock()
}

// ClearHealBadgeIfHealthy 在手动换 IP 且当前未处于熔断态时清理旧的自愈提示横幅。
func (w *WarpWatchdog) ClearHealBadgeIfHealthy() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if !w.degraded {
		w.autoHealStatus = ""
		w.lastHealedAt = ""
	}
	w.mu.Unlock()
}

// RestoreSavedRoutingIfDegraded 在手动 rekey/ensure 修复隧道后，若此前处于阶段 3 熔断降级态则自动切回保存的分流策略。
func (w *WarpWatchdog) RestoreSavedRoutingIfDegraded(cfg *config.Config) bool {
	if w == nil {
		return false
	}
	w.mu.Lock()
	degraded := w.degraded
	w.failStreak = 0
	w.mu.Unlock()
	if !degraded || cfg == nil {
		return false
	}
	if _, applyErr := ApplyLiveWarpRouting(w.sbConfigPath(), cfg.Server.WarpRouting, w.liveDeps(cfg)); applyErr != nil && !errors.Is(applyErr, os.ErrNotExist) {
		return false
	}
	w.mu.Lock()
	w.degraded = false
	w.autoHealStatus = "已手动恢复 WARP 隧道并切回原有分流策略"
	w.lastHealedAt = time.Now().Format("2006-01-02 15:04:05")
	w.mu.Unlock()
	return true
}

// DecorateDaemonStatus 将看门狗当前的熔断降级状态与最近自愈提示叠加到守护状态响应中。
func (w *WarpWatchdog) DecorateDaemonStatus(status *WarpDaemonStatus) {
	if w == nil || status == nil {
		return
	}
	w.mu.Lock()
	degraded := w.degraded
	healMsg := w.autoHealStatus
	healedAt := w.lastHealedAt
	w.mu.Unlock()

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
