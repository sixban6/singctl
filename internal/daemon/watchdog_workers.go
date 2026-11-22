// 文件职责：实现守护进程后台异步巡检子任务（设备行为采样、限速表对账、Tailscale P2P 对账、规则集静默刷新与 sing-box 自愈重启）。
package daemon

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"runtime"
	"singctl/internal/audit"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/tailscale"
	"slices"
	"strings"
	"time"
)

func (d *Daemon) recordHealthResult(res HealthCheckResult) {
	at := res.CheckTime
	if at.IsZero() {
		at = time.Now()
	}
	UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
		snap.LastHealthAt = at.Format(time.DateTime)
		snap.LastHealthOK = res.Healthy
		snap.LastHealthDetail = res.Details
		snap.LastHealthDelayMs = res.LatencyMs
	})
}

func (d *Daemon) maybeSampleDeviceAuditAsync() {
	if !d.auditSampling.CompareAndSwap(false, true) {
		return
	}
	cfg := d.currentConfig()
	collector := d.auditCollector
	if collector == nil {
		collector = audit.NewCollector(cfg)
		d.auditCollector = collector
	}
	go func() {
		defer d.auditSampling.Store(false)
		ctx, cancel := context.WithTimeout(d.ctx, 3*time.Second)
		defer cancel()
		collector.UpdateConfig(cfg)
		if collector.SampleActiveConnections(ctx) {
			d.maybeObserveAuditAlerts(ctx, cfg, collector)
		}
	}()
}

func (d *Daemon) maybeReconcileAuditThrottlesAsync(force bool) {
	if runtime.GOOS != "linux" {
		return
	}
	cfg := d.currentConfig()
	if cfg == nil || (!force && len(cfg.Audit.Throttles) == 0) {
		return
	}
	if !d.throttleReconciling.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.throttleReconciling.Store(false)
		ctx, cancel := context.WithTimeout(d.ctx, 6*time.Second)
		defer cancel()
		res := audit.ApplyThrottleRules(ctx, cfg)
		if !res.Applied && len(cfg.Audit.Throttles) > 0 && res.Message != "" {
			logger.Warn("[Audit-Throttle] 同步内核限速表异常: %s", res.Message)
		}
	}()
}

// ReconcileTailscaleP2POnce 同步执行单次 Tailscale P2P 防线对账并按变化写回运行态快照。
// 当宿主机缺失 nftables (nft) 时由控制器执行 30 分钟长退避，仅首次打印 1 次清晰告警并记录 LastError。
func (d *Daemon) ReconcileTailscaleP2POnce(ctx context.Context, force bool) {
	if d == nil || d.p2pCtrl == nil {
		return
	}
	cfg := d.currentConfig()
	if cfg == nil {
		return
	}
	p2pCfg := cfg.Tailscale.P2PAssist
	if !p2pCfg.Enabled && !d.p2pLastActive.Load() && !force {
		return
	}
	res, err := d.p2pCtrl.Reconcile(ctx, p2pCfg)
	if err != nil {
		if errors.Is(err, tailscale.ErrNFTUnavailable) || errors.Is(err, exec.ErrNotFound) {
			logger.Warn("[Tailscale-P2P] 当前宿主机未检测到 nftables (nft)，已跳过 fw4 P2P 防线并进入 30 分钟静默退避: %v", err)
		} else {
			logger.Warn("[Tailscale-P2P] Reconcile error: %v", err)
		}
	}
	d.p2pLastActive.Store(res.Enabled)

	var peerParts []string
	for _, k := range slices.Sorted(maps.Keys(res.PeerStates)) {
		ps := res.PeerStates[k]
		peerParts = append(peerParts, fmt.Sprintf("%s=%s:%d:%s", k, ps.LastResult, ps.ConsecutiveFails, ps.LastUpgradeAt))
	}
	summaryKey := fmt.Sprintf("%v|%s|%d|%s|%s", res.Enabled, res.ApplyMode, res.OpenPinholes, res.LastError, strings.Join(peerParts, ","))
	d.p2pSnapMu.Lock()
	changed := d.p2pLastSnapSummary != summaryKey || res.OpenPinholes > 0
	if changed {
		d.p2pLastSnapSummary = summaryKey
	}
	d.p2pSnapMu.Unlock()

	if changed {
		snapCopy := res
		d.effectiveStateStore().Update(func(snap *DaemonRuntimeSnapshot) {
			snap.TailscaleP2P = &snapCopy
		})
	}
}

func (d *Daemon) maybeReconcileTailscaleP2PAsync(force bool) {
	if runtime.GOOS != "linux" || d.p2pCtrl == nil {
		return
	}
	cfg := d.currentConfig()
	if cfg == nil {
		return
	}
	p2pCfg := cfg.Tailscale.P2PAssist
	if !p2pCfg.Enabled && !d.p2pLastActive.Load() && !force {
		return
	}
	if !d.p2pReconciling.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.p2pReconciling.Store(false)
		ctx, cancel := context.WithTimeout(d.ctx, 8*time.Second)
		defer cancel()
		d.ReconcileTailscaleP2POnce(ctx, force)
	}()
}

func (d *Daemon) maybeRefreshRuleSetsAsync() {
	if d.ruleSetRefreshing.Load() {
		return
	}

	d.ruleSetMu.Lock()
	if !d.lastRuleSetFailedAt.IsZero() && time.Since(d.lastRuleSetFailedAt) < ruleSetRetryCooldown {
		d.ruleSetMu.Unlock()
		return
	}
	d.ruleSetMu.Unlock()

	cfg := d.currentConfig()
	mirrorURL := ""
	if cfg != nil {
		mirrorURL = cfg.GitHub.MirrorURL
	}
	opts := singbox.LocalizeOptions{
		MirrorURL: mirrorURL,
		CacheTTL:  singbox.DefaultRuleSetCacheTTL,
		Workers:   2,
		Silent:    true,
	}
	if !singbox.NeedsCacheRefresh(constant.SingBoxConfigFile, opts) {
		return
	}

	if !d.ruleSetRefreshing.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer d.ruleSetRefreshing.Store(false)

		_, stats, err := singbox.RefreshConfigCache(constant.SingBoxConfigFile, opts)
		nowStr := time.Now().Format(time.DateTime)
		if err != nil || stats.Aborted {
			d.ruleSetMu.Lock()
			d.lastRuleSetFailedAt = time.Now()
			d.ruleSetMu.Unlock()
			if err != nil {
				logger.Warn("[RuleSet] Background silent refresh failed: %v", err)
			}
			UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
				snap.LastRuleSetAt = nowStr
				snap.LastRuleSetResult = "静默刷新推迟重试"
			})
			return
		}

		d.ruleSetMu.Lock()
		d.lastRuleSetFailedAt = time.Time{}
		d.ruleSetMu.Unlock()

		summary := fmt.Sprintf("已更新 %d 个 / 缓存就绪 %d 个", stats.Refreshed+stats.Localized, stats.Cached)
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastRuleSetAt = nowStr
			snap.LastRuleSetResult = summary
		})

		if stats.Refreshed > 0 || stats.Localized > 0 {
			logger.Info("[RuleSet] Background silent refresh completed: refreshed=%d, localized=%d, cached=%d",
				stats.Refreshed, stats.Localized, stats.Cached)
			AppendRuntimeEvent(WatchdogEventRecord{
				Time:    nowStr,
				Action:  "RULESET_REFRESH",
				Healthy: true,
				Summary: summary,
			})
		}
	}()
}

// runWatchdogCheck 健康检查：先维护 tailscaled OOM 免疫与宿主机资源预警，再守护本地 DNS 与 sing-box，不健康则二次确认后重启。
func (d *Daemon) runWatchdogCheck() {
	if d.reloading.Load() {
		return
	}
	d.GuardTailscaleOOMOnce()
	d.CheckHostResourcesOnce()
	d.GuardLocalDNSOnce(d.ctx)
	cfg := d.currentConfig()

	mon := NewMonitor(cfg)
	result1 := mon.CheckHealth()
	d.recordHealthResult(result1)
	if result1.Healthy {
		if d.watchdogUnhealthy.Swap(false) {
			d.RecordWatchdogHealEvent(true, "recovered", result1.Details)
		}
		d.maybeRefreshRuleSetsAsync()
		d.maybeSyncSubscriptionsAsync()
		return
	}

	confirmWait := 30
	if cfg != nil && cfg.Watchdog.ConfirmWait > 0 {
		confirmWait = cfg.Watchdog.ConfirmWait
	}

	logger.Warn("[Watchdog] Health check failed (round 1): %s - %s, waiting %ds for confirmation...",
		result1.FailedReason, result1.Details, confirmWait)
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "DETECT",
		CheckResult:   result1,
		RestartResult: "-",
	})

	select {
	case <-time.After(time.Duration(confirmWait) * time.Second):
	case <-d.ctx.Done():
		return
	}

	if d.reloading.Load() {
		return
	}

	result2 := NewMonitor(d.currentConfig()).CheckHealth()
	d.recordHealthResult(result2)
	if result2.Healthy {
		logger.Info("[Watchdog] Health recovered on confirmation check, no action needed")
		return
	}

	logger.Warn("[Watchdog] Health check confirmed unhealthy (round 2): %s - %s, preparing restart...",
		result2.FailedReason, result2.Details)
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "CONFIRM",
		CheckResult:   result2,
		RestartResult: "-",
	})

	d.watchdogUnhealthy.Store(true)
	d.RecordWatchdogHealEvent(false, result2.FailedReason, result2.Details)
	d.doRestart(result2, result2.FailedReason)
}

func (d *Daemon) doRestart(checkResult HealthCheckResult, reason string) {
	if !d.limiter.CanRestart() {
		logger.Error("[Watchdog] Restart limit exceeded (%d restarts in last hour), skipping auto-restart",
			d.limiter.GetMaxRestarts())
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "RESTART_BLOCKED",
			CheckResult:   checkResult,
			RestartResult: "rate limited",
		})
		return
	}

	if delay := d.limiter.GetRestartDelay(); delay > 0 {
		logger.Warn("[Watchdog] Backing off %s before restart (%d restarts in last hour)...",
			delay, d.limiter.GetRestartCount())
		select {
		case <-time.After(delay):
		case <-d.ctx.Done():
			return
		}
		if !d.limiter.CanRestart() {
			logger.Error("[Watchdog] Restart limit exceeded after backoff, skipping auto-restart")
			LogWatchdogEvent(WatchdogEvent{
				Time:          time.Now(),
				Action:        "RESTART_BLOCKED",
				CheckResult:   checkResult,
				RestartResult: "rate limited after backoff",
			})
			return
		}
	}

	d.lifecycleMu.Lock()
	d.reloading.Store(true)
	defer func() {
		d.reloading.Store(false)
		d.lifecycleMu.Unlock()
	}()

	cfg := d.currentConfig()
	sb := singbox.New(cfg)

	// 零断网保护：先校验配置文件可用性，若损坏则尝试先重新生成，生成失败绝不盲目停掉尚存进程
	if err := sb.ValidateConfig(); err != nil {
		logger.Warn("[Watchdog] Current config invalid (%v), attempting pre-generation before restart...", err)
		if genErr := sb.GenerateConfig(); genErr != nil {
			logger.Error("[Watchdog] Pre-generation failed (%s), aborting destructive stop", singbox.MaskSensitiveText(genErr.Error()))
			LogWatchdogEvent(WatchdogEvent{
				Time:          time.Now(),
				Action:        "RESTART",
				CheckResult:   checkResult,
				RestartResult: "aborted: invalid config",
			})
			return
		}
	}

	logger.Warn("[Watchdog] Executing full restart: stop → start (reason: %s)", reason)

	if err := sb.Stop(); err != nil {
		logger.Error("[Watchdog] Stop failed: %v", err)
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "RESTART",
			CheckResult:   checkResult,
			RestartResult: fmt.Sprintf("stop failed: %v", err),
		})
		return
	}

	select {
	case <-time.After(2 * time.Second):
	case <-d.ctx.Done():
		return
	}

	if err := sb.Start(); err != nil {
		logger.Error("[Watchdog] Start failed: %v", err)
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "RESTART",
			CheckResult:   checkResult,
			RestartResult: fmt.Sprintf("start failed: %v", err),
		})
		return
	}

	d.limiter.RecordRestart()
	now := time.Now()
	logger.Success("[Watchdog] sing-box restarted successfully (reason: %s)", reason)
	resAfter := NewMonitor(cfg).CheckHealth()
	d.recordHealthResult(resAfter)
	if resAfter.Healthy {
		d.watchdogUnhealthy.Store(false)
		d.RecordWatchdogHealEvent(true, reason, fmt.Sprintf("sing-box 已自动重启恢复健康 (原因: %s)", reason))
	}
	LogWatchdogEvent(WatchdogEvent{
		Time:   now,
		Action: "RESTART",
		CheckResult: HealthCheckResult{
			Healthy:   resAfter.Healthy,
			CheckTime: now,
			Details:   fmt.Sprintf("已自动重启恢复 (触发原因: %s)", reason),
		},
		RestartResult: "success",
	})
}
