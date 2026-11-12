package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"singctl/internal/constant"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

// maybeSyncSubscriptionsAsync silently checks whether upstream subscription proxy outbounds
// have changed (e.g. a new VPS was bootstrapped or credentials were rotated on Fleet Master).
//
// Safety guarantees (Zero-Outage Policy):
//  1. Reloads latest on-disk singctl.yaml first so recent block rules / whitelists are always preserved.
//  2. Uses Silent ConfigGenerator so unchanged checks emit zero log noise.
//  3. Pre-validates via `sing-box check`, holds shared lifecycleMu, preserves Clash API selector choices,
//     and automatically rolls back if sing-box fails health check after reload.
func (d *Daemon) maybeSyncSubscriptionsAsync() {
	cfg := d.currentConfig()
	if cfg == nil || cfg.Watchdog.SubSyncInterval < 0 || len(cfg.Subs) == 0 {
		return
	}
	if doctor.IsServerEnvironment(cfg) {
		return
	}
	if d.subSyncRunning.Load() {
		return
	}

	syncInterval := time.Duration(cfg.Watchdog.SubSyncInterval) * time.Second
	if syncInterval <= 0 {
		syncInterval = 10 * time.Minute
	}

	d.subSyncMu.Lock()
	if !d.lastSubSyncCheckAt.IsZero() && time.Since(d.lastSubSyncCheckAt) < syncInterval {
		d.subSyncMu.Unlock()
		return
	}
	d.lastSubSyncCheckAt = time.Now()
	d.subSyncMu.Unlock()

	if !d.subSyncRunning.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer d.subSyncRunning.Store(false)
		d.syncSubscriptionsIfChanged()
	}()
}

func (d *Daemon) syncSubscriptionsIfChanged() {
	cfg := d.currentConfig()
	if cfg == nil || cfg.Watchdog.SubSyncInterval < 0 || len(cfg.Subs) == 0 {
		return
	}

	cfgPath := constant.SingBoxConfigFile
	currentBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	oldHash, oldCount, err := singbox.ProxyOutboundsFingerprint(string(currentBytes))
	if err != nil {
		return
	}

	gen := singbox.NewConfigGenerator(cfg)
	gen.SetSilent(true)
	freshJSON, err := gen.Generate()
	nowStr := time.Now().Format(time.DateTime)
	if err != nil {
		maskedErr := singbox.MaskSensitiveText(err.Error())
		logger.Warn("[SubSync] Upstream subscription poll failed (keeping active config): %s", maskedErr)
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastSubSyncAt = nowStr
			snap.LastSubSyncNodeCt = oldCount
			snap.LastSubSyncResult = "拉取失败(保留原配置)"
		})
		return
	}

	newHash, newCount, err := singbox.ProxyOutboundsFingerprint(freshJSON)
	if err != nil || newCount == 0 {
		logger.Warn("[SubSync] Upstream subscription returned 0 valid proxy outbounds, ignoring")
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastSubSyncAt = nowStr
			snap.LastSubSyncNodeCt = oldCount
			snap.LastSubSyncResult = "返回空节点(已忽略)"
		})
		return
	}

	if newHash == oldHash {
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastSubSyncAt = nowStr
			snap.LastSubSyncNodeCt = newCount
			snap.LastSubSyncResult = fmt.Sprintf("指纹一致 (%d 节点)", newCount)
		})
		return
	}

	logger.Info("[SubSync] Detected subscription node change (%d -> %d proxy outbounds), pre-validating new config...", oldCount, newCount)

	if localized, _, locErr := singbox.LocalizeRuleSets(freshJSON, singbox.LocalizeOptions{
		MirrorURL:    cfg.GitHub.MirrorURL,
		CacheTTL:     singbox.DefaultRuleSetCacheTTL,
		OfflineFirst: true,
		Silent:       true,
	}); locErr == nil {
		freshJSON = localized
	}

	tmpPath := cfgPath + ".subsync.tmp"
	if err := os.WriteFile(tmpPath, []byte(freshJSON), 0600); err != nil {
		logger.Warn("[SubSync] Write staged config failed: %v", err)
		return
	}
	_ = os.Chmod(tmpPath, 0600)

	checkCmd := exec.Command(constant.SingBoxInstallDir, "check", "-c", tmpPath)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmpPath)
		logger.Warn("[SubSync] Pre-validation (sing-box check) failed, aborting sync: %v (%s)", err, string(out))
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastSubSyncAt = nowStr
			snap.LastSubSyncNodeCt = oldCount
			snap.LastSubSyncResult = "新配置预检未通过(已拦截)"
		})
		return
	}

	d.lifecycleMu.Lock()
	d.reloading.Store(true)
	defer func() {
		d.reloading.Store(false)
		d.lifecycleMu.Unlock()
	}()

	savedSelections := singbox.SnapshotClashSelections()
	sb := singbox.New(cfg)
	mon := NewMonitor(cfg)

	bakPath := cfgPath + ".subsync.bak"
	_ = os.WriteFile(bakPath, currentBytes, 0600)
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		_ = os.Remove(tmpPath)
		logger.Warn("[SubSync] Atomic config swap failed: %v", err)
		return
	}

	if err := sb.Stop(); err != nil {
		logger.Warn("[SubSync] Stop sing-box returned error: %v", err)
	}
	select {
	case <-time.After(2 * time.Second):
	case <-d.ctx.Done():
		return
	}

	startErr := sb.Start()
	healthy := false
	if startErr == nil {
		for range 3 {
			if mon.CheckHealth().Healthy {
				healthy = true
				break
			}
			time.Sleep(2 * time.Second)
		}
	}

	now := time.Now()
	if startErr != nil || !healthy {
		logger.Error("[SubSync] Reload failed health verification, rolling back previous config...")
		_ = os.Rename(bakPath, cfgPath)
		_ = sb.Stop()
		time.Sleep(2 * time.Second)
		_ = sb.Start()
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastSubSyncAt = now.Format(time.DateTime)
			snap.LastSubSyncNodeCt = oldCount
			snap.LastSubSyncResult = "健康校验失败已回滚"
		})
		LogWatchdogEvent(WatchdogEvent{
			Time:   now,
			Action: "SUB_SYNC",
			CheckResult: HealthCheckResult{
				Healthy:      false,
				CheckTime:    now,
				FailedReason: "subsync_health_failed",
				Details:      "重载后健康校验未通过，已自动回滚旧配置",
			},
			RestartResult: "rolled back to previous config",
		})
		return
	}

	singbox.RestoreClashSelections(savedSelections)
	logger.Success("[SubSync] Subscription nodes auto-synced seamlessly (%d -> %d outbounds)", oldCount, newCount)
	UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
		snap.LastSubSyncAt = now.Format(time.DateTime)
		snap.LastSubSyncNodeCt = newCount
		snap.LastSubSyncResult = fmt.Sprintf("已无感同步 (%d → %d 节点)", oldCount, newCount)
	})
	LogWatchdogEvent(WatchdogEvent{
		Time:   now,
		Action: "SUB_SYNC",
		CheckResult: HealthCheckResult{
			Healthy:   true,
			CheckTime: now,
			Details:   fmt.Sprintf("节点数 %d -> %d", oldCount, newCount),
		},
		RestartResult: fmt.Sprintf("synced %d -> %d outbounds", oldCount, newCount),
	})
}
