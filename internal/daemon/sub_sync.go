// 文件职责：实现上游订阅节点静默轮询检测、候选配置预检、0600 原子切换与异常自动回滚（零断网策略）。
package daemon

import (
	"fmt"
	"os"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

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

type subSyncCandidate struct {
	pureBaseJSON     string
	candidateJSON    string
	baseSnap         string
	oldCount         int
	newCount         int
	preservedChanges int
	changed          bool
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
	cand, ok := d.buildSubSyncCandidate(cfg, cfgPath, currentBytes)
	if !ok || !cand.changed {
		return
	}

	logger.Info("[SubSync] Detected subscription node change (%d -> %d proxy outbounds), pre-validating new config...", cand.oldCount, cand.newCount)
	tmpPath, out, err := d.PreValidateSubSyncConfig(cfgPath, cand.candidateJSON)
	if err != nil {
		logger.Warn("[SubSync] Pre-validation (sing-box check) failed, aborting sync: %v (%s)", err, string(out))
		recordSubSyncStatus(time.Now(), cand.oldCount, "新配置预检未通过(已拦截)")
		return
	}

	d.executeAtomicSubSyncSwap(cfg, cfgPath, currentBytes, tmpPath, cand)
}

func (d *Daemon) buildSubSyncCandidate(cfg *config.Config, cfgPath string, currentBytes []byte) (subSyncCandidate, bool) {
	oldHash, oldCount, err := singbox.ProxyOutboundsFingerprint(string(currentBytes))
	if err != nil {
		return subSyncCandidate{}, false
	}

	gen := singbox.NewConfigGenerator(cfg)
	gen.SetSilent(true)
	freshJSON, err := gen.Generate()
	now := time.Now()
	if err != nil {
		maskedErr := singbox.MaskSensitiveText(err.Error())
		logger.Warn("[SubSync] Upstream subscription poll failed (keeping active config): %s", maskedErr)
		recordSubSyncStatus(now, oldCount, "拉取失败(保留原配置)")
		return subSyncCandidate{}, false
	}

	_, subNodeCount, err := singbox.ProxyOutboundsFingerprint(freshJSON)
	if err != nil || subNodeCount == 0 {
		logger.Warn("[SubSync] Upstream subscription returned 0 valid proxy outbounds, ignoring")
		recordSubSyncStatus(now, oldCount, "返回空节点(已忽略)")
		return subSyncCandidate{}, false
	}

	pureBaseJSON := freshJSON
	if localized, _, locErr := singbox.LocalizeRuleSets(freshJSON, singbox.LocalizeOptions{
		MirrorURL:    cfg.GitHub.MirrorURL,
		CacheTTL:     singbox.DefaultRuleSetCacheTTL,
		OfflineFirst: true,
		Silent:       true,
	}); locErr == nil {
		pureBaseJSON = localized
	}

	baseSnap, _ := singbox.LoadBaseSnapshot(cfgPath)
	candidateJSON := pureBaseJSON
	preservedChanges := 0
	if cfg.Watchdog.ShouldPreserveManualConfig() {
		if merged, cnt, mErr := singbox.MergeManualConfig(baseSnap, string(currentBytes), pureBaseJSON); mErr == nil {
			candidateJSON = merged
			preservedChanges = cnt
		}
	}

	newHash, newCount, err := singbox.ProxyOutboundsFingerprint(candidateJSON)
	if err != nil || newCount == 0 {
		return subSyncCandidate{}, false
	}
	if newHash == oldHash {
		if baseSnap == "" {
			_ = singbox.SaveBaseSnapshot(cfgPath, pureBaseJSON)
		}
		recordSubSyncStatus(now, newCount, fmt.Sprintf("指纹一致 (%d 节点)", newCount))
		return subSyncCandidate{oldCount: oldCount, newCount: newCount, changed: false}, true
	}

	return subSyncCandidate{
		pureBaseJSON:     pureBaseJSON,
		candidateJSON:    candidateJSON,
		baseSnap:         baseSnap,
		oldCount:         oldCount,
		newCount:         newCount,
		preservedChanges: preservedChanges,
		changed:          true,
	}, true
}

func (d *Daemon) executeAtomicSubSyncSwap(cfg *config.Config, cfgPath string, currentBytes []byte, tmpPath string, cand subSyncCandidate) {
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
	_ = fsx.WriteAtomic0600(bakPath, currentBytes)
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
		rollbackFailedSubSync(sb, bakPath, cfgPath, now, cand.oldCount)
		return
	}

	_ = singbox.SaveBaseSnapshot(cfgPath, cand.pureBaseJSON)
	singbox.RestoreClashSelections(savedSelections)
	if cand.preservedChanges > 0 {
		logger.Success("[SubSync] Subscription nodes auto-synced (%d -> %d outbounds, preserved %d manual config edits)", cand.oldCount, cand.newCount, cand.preservedChanges)
	} else {
		logger.Success("[SubSync] Subscription nodes auto-synced seamlessly (%d -> %d outbounds)", cand.oldCount, cand.newCount)
	}
	recordSubSyncStatus(now, cand.newCount, fmt.Sprintf("已无感同步 (%d → %d 节点)", cand.oldCount, cand.newCount))
	LogWatchdogEvent(WatchdogEvent{
		Time:   now,
		Action: "SUB_SYNC",
		CheckResult: HealthCheckResult{
			Healthy:   true,
			CheckTime: now,
			Details:   fmt.Sprintf("节点数 %d -> %d", cand.oldCount, cand.newCount),
		},
		RestartResult: fmt.Sprintf("synced %d -> %d outbounds", cand.oldCount, cand.newCount),
	})
}

func rollbackFailedSubSync(sb *singbox.SingBox, bakPath, cfgPath string, now time.Time, oldCount int) {
	logger.Error("[SubSync] Reload failed health verification, rolling back previous config...")
	_ = os.Rename(bakPath, cfgPath)
	_ = sb.Stop()
	time.Sleep(2 * time.Second)
	_ = sb.Start()
	recordSubSyncStatus(now, oldCount, "健康校验失败已回滚")
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
}

func recordSubSyncStatus(at time.Time, nodeCount int, result string) {
	nowStr := at.Format(time.DateTime)
	UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
		snap.LastSubSyncAt = nowStr
		snap.LastSubSyncNodeCt = nodeCount
		snap.LastSubSyncResult = result
	})
}
