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
//  1. Never runs if sing-box is unhealthy or on server deployments without client subs.
//  2. If upstream fetch fails or returns 0 proxy nodes, existing config is untouched.
//  3. If proxy outbounds SHA-256 fingerprint is unchanged, zero disk writes and zero restarts occur.
//  4. When changed, pre-validates via `sing-box check`, preserves Clash API selector choices,
//     and automatically rolls back if sing-box fails health check after reload.
func (d *Daemon) maybeSyncSubscriptionsAsync() {
	if d.config == nil || d.config.Watchdog.SubSyncInterval < 0 || len(d.config.Subs) == 0 {
		return
	}
	if doctor.IsServerEnvironment(d.config) {
		return
	}
	if d.subSyncRunning.Load() {
		return
	}

	syncInterval := time.Duration(d.config.Watchdog.SubSyncInterval) * time.Second
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
	cfgPath := constant.SingBoxConfigFile
	currentBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return
	}
	oldHash, oldCount, err := singbox.ProxyOutboundsFingerprint(string(currentBytes))
	if err != nil {
		return
	}

	gen := singbox.NewConfigGenerator(d.config)
	freshJSON, err := gen.Generate()
	if err != nil {
		logger.Warn("[SubSync] Upstream subscription poll failed (keeping active config): %v", err)
		return
	}

	newHash, newCount, err := singbox.ProxyOutboundsFingerprint(freshJSON)
	if err != nil || newCount == 0 {
		logger.Warn("[SubSync] Upstream subscription returned 0 valid proxy outbounds, ignoring")
		return
	}

	if newHash == oldHash {
		return
	}

	logger.Info("[SubSync] Detected subscription node change (%d -> %d proxy outbounds), pre-validating new config...", oldCount, newCount)

	if localized, _, locErr := singbox.LocalizeRuleSets(freshJSON, singbox.LocalizeOptions{
		MirrorURL:    d.config.GitHub.MirrorURL,
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
		return
	}

	savedSelections := singbox.SnapshotClashSelections()

	bakPath := cfgPath + ".subsync.bak"
	_ = os.WriteFile(bakPath, currentBytes, 0600)
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		_ = os.Remove(tmpPath)
		logger.Warn("[SubSync] Atomic config swap failed: %v", err)
		return
	}

	if err := d.singbox.Stop(); err != nil {
		logger.Warn("[SubSync] Stop sing-box returned error: %v", err)
	}
	select {
	case <-time.After(2 * time.Second):
	case <-d.ctx.Done():
		return
	}

	startErr := d.singbox.Start()
	healthy := false
	if startErr == nil {
		for range 3 {
			if d.monitor.CheckHealth().Healthy {
				healthy = true
				break
			}
			time.Sleep(2 * time.Second)
		}
	}

	if startErr != nil || !healthy {
		logger.Error("[SubSync] Reload failed health verification, rolling back previous config...")
		_ = os.Rename(bakPath, cfgPath)
		_ = d.singbox.Stop()
		time.Sleep(2 * time.Second)
		_ = d.singbox.Start()
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "SUB_SYNC",
			RestartResult: "rolled back to previous config",
		})
		return
	}

	singbox.RestoreClashSelections(savedSelections)
	logger.Success("[SubSync] Subscription nodes auto-synced seamlessly (%d -> %d outbounds)", oldCount, newCount)
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "SUB_SYNC",
		RestartResult: fmt.Sprintf("synced %d -> %d outbounds", oldCount, newCount),
	})
}
