package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

const (
	envDaemonized        = "SINGCTL_DAEMONIZED"
	readyFd              = 3
	ruleSetRetryCooldown = 30 * time.Minute
)

// Daemon 守护进程
type Daemon struct {
	cfgMu               sync.RWMutex
	config              *config.Config
	configPath          string
	cfgModTime          time.Time
	cfgSize             int64
	version             string
	monitor             *Monitor
	limiter             *RestartLimiter
	singbox             *singbox.SingBox
	ctx                 context.Context
	cancel              context.CancelFunc
	logMu               sync.Mutex
	logFile             *os.File
	lifecycleMu         sync.Mutex
	reloading           atomic.Bool
	reloadCh            chan struct{}
	ruleSetRefreshing   atomic.Bool
	ruleSetMu           sync.Mutex
	lastRuleSetFailedAt time.Time
	subSyncRunning      atomic.Bool
	subSyncMu           sync.Mutex
	lastSubSyncCheckAt  time.Time
	failoverRunning     atomic.Bool
	failover            *GroupFailoverState
	auditSampling       atomic.Bool
}

// NewDaemon 创建守护进程
func NewDaemon(cfg *config.Config) *Daemon {
	return NewDaemonWithMeta(cfg, "", "dev")
}

// NewDaemonWithMeta 创建带配置文件路径（支持热重载）与版本号标识的守护进程。
func NewDaemonWithMeta(cfg *config.Config, configPath, version string) *Daemon {
	if cfg == nil {
		cfg = &config.Config{}
	}
	ctx, cancel := context.WithCancel(context.Background())

	limiter := NewRestartLimiterFromState(cfg.Watchdog.MaxRestarts)
	failover := NewGroupFailoverState()
	failover.ApplyConfig(cfg.Watchdog.Failover)

	var modTime time.Time
	var fSize int64
	if configPath != "" {
		if fi, err := os.Stat(configPath); err == nil {
			modTime = fi.ModTime()
			fSize = fi.Size()
		}
	}

	ver := strings.TrimSpace(version)
	if ver == "" {
		ver = "dev"
	}

	return &Daemon{
		config:             cfg,
		configPath:         configPath,
		cfgModTime:         modTime,
		cfgSize:            fSize,
		version:            ver,
		monitor:            NewMonitor(cfg),
		limiter:            limiter,
		singbox:            singbox.New(cfg),
		ctx:                ctx,
		cancel:             cancel,
		reloadCh:           make(chan struct{}, 1),
		lastSubSyncCheckAt: time.Now(), // 启动时配置已是最新或刚校验，等待首个周期后再静默比对
		failover:           failover,
	}
}

// currentConfig 获取最新配置（若磁盘上 singctl.yaml 已变更则自动热重载）。
func (d *Daemon) currentConfig() *config.Config {
	_, cfg := d.reloadConfigIfChanged(false)
	return cfg
}

// reloadConfigIfChanged 检测磁盘 singctl.yaml 指纹（或 force=true 时强制重载）并热更新内存组件。
func (d *Daemon) reloadConfigIfChanged(force bool) (bool, *config.Config) {
	d.cfgMu.RLock()
	path := d.configPath
	oldMod := d.cfgModTime
	oldSize := d.cfgSize
	curCfg := d.config
	d.cfgMu.RUnlock()

	if path == "" {
		return false, curCfg
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false, curCfg
	}
	if !force && fi.ModTime().Equal(oldMod) && fi.Size() == oldSize {
		return false, curCfg
	}

	freshCfg, err := config.Load(path)
	if err != nil {
		logger.Warn("[Watchdog] Hot-reload config failed (keeping active config): %v", err)
		return false, curCfg
	}

	d.cfgMu.Lock()
	d.config = freshCfg
	d.cfgModTime = fi.ModTime()
	d.cfgSize = fi.Size()
	d.monitor = NewMonitor(freshCfg)
	d.singbox = singbox.New(freshCfg)
	d.cfgMu.Unlock()

	d.limiter.SetMaxRestarts(freshCfg.Watchdog.MaxRestarts)
	if d.failover != nil {
		d.failover.ApplyConfig(freshCfg.Watchdog.Failover)
	}
	return true, freshCfg
}

// Start 启动守护进程。
func (d *Daemon) Start() error {
	if os.Getenv(envDaemonized) == "1" {
		return d.runForeground()
	}

	if err := AcquirePidLock(); err != nil {
		if errors.Is(err, ErrDaemonAlreadyRunning) {
			logger.Error("daemon already running")
		}
		return err
	}

	return d.spawn()
}

// runForeground 子进程主体：初始化并进入监控循环（阻塞）
func (d *Daemon) runForeground() error {
	if err := d.setupLogFile(); err != nil {
		notifyParentReady(false)
		logger.Error("failed to setup log file: %v", err)
		return fmt.Errorf("failed to setup log file: %w", err)
	}

	if err := WritePidFile(); err != nil {
		notifyParentReady(false)
		logger.Error("failed to write pid file: %v", err)
		return fmt.Errorf("failed to write pid file: %w", err)
	}

	d.setupSignalHandler()
	installReloadSignal(func() {
		select {
		case d.reloadCh <- struct{}{}:
		default:
		}
	})

	cfg := d.currentConfig()
	startedAt := time.Now().Format(time.DateTime)
	ver := d.version
	UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
		snap.DaemonVersion = ver
		snap.StartedAt = startedAt
	})

	logger.Success("Daemon started successfully (version=%s, pid=%d, check every %ds)", ver, os.Getpid(), cfg.Watchdog.Interval)

	notifyParentReady(true)

	return d.monitorLoop()
}

// spawn fork 后台子进程并等待就绪信号
func (d *Daemon) spawn() error {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), envDaemonized+"=1")

	d.setProcAttrs(cmd)

	devNull := "/dev/null"
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	nullFile, err := os.OpenFile(devNull, os.O_RDWR, 0)
	if err != nil {
		_ = RemovePidFile()
		return err
	}
	defer nullFile.Close()

	cmd.Stdin = nullFile
	cmd.Stdout = nullFile
	cmd.Stderr = nullFile

	var readyR *os.File
	if runtime.GOOS != "windows" {
		var readyW *os.File
		readyR, readyW, err = os.Pipe()
		if err == nil {
			cmd.ExtraFiles = []*os.File{readyW}
		}
	}

	if err := cmd.Start(); err != nil {
		logger.Error("failed to daemonize: %v", err)
		_ = RemovePidFile()
		return fmt.Errorf("failed to daemonize: %w", err)
	}

	if readyR == nil {
		logger.Success("Daemon started in background (pid=%d)", cmd.Process.Pid)
		return nil
	}

	if extra := cmd.ExtraFiles; len(extra) > 0 {
		_ = extra[0].Close()
	}

	err = waitReady(readyR, 10*time.Second)
	_ = readyR.Close()
	switch {
	case err == nil:
		logger.Success("Daemon started in background (pid=%d)", cmd.Process.Pid)
		return nil
	case errors.Is(err, errChildDied):
		_ = RemovePidFile()
		logger.Error("daemon child exited during startup")
		return err
	default:
		logger.Warn("daemon startup not confirmed within timeout; check %s", GetDaemonLogPath())
		return nil
	}
}

var errChildDied = errors.New("daemon child exited during startup")

func waitReady(r *os.File, timeout time.Duration) error {
	ch := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		n, err := r.Read(buf)
		switch {
		case n > 0 && buf[0] == 1:
			ch <- nil
		case n > 0:
			ch <- fmt.Errorf("unexpected ready signal: %d", buf[0])
		case err != nil:
			ch <- errChildDied
		default:
			ch <- errChildDied
		}
	}()

	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for daemon ready signal")
	}
}

func notifyParentReady(ok bool) {
	if runtime.GOOS == "windows" {
		return
	}
	f := os.NewFile(readyFd, "ready-pipe")
	if f == nil {
		return
	}
	b := []byte{0}
	if ok {
		b[0] = 1
	}
	_, _ = f.Write(b)
	_ = f.Close()
}

// Stop 停止守护进程
func (d *Daemon) Stop() error {
	return StopDaemon()
}

// Status 获取守护进程状态
func (d *Daemon) Status() MonitorStatus {
	return d.monitor.GetStatus()
}

func (d *Daemon) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		logger.Info("Received signal %v, shutting down daemon...", sig)
		d.cancel()
	}()
}

func calcIntervals(cfg *config.Config) (time.Duration, time.Duration) {
	wdInt := 3 * time.Minute
	foInt := defaultGroupFailoverInterval
	if cfg != nil {
		if cfg.Watchdog.Interval > 0 {
			wdInt = time.Duration(max(15, cfg.Watchdog.Interval)) * time.Second
		}
		foInt = cfg.Watchdog.Failover.EffectivePatrolInterval()
	}
	return wdInt, foInt
}

// monitorLoop 监控循环
func (d *Daemon) monitorLoop() error {
	cfg := d.currentConfig()
	curWDInterval, curFOInterval := calcIntervals(cfg)

	watchdogTicker := time.NewTicker(curWDInterval)
	failoverTicker := time.NewTicker(curFOInterval)
	initHealthTimer := time.NewTimer(2 * time.Second)
	initFailoverTimer := time.NewTimer(8 * time.Second)
	initRefreshTimer := time.NewTimer(30 * time.Second)

	defer func() {
		watchdogTicker.Stop()
		failoverTicker.Stop()
		initHealthTimer.Stop()
		initFailoverTimer.Stop()
		initRefreshTimer.Stop()
		logger.Info("Daemon stopped")
		RemovePidFile()
		d.logMu.Lock()
		if d.logFile != nil {
			_ = d.logFile.Close()
			d.logFile = nil
		}
		d.logMu.Unlock()
	}()

	logger.Info("Daemon watchdog started (check interval: %s, group failover: %v / %s)",
		curWDInterval, cfg.Watchdog.Failover.IsEnabled(), curFOInterval)

	applyHotReload := func(force bool) {
		reloaded, latest := d.reloadConfigIfChanged(force)
		if !reloaded || latest == nil {
			return
		}
		newWD, newFO := calcIntervals(latest)
		if newWD != curWDInterval {
			curWDInterval = newWD
			watchdogTicker.Reset(curWDInterval)
		}
		if newFO != curFOInterval {
			curFOInterval = newFO
			failoverTicker.Reset(curFOInterval)
		}
		if !latest.Watchdog.Failover.IsEnabled() {
			UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
				snap.ActiveFailovers = nil
			})
		}
		logger.Info("[Watchdog] Config hot-reloaded (interval=%s, failover=%v/%s, sub_sync=%ds)",
			curWDInterval, latest.Watchdog.Failover.IsEnabled(), curFOInterval, latest.Watchdog.SubSyncInterval)
	}

	for {
		select {
		case <-d.ctx.Done():
			return nil

		case <-d.reloadCh:
			applyHotReload(true)
			d.maybePatrolGroupFailoverAsync()

		case <-initHealthTimer.C:
			res := NewMonitor(d.currentConfig()).CheckHealth()
			d.recordHealthResult(res)

		case <-initFailoverTimer.C:
			applyHotReload(false)
			d.maybePatrolGroupFailoverAsync()

		case <-failoverTicker.C:
			applyHotReload(false)
			d.maybePatrolGroupFailoverAsync()
			d.maybeSampleDeviceAuditAsync()

		case <-initRefreshTimer.C:
			if NewMonitor(d.currentConfig()).CheckHealth().Healthy {
				d.maybeRefreshRuleSetsAsync()
			}

		case <-watchdogTicker.C:
			applyHotReload(false)
			d.maybeRotateLogFile()
			d.runWatchdogCheck()
		}
	}
}

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
	go func() {
		defer d.auditSampling.Store(false)
		ctx, cancel := context.WithTimeout(d.ctx, 4*time.Second)
		defer cancel()
		_ = audit.NewCollector(cfg).Collect(ctx, audit.CollectOptions{Limit: 10})
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

// runWatchdogCheck 健康检查：先确保本地 AdGuard Home 在线，再探测 sing-box 健康，不健康则二次确认后重启。
func (d *Daemon) runWatchdogCheck() {
	if d.reloading.Load() {
		return
	}
	cfg := d.currentConfig()
	if runtime.GOOS == "linux" && cfg != nil && cfg.DNS.IsEnabled() && adguard.IsInstalled() {
		if err := adguard.NewManager(cfg, d.configPath).EnsureHealthy(); err != nil {
			logger.Warn("[Watchdog] AdGuard Home 自愈启动失败: %v", err)
		}
	}

	mon := NewMonitor(cfg)
	result1 := mon.CheckHealth()
	d.recordHealthResult(result1)
	if result1.Healthy {
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

func (d *Daemon) setupLogFile() error {
	logPath := GetDaemonLogPath()
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	_, _ = CleanAndTrimDaemonLog(logPath, MaxDaemonLogBytes)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	_ = logFile.Chmod(0600)

	d.logMu.Lock()
	d.logFile = logFile
	logger.SetOutput(logFile)
	logger.SetColor(false)
	d.logMu.Unlock()

	return nil
}

func (d *Daemon) maybeRotateLogFile() {
	logPath := GetDaemonLogPath()
	trimmed, err := CleanAndTrimDaemonLog(logPath, MaxDaemonLogBytes)
	if err != nil || !trimmed {
		return
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	newFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	_ = newFile.Chmod(0600)
	logger.SetOutput(newFile)
	if d.logFile != nil {
		_ = d.logFile.Close()
	}
	d.logFile = newFile
}
