package daemon

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/lifecycle"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"
)

const (
	envDaemonized                         = "SINGCTL_DAEMONIZED"
	readyFd                               = 3
	ruleSetRetryCooldown                  = 30 * time.Minute
	p2pDirectEventInterval                = 2 * time.Hour
	defaultAuditSampleInterval            = 15 * time.Second
	defaultAuditThrottleReconcileInterval = 10 * time.Minute
)

type p2pEventGate struct {
	mu       sync.Mutex
	lastSent map[string]time.Time
}

func extractP2PPeerLabel(summary string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(summary), "节点"))
	fields := strings.Fields(trimmed)
	if len(fields) > 0 {
		return fields[0]
	}
	return "default"
}

func (g *p2pEventGate) shouldAppendRuntimeEvent(action, summary string, now time.Time) bool {
	if action != "TS_P2P_DIRECT_OK" {
		return true
	}
	peerKey := extractP2PPeerLabel(summary)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastSent == nil {
		g.lastSent = make(map[string]time.Time)
	}
	if last, ok := g.lastSent[peerKey]; ok && now.Sub(last) < p2pDirectEventInterval {
		return false
	}
	g.lastSent[peerKey] = now
	return true
}

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
	subSyncCheckTimeout time.Duration
	subSyncBinOverride  string
	failoverRunning     atomic.Bool
	failover            *GroupFailoverState
	auditCollector      *audit.Collector
	auditSampling       atomic.Bool
	throttleReconciling atomic.Bool
	p2pCtrl             *tailscale.P2PAssistController
	p2pReconciling      atomic.Bool
	p2pLastActive       atomic.Bool
	p2pSnapMu           sync.Mutex
	p2pLastSnapSummary  string

	// 测试注入钩子（留空回退生产实现，避免单测修改全局状态）
	logPathOverride string
	skipSignalSetup bool
	pidWriter       func() error
	pidRemover      func() error
}

// NewDaemonWithMeta 创建带配置文件路径（支持热重载）与版本号标识的守护进程。
func NewDaemonWithMeta(cfg *config.Config, configPath, version string) *Daemon {
	if cfg == nil {
		cfg = &config.Config{}
	}
	ctx, cancel := context.WithCancel(context.Background())

	limiter := NewRestartLimiterFromState(cfg.Watchdog.MaxRestarts)
	failover := NewGroupFailoverState()
	failover.SingBoxConfigPath = constant.SingBoxConfigFile
	failover.EnableWANGate = true
	failover.ApplyConfig(cfg.EffectiveFailoverConfig())
	failover.RestoreSnapshot(LoadRuntimeSnapshot().ActiveFailovers)

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

	eventGate := &p2pEventGate{}
	p2pCtrl := &tailscale.P2PAssistController{
		BaseCtx: ctx,
		DefaultLANCIDR: func() string {
			s, err := netinfo.GetLANSubnet()
			if err != nil {
				return ""
			}
			return s
		},
		OnEvent: func(action string, healthy bool, summary string) {
			logger.Info("[Tailscale-P2P] %s: %s", action, summary)
			if !eventGate.shouldAppendRuntimeEvent(action, summary, time.Now()) {
				return
			}
			AppendRuntimeEvent(WatchdogEventRecord{
				Action:  action,
				Healthy: healthy,
				Summary: summary,
			})
		},
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
		auditCollector:     audit.NewCollector(cfg),
		p2pCtrl:            p2pCtrl,
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
		d.failover.ApplyConfig(freshCfg.EffectiveFailoverConfig())
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

func (d *Daemon) closeLogFile() {
	d.logMu.Lock()
	if d.logFile != nil {
		_ = d.logFile.Close()
		d.logFile = nil
	}
	d.logMu.Unlock()
}

// buildForegroundLifecycle 构建守护进程前台运行时的三阶段确定性生命周期编排组。
// 当后续阶段初始化失败（如写 PID 失败）时自动按逆序关闭先打开的日志文件，防止句柄泄漏。
func (d *Daemon) buildForegroundLifecycle() *lifecycle.Group {
	pidWrite := d.pidWriter
	if pidWrite == nil {
		pidWrite = WritePidFile
	}
	pidRemove := d.pidRemover
	if pidRemove == nil {
		pidRemove = RemovePidFile
	}

	g := lifecycle.NewGroup()
	g.Add(
		lifecycle.FuncService{
			ServiceName: "daemon-log",
			OnInit: func(context.Context) error {
				return d.setupLogFile()
			},
			OnClose: func() error {
				if d.logPathOverride == "" {
					logger.Info("Daemon stopped")
				}
				d.closeLogFile()
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "pid-file",
			OnInit: func(context.Context) error {
				return pidWrite()
			},
			OnClose: func() error {
				return pidRemove()
			},
		},
		lifecycle.FuncService{
			ServiceName: "runtime-signals",
			OnStart: func(context.Context) error {
				if d.skipSignalSetup {
					return nil
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
				return nil
			},
			OnClose: func() error {
				if d.cancel != nil {
					d.cancel()
				}
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "pcdn-default-sync",
			OnPostStart: func(ctx context.Context) error {
				if d.skipSignalSetup {
					return nil
				}
				go func() {
					select {
					case <-d.ctx.Done():
						return
					case <-ctx.Done():
						return
					case <-time.After(1 * time.Second):
					}
					syncCtx, cancel := context.WithTimeout(d.ctx, 15*time.Second)
					defer cancel()
					if applied, syncErr := audit.NewEnforcer(d.currentConfig(), d.configPath).EnsureDefaultPCDNBlock(syncCtx); syncErr != nil {
						logger.Warn("[Audit] 自动同步内置防 PCDN 规则集失败: %v", syncErr)
					} else if applied {
						logger.Info("[Audit] 已自动启用内置默认防 PCDN 规则集并热重载 sing-box")
					}
				}()
				return nil
			},
		},
	)
	return g
}

// runForeground 子进程主体：通过确定性生命周期编排器初始化并进入监控循环（阻塞）
func (d *Daemon) runForeground() error {
	lc := d.buildForegroundLifecycle()
	if err := lc.Start(d.ctx); err != nil {
		notifyParentReady(false)
		logger.Error("failed to start daemon foreground lifecycle: %v", err)
		return err
	}
	defer func() {
		_ = lc.Close()
	}()

	notifyParentReady(true)

	return d.monitorLoop()
}

// spawn fork 后台子进程并等待就绪信号
func (d *Daemon) spawn() error {
	// Intentional bare exec.Command: detached background daemon child must outlive spawn().
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

func shouldRunP2PAssistTicker(cfg *config.Config, p2pLastActive bool) bool {
	if p2pLastActive {
		return true
	}
	return cfg != nil && cfg.Tailscale.P2PAssist.Enabled
}

func shouldRunThrottleTicker(cfg *config.Config) bool {
	return cfg != nil && len(cfg.Audit.Throttles) > 0
}

// monitorLoop 监控循环
func (d *Daemon) monitorLoop() error {
	cfg := d.currentConfig()
	curWDInterval, curFOInterval := calcIntervals(cfg)

	watchdogTicker := time.NewTicker(curWDInterval)
	failoverTicker := time.NewTicker(curFOInterval)
	p2pAssistTicker := time.NewTicker(3 * time.Second)
	auditSampleTicker := time.NewTicker(defaultAuditSampleInterval)
	throttleReconcileTicker := time.NewTicker(defaultAuditThrottleReconcileInterval)
	initHealthTimer := time.NewTimer(2 * time.Second)
	initFailoverTimer := time.NewTimer(8 * time.Second)
	initRefreshTimer := time.NewTimer(30 * time.Second)

	p2pTickerRunning := true
	throttleTickerRunning := true
	// 空闲休眠优化：未启用 Tailscale P2P 辅助或无内核限速规则时停用对应高频定时器，
	// 避免守护进程每 3 秒无效唤醒；配置热重载开启后通过 Reset() 瞬间恢复。
	syncOptionalTickers := func(curCfg *config.Config) {
		wantP2P := shouldRunP2PAssistTicker(curCfg, d.p2pLastActive.Load())
		if wantP2P && !p2pTickerRunning {
			p2pAssistTicker.Reset(3 * time.Second)
			p2pTickerRunning = true
		} else if !wantP2P && p2pTickerRunning {
			p2pAssistTicker.Stop()
			p2pTickerRunning = false
		}

		wantThrottle := shouldRunThrottleTicker(curCfg)
		if wantThrottle && !throttleTickerRunning {
			throttleReconcileTicker.Reset(defaultAuditThrottleReconcileInterval)
			throttleTickerRunning = true
		} else if !wantThrottle && throttleTickerRunning {
			throttleReconcileTicker.Stop()
			throttleTickerRunning = false
		}
	}
	syncOptionalTickers(cfg)

	defer func() {
		watchdogTicker.Stop()
		failoverTicker.Stop()
		p2pAssistTicker.Stop()
		auditSampleTicker.Stop()
		throttleReconcileTicker.Stop()
		initHealthTimer.Stop()
		initFailoverTimer.Stop()
		initRefreshTimer.Stop()
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
		syncOptionalTickers(latest)
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
			d.maybeReconcileTailscaleP2PAsync(true)
			d.maybeReconcileAuditThrottlesAsync(true)

		case <-initHealthTimer.C:
			res := NewMonitor(d.currentConfig()).CheckHealth()
			d.recordHealthResult(res)
			d.maybeReconcileTailscaleP2PAsync(true)
			d.maybeReconcileAuditThrottlesAsync(true)

		case <-p2pAssistTicker.C:
			d.maybeReconcileTailscaleP2PAsync(false)
			syncOptionalTickers(d.currentConfig())

		case <-auditSampleTicker.C:
			d.maybeSampleDeviceAuditAsync()

		case <-throttleReconcileTicker.C:
			d.maybeReconcileAuditThrottlesAsync(false)

		case <-initFailoverTimer.C:
			applyHotReload(false)
			d.maybePatrolGroupFailoverAsync()

		case <-failoverTicker.C:
			applyHotReload(false)
			d.maybePatrolGroupFailoverAsync()

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
		_ = collector.SampleActiveConnections(ctx)
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
		res, err := d.p2pCtrl.Reconcile(ctx, p2pCfg)
		if err != nil {
			logger.Warn("[Tailscale-P2P] Reconcile error: %v", err)
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
			UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
				snap.TailscaleP2P = &snapCopy
			})
		}
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
		dnsPort := cfg.DNS.GetDNSPort()
		linked, _ := singbox.InspectSingBoxDNSLocal("")
		if err := adguard.NewManager(cfg, d.configPath).EnsureHealthy(); err != nil {
			logger.Warn("[Watchdog] AdGuard Home 自愈启动失败: %v", err)
			if linked {
				logger.Warn("[Watchdog] 触发 DNS 应急降级：将 sing-box dns_local 临时切回内置纯 IP 加密 DoH，保障全屋不断网")
				_, _ = singbox.SyncLiveSingBoxDNSLocal(d.ctx, "", "", false, dnsPort)
			}
		} else if !linked {
			logger.Info("[Watchdog] AdGuard Home 已恢复在线，自动将 sing-box dns_local 切回本地防劫持引擎 (127.0.0.1:%d)", dnsPort)
			_, _ = singbox.SyncLiveSingBoxDNSLocal(d.ctx, "", "", true, dnsPort)
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
	logPath := cmp.Or(d.logPathOverride, GetDaemonLogPath())
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
	if d.logPathOverride == "" {
		logger.SetOutput(logFile)
		logger.SetColor(false)
	}
	d.logMu.Unlock()

	return nil
}

func (d *Daemon) maybeRotateLogFile() {
	for _, sbLog := range []string{constant.SingBoxBasicLogFile, constant.SingBoxSimpleLogFile} {
		if sbLog != "" {
			_, _ = TrimLogInPlace(sbLog, MaxSingBoxLogBytes)
		}
	}
	logPath := cmp.Or(d.logPathOverride, GetDaemonLogPath())
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
	if d.logPathOverride == "" {
		logger.SetOutput(newFile)
	}
	if d.logFile != nil {
		_ = d.logFile.Close()
	}
	d.logFile = newFile
}
