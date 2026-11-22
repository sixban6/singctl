// 文件职责：实现客户端看门狗守护进程核心编排（生命周期托管、配置热重载与多维轮询调度循环）。
package daemon

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/lifecycle"
	"singctl/internal/logger"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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
	cfgStore            *config.Store
	configPath          string
	version             string
	limiter             *RestartLimiter
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

	cfgStore := config.NewStore(
		configPath,
		config.WithInitialConfig(cfg),
		config.WithLoader(func(p string) (*config.Config, error) {
			loaded, err := config.Load(p)
			if err != nil {
				logger.Warn("[Watchdog] Hot-reload config failed (keeping active config): %v", err)
			}
			return loaded, err
		}),
	)

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
		cfgStore:           cfgStore,
		configPath:         configPath,
		version:            ver,
		limiter:            limiter,
		ctx:                ctx,
		cancel:             cancel,
		reloadCh:           make(chan struct{}, 1),
		lastSubSyncCheckAt: time.Now(),
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
	if d.cfgStore == nil {
		return false, &config.Config{}
	}
	reloaded, freshCfg := d.cfgStore.ReloadIfChanged(force)
	if !reloaded || freshCfg == nil {
		return false, freshCfg
	}
	if d.limiter != nil {
		d.limiter.SetMaxRestarts(freshCfg.Watchdog.MaxRestarts)
	}
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

// buildForegroundLifecycle 构建守护进程前台运行时的三阶段确定性生命周期编排组。
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
