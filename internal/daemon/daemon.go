// 文件职责：实现客户端看门狗守护进程核心编排（生命周期托管、配置热重载与多维轮询调度循环）。
package daemon

import (
	"cmp"
	"context"
	"errors"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"singctl/internal/audit"
	"singctl/internal/common/netx"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/lifecycle"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/notify"
	"singctl/internal/safecommit"
	"singctl/internal/smartdns"
	"singctl/internal/tailscale"
)

const (
	envDaemonized                         = "SINGCTL_DAEMONIZED"
	readyFd                               = 3
	ruleSetRetryCooldown                  = 30 * time.Minute
	p2pDirectEventInterval                = 2 * time.Hour
	defaultAuditSampleInterval            = 15 * time.Second
	defaultAuditThrottleReconcileInterval = 10 * time.Minute
)

// P2PEventGate 对高频重复的 TS_P2P_DIRECT_OK 成功事件按节点执行时间窗去重，保留告警与手动测试事件。
type P2PEventGate struct {
	mu       sync.Mutex
	lastSent map[string]time.Time
}

// NewP2PEventGate 创建 P2P 事件节流门控实例。
func NewP2PEventGate() *P2PEventGate {
	return &P2PEventGate{lastSent: make(map[string]time.Time)}
}

func extractP2PPeerLabel(summary string) string {
	trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(summary), "节点"))
	fields := strings.Fields(trimmed)
	if len(fields) > 0 {
		return fields[0]
	}
	return "default"
}

// ShouldAppendRuntimeEvent 判断该 P2P 事件是否应追加至状态快照时间线。
func (g *P2PEventGate) ShouldAppendRuntimeEvent(action, summary string, now time.Time) bool {
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

// DaemonOptions 显式配置守护进程的运行参数与测试注入替身（无需篡改包级全局变量）。
type DaemonOptions struct {
	ConfigPath          string
	Version             string
	Paths               Paths
	SkipSignalSetup     bool
	PidWriter           func() error
	PidRemover          func() error
	SubSyncCheckTimeout time.Duration
	SubSyncBinOverride  string
	EmbeddedService     func(ctx context.Context, cfgStore *config.Store) error
	WebEmbeddedListen   string
	LowMemoryMode       *bool
	P2PController       *tailscale.P2PAssistController
	DNSDeps             *localdns.EngineDeps
	NotifyDispatcher    *notify.Dispatcher
	NotifyDeps          notify.DispatcherDeps
	TelemetryDeps       *sysinfo.TelemetryDeps
	OOMProcRoot         string
	ProtectOOMFunc      func(procRoot string) (safecommit.OOMShieldStatus, error)
}

// Daemon 守护进程。
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
	subSyncFailed       atomic.Bool
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
	p2pSnapMu             sync.Mutex
	p2pLastSnapSummary    string
	homeDomainWorker      *HomeDomainWorker
	homeDomainReconciling atomic.Bool

	logPathOverride     string
	webLogOverride      string
	webEmbeddedFile     string
	webEmbeddedMu       sync.Mutex
	webEmbeddedListen   string
	embeddedService     func(ctx context.Context, cfgStore *config.Store) error
	lowMemory           bool
	stateStore          *StateStore
	skipSignalSetup     bool
	pidWriter           func() error
	pidRemover          func() error
	dnsDeps             *localdns.EngineDeps
	dnsSmartStats       *localdns.StatsRing
	smartDNSTailer      *smartdns.AuditLogTailer
	dnsTickRunning      atomic.Bool
	notifier            *notify.Dispatcher
	ownsNotifier        bool
	cpuSampler          *sysinfo.CPUSampler
	telemetryDeps       *sysinfo.TelemetryDeps
	resourceGuard       *resourceGuardState
	auditGuard          *auditNotifyGuard
	watchdogUnhealthy   atomic.Bool
	oomProcRoot         string
	protectOOMFn        func(procRoot string) (safecommit.OOMShieldStatus, error)
	oomGuardMu          sync.Mutex
	lastOOMProtectedPID int
}

// NewDaemonWithMeta 创建带配置文件路径（支持热重载）与版本号标识的守护进程。
func NewDaemonWithMeta(cfg *config.Config, configPath, version string) *Daemon {
	return NewDaemonWithOptions(cfg, DaemonOptions{
		ConfigPath: configPath,
		Version:    version,
	})
}

// NewDaemonWithOptions 使用显式选项创建守护进程实例。
func NewDaemonWithOptions(cfg *config.Config, opts DaemonOptions) *Daemon {
	if cfg == nil {
		cfg = &config.Config{}
	}
	ctx, cancel := context.WithCancel(context.Background())

	var stateStore *StateStore
	if strings.TrimSpace(opts.Paths.StateFile) != "" || strings.TrimSpace(opts.Paths.LogFile) != "" || strings.TrimSpace(opts.Paths.PidFile) != "" {
		stateStore = NewStateStore(opts.Paths)
	} else {
		stateStore = defaultStateStore
	}

	lowMem := IsLowMemoryDevice() || opts.EmbeddedService != nil
	if opts.LowMemoryMode != nil {
		lowMem = *opts.LowMemoryMode
	}

	limiter := NewRestartLimiterFromState(cfg.Watchdog.MaxRestarts)
	failover := NewGroupFailoverState()
	failover.SingBoxConfigPath = constant.SingBoxConfigFile
	failover.EnableWANGate = true
	failover.ApplyConfig(cfg.EffectiveFailoverConfig())
	failover.RestoreSnapshot(stateStore.Load().ActiveFailovers)

	cfgStore := config.NewStore(
		opts.ConfigPath,
		config.WithInitialConfig(cfg),
		config.WithLoader(func(p string) (*config.Config, error) {
			loaded, err := config.Load(p)
			if err != nil {
				logger.Warn("[Watchdog] Hot-reload config failed (keeping active config): %v", err)
			}
			return loaded, err
		}),
	)

	ver := cmp.Or(strings.TrimSpace(opts.Version), "dev")
	p2pCtrl := opts.P2PController
	if p2pCtrl == nil {
		eventGate := NewP2PEventGate()
		p2pCtrl = &tailscale.P2PAssistController{
			BaseCtx: ctx,
			DefaultLANCIDR: func() string {
				s, err := netx.GetLANSubnet()
				if err != nil {
					return ""
				}
				return s
			},
			OnEvent: func(action string, healthy bool, summary string) {
				logger.Info("[Tailscale-P2P] %s: %s", action, summary)
				if !eventGate.ShouldAppendRuntimeEvent(action, summary, time.Now()) {
					return
				}
				stateStore.AppendEvent(WatchdogEventRecord{
					Action:  action,
					Healthy: healthy,
					Summary: summary,
				})
			},
		}
	}

	auditLogPath := constant.SmartDNSAuditLogPath
	if opts.DNSDeps != nil && strings.TrimSpace(opts.DNSDeps.SmartDNSAuditLogPath) != "" {
		auditLogPath = strings.TrimSpace(opts.DNSDeps.SmartDNSAuditLogPath)
	}
	sdStats := localdns.NewStatsRing(lowMem)
	sdTailer := smartdns.NewAuditLogTailer(auditLogPath)
	if opts.DNSDeps != nil {
		if opts.DNSDeps.SmartDNSStats != nil {
			sdStats = opts.DNSDeps.SmartDNSStats
		}
		if opts.DNSDeps.SmartDNSTailer != nil {
			sdTailer = opts.DNSDeps.SmartDNSTailer
		}
	}

	notifier := opts.NotifyDispatcher
	ownsNotifier := false
	if notifier == nil {
		notifier = notify.NewDispatcher(notify.OptionsFromConfig(cfg.Notify), opts.NotifyDeps)
		ownsNotifier = true
	}
	cpuSampler := sysinfo.NewCPUSampler()
	cpuSampler.Prime()

	d := &Daemon{
		cfgStore:            cfgStore,
		configPath:          opts.ConfigPath,
		version:             ver,
		limiter:             limiter,
		ctx:                 ctx,
		cancel:              cancel,
		reloadCh:            make(chan struct{}, 1),
		lastSubSyncCheckAt:  time.Now(),
		subSyncCheckTimeout: opts.SubSyncCheckTimeout,
		subSyncBinOverride:  opts.SubSyncBinOverride,
		failover:            failover,
		auditCollector:      audit.NewCollectorWithOptions(cfg, audit.CollectorOptions{LowMemory: &lowMem}),
		p2pCtrl:             p2pCtrl,
		logPathOverride:     strings.TrimSpace(opts.Paths.LogFile),
		webLogOverride:      strings.TrimSpace(opts.Paths.WebLogFile),
		webEmbeddedFile:     strings.TrimSpace(opts.Paths.WebEmbeddedFile),
		webEmbeddedListen:   strings.TrimSpace(opts.WebEmbeddedListen),
		embeddedService:     opts.EmbeddedService,
		lowMemory:           lowMem,
		stateStore:          stateStore,
		skipSignalSetup:     opts.SkipSignalSetup,
		pidWriter:           opts.PidWriter,
		pidRemover:          opts.PidRemover,
		dnsDeps:             opts.DNSDeps,
		dnsSmartStats:       sdStats,
		smartDNSTailer:      sdTailer,
		notifier:            notifier,
		ownsNotifier:        ownsNotifier,
		cpuSampler:          cpuSampler,
		telemetryDeps:       opts.TelemetryDeps,
		resourceGuard:       &resourceGuardState{},
		auditGuard:          newAuditNotifyGuard(),
		oomProcRoot:         strings.TrimSpace(opts.OOMProcRoot),
		protectOOMFn:        opts.ProtectOOMFunc,
	}
	failover.OnNotify = d.emitNotify
	return d
}

// SmartDNSStatsRing 返回守护进程持有的 SmartDNS 24h 审计统计环（供单进程合体 WebUI 共享）。
func (d *Daemon) SmartDNSStatsRing() *localdns.StatsRing {
	if d == nil {
		return nil
	}
	return d.dnsSmartStats
}

// SmartDNSTailer 返回守护进程持有的 SmartDNS 审计日志增量追踪器（供单进程合体 WebUI 共享）。
func (d *Daemon) SmartDNSTailer() *smartdns.AuditLogTailer {
	if d == nil {
		return nil
	}
	return d.smartDNSTailer
}

// HasOpenLogFile 返回当前守护实例是否持有已打开的日志文件句柄。
func (d *Daemon) HasOpenLogFile() bool {
	if d == nil {
		return false
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	return d.logFile != nil
}

// ConfigStore 返回守护进程持有的只读不可变配置快照仓库。
func (d *Daemon) ConfigStore() *config.Store {
	if d == nil {
		return nil
	}
	return d.cfgStore
}

// AuditCollector 返回守护进程持有的设备行为审计采集器实例。
func (d *Daemon) AuditCollector() *audit.Collector {
	if d == nil {
		return nil
	}
	return d.auditCollector
}

func (d *Daemon) effectiveStateStore() *StateStore {
	if d != nil && d.stateStore != nil {
		return d.stateStore
	}
	return defaultStateStore
}

func (d *Daemon) effectiveWebEmbeddedPath() string {
	if d == nil {
		return GetWebEmbeddedPath()
	}
	return cmp.Or(d.webEmbeddedFile, GetWebEmbeddedPath())
}

// RecordWebEmbeddedListen 记录并广播内嵌 WebUI 实际绑定的监听地址到状态快照与标记文件。
func (d *Daemon) RecordWebEmbeddedListen(listen string) {
	if d == nil {
		return
	}
	clean := strings.TrimSpace(listen)
	if clean == "" {
		return
	}
	d.webEmbeddedMu.Lock()
	d.webEmbeddedListen = clean
	embPath := d.effectiveWebEmbeddedPath()
	cfgPath := d.configPath
	d.webEmbeddedMu.Unlock()

	_ = WriteWebEmbeddedStateAt(embPath, WebEmbeddedState{
		Pid:        os.Getpid(),
		Listen:     clean,
		ConfigPath: cfgPath,
		StartedAt:  time.Now().Format(time.DateTime),
	})
	d.effectiveStateStore().Update(func(snap *DaemonRuntimeSnapshot) {
		snap.WebEmbedded = true
		snap.WebEmbeddedListen = clean
	})
}

func (d *Daemon) clearWebEmbeddedState() {
	if d == nil {
		return
	}
	d.webEmbeddedMu.Lock()
	embPath := d.effectiveWebEmbeddedPath()
	d.webEmbeddedMu.Unlock()

	_ = RemoveWebEmbeddedFileAt(embPath)
	d.effectiveStateStore().Update(func(snap *DaemonRuntimeSnapshot) {
		snap.WebEmbedded = false
		snap.WebEmbeddedListen = ""
	})
}

// RotateLogsNow 立即执行一次守护日志与关联日志截断维护（供巡检与单测驱动）。
func (d *Daemon) RotateLogsNow() {
	if d == nil {
		return
	}
	d.maybeRotateLogFile()
}

func (d *Daemon) currentConfig() *config.Config {
	_, cfg := d.reloadConfigIfChanged(false)
	return cfg
}

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
	if d.p2pCtrl != nil {
		d.p2pCtrl.ResetNFTUnavailableBackoff()
	}
	d.syncNotifierConfig(freshCfg)
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

// BuildForegroundLifecycle 构建守护进程前台运行时的三阶段确定性生命周期编排组。
func (d *Daemon) BuildForegroundLifecycle() *lifecycle.Group {
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
				d.effectiveStateStore().Update(func(snap *DaemonRuntimeSnapshot) {
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
			ServiceName: "daemon-notifier",
			OnStart: func(context.Context) error {
				if d.notifier != nil && d.ownsNotifier {
					d.notifier.Start(d.ctx)
				}
				return nil
			},
			OnClose: func() error {
				if d.notifier != nil && d.ownsNotifier {
					d.notifier.Close()
				}
				return nil
			},
		},
	)

	if d.embeddedService != nil {
		var (
			embCancel    context.CancelFunc
			embStopAfter func() bool
			embDone      chan struct{}
		)
		g.Add(lifecycle.FuncService{
			ServiceName: "embedded-webui",
			OnStart: func(startCtx context.Context) error {
				svcCtx, cancel := context.WithCancel(d.ctx)
				embCancel = cancel
				if startCtx != nil {
					embStopAfter = context.AfterFunc(startCtx, cancel)
				}
				embDone = make(chan struct{})
				d.webEmbeddedMu.Lock()
				initListen := d.webEmbeddedListen
				d.webEmbeddedMu.Unlock()
				if initListen != "" {
					d.RecordWebEmbeddedListen(initListen)
				}
				svcFn := d.embeddedService
				store := d.cfgStore
				go func() {
					defer close(embDone)
					if err := svcFn(svcCtx, store); err != nil && svcCtx.Err() == nil {
						logger.Warn("[Daemon] Embedded service exited with error: %v", err)
						d.clearWebEmbeddedState()
					}
				}()
				return nil
			},
			OnClose: func() error {
				if embStopAfter != nil {
					embStopAfter()
				}
				if embCancel != nil {
					embCancel()
				}
				if embDone != nil {
					select {
					case <-embDone:
					case <-time.After(4 * time.Second):
					}
				}
				d.clearWebEmbeddedState()
				return nil
			},
		})
	}

	g.Add(
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
		lifecycle.FuncService{
			ServiceName: "lowmem-host-tune",
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
					case <-time.After(3 * time.Second):
					}
					tuneCtx, cancel := context.WithTimeout(d.ctx, 15*time.Second)
					defer cancel()
					ReconcileLowMemHostDefault(tuneCtx, d.embeddedService != nil)
				}()
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "home-domain-dns",
			OnStart: func(startCtx context.Context) error {
				if d.skipSignalSetup {
					return nil
				}
				worker := d.ensureHomeDomainWorker()
				go func() {
					// 首次延迟 1 秒启动，待 Tailscale/dnsmasq 稳定后立即拉起 Split-DNS 应答器并每 60 秒巡检 DHCP 变更与网卡重绑
					select {
					case <-d.ctx.Done():
						return
					case <-time.After(1 * time.Second):
					}
					rCtx, cancel := context.WithTimeout(d.ctx, 12*time.Second)
					_ = worker.Reconcile(rCtx, d.currentConfig())
					cancel()

					ticker := time.NewTicker(60 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-d.ctx.Done():
							return
						case <-ticker.C:
							tCtx, tCancel := context.WithTimeout(d.ctx, 12*time.Second)
							worker.ReconcileDHCP(tCtx)
							_ = worker.Reconcile(tCtx, d.currentConfig())
							tCancel()
						}
					}
				}()
				return nil
			},
			OnClose: func() error {
				if d.homeDomainWorker != nil {
					return d.homeDomainWorker.Close()
				}
				return nil
			},
		},
	)
	return g
}

func (d *Daemon) runForeground() error {
	lc := d.BuildForegroundLifecycle()
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
	return p2pLastActive || (cfg != nil && cfg.Tailscale.P2PAssist.Enabled)
}

func shouldRunThrottleTicker(cfg *config.Config) bool {
	return cfg != nil && len(cfg.Audit.Throttles) > 0
}

type optionalTickerState struct {
	p2pTicker      *time.Ticker
	throttleTicker *time.Ticker
	p2pRunning     bool
	throtRunning   bool
}

func (ts *optionalTickerState) sync(cfg *config.Config, p2pLastActive bool) {
	wantP2P := shouldRunP2PAssistTicker(cfg, p2pLastActive)
	if wantP2P && !ts.p2pRunning {
		ts.p2pTicker.Reset(3 * time.Second)
		ts.p2pRunning = true
	} else if !wantP2P && ts.p2pRunning {
		ts.p2pTicker.Stop()
		ts.p2pRunning = false
	}

	wantThrottle := shouldRunThrottleTicker(cfg)
	if wantThrottle && !ts.throtRunning {
		ts.throttleTicker.Reset(defaultAuditThrottleReconcileInterval)
		ts.throtRunning = true
	} else if !wantThrottle && ts.throtRunning {
		ts.throttleTicker.Stop()
		ts.throtRunning = false
	}
}

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

	optTickers := &optionalTickerState{
		p2pTicker:      p2pAssistTicker,
		throttleTicker: throttleReconcileTicker,
		p2pRunning:     true,
		throtRunning:   true,
	}
	optTickers.sync(cfg, d.p2pLastActive.Load())

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
		optTickers.sync(latest, d.p2pLastActive.Load())
		logger.Info("[Watchdog] Config hot-reloaded (interval=%s, failover=%v/%s, sub_sync=%ds)",
			curWDInterval, latest.Watchdog.Failover.IsEnabled(), curFOInterval, latest.Watchdog.SubSyncInterval)
	}

	for {
		select {
		case <-d.ctx.Done():
			return nil
		case <-d.reloadCh:
			applyHotReload(true)
			if d.p2pCtrl != nil {
				d.p2pCtrl.ResetNFTUnavailableBackoff()
			}
			d.maybePatrolGroupFailoverAsync()
			d.maybeReconcileTailscaleP2PAsync(true)
			d.maybeReconcileAuditThrottlesAsync(true)
			d.reconcileHomeDomainAsync()
		case <-initHealthTimer.C:
			d.GuardTailscaleOOMOnce()
			res := NewMonitor(d.currentConfig()).CheckHealth()
			d.recordHealthResult(res)
			d.maybeReconcileTailscaleP2PAsync(true)
			d.maybeReconcileAuditThrottlesAsync(true)
		case <-p2pAssistTicker.C:
			d.maybeReconcileTailscaleP2PAsync(false)
			optTickers.sync(d.currentConfig(), d.p2pLastActive.Load())
		case <-auditSampleTicker.C:
			d.maybeSampleDeviceAuditAsync()
			d.maybeTickLocalDNSAuditAndExpiryAsync()
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
