// 文件职责：组装服务端 Web 管理面板薄控制面、66 条 HTTP 路由注册、确定性三阶段生命周期与领域协作者显式注入。
package serverweb

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/common/httpx"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/fleet"
	"singctl/internal/heal"
	"singctl/internal/lifecycle"
	"singctl/internal/logger"
	"singctl/internal/sniff"
	"singctl/internal/subhub"
	"singctl/internal/telemetry"
)

const sessionCookieName = "singctl_server_session"

// Options 服务端 Web 界面配置。
type Options struct {
	ConfigPath        string
	ConfigStore       *config.Store // (可选) 外部注入的配置快照仓库；为空时自动按 ConfigPath 创建
	SingBoxConfigPath string        // (可选) sing-box 配置文件路径，默认 /etc/sing-box/config.json
	SubStoreDir       string        // (可选) SubHub 数据存储目录，默认 /etc/sub-store
	FleetFilePath     string        // (可选) 节点舰队存储文件路径，默认 <ConfigDir>/fleet.yaml
	BanFilePath       string        // (可选) 防爆破封禁列表存储文件 (默认: <ConfigDir>/.serverweb_bans.json)
	AuditFilePath     string        // (可选) 管理操作审计日志存储文件 (默认: <ConfigDir>/.serverweb_audit.json)
	Listen            string
	Username          string
	Password          string
	Version           string
	OnReady           func(listenAddr string)
}

// Deps 定义控制面测试可替换协作者依赖（未设置字段自动回退生产默认实现）。
type Deps struct {
	CmdRunner          execx.Runner
	ServiceConfigPaths map[string]string
	SingBoxBin         string
	ConfigLoader       func(string) (*config.Config, error)
	StatusProber       func() map[string]ServiceProbeSnapshot
	HealScanner        func(ctx context.Context, configPath, currentVer string) heal.StatusReport
	WarpApplyDeps      *deploy.LiveWarpApplyDeps
	WarpDaemonProbe    func(forceRefresh bool) WarpDaemonStatus
	WarpPortChecker    func() bool
	WarpExitFetcher    func(timeout time.Duration) (ip, loc, traceRaw string, ok bool)
	WarpRotateIdentity func(previousIP string) (string, string, error)
	WarpWatchdogDeps   *WarpWatchdogDeps
}

// SessionRecord 记录管理员会话创建时间与最后活跃时间。
type SessionRecord struct {
	Created time.Time
	Last    time.Time
}

const (
	sessionIdleTTL     = 2 * time.Hour
	sessionAbsoluteTTL = 12 * time.Hour
	MaxActiveSessions  = 50
)

// Server 服务端 Web 薄控制面实例（状态与锁按子职责内聚下沉至各领域协作者）。
type Server struct {
	opts               Options
	Mux                *http.ServeMux
	cfgStore           *config.Store
	subStore           *subhub.Store
	telemetry          *telemetry.Collector
	fleet              *fleet.Manager
	limiter            *IPLimiter
	audit              *AuditManager
	geo                *IPGeoResolver
	sniff              *SniffTracker
	warp               *warpRuntime
	caches             *statusCaches
	deps               Deps
	cliToken           string
	mu                 sync.RWMutex
	passwordPendingAck bool
	gatewayToken       string
	SessionsMu         sync.Mutex
	Sessions           map[string]SessionRecord
}

// New 创建服务端 Web 实例并完成领域协作者装配与路由注册。
func New(opts Options) *Server {
	pendingAck := false
	gatewayToken := ""
	var initialCfg *config.Config
	if opts.ConfigPath != "" {
		if cfg, err := config.Load(opts.ConfigPath); err == nil && cfg != nil {
			if cfg.Server.EnsureWebAdminCredentials() {
				_ = config.Save(opts.ConfigPath, cfg)
			}
			initialCfg = cfg
			if opts.Username == "" {
				opts.Username = cfg.Server.GetWebAdminUsername()
			}
			if opts.Password == "" {
				opts.Password = cfg.Server.GetWebAdminPassword()
			}
			if opts.Listen == "" || opts.Listen == DefaultListenAddr {
				opts.Listen = fmt.Sprintf("127.0.0.1:%d", cfg.Server.GetWebAdminPort())
			}
			pendingAck = cfg.Server.WebAdmin.PasswordPendingAck
			gatewayToken = config.DeriveGatewayToken(cfg.Server.GetWebAdminPath())
		}
	}
	if opts.Listen == "" {
		opts.Listen = DefaultListenAddr
	}
	if opts.Username == "" {
		opts.Username = "singctl"
	}

	banFile := resolveBanFilePath(opts)
	if banFile != "" {
		CleanupStaleServerWebTmpFiles(filepath.Dir(banFile))
	}
	auditFile := resolveAuditFilePath(opts)
	cliToken := ensureCLIToken(ResolveCLITokenPath(opts.ConfigPath))

	subStore := subhub.NewStore(opts.SubStoreDir, "")
	fleetFile := opts.FleetFilePath
	if fleetFile == "" {
		fleetFile = fleet.ResolveFleetFilePath(opts.ConfigPath)
	}
	fleetStore := fleet.NewStore(fleetFile)
	fleetMgr := fleet.NewManager(fleetStore, subStore)
	if opts.ConfigPath != "" {
		fleetMgr.ConfigPath = opts.ConfigPath
	}

	limiter := NewIPLimiter(3, 10*time.Minute, 15*time.Minute, banFile)
	geo := NewIPGeoResolver(resolveGeoFilePath(opts))
	sniffTracker := NewSniffTracker(geo, limiter, resolveSniffFilePath(opts))
	wireSniffRemoteProvider(sniffTracker, fleetMgr)

	cfgStore := opts.ConfigStore
	if cfgStore == nil {
		cfgStore = config.NewStore(opts.ConfigPath, config.WithInitialConfig(initialCfg))
	} else if initialCfg != nil && cfgStore.Revision() == 0 {
		cfgStore.Set(initialCfg)
	}

	s := &Server{
		opts:               opts,
		Mux:                http.NewServeMux(),
		cfgStore:           cfgStore,
		subStore:           subStore,
		telemetry:          telemetry.NewCollector(opts.SingBoxConfigPath),
		fleet:              fleetMgr,
		limiter:            limiter,
		audit:              NewAuditManager(auditFile),
		geo:                geo,
		sniff:              sniffTracker,
		cliToken:           cliToken,
		passwordPendingAck: pendingAck,
		gatewayToken:       gatewayToken,
		Sessions:           make(map[string]SessionRecord),
	}
	s.caches = newStatusCaches(s)
	s.warp = newWarpRuntime(s)
	if initialCfg != nil {
		s.updateConfigCache(initialCfg)
	}

	s.mountStaticRoutes()

	s.registerRoutes()
	return s
}

func (s *Server) mountStaticRoutes() {
	if staticContent, err := fs.Sub(staticFS, "static"); err == nil {
		if _, statErr := fs.Stat(staticContent, "index.html"); statErr == nil {
			fileServer := http.FileServer(http.FS(staticContent))
			s.Mux.Handle("/", wrapStaticCacheHeaders(fileServer))
			return
		}
	}
	s.Mux.Handle("/", wrapStaticCacheHeaders(http.HandlerFunc(serveLiteStaticPlaceholder)))
}

func serveLiteStaticPlaceholder(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><title>SingCtl Lite</title><script src=\"/assets/lite-notice.js\"></script></head><body>SingCtl -lite 客户端精简构建未内嵌服务端 Web 管理静态资源，服务端请安装标准完整版。</body></html>"))
	case "/assets/lite-notice.js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		_, _ = w.Write([]byte("// singctl lite build: server web static bundle omitted\n"))
	default:
		http.NotFound(w, r)
	}
}

func wireSniffRemoteProvider(tracker *SniffTracker, fleetMgr *fleet.Manager) {
	if tracker == nil || fleetMgr == nil {
		return
	}
	tracker.SetRemoteProvider(&sniff.RemoteProvider{
		TelemetryAddr: telemetry.DefaultControllerAddr,
		Revision: func() uint64 {
			if fleetMgr.Store == nil {
				return 0
			}
			return fleetMgr.Store.Revision()
		},
		ListTargets: func() ([]sniff.RemoteTarget, error) {
			if fleetMgr.Store == nil {
				return nil, nil
			}
			nodes, err := fleetMgr.Store.List()
			if err != nil {
				return nil, err
			}
			out := make([]sniff.RemoteTarget, 0, len(nodes))
			for _, n := range nodes {
				out = append(out, sniff.RemoteTarget{
					ID:      n.ID,
					Name:    cmp.Or(n.Name, n.ID),
					Host:    cmp.Or(n.Host, n.Domain),
					Enabled: n.Enabled,
					Online:  n.Online,
				})
			}
			return out, nil
		},
		Exec: func(ctx context.Context, target sniff.RemoteTarget, script string) (string, int, error) {
			if fleetMgr.Store == nil {
				return "", 0, errors.New("fleet store unavailable")
			}
			node, ok, err := fleetMgr.Store.Get(target.ID)
			if err != nil || !ok {
				return "", 0, fmt.Errorf("fleet node %q not found", target.ID)
			}
			runner := fleetMgr.Runner
			if runner == nil {
				runner = fleet.DefaultSSHRunner
			}
			return runner(ctx, node, script)
		},
	})
}

// SetDeps 按非零字段增量注入测试协作者（并发安全）。
func (s *Server) SetDeps(d Deps) {
	s.mu.Lock()
	if d.CmdRunner != nil {
		s.deps.CmdRunner = d.CmdRunner
	}
	if d.ServiceConfigPaths != nil {
		s.deps.ServiceConfigPaths = maps.Clone(d.ServiceConfigPaths)
	}
	if d.SingBoxBin != "" {
		s.deps.SingBoxBin = d.SingBoxBin
	}
	if d.ConfigLoader != nil {
		s.deps.ConfigLoader = d.ConfigLoader
	}
	if d.StatusProber != nil {
		s.deps.StatusProber = d.StatusProber
	}
	if d.HealScanner != nil {
		s.deps.HealScanner = d.HealScanner
	}
	if d.WarpApplyDeps != nil {
		s.deps.WarpApplyDeps = d.WarpApplyDeps
	}
	if d.WarpRotateIdentity != nil {
		s.deps.WarpRotateIdentity = d.WarpRotateIdentity
	}
	s.mu.Unlock()

	if s.warp != nil {
		if d.WarpDaemonProbe != nil {
			s.warp.prober.DaemonProbe = d.WarpDaemonProbe
		}
		if d.WarpPortChecker != nil {
			s.warp.prober.PortChecker = d.WarpPortChecker
		}
		if d.WarpExitFetcher != nil {
			s.warp.prober.ExitFetcher = d.WarpExitFetcher
		}
		if d.WarpWatchdogDeps != nil {
			s.warp.watchdog.SetDeps(d.WarpWatchdogDeps)
		}
	}
}

func (s *Server) snapshotDeps() Deps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.deps
}

// FleetManager 暴露底层舰队编排管理器。
func (s *Server) FleetManager() *fleet.Manager { return s.fleet }

// SubStore 暴露底层 SubHub 存储实例。
func (s *Server) SubStore() *subhub.Store { return s.subStore }

// SniffTracker 暴露底层嗅探雷达追踪器。
func (s *Server) SniffTracker() *SniffTracker { return s.sniff }

// GeoResolver 暴露底层实例级 GeoIP 解析器。
func (s *Server) GeoResolver() *IPGeoResolver { return s.geo }

// Limiter 暴露底层登录防爆破限流器。
func (s *Server) Limiter() *IPLimiter { return s.limiter }

// AuditManager 暴露底层操作审计日志管理器。
func (s *Server) AuditManager() *AuditManager { return s.audit }

// CLIToken 返回本机回环 CLI 管理令牌。
func (s *Server) CLIToken() string { return s.cliToken }

// SeedStatusCaches 预置组件版本与证书健康快照缓存（供测试隔离外部子进程调用）。
func (s *Server) SeedStatusCaches(versions map[string]string, certs []CertHealth) {
	if s.caches == nil {
		return
	}
	if versions != nil {
		s.caches.versions.Set(maps.Clone(versions))
	}
	if certs != nil {
		s.caches.certs.Set(slices.Clone(certs))
	}
}

// SeedHealCache 预置安全自愈状态缓存与采集时间。
func (s *Server) SeedHealCache(rep *heal.StatusReport, fetchedAt time.Time) {
	if s.caches == nil || s.caches.heal == nil || rep == nil {
		return
	}
	s.caches.heal.set(rep, fetchedAt)
}

// SeedWarpExitCache 预置本地 WARP 出口 IP 与地区缓存。
func (s *Server) SeedWarpExitCache(ip, loc string, at time.Time) {
	if s.warp != nil && s.warp.prober != nil {
		s.warp.prober.SetCachedExit(ip, loc, at)
	}
}

// serverWebCSP 服务端管理面板严格纯同源 CSP，彻底阻断任何未授权外部脚本与外泄连接。
const serverWebCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

func applyServerWebBaseSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", serverWebCSP)
}

func wrapStaticCacheHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applyServerWebBaseSecurityHeaders(w)
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	// 状态与总览
	s.Mux.HandleFunc("GET /api/server/status", s.guard(s.handleStatus))
	s.Mux.HandleFunc("GET /api/server/nodes", s.guard(s.handleNodes))

	// 实时流量与分流遥测驾驶舱
	s.Mux.HandleFunc("GET /api/server/telemetry/snapshot", s.guard(s.handleTelemetrySnapshot))
	s.Mux.HandleFunc("GET /api/server/telemetry/stream", s.guard(s.handleTelemetrySSE))
	s.Mux.HandleFunc("POST /api/server/telemetry/enable", s.guard(s.handleEnableTelemetry))

	// 原生 SubHub 订阅管理与防盗刷访问审计
	s.Mux.HandleFunc("GET /api/server/subscriptions", s.guard(s.handleSubscriptions))
	s.Mux.HandleFunc("POST /api/server/subscriptions/sources", s.guard(s.handleUpsertSubscriptionSource))
	s.Mux.HandleFunc("POST /api/server/subscriptions/sources/refresh", s.guard(s.handleRefreshSubscriptionSources))
	s.Mux.HandleFunc("DELETE /api/server/subscriptions/sources", s.guard(s.handleDeleteSubscriptionSource))
	s.Mux.HandleFunc("POST /api/server/subscriptions/rotate-key", s.guard(s.handleRotateSubscriptionKey))
	s.Mux.HandleFunc("GET /api/server/subscriptions/preview", s.guard(s.handlePreviewSubscription))
	s.Mux.HandleFunc("GET /api/server/subscriptions/audit", s.guard(s.handleListSubscriptionAccessLogs))
	s.Mux.HandleFunc("DELETE /api/server/subscriptions/audit", s.guard(s.handleClearSubscriptionAccessLogs))

	// 多节点舰队编排 (Multi-Node Fleet)
	s.Mux.HandleFunc("GET /api/server/fleet", s.guard(s.handleFleetList))
	s.Mux.HandleFunc("POST /api/server/fleet/probe", s.guard(s.handleFleetProbe))
	s.Mux.HandleFunc("GET /api/server/fleet/defaults", s.guard(s.handleFleetDefaults))
	s.Mux.HandleFunc("POST /api/server/fleet/preview-bootstrap", s.guard(s.handleFleetPreviewBootstrap))
	s.Mux.HandleFunc("POST /api/server/fleet/nodes", s.guard(s.handleFleetUpsertNode))
	s.Mux.HandleFunc("DELETE /api/server/fleet/nodes", s.guard(s.handleFleetDeleteNode))
	s.Mux.HandleFunc("POST /api/server/fleet/action", s.guard(s.handleFleetAction))
	s.Mux.HandleFunc("POST /api/server/fleet/bootstrap", s.guard(s.handleFleetBootstrap))

	// 四核服务生命周期与配置编辑
	s.Mux.HandleFunc("POST /api/server/action", s.guard(s.handleAction))
	s.Mux.HandleFunc("POST /api/server/service/action", s.guard(s.handleServiceAction))
	s.Mux.HandleFunc("GET /api/server/service/check-update", s.guard(s.handleCheckServiceUpdate))
	s.Mux.HandleFunc("POST /api/server/service/upgrade", s.guard(s.handleUpgradeService))
	s.Mux.HandleFunc("GET /api/server/service/logs", s.guard(s.handleServiceLogs))
	s.Mux.HandleFunc("GET /api/server/service/config", s.guard(s.handleServiceConfig))
	s.Mux.HandleFunc("PUT /api/server/service/config", s.guard(s.handleUpdateServiceConfig))
	s.Mux.HandleFunc("GET /api/server/logs/stream", s.guard(s.handleLogsSSE))

	// 网络诊断、体检与隐蔽安全管理
	s.Mux.HandleFunc("GET /api/server/net/return", s.guard(s.handleNetReturn))
	s.Mux.HandleFunc("POST /api/server/net/return", s.guard(s.handleNetReturn))
	s.Mux.HandleFunc("POST /api/server/bbr", s.guard(s.handleEnableBBR))
	s.Mux.HandleFunc("GET /api/server/warp/diagnose", s.guard(s.handleWarpDiagnose))
	s.Mux.HandleFunc("GET /api/server/warp/routing", s.guard(s.handleGetWarpRouting))
	s.Mux.HandleFunc("PUT /api/server/warp/routing", s.guard(s.handleUpdateWarpRouting))
	s.Mux.HandleFunc("POST /api/server/warp/quick-switch", s.guard(s.handleQuickSwitchWarp))
	s.Mux.HandleFunc("GET /api/server/warp/connections", s.guard(s.handleGetWarpConnections))
	s.Mux.HandleFunc("POST /api/server/warp/action", s.guard(s.handleWarpAction))
	s.Mux.HandleFunc("POST /api/server/path/regenerate", s.guard(s.handleRegeneratePath))
	s.Mux.HandleFunc("POST /api/server/mask-site/regenerate", s.guard(s.handleRegenerateMaskSite))
	s.Mux.HandleFunc("PUT /api/server/sni", s.guard(s.handleUpdateSNI))
	s.Mux.HandleFunc("PUT /api/server/cf-token", s.guard(s.handleUpdateCFToken))
	s.Mux.HandleFunc("PUT /api/server/credentials", s.guard(s.handleUpdateCredentials))
	s.Mux.HandleFunc("POST /api/server/credentials/ack", s.guard(s.handleAckCredentials))
	s.Mux.HandleFunc("GET /api/server/session/url", s.guard(s.handleSessionURL))
	s.Mux.HandleFunc("GET /api/server/bans", s.guard(s.handleListBans))
	s.Mux.HandleFunc("POST /api/server/unban", s.guard(s.handleUnban))
	s.Mux.HandleFunc("GET /api/server/security/sniffers", s.guard(s.handleGetSniffers))
	s.Mux.HandleFunc("POST /api/server/security/block", s.guard(s.handleBlockSniffer))
	s.Mux.HandleFunc("POST /api/server/security/unblock", s.guard(s.handleUnban))
	s.Mux.HandleFunc("GET /api/server/certs", s.guard(s.handleInspectCerts))
	s.Mux.HandleFunc("POST /api/server/backup/export", s.guard(s.handleBackupExport))
	s.Mux.HandleFunc("POST /api/server/backup/restore", s.guard(s.handleBackupRestore))
	s.Mux.HandleFunc("GET /api/server/audit-logs", s.guard(s.handleListAuditLogs))
	s.Mux.HandleFunc("GET /api/server/doctor", s.guard(s.handleDoctor))
	s.Mux.HandleFunc("GET /api/server/diagnose/unlock", s.guard(s.handleUnlockDiagnose))
	s.Mux.HandleFunc("GET /api/server/camouflage/defaults", s.guard(s.handleCamouflageDefaults))
	s.Mux.HandleFunc("POST /api/server/camouflage/probe", s.guard(s.handleCamouflageProbe))

	// 三层自动化安全漏洞自愈中心
	s.Mux.HandleFunc("GET /api/server/heal/status", s.guard(s.handleHealStatus))
	s.Mux.HandleFunc("POST /api/server/heal/run", s.guard(s.handleHealRun))
	s.Mux.HandleFunc("PUT /api/server/heal/policy", s.guard(s.handleHealPolicy))

	// 认证 API (公开访问)
	s.Mux.HandleFunc("POST /api/server/login", s.handleLogin)
	s.Mux.HandleFunc("POST /api/server/logout", s.handleLogout)
}

// ListenAndServe 启动 HTTP 服务（阻塞直至服务退出）。
func (s *Server) ListenAndServe() error {
	return s.ServeContext(context.Background())
}

// buildLifecycle 构建服务端后台协程与持久化落盘的确定性三阶段生命周期编排组。
func (s *Server) buildLifecycle(patrolCtx context.Context, cancelPatrol context.CancelFunc) *lifecycle.Group {
	g := lifecycle.NewGroup()
	g.Add(
		lifecycle.FuncService{
			ServiceName: "persistence",
			OnClose: func() error {
				if s.audit != nil {
					s.audit.Flush()
				}
				if s.limiter != nil {
					s.limiter.Close()
				}
				if s.sniff != nil {
					s.sniff.Flush()
				}
				if s.geo != nil {
					s.geo.Flush()
				}
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "fleet-patrol",
			OnStart: func(context.Context) error {
				s.fleet.StartBackgroundPatrol(patrolCtx, fleet.DefaultPatrolInterval)
				return nil
			},
			OnClose: func() error {
				if cancelPatrol != nil {
					cancelPatrol()
				}
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "warp-watchdog",
			OnStart: func(context.Context) error {
				s.warp.watchdog.Start(patrolCtx, deploy.DefaultWarpWatchdogInterval)
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "heal-boot-scan",
			OnPostStart: func(context.Context) error {
				tryRunSingleFlight(&s.caches.heal.refreshing, 45*time.Second, func(bgCtx context.Context) {
					s.runHealScanSync(bgCtx)
				})
				return nil
			},
		},
	)
	return g
}

// ServeContext 启动服务端 HTTP 面板与后台巡检编排组，并在 ctx 取消时优雅关闭及逆序刷盘。
func (s *Server) ServeContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(s.GetPassword()) == "" {
		return fmt.Errorf("服务端管理密码为空，拒绝启动。请在配置 web_admin.password 中设置密码")
	}
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	if s.opts.OnReady != nil {
		s.opts.OnReady(ln.Addr().String())
	}

	logger.Success("SingCtl 服务端管理面板已启动")
	logger.Info("  ➜  http://%s", ln.Addr().String())

	patrolCtx, cancelPatrol := context.WithCancel(ctx)
	lc := s.buildLifecycle(patrolCtx, cancelPatrol)
	if err := lc.Start(patrolCtx); err != nil {
		cancelPatrol()
		_ = ln.Close()
		return err
	}
	defer func() {
		cancelPatrol()
		_ = lc.Close()
	}()

	srv := &http.Server{
		Handler:           s.Mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutCtx)
			shutCancel()
		case <-serveDone:
		}
	}()

	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) && ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) invalidateStatusCaches() {
	if s.caches == nil {
		return
	}
	s.caches.serviceProbes.Invalidate()
	s.caches.versions.Invalidate()
	s.caches.certs.Invalidate()
}

func (s *Server) loadConfigSnapshot() (*config.Config, error) {
	if loader := s.snapshotDeps().ConfigLoader; loader != nil {
		return loader(s.opts.ConfigPath)
	}
	if s.cfgStore != nil {
		return s.cfgStore.LoadLatest()
	}
	return config.Load(s.opts.ConfigPath)
}

func (s *Server) readConfigOrNil() *config.Config {
	if cfg, err := s.loadConfigSnapshot(); err == nil && cfg != nil {
		return cfg
	}
	if s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		return s.cfgStore.Get()
	}
	return nil
}

func (s *Server) loadMutableConfig() (*config.Config, error) {
	snap, err := s.loadConfigSnapshot()
	if err != nil || snap == nil {
		if err == nil {
			err = fmt.Errorf("empty config")
		}
		return nil, err
	}
	return snap.Clone(), nil
}

func (s *Server) saveConfig(cfg *config.Config) error {
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		return err
	}
	s.updateConfigCache(cfg)
	return nil
}

func (s *Server) updateConfigCache(cfg *config.Config) {
	if cfg == nil {
		return
	}
	if s.cfgStore != nil && s.cfgStore.Get() != cfg {
		s.cfgStore.Set(cfg)
	}
	if s.caches != nil && s.caches.config != nil {
		s.caches.config.Set(cachedConfigBundle{
			cfg:         cfg,
			subAdminURL: s.resolveSubstoreAdminURLFast(cfg),
		})
	}
}

// InvalidateConfigCache 主动失效配置 SWR 缓存与底层 config.Store 指纹。
func (s *Server) InvalidateConfigCache() {
	if s.caches != nil && s.caches.config != nil {
		s.caches.config.Invalidate()
	}
	if s.cfgStore != nil {
		s.cfgStore.Invalidate()
	}
}

func applySecurityResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	applyServerWebBaseSecurityHeaders(w)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	applySecurityResponseHeaders(w)
	httpx.WriteJSON(w, status, v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	applySecurityResponseHeaders(w)
	httpx.WriteError(w, httpx.NewStatusError(status, msg, nil))
}

func decodeBodyJSON[T any](w http.ResponseWriter, r *http.Request, maxBytes int64, allowEmpty bool, badReqMsg string) (T, bool) {
	out, err := httpx.DecodeJSON[T](w, r, maxBytes, allowEmpty)
	if err == nil {
		return out, true
	}
	if se, ok := errors.AsType[*httpx.StatusError](err); ok && se.Code == http.StatusRequestEntityTooLarge {
		writeJSONError(w, http.StatusRequestEntityTooLarge, se.Error())
		return out, false
	}
	writeJSONError(w, http.StatusBadRequest, cmp.Or(badReqMsg, err.Error()))
	return out, false
}
