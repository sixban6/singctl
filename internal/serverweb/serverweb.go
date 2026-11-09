package serverweb

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/fleet"
	"singctl/internal/logger"
	"singctl/internal/subhub"
	"singctl/internal/telemetry"
)

//go:embed static
var staticFS embed.FS

const sessionCookieName = "singctl_server_session"

// Options 服务端 Web 界面配置
type Options struct {
	ConfigPath        string
	SingBoxConfigPath string // (可选) sing-box 配置文件路径，默认 /etc/sing-box/config.json
	SubStoreDir       string // (可选) SubHub 数据存储目录，默认 /etc/sub-store
	FleetFilePath     string // (可选) 节点舰队存储文件路径，默认 <ConfigDir>/fleet.yaml
	BanFilePath       string // (可选) 防爆破封禁列表存储文件 (默认: <ConfigDir>/.serverweb_bans.json)
	AuditFilePath     string // (可选) 管理操作审计日志存储文件 (默认: <ConfigDir>/.serverweb_audit.json)
	Listen            string
	Username          string
	Password          string
	Version           string
	OnReady           func(listenAddr string)
}

// Server 服务端 Web 实例
type Server struct {
	opts               Options
	Mux                *http.ServeMux
	subStore           *subhub.Store
	telemetry          *telemetry.Collector
	fleet              *fleet.Manager
	mu                 sync.RWMutex
	Sessions           map[string]SessionRecord
	SessionsMu         sync.Mutex
	limiter            *IPLimiter
	audit              *AuditManager
	geo                *IPGeoResolver
	sniff              *SniffTracker
	passwordPendingAck bool
	gatewayToken       string
	cliToken           string
}

type SessionRecord struct {
	Created time.Time
	Last    time.Time
}

const (
	sessionIdleTTL     = 2 * time.Hour
	sessionAbsoluteTTL = 12 * time.Hour
	MaxActiveSessions  = 50
)

// New 创建服务端 Web 实例
func New(opts Options) *Server {
	pendingAck := false
	gatewayToken := ""
	if opts.ConfigPath != "" {
		if cfg, err := config.Load(opts.ConfigPath); err == nil && cfg != nil {
			if cfg.Server.EnsureWebAdminCredentials() {
				_ = config.Save(opts.ConfigPath, cfg)
			}
			if opts.Username == "" {
				opts.Username = cfg.Server.GetWebAdminUsername()
			}
			if opts.Password == "" {
				opts.Password = cfg.Server.GetWebAdminPassword()
			}
			if opts.Listen == "" || opts.Listen == "127.0.0.1:8092" {
				opts.Listen = fmt.Sprintf("127.0.0.1:%d", cfg.Server.GetWebAdminPort())
			}
			pendingAck = cfg.Server.WebAdmin.PasswordPendingAck
			gatewayToken = config.DeriveGatewayToken(cfg.Server.GetWebAdminPath())
		}
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8092"
	}
	if opts.Username == "" {
		opts.Username = "singctl"
	}

	banFile := resolveBanFilePath(opts)
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
	sniffFile := resolveSniffFilePath(opts)
	sniffTracker := NewSniffTracker(geo, limiter, sniffFile)
	sniffTracker.SetFleetManager(fleetMgr)
	s := &Server{
		opts:               opts,
		Mux:                http.NewServeMux(),
		subStore:           subStore,
		telemetry:          telemetry.NewCollector(opts.SingBoxConfigPath),
		fleet:              fleetMgr,
		Sessions:           make(map[string]SessionRecord),
		limiter:            limiter,
		audit:              NewAuditManager(auditFile),
		geo:                geo,
		sniff:              sniffTracker,
		passwordPendingAck: pendingAck,
		gatewayToken:       gatewayToken,
		cliToken:           cliToken,
	}

	// 静态单页面：放行静态资源，敏感 API 均受 guard 保护
	staticContent, err := fs.Sub(staticFS, "static")
	if err == nil {
		fileServer := http.FileServer(http.FS(staticContent))
		s.Mux.Handle("/", fileServer)
	}

	s.registerRoutes()
	return s
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
	s.Mux.HandleFunc("GET /api/server/audit-logs", s.guard(s.handleListAuditLogs))
	s.Mux.HandleFunc("GET /api/server/doctor", s.guard(s.handleDoctor))
	s.Mux.HandleFunc("GET /api/server/diagnose/unlock", s.guard(s.handleUnlockDiagnose))
	s.Mux.HandleFunc("GET /api/server/camouflage/defaults", s.guard(s.handleCamouflageDefaults))
	s.Mux.HandleFunc("POST /api/server/camouflage/probe", s.guard(s.handleCamouflageProbe))

	// 三层自动化安全漏洞自愈中心 (3-Layer Security Self-Healing)
	s.Mux.HandleFunc("GET /api/server/heal/status", s.guard(s.handleHealStatus))
	s.Mux.HandleFunc("POST /api/server/heal/run", s.guard(s.handleHealRun))
	s.Mux.HandleFunc("PUT /api/server/heal/policy", s.guard(s.handleHealPolicy))

	// 认证 API (公开访问)
	s.Mux.HandleFunc("POST /api/server/login", s.handleLogin)
	s.Mux.HandleFunc("POST /api/server/logout", s.handleLogout)
}

// FleetManager exposes the underlying fleet manager (useful for testing/injection).
func (s *Server) FleetManager() *fleet.Manager {
	return s.fleet
}

// SubStore exposes the underlying SubHub store.
func (s *Server) SubStore() *subhub.Store {
	return s.subStore
}

// ListenAndServe 启动 HTTP 服务
func (s *Server) ListenAndServe() error {
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

	patrolCtx, cancelPatrol := context.WithCancel(context.Background())
	defer cancelPatrol()
	s.fleet.StartBackgroundPatrol(patrolCtx, fleet.DefaultPatrolInterval)

	srv := &http.Server{
		Handler:           s.Mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return srv.Serve(ln)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
