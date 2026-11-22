// 文件职责：提供客户端 Web 管理服务实例初始化、77 个 HTTP 路由装配、config.Store 快照读写与生命周期托管。
package webui

import (
	"cmp"
	"context"
	"embed"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/audit"
	"singctl/internal/common/httpx"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
	"singctl/internal/lifecycle"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
	"singctl/internal/netdiag/dohprobe"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/singbox/clashapi"
	"singctl/internal/smartdns"
	"singctl/internal/tailscale"
)

// SessionCookieName 持久化 Cookie 键名，用于 Safari/PWA 独立沙盒免密免登。
const SessionCookieName = "singctl_session"

//go:embed static
var staticFS embed.FS

// Options Web 服务显式配置与测试依赖注入选项。
type Options struct {
	ConfigPath              string                                                                            // singctl 配置文件路径
	SingBoxConfigPath       string                                                                            // 可选：测试/定制 sing-box config.json 路径（留空使用 constant.SingBoxConfigFile）
	SingBoxWorkConfigPath   string                                                                            // 可选：测试/定制沙盒副本 config.json 路径
	AdGuardBinPath                     string                                                                                                             // 可选：测试/定制 AdGuardHome 二进制路径
	AdGuardConfigPath                  string                                                                                                             // 可选：测试/定制 AdGuardHome.yaml 路径
	AdGuardMemInfoForTest              func() sysinfo.MemInfo                                                                                             // 仅供离线单元测试注入宿主机内存信息（低内存防 OOM 护栏）
	SmartDNSBinPath                    string                                                                                                             // 可选：测试/定制 SmartDNS 二进制路径
	SmartDNSConfigPath                 string                                                                                                             // 可选：测试/定制 smartdns.conf 路径
	SmartDNSRulesDir                   string                                                                                                             // 可选：测试/定制 smartdns-rules.d 目录
	SmartDNSAuditLogPath               string                                                                                                             // 可选：测试/定制 SmartDNS 审计日志路径
	DiskSpaceForTest                   func(path string) (sysinfo.DiskSpace, error)                                                                       // 仅供离线单元测试注入磁盘剩余空间探测
	LocalDNSServiceMgr                 servicemgr.Manager                                                                                                 // 可选：测试注入服务管理器替身
	DNSProbeUpstreamForTest            func(ctx context.Context, upstreams []string, domain string, timeout time.Duration) []adguard.UpstreamProbeItem    // 仅供离线单元测试注入上游探测结果
	LocalDNSProbeDNSForTest            func(addr string, timeout time.Duration) error                                                                     // 仅供离线单元测试注入本地 DNS 端口探活
	LocalDNSProbeResForTest            func(addr, domain string, timeout time.Duration) ([]string, time.Duration, error)                                  // 仅供离线单元测试注入域名实测解析
	LocalDNSSyncSingBoxEnhancedForTest func(ctx context.Context, sbCfgPath, workPath string, dnsCfg config.ClientDNSConfig, subDomains []string, now time.Time) (bool, error)
	LocalDNSSyncSingBoxDNSLocalForTest func(ctx context.Context, sbCfgPath, workPath string, useExternal bool, dnsPort int) (bool, error)
	SingBoxStatsRing                   *localdns.StatsRing                                                                                                // 可选：与单进程合体守护进程共享 sing-box DNS 遥测统计环
	SmartDNSStatsRing                  *localdns.StatsRing                                                                                                // 可选：与单进程合体守护进程共享 SmartDNS 审计统计环
	SmartDNSTailer                     *smartdns.AuditLogTailer                                                                                           // 可选：与单进程合体守护进程共享 SmartDNS 审计日志追踪器
	ExecutablePath          string                                                                            // 可选：测试/定制 singctl 可执行文件路径
	SingBoxLookPath         func(file string) (string, error)                                                 // 可选：测试/定制 sing-box 二进制查找函数
	IOSGenerator            func(cfg *config.Config) (string, error)                                          // 可选：测试/定制 iOS 配置生成函数
	AuditCollector          *audit.Collector                                                                  // 可选：显式注入设备审计采集器
	AuditLimiter            *AuditRateLimiter                                                                 // 可选：显式注入审计限流器
	SkipAdGuardProbeForTest bool                                                                              // 仅供离线单元测试跳过公网上游实测
	GatewayProberForTest    func() gateway.TopologyInfo                                                       // 仅供单元测试注入网络拓扑探测结果
	DNSLeakRunnerForTest    func(ctx context.Context, opts netdiag.DNSLeakTestOptions) *netdiag.DNSLeakReport // 仅供单元测试注入离线 DNS 泄漏实测结果
	BrowserDoHForTest       *BrowserDoHTestHooks                                                              // 仅供单元测试注入浏览器 DoH 旁路检测依赖
	TailscaleP2PForTest     *TailscaleP2PTestHooks                                                            // 仅供单元测试注入 Tailscale P2P 防线依赖
	TailscaleUpgradeForTest *TailscaleUpgradeTestHooks                                                        // 仅供单元测试注入 Tailscale 零失联升级体检与状态
	Listen                  string                                                                            // 监听地址,如 ":8090"
	Password                string                                                                            // 可选的访问口令(空=不启用鉴权,建议仅在可信内网使用)
	Version                 string                                                                            // singctl 版本号
	OnReady                 func(listenAddr string)                                                           // Listen 成功后的回调(后台子进程用于就绪握手)
	ConfigStore             *config.Store                                                                     // 可选：与单进程合体守护进程共享同一个 config.Store
	LowMemoryMode           *bool                                                                             // 可选：显式指定低内存模式（控制 256 KiB 日志截断）
	EmbeddedInDaemon        bool                                                                              // 标记当前 WebUI 服务内嵌运行于单进程合体守护进程中
	UnifiedHandoffCheck     func() bool                                                                       // 可选：测试注入单进程合体接管状态探测函数
	HandoffShutdownDelay    time.Duration                                                                     // 可选：独立进程推流完毕后异步优雅关闭前的等待时长（默认 300ms）
	IdleThreshold           time.Duration                                                                     // 可选：冷态闲置触发物理内存归还阈值（默认 3 分钟）
	IdleCheckInterval       time.Duration                                                                     // 可选：冷态闲置巡检间隔（默认 30 秒）
	NowFunc                 func() time.Time                                                                  // 可选：测试注入可控时钟（默认 time.Now）
	ScavengeFunc            func()                                                                            // 可选：测试注入物理内存归还动作（默认 GC+FreeOSMemory）
}

// Server 客户端 Web 管理服务。
type Server struct {
	opts Options

	Mux *http.ServeMux

	actionBusy atomic.Bool

	// iOS 配置生成缓存: 实时生成需拉订阅(秒级), 缓存让 SFI 同步/重复扫码瞬时返回
	iosMu       sync.Mutex
	iosCacheKey string
	iosCacheVal string

	cfgMu          sync.Mutex
	cfgStore       *config.Store
	auditLimiter   *AuditRateLimiter
	auditCollector *audit.Collector
	loginLimiter   *loginRateLimiter

	clash             *clashapi.Client
	dohProber         *dohprobe.Prober
	dnsStatsRing      *localdns.StatsRing
	smartDNSStatsRing *localdns.StatsRing
	smartDNSTailer    *smartdns.AuditLogTailer
	dnsTelemetry      *localdns.DomainTelemetryTracker

	// /api/sb/traffic 按需后台采样器（无请求 15s 自动停止）
	trafficMu                  sync.Mutex
	trafficState               SbTrafficResponse
	trafficSampledAt           time.Time
	trafficLastReqAt           time.Time
	trafficRunning             bool
	trafficMemUnsupportedUntil time.Time

	tsP2PMu   sync.Mutex
	tsP2PCtrl *tailscale.P2PAssistController

	lastReqUnixNano atomic.Int64
	activeEpoch     atomic.Uint64
	scavengedEpoch  atomic.Uint64

	shutdownOnce sync.Once
	shutdownCh   chan struct{}
	shutdownReq  atomic.Bool
}

// New 创建客户端 Web 服务并完成全部路由与领域组件装配。
func New(opts Options) *Server {
	sbCfgPath := cmp.Or(strings.TrimSpace(opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	clashCli := clashapi.NewClient(clashapi.Options{ConfigPath: sbCfgPath})

	audCollector := opts.AuditCollector
	if audCollector == nil {
		audCollector = audit.NewCollector(nil)
	}
	audLimiter := opts.AuditLimiter
	if audLimiter == nil {
		audLimiter = NewAuditRateLimiter()
	}
	cfgStore := opts.ConfigStore
	if cfgStore == nil {
		cfgStore = config.NewStore(opts.ConfigPath)
	}

	lowMemRing := opts.LowMemoryMode != nil && *opts.LowMemoryMode
	sbRing := opts.SingBoxStatsRing
	if sbRing == nil {
		sbRing = localdns.NewStatsRing(lowMemRing)
	}
	sdRing := opts.SmartDNSStatsRing
	if sdRing == nil {
		sdRing = localdns.NewStatsRing(lowMemRing)
	}
	sdTailer := opts.SmartDNSTailer
	if sdTailer == nil {
		sdTailer = smartdns.NewAuditLogTailer(cmp.Or(strings.TrimSpace(opts.SmartDNSAuditLogPath), constant.SmartDNSAuditLogPath))
	}
	telemetryCap := 1024
	if lowMemRing {
		telemetryCap = 256
	}

	s := &Server{
		opts:              opts,
		Mux:               http.NewServeMux(),
		cfgStore:          cfgStore,
		auditLimiter:      audLimiter,
		auditCollector:    audCollector,
		loginLimiter:      newLoginRateLimiter(),
		clash:             clashCli,
		dnsStatsRing:      sbRing,
		smartDNSStatsRing: sdRing,
		smartDNSTailer:    sdTailer,
		dnsTelemetry:      localdns.NewDomainTelemetryTracker(sbRing, telemetryCap),
		shutdownCh:        make(chan struct{}),
	}
	s.lastReqUnixNano.Store(s.now().UnixNano())
	s.activeEpoch.Store(1)
	s.dohProber = newBrowserDoHProber(opts.BrowserDoHForTest, clashCli)

	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	s.Mux.Handle("/", s.authOnly(fileServer))

	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	// 公开鉴权握手与登录 API
	s.Mux.HandleFunc("GET /api/auth/check", s.handleAuthCheck)
	s.Mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)

	// 只读与基础配置 API
	s.Mux.HandleFunc("GET /api/status", s.guard(s.handleStatus))
	s.Mux.HandleFunc("GET /api/health", s.guard(s.handleHealth))
	s.Mux.HandleFunc("GET /api/config", s.guard(s.handleConfigGet))
	s.Mux.HandleFunc("PUT /api/config", s.guard(s.handleConfigPut))
	s.Mux.HandleFunc("GET /api/config/raw", s.guard(s.handleConfigRawGet))
	s.Mux.HandleFunc("PUT /api/config/raw", s.guard(s.handleConfigRawPut))
	s.Mux.HandleFunc("GET /api/cache", s.guard(s.handleCache))
	s.Mux.HandleFunc("GET /api/logs", s.guard(s.handleLogs))
	s.Mux.HandleFunc("POST /api/logs/clear", s.guard(s.handleLogsClear))
	s.Mux.HandleFunc("POST /api/backup/export", s.guard(s.handleClientBackupExport))
	s.Mux.HandleFunc("POST /api/backup/restore", s.guard(s.handleClientBackupRestore))

	// 登出与会话 API
	s.Mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.Mux.HandleFunc("GET /api/session/url", s.guard(s.handleSessionURL))

	// iOS(sing-box App) 配置下载
	s.Mux.HandleFunc("GET /api/gen/ios", s.guardIOSDownload(s.handleIOSConfig))
	s.Mux.HandleFunc("GET /api/gen/ios/{$}", s.guardIOSDownload(s.handleIOSConfig))
	s.Mux.HandleFunc("GET /api/gen/ios/url", s.guard(s.handleIOSConfigURL))

	// sing-box 配置文件编辑 & 客户端智能分流开关中心
	s.Mux.HandleFunc("GET /api/sbconfig", s.guard(s.handleSbConfigGet))
	s.Mux.HandleFunc("PUT /api/sbconfig", s.guard(s.handleSbConfigPut))
	s.Mux.HandleFunc("PUT /api/sbconfig/preserve", s.guard(s.handleSbConfigPreservePut))
	s.Mux.HandleFunc("POST /api/sbconfig/restore", s.guard(s.handleSbConfigRestore))
	s.Mux.HandleFunc("PUT /api/sb/subs", s.guard(s.handleSbSubsPut))
	s.Mux.HandleFunc("GET /api/traffic-routing", s.guard(s.handleTrafficRoutingGet))
	s.Mux.HandleFunc("PUT /api/traffic-routing", s.guard(s.handleTrafficRoutingPut))
	s.Mux.HandleFunc("GET /api/groups", s.guard(s.handleGroupsGet))
	s.Mux.HandleFunc("POST /api/groups/preview", s.guard(s.handleGroupsPreviewPost))
	s.Mux.HandleFunc("PUT /api/groups", s.guard(s.handleGroupsPut))
	s.Mux.HandleFunc("GET /api/gateway", s.guard(s.handleGatewayGet))
	s.Mux.HandleFunc("PUT /api/gateway", s.guard(s.handleGatewayPut))
	s.Mux.HandleFunc("POST /api/dns/leak-test", s.guard(s.handleDNSLeakTestPost))
	s.Mux.HandleFunc("POST /api/dns/browser-doh", s.guard(s.handleBrowserDoHCheckPost))

	// Tailscale 局部配置、P2P 直连防线与升级 API
	s.Mux.HandleFunc("GET /api/tailscale/config", s.guard(s.handleTailscaleConfigGet))
	s.Mux.HandleFunc("PUT /api/tailscale/config", s.guard(s.handleTailscaleConfigPut))
	s.Mux.HandleFunc("GET /api/tailscale/p2p", s.guard(s.handleTailscaleP2PGet))
	s.Mux.HandleFunc("PUT /api/tailscale/p2p", s.guard(s.handleTailscaleP2PPut))
	s.Mux.HandleFunc("POST /api/tailscale/p2p/poke", s.guard(s.handleTailscaleP2PPokePost))
	s.Mux.HandleFunc("PUT /api/system/mirror", s.guard(s.handleSystemMirrorPut))
	s.Mux.HandleFunc("GET /api/tailscale/upgrade/preflight", s.guard(s.handleTailscaleUpgradePreflightGet))
	s.Mux.HandleFunc("GET /api/tailscale/upgrade/status", s.guard(s.handleTailscaleUpgradeStatusGet))

	// 看门狗守护与策略组容灾控制 API
	s.Mux.HandleFunc("GET /api/watchdog", s.guard(s.handleWatchdogGet))
	s.Mux.HandleFunc("PUT /api/watchdog/config", s.guard(s.handleWatchdogConfigPut))
	s.Mux.HandleFunc("POST /api/watchdog/patrol", s.guard(s.handleWatchdogPatrolPost))

	// 统一三引擎防劫持 DNS 管控中心 API (/api/dns/* 主契约 + /api/adguard/* 向后兼容别名)
	s.Mux.HandleFunc("GET /api/dns/overview", s.guard(s.handleDNSOverviewGet))
	s.Mux.HandleFunc("GET /api/dns/credentials", s.guard(s.handleDNSCredentialsGet))
	s.Mux.HandleFunc("POST /api/dns/credentials/reset", s.guard(s.handleDNSCredentialsResetPost))
	s.Mux.HandleFunc("GET /api/dns/config-preview", s.guard(s.handleDNSConfigPreviewGet))
	s.Mux.HandleFunc("POST /api/dns/engine", s.guard(s.handleDNSEngineSwitchPost))
	s.Mux.HandleFunc("POST /api/dns/protection", s.guard(s.handleDNSProtectionPost))
	s.Mux.HandleFunc("POST /api/dns/cache/clear", s.guard(s.handleDNSCacheClearPost))
	s.Mux.HandleFunc("POST /api/dns/probe", s.guard(s.handleDNSProbePost))
	s.Mux.HandleFunc("POST /api/dns/upstreams", s.guard(s.handleDNSUpstreamsPost))
	s.Mux.HandleFunc("POST /api/dns/whitelist", s.guard(s.handleDNSWhitelistPost))
	s.Mux.HandleFunc("POST /api/dns/rewrites", s.guard(s.handleDNSRewritesPost))
	s.Mux.HandleFunc("POST /api/dns/filters", s.guard(s.handleDNSFiltersPost))
	s.Mux.HandleFunc("POST /api/dns/block-aaaa", s.guard(s.handleDNSBlockAAAAPost))

	// 向后兼容原有 AdGuard Home API 路由别名
	s.Mux.HandleFunc("GET /api/adguard", s.guard(s.handleDNSOverviewGet))
	s.Mux.HandleFunc("GET /api/adguard/credentials", s.guard(s.handleDNSCredentialsGet))
	s.Mux.HandleFunc("POST /api/adguard/credentials/reset", s.guard(s.handleDNSCredentialsResetPost))
	s.Mux.HandleFunc("POST /api/adguard/protection", s.guard(s.handleDNSProtectionPost))
	s.Mux.HandleFunc("POST /api/adguard/cache/clear", s.guard(s.handleDNSCacheClearPost))
	s.Mux.HandleFunc("POST /api/adguard/probe", s.guard(s.handleDNSProbePost))
	s.Mux.HandleFunc("POST /api/adguard/upstreams", s.guard(s.handleDNSUpstreamsPost))
	s.Mux.HandleFunc("POST /api/adguard/whitelist", s.guard(s.handleDNSWhitelistPost))
	s.Mux.HandleFunc("POST /api/adguard/rewrites", s.guard(s.handleDNSRewritesPost))
	s.Mux.HandleFunc("POST /api/adguard/filters", s.guard(s.handleDNSFiltersPost))

	// 局域网设备行为审计与拉黑 API
	s.Mux.HandleFunc("GET /api/audit", s.guard(s.handleAuditGet))
	s.Mux.HandleFunc("GET /api/audit/ai-config", s.guard(s.handleAuditAIConfigGet))
	s.Mux.HandleFunc("POST /api/audit/ai-config", s.guard(s.handleAuditAIConfigPost))
	s.Mux.HandleFunc("POST /api/audit/ai-models", s.guard(s.handleAuditAIModelsPost))
	s.Mux.HandleFunc("POST /api/audit/ai-review", s.guard(s.handleAuditAIReviewPost))
	s.Mux.HandleFunc("POST /api/audit/block", s.guard(s.handleAuditBlock))
	s.Mux.HandleFunc("POST /api/audit/unblock", s.guard(s.handleAuditUnblock))
	s.Mux.HandleFunc("POST /api/audit/pcdn-block", s.guard(s.handleAuditPCDNBlock))
	s.Mux.HandleFunc("POST /api/audit/throttle", s.guard(s.handleAuditThrottle))
	s.Mux.HandleFunc("POST /api/audit/whitelist", s.guard(s.handleAuditWhitelist))
	s.Mux.HandleFunc("POST /api/audit/close-connections", s.guard(s.handleAuditCloseConnections))

	// 防火墙加固可视化与规则治理 API
	s.Mux.HandleFunc("GET /api/firewall/overview", s.guard(s.handleFirewallOverviewGet))
	s.Mux.HandleFunc("GET /api/firewall/logs", s.guard(s.handleFirewallLogsGet))
	s.Mux.HandleFunc("POST /api/firewall/apply", s.guard(s.handleFirewallApplyPost))
	s.Mux.HandleFunc("POST /api/firewall/disable", s.guard(s.handleFirewallDisablePost))
	s.Mux.HandleFunc("POST /api/firewall/ban", s.guard(s.handleFirewallBanPost))
	s.Mux.HandleFunc("POST /api/firewall/unban", s.guard(s.handleFirewallUnbanPost))
	s.Mux.HandleFunc("POST /api/firewall/clear-dynamic", s.guard(s.handleFirewallClearDynamicPost))
	s.Mux.HandleFunc("POST /api/firewall/whitelist", s.guard(s.handleFirewallWhitelistPost))

	// 原生 sing-box 策略组控制与实时速率 API
	s.Mux.HandleFunc("GET /api/sb/proxies", s.guard(s.handleSbProxiesGet))
	s.Mux.HandleFunc("PUT /api/sb/proxies/switch", s.guard(s.handleSbProxySwitchPut))
	s.Mux.HandleFunc("POST /api/sb/proxies/delay", s.guard(s.handleSbProxyDelayPost))
	s.Mux.HandleFunc("PUT /api/sb/mode", s.guard(s.handleSbModePut))
	s.Mux.HandleFunc("GET /api/sb/traffic", s.guard(s.handleSbTrafficGet))

	// 流式动作执行 API
	s.Mux.HandleFunc("POST /api/action", s.guard(s.handleAction))
}

// ConfigStore 返回底层只读配置快照存储实例。
func (s *Server) ConfigStore() *config.Store { return s.cfgStore }

// AuditCollector 返回当前服务实例绑定的设备审计采集器。
func (s *Server) AuditCollector() *audit.Collector { return s.auditCollector }

// AuditLimiter 返回当前服务实例绑定的审计接口限流器。
func (s *Server) AuditLimiter() *AuditRateLimiter { return s.auditLimiter }

// LoadConfigSnapshot 读取最新不可变配置快照。
func (s *Server) LoadConfigSnapshot() (*config.Config, error) { return s.loadConfigSnapshot() }

// ReadConfigOrEmpty 读取最新不可变配置快照（不存在时返回零值配置）。
func (s *Server) ReadConfigOrEmpty() *config.Config { return s.readConfigOrEmpty() }

// SaveConfig 以 0600 原子落盘并立即写透更新内存快照。
func (s *Server) SaveConfig(cfg *config.Config) error { return s.saveConfig(cfg) }

func (s *Server) loadConfigSnapshot() (*config.Config, error) {
	if s.cfgStore == nil {
		return config.Load(configPathFor(s))
	}
	return s.cfgStore.LoadLatest()
}

func (s *Server) readConfigOrEmpty() *config.Config {
	cfg, err := s.loadConfigSnapshot()
	if err == nil && cfg != nil {
		return cfg
	}
	if s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		return s.cfgStore.Get()
	}
	return &config.Config{}
}

func (s *Server) loadMutableConfig() *config.Config {
	cfgPath := configPathFor(s)
	snap, err := s.loadConfigSnapshot()
	if err == nil && snap != nil {
		cp := snap.Clone()
		if cp.SourcePath() == "" && cfgPath != "" {
			cp.SetSourcePath(cfgPath)
		}
		return cp
	}
	if s.cfgStore != nil && s.cfgStore.Revision() > 0 {
		cp := s.cfgStore.GetClone()
		if cp.SourcePath() == "" && cfgPath != "" {
			cp.SetSourcePath(cfgPath)
		}
		return cp
	}
	empty := &config.Config{}
	if cfgPath != "" {
		empty.SetSourcePath(cfgPath)
	}
	return empty
}

func (s *Server) saveConfig(cfg *config.Config) error {
	if err := config.Save(configPathFor(s), cfg); err != nil {
		return err
	}
	if s.cfgStore != nil {
		s.cfgStore.Set(cfg)
	}
	return nil
}

func (s *Server) invalidateConfigStore() {
	if s.cfgStore != nil {
		s.cfgStore.Invalidate()
	}
}

func (s *Server) buildLifecycle(bgCtx context.Context, cancelBg context.CancelFunc) *lifecycle.Group {
	g := lifecycle.NewGroup(lifecycle.WithCloseTimeout(5 * time.Second))
	g.Add(
		lifecycle.FuncService{
			ServiceName: "webui-runtime",
			OnClose: func() error {
				if cancelBg != nil {
					cancelBg()
				}
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "webui-idle-scavenger",
			OnStart: func(context.Context) error {
				go s.runIdleScavengerLoop(bgCtx)
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "webui-dns-telemetry",
			OnStart: func(context.Context) error {
				go s.runDNSTelemetryLoop(bgCtx)
				return nil
			},
		},
		lifecycle.FuncService{
			ServiceName: "webui-pcdn-boot-sync",
			OnPostStart: func(context.Context) error {
				go s.ensureDefaultPCDNBlockWithContext(bgCtx)
				return nil
			},
		},
	)
	return g
}

// RequestShutdown 幂等、并发安全地请求当前 WebUI 服务优雅停止 HTTP 监听并释放端口。
func (s *Server) RequestShutdown() {
	if s == nil {
		return
	}
	s.shutdownReq.Store(true)
	s.shutdownOnce.Do(func() {
		if s.shutdownCh != nil {
			close(s.shutdownCh)
		}
	})
}

// ShutdownRequested 返回是否已触发优雅关闭请求。
func (s *Server) ShutdownRequested() bool {
	return s != nil && s.shutdownReq.Load()
}

// ServeContext 启动客户端 Web 面板与受控后台生命周期编排组，并在 ctx 取消或 RequestShutdown 时优雅关闭。
func (s *Server) ServeContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.shutdownReq.Load() {
		if !s.opts.EmbeddedInDaemon {
			removeOwnWebStateFile()
		}
		return nil
	}

	s.opts.Listen = NormalizeLegacyWildcardListen(s.opts.Listen)
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil && strings.HasPrefix(s.opts.Listen, ":") {
		ln, err = net.Listen("tcp4", "0.0.0.0"+s.opts.Listen)
	}
	if err != nil {
		return err
	}
	actualAddr := ln.Addr().String()
	if strings.TrimSpace(s.opts.Listen) == "" || strings.HasSuffix(strings.TrimSpace(s.opts.Listen), ":0") {
		s.opts.Listen = actualAddr
	}

	bgCtx, cancelBg := context.WithCancel(ctx)
	lc := s.buildLifecycle(bgCtx, cancelBg)
	if err := lc.Start(bgCtx); err != nil {
		cancelBg()
		_ = ln.Close()
		return err
	}
	defer func() {
		cancelBg()
		_ = lc.Close()
	}()

	if s.opts.OnReady != nil {
		s.opts.OnReady(actualAddr)
	}
	s.printBanner(ln)

	srv := &http.Server{
		Handler:           s.Handler(),
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
		case <-s.shutdownCh:
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(shutCtx)
			shutCancel()
		case <-serveDone:
		}
	}()

	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) && (ctx.Err() != nil || s.shutdownReq.Load()) {
		if s.shutdownReq.Load() && !s.opts.EmbeddedInDaemon {
			removeOwnWebStateFile()
		}
		return nil
	}
	return err
}

// ListenAndServe 启动 HTTP 服务(阻塞)。
func (s *Server) ListenAndServe() error {
	return s.ServeContext(context.Background())
}

func (s *Server) ensureDefaultPCDNBlockWithContext(ctx context.Context) {
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	if ctx.Err() != nil || daemon.IsDaemonRunning() || strings.TrimSpace(s.opts.ConfigPath) == "" {
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	enforcer := s.newAuditEnforcer(cfg)
	if applied, syncErr := enforcer.EnsureDefaultPCDNBlock(runCtx); syncErr != nil {
		logger.Warn("[Audit] WebUI 启动同步内置防 PCDN 规则集失败: %v", syncErr)
	} else if applied {
		s.invalidateConfigStore()
		logger.Info("[Audit] 已通过 WebUI 启动自检启用内置防 PCDN 规则集并热重载 sing-box")
	}
}

func (s *Server) printBanner(ln net.Listener) {
	logger.Success("SingCtl WebUI 已启动")
	for _, a := range FormatListenURLs(ln.Addr().String()) {
		logger.Info("  ➜  http://%s", a)
	}
	if s.opts.Password == "" {
		logger.Warn("  ⚠  未设置访问口令,请确保仅暴露在可信内网(建议 --password 或 SINGCTL_WEB_PASSWORD)")
	}
}

func lanIPv4() string {
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					return ipnet.IP.String()
				}
			}
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	httpx.WriteJSON(w, status, v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	httpx.WriteError(w, httpx.NewStatusError(status, cmp.Or(msg, "unknown error"), nil))
}
