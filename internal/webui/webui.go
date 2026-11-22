// Package webui 提供 singctl 的客户端 Web 管理界面与控制面生命周期托管。
//
// 设计原则:
//   - 非侵入:所有"动作"通过重新执行 singctl 自身子命令完成,复用既有 CLI 逻辑;
//   - 零依赖:仅使用 Go 标准库,前端资源内嵌,适配 OpenWrt 等嵌入式系统;
//   - 单任务:同一时刻只允许一个动作执行,避免并发写配置冲突。
package webui

import (
	"cmp"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
	"singctl/internal/lifecycle"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
	"singctl/internal/tailscale"
)

// SessionCookieName 持久化 Cookie 键名,用于 Safari/PWA 独立沙盒免密免登
const SessionCookieName = "singctl_session"

//go:embed static
var staticFS embed.FS

// Options Web 服务配置
type Options struct {
	ConfigPath              string                                                                            // singctl 配置文件路径
	SingBoxConfigPath       string                                                                            // 可选：测试/定制 sing-box config.json 路径（留空使用 constant.SingBoxConfigFile）
	SingBoxWorkConfigPath   string                                                                            // 可选：测试/定制沙盒副本 config.json 路径
	AdGuardBinPath          string                                                                            // 可选：测试/定制 AdGuardHome 二进制路径
	AdGuardConfigPath       string                                                                            // 可选：测试/定制 AdGuardHome.yaml 路径
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
}

// Server Web 管理服务
type Server struct {
	opts Options

	Mux *http.ServeMux

	// iOS 配置生成缓存: 实时生成需拉订阅(秒级), 缓存让 SFI 同步/重复扫码瞬时返回
	iosMu       sync.Mutex
	iosCacheKey string // singctl.yaml 的 path|mtime|size 指纹
	iosCacheVal string

	cfgMu          sync.Mutex
	cfgStore       *config.Store
	auditLimiter   *auditRateLimiter
	auditCollector *audit.Collector
	loginLimiter   *loginRateLimiter

	// Clash 控制接口（endpoint + secret）短缓存，避免高频轮询重复探测 /version
	clashMu          sync.Mutex
	clashFingerprint string
	clashEndpoint    string
	clashSecret      string
	clashCachedAt    time.Time

	// /api/sb/traffic 按需后台采样器（无请求 15s 自动停止）
	trafficMu                  sync.Mutex
	trafficState               sbTrafficResponse
	trafficSampledAt           time.Time
	trafficLastReqAt           time.Time
	trafficRunning             bool
	trafficMemUnsupportedUntil time.Time

	tsP2PMu   sync.Mutex
	tsP2PCtrl *tailscale.P2PAssistController

	gwEDNSMu       sync.Mutex
	gwEDNSProfile  *netdiag.DNSResolverProfile
	gwEDNSCachedAt time.Time

	dohProbeMu        sync.Mutex
	dohProbeSnapshots map[string]dohProbeSnapshot
}

// New 创建 Web 服务
func New(opts Options) *Server {
	s := &Server{
		opts:           opts,
		Mux:            http.NewServeMux(),
		cfgStore:       config.NewStore(opts.ConfigPath),
		auditLimiter:   newAuditRateLimiter(),
		auditCollector: audit.NewCollector(nil),
		loginLimiter:   newLoginRateLimiter(),
	}

	// 静态资源（统一受 WebUI 口令鉴权保护，未授权访问 / 返回内嵌口令登录页而绝不弹窗卡死）
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	s.Mux.Handle("/", s.authOnly(fileServer))

	// 公开鉴权握手与登录 API（用于重启在线探测与内嵌登录，不泄漏敏感状态）
	s.Mux.HandleFunc("GET /api/auth/check", s.handleAuthCheck)
	s.Mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)

	// 只读 API
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

	// 登出 API (清除持久化 Cookie)
	s.Mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.Mux.HandleFunc("GET /api/session/url", s.guard(s.handleSessionURL))

	// iOS(sing-box App) 配置下载: 支持扫码 ?password= 鉴权(同时容忍尾斜杠)
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

	// Tailscale 局部配置、P2P 直连防线与 3 态双向管控 API
	s.Mux.HandleFunc("GET /api/tailscale/config", s.guard(s.handleTailscaleConfigGet))
	s.Mux.HandleFunc("PUT /api/tailscale/config", s.guard(s.handleTailscaleConfigPut))
	s.Mux.HandleFunc("GET /api/tailscale/p2p", s.guard(s.handleTailscaleP2PGet))
	s.Mux.HandleFunc("PUT /api/tailscale/p2p", s.guard(s.handleTailscaleP2PPut))
	s.Mux.HandleFunc("POST /api/tailscale/p2p/poke", s.guard(s.handleTailscaleP2PPokePost))

	// 系统全局加速镜像局部更新 API
	s.Mux.HandleFunc("PUT /api/system/mirror", s.guard(s.handleSystemMirrorPut))

	// Tailscale 两阶段零失联升级体检与状态轮询 API
	s.Mux.HandleFunc("GET /api/tailscale/upgrade/preflight", s.guard(s.handleTailscaleUpgradePreflightGet))
	s.Mux.HandleFunc("GET /api/tailscale/upgrade/status", s.guard(s.handleTailscaleUpgradeStatusGet))

	// 看门狗守护与策略组容灾控制 API
	s.Mux.HandleFunc("GET /api/watchdog", s.guard(s.handleWatchdogGet))
	s.Mux.HandleFunc("PUT /api/watchdog/config", s.guard(s.handleWatchdogConfigPut))
	s.Mux.HandleFunc("POST /api/watchdog/patrol", s.guard(s.handleWatchdogPatrolPost))

	// 客户端本地防劫持 DNS (AdGuard Home) 管控中心 API
	s.Mux.HandleFunc("GET /api/adguard", s.guard(s.handleAdGuardOverviewGet))
	s.Mux.HandleFunc("GET /api/adguard/credentials", s.guard(s.handleAdGuardCredentialsGet))
	s.Mux.HandleFunc("POST /api/adguard/credentials/reset", s.guard(s.handleAdGuardCredentialsResetPost))
	s.Mux.HandleFunc("POST /api/adguard/protection", s.guard(s.handleAdGuardProtectionPost))
	s.Mux.HandleFunc("POST /api/adguard/cache/clear", s.guard(s.handleAdGuardCacheClearPost))
	s.Mux.HandleFunc("POST /api/adguard/probe", s.guard(s.handleAdGuardProbePost))
	s.Mux.HandleFunc("POST /api/adguard/upstreams", s.guard(s.handleAdGuardUpstreamsPost))
	s.Mux.HandleFunc("POST /api/adguard/whitelist", s.guard(s.handleAdGuardWhitelistPost))
	s.Mux.HandleFunc("POST /api/adguard/rewrites", s.guard(s.handleAdGuardRewritesPost))
	s.Mux.HandleFunc("POST /api/adguard/filters", s.guard(s.handleAdGuardFiltersPost))

	// 局域网设备行为审计与双层一键拉黑 API
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

	// nftables inet security 防火墙加固可视化与规则治理 API
	s.Mux.HandleFunc("GET /api/firewall/overview", s.guard(s.handleFirewallOverviewGet))
	s.Mux.HandleFunc("GET /api/firewall/logs", s.guard(s.handleFirewallLogsGet))
	s.Mux.HandleFunc("POST /api/firewall/apply", s.guard(s.handleFirewallApplyPost))
	s.Mux.HandleFunc("POST /api/firewall/disable", s.guard(s.handleFirewallDisablePost))
	s.Mux.HandleFunc("POST /api/firewall/ban", s.guard(s.handleFirewallBanPost))
	s.Mux.HandleFunc("POST /api/firewall/unban", s.guard(s.handleFirewallUnbanPost))
	s.Mux.HandleFunc("POST /api/firewall/clear-dynamic", s.guard(s.handleFirewallClearDynamicPost))
	s.Mux.HandleFunc("POST /api/firewall/whitelist", s.guard(s.handleFirewallWhitelistPost))

	// 原生 sing-box 策略组切换、测速、运行模式与实时速率 API（全部经由 WebUI 登录态统一鉴权）
	s.Mux.HandleFunc("GET /api/sb/proxies", s.guard(s.handleSbProxiesGet))
	s.Mux.HandleFunc("PUT /api/sb/proxies/switch", s.guard(s.handleSbProxySwitchPut))
	s.Mux.HandleFunc("POST /api/sb/proxies/delay", s.guard(s.handleSbProxyDelayPost))
	s.Mux.HandleFunc("PUT /api/sb/mode", s.guard(s.handleSbModePut))
	s.Mux.HandleFunc("GET /api/sb/traffic", s.guard(s.handleSbTrafficGet))

	// 动作 API(流式输出)
	s.Mux.HandleFunc("POST /api/action", s.guard(s.handleAction))

	return s
}

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

// loadMutableConfig 返回独立深拷贝的可变配置实例，严禁原地修改共享只读快照指针。
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
			ServiceName: "webui-pcdn-boot-sync",
			OnPostStart: func(context.Context) error {
				go s.ensureDefaultPCDNBlockWithContext(bgCtx)
				return nil
			},
		},
	)
	return g
}

// ServeContext 启动客户端 Web 面板与受控后台生命周期编排组，并在 ctx 取消时优雅关闭。
func (s *Server) ServeContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.opts.Listen = NormalizeLegacyWildcardListen(s.opts.Listen)
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil && strings.HasPrefix(s.opts.Listen, ":") {
		// 纯 IPv4 内核兜底
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

// ListenAndServe 启动 HTTP 服务(阻塞)
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

// lanIPv4 返回第一个非回环内网 IPv4(无则空串)
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
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": cmp.Or(msg, "unknown error")})
}
