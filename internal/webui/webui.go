// Package webui 提供 singctl 的 Web 管理界面。
//
// 设计原则:
//   - 非侵入:所有"动作"通过重新执行 singctl 自身子命令完成,复用既有 CLI 逻辑;
//   - 零依赖:仅使用 Go 标准库,前端资源内嵌,适配 OpenWrt 等嵌入式系统;
//   - 单任务:同一时刻只允许一个动作执行,避免并发写配置冲突。
package webui

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"singctl/internal/audit"
	"singctl/internal/gateway"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"
)

// sessionCookieName 持久化 Cookie 键名,用于 Safari/PWA 独立沙盒免密免登
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
	s.Mux.HandleFunc("POST /api/audit/whitelist", s.guard(s.handleAuditWhitelist))
	s.Mux.HandleFunc("POST /api/audit/close-connections", s.guard(s.handleAuditCloseConnections))

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

// ListenAndServe 启动 HTTP 服务(阻塞)
func (s *Server) ListenAndServe() error {
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
	if s.opts.OnReady != nil {
		s.opts.OnReady(actualAddr)
	}

	s.printBanner(ln)
	srv := &http.Server{Handler: s.Mux}
	return srv.Serve(ln)
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

// sessionToken 根据访问口令派生无状态持久化 Token (HMAC-SHA256)
func (s *Server) SessionToken() string {
	if s.opts.Password == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("singctl-webui-session-salt-v1"))
	mac.Write([]byte(s.opts.Password))
	return hex.EncodeToString(mac.Sum(nil))
}

// issueAuthCookie 强制下发 30 天持久化 Cookie
func (s *Server) issueAuthCookie(w http.ResponseWriter) {
	token := s.SessionToken()
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   30 * 86400, // 30 天持久化,完美解决 iOS 添加到主屏幕后频繁要求输密码的问题
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// setAuthCookie 若客户端未携带或携带无效 Cookie, 在通过鉴权后下发 30 天持久化 Cookie
func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request) {
	token := s.SessionToken()
	if token == "" {
		return
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) == 1 {
		return
	}
	s.issueAuthCookie(w)
}

// guard 包装器:统一鉴权、反爬虫头注入、JSON 错误输出、方法校验
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if !s.authorized(r) {
			// 前端 XHR 请求携带 X-Requested-With 时不返回 WWW-Authenticate，避免浏览器乱弹原生 Basic Auth 框
			if r.Header.Get("X-Requested-With") == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="SingCtl WebUI"`)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":        "unauthorized",
				"authRequired": true,
			})
			return
		}
		s.setAuthCookie(w, r)
		// 轻量 CSRF 与包体上限防护: 写操作限制请求体 <= 4MB 并要求 JSON Content-Type(跨站表单无法伪造)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}
		}
		next(w, r)
	}
}

// authOnly 仅鉴权(用于静态资源,不校验 Content-Type)。
// 关键修复：
//  1. 首页 `/` 与 `/index.html` 强制 `Cache-Control: no-store`，彻底消除自更新后浏览器缓存旧 index.html 导致白屏或 401 刷新死循环；
//  2. 未授权访问首页时返回 401 状态码 + 自包含口令登录页（不发 WWW-Authenticate），彻底告别 Safari/PWA/移动端不弹 Basic Auth 框导致无法登录。
func (s *Server) authOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !s.authorized(r) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.URL.Path == "/" || r.URL.Path == "/index.html") {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte(embeddedLoginHTML))
				}
				return
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.setAuthCookie(w, r)
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		}
		next.ServeHTTP(w, r)
	})
}

// authorized 校验多通道凭据 (支持 Cookie、Bearer Token、URL 参数、Basic Auth)
func (s *Server) authorized(r *http.Request) bool {
	if s.opts.Password == "" {
		return true
	}
	expectedToken := s.SessionToken()

	// 1. 持久化 Cookie (最适合 iOS 桌面 WebApp 沙盒持久化)
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expectedToken)) == 1 {
			return true
		}
	}

	// 2. Header: Authorization: Bearer <token>
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1 {
			return true
		}
	}

	// 3. URL Query 参数 (?token=... 或 ?password=...), 方便添加到手机桌面时内嵌免密凭据
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		if subtle.ConstantTimeCompare([]byte(qToken), []byte(expectedToken)) == 1 {
			return true
		}
	}
	if qPass := r.URL.Query().Get("password"); qPass != "" {
		if subtle.ConstantTimeCompare([]byte(qPass), []byte(s.opts.Password)) == 1 {
			return true
		}
	}

	// 4. 标准 HTTP Basic Auth (admin / password)
	user, pass, ok := r.BasicAuth()
	if ok && user == "admin" {
		if subtle.ConstantTimeCompare([]byte(pass), []byte(s.opts.Password)) == 1 {
			return true
		}
	}

	return false
}

// guardIOSDownload iOS 配置下载端点专用鉴权
func (s *Server) guardIOSDownload(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleAuthCheck 公开鉴权在线探测接口（供前端自更新热重启重连探测及会话校验使用，未登录不泄漏敏感信息）
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	authed := s.authorized(r)
	if authed {
		s.setAuthCookie(w, r)
	}
	resp := map[string]any{
		"ok":            true,
		"authRequired":  s.opts.Password != "",
		"authenticated": authed,
	}
	if authed && s.opts.Version != "" {
		resp["version"] = s.opts.Version
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAuthLogin 内嵌口令登录接口：恒定时间校验口令、同 IP 限流防爆破，成功后下发 30 天 HttpOnly Cookie 及会话 Token
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	clientIP := remoteClientIP(r)
	if s.loginLimiter != nil && !s.loginLimiter.allow(clientIP) {
		writeJSONError(w, http.StatusTooManyRequests, "登录尝试过于频繁，请 5 分钟后再试")
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	if s.opts.Password == "" {
		if s.loginLimiter != nil {
			s.loginLimiter.reset(clientIP)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": ""})
		return
	}

	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.opts.Password)) != 1 {
		if s.loginLimiter != nil {
			s.loginLimiter.recordFailure(clientIP)
		}
		writeJSONError(w, http.StatusUnauthorized, "访问口令错误，请重试")
		return
	}

	if s.loginLimiter != nil {
		s.loginLimiter.reset(clientIP)
	}
	s.issueAuthCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"token": s.SessionToken(),
	})
}

// handleLogout 登出并清理 Cookie
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "已退出登录"})
}

// handleSessionURL 返回手机添加到主屏幕专用的免密访问 URL (含局域网 IP 与持久 Token)
func (s *Server) handleSessionURL(w http.ResponseWriter, r *http.Request) {
	lanIP := "127.0.0.1"
	if ni, err := netinfo.Get(); err == nil && ni.LANIPv4 != "" {
		lanIP = ni.LANIPv4
	}
	_, port, err := net.SplitHostPort(s.opts.Listen)
	if err != nil || port == "" {
		port = "8090"
	}
	targetURL := fmt.Sprintf("http://%s:%s/", lanIP, port)
	token := s.SessionToken()
	if token != "" {
		targetURL += "?token=" + token
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"url":   targetURL,
		"token": token,
	})
}

// ───────────────────────── 登录防爆破限流器 ─────────────────────────

type loginAttemptEntry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
}

type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttemptEntry
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{entries: make(map[string]*loginAttemptEntry)}
}

func (l *loginRateLimiter) allow(ip string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.entries) > 256 {
		for k, v := range l.entries {
			if now.Sub(v.windowStart) > 10*time.Minute && now.After(v.lockedUntil) {
				delete(l.entries, k)
			}
		}
	}
	ent, ok := l.entries[ip]
	if !ok {
		return true
	}
	if now.Before(ent.lockedUntil) {
		return false
	}
	if now.Sub(ent.windowStart) > 5*time.Minute {
		delete(l.entries, ip)
	}
	return true
}

func (l *loginRateLimiter) recordFailure(ip string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	ent, ok := l.entries[ip]
	if !ok || now.Sub(ent.windowStart) > 5*time.Minute {
		ent = &loginAttemptEntry{windowStart: now}
		l.entries[ip] = ent
	}
	ent.failures++
	if ent.failures >= 8 {
		ent.lockedUntil = now.Add(5 * time.Minute)
	}
}

func (l *loginRateLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.entries, ip)
	l.mu.Unlock()
}

func remoteClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

const embeddedLoginHTML = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover" />
  <meta name="robots" content="noindex,nofollow" />
  <title>SingCtl WebUI · 访问验证</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #f4f6fb;
      --card: #ffffff;
      --border: rgba(15, 23, 42, 0.09);
      --text: #0f172a;
      --muted: #64748b;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --danger: #dc2626;
      --danger-bg: rgba(220, 38, 38, 0.08);
      --input-bg: #f8fafc;
      --shadow: 0 20px 50px rgba(15, 23, 42, 0.08);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #090d16;
        --card: #111827;
        --border: rgba(148, 163, 184, 0.16);
        --text: #f8fafc;
        --muted: #94a3b8;
        --accent: #3b82f6;
        --accent-hover: #2563eb;
        --danger: #f87171;
        --danger-bg: rgba(248, 113, 113, 0.12);
        --input-bg: #0b1120;
        --shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.12), transparent 55%), var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif;
    }
    .card {
      width: 100%;
      max-width: 390px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px 24px;
      box-shadow: var(--shadow);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 18px;
    }
    .logo {
      width: 40px;
      height: 40px;
      border-radius: 11px;
      background: linear-gradient(135deg, #2563eb, #06b6d4);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-weight: 700;
      font-size: 18px;
      flex-shrink: 0;
    }
    h1 {
      margin: 0;
      font-size: 18px;
      font-weight: 700;
      letter-spacing: -0.01em;
    }
    .sub {
      margin: 2px 0 0;
      font-size: 12.5px;
      color: var(--muted);
    }
    label {
      display: block;
      font-size: 12.5px;
      font-weight: 600;
      margin-bottom: 8px;
      color: var(--muted);
    }
    .field {
      position: relative;
      margin-bottom: 14px;
    }
    input {
      width: 100%;
      height: 42px;
      padding: 0 62px 0 13px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: var(--input-bg);
      color: var(--text);
      font-size: 14px;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus { border-color: var(--accent); }
    .toggle {
      position: absolute;
      right: 8px;
      top: 50%;
      transform: translateY(-50%);
      border: none;
      background: transparent;
      color: var(--muted);
      font-size: 12px;
      padding: 4px 6px;
      cursor: pointer;
    }
    .err {
      display: none;
      margin-bottom: 14px;
      padding: 9px 12px;
      border-radius: 10px;
      background: var(--danger-bg);
      color: var(--danger);
      font-size: 12.5px;
      line-height: 1.45;
    }
    .btn {
      width: 100%;
      height: 42px;
      border: none;
      border-radius: 10px;
      background: var(--accent);
      color: #fff;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s, opacity 0.15s;
    }
    .btn:hover:not(:disabled) { background: var(--accent-hover); }
    .btn:disabled { opacity: 0.65; cursor: not-allowed; }
    .hint {
      margin-top: 14px;
      font-size: 11.5px;
      color: var(--muted);
      text-align: center;
    }
  </style>
</head>
<body>
  <form class="card" id="loginForm" autocomplete="on">
    <div class="brand">
      <div class="logo">S</div>
      <div>
        <h1>SingCtl 客户端控制台</h1>
        <p class="sub">请输入 WebUI 访问口令继续</p>
      </div>
    </div>
    <div class="err" id="errBox"></div>
    <label for="pwdInput">访问口令</label>
    <div class="field">
      <input id="pwdInput" name="password" type="password" autocomplete="current-password" placeholder="输入启动时设置的口令" required autofocus />
      <button type="button" class="toggle" id="toggleBtn">显示</button>
    </div>
    <button type="submit" class="btn" id="submitBtn">登录控制台</button>
    <div class="hint">验证成功后自动保持 30 天免密登录态</div>
  </form>
  <script>
    (function () {
      var form = document.getElementById('loginForm');
      var pwd = document.getElementById('pwdInput');
      var btn = document.getElementById('submitBtn');
      var errBox = document.getElementById('errBox');
      var toggleBtn = document.getElementById('toggleBtn');

      toggleBtn.addEventListener('click', function () {
        var show = pwd.type === 'password';
        pwd.type = show ? 'text' : 'password';
        toggleBtn.textContent = show ? '隐藏' : '显示';
        pwd.focus();
      });

      function showErr(msg) {
        errBox.textContent = msg;
        errBox.style.display = 'block';
      }

      form.addEventListener('submit', function (e) {
        e.preventDefault();
        var val = pwd.value || '';
        if (!val) {
          showErr('请输入访问口令');
          return;
        }
        errBox.style.display = 'none';
        btn.disabled = true;
        btn.textContent = '正在验证...';

        var ctrl = typeof AbortController !== 'undefined' ? new AbortController() : null;
        var timer = ctrl ? setTimeout(function () { ctrl.abort(); }, 10000) : null;

        fetch('/api/auth/login', {
          method: 'POST',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'SingCtlWebUI'
          },
          body: JSON.stringify({ password: val }),
          signal: ctrl ? ctrl.signal : undefined
        })
          .then(function (resp) {
            return resp.json().catch(function () { return {}; }).then(function (data) {
              if (!resp.ok) {
                throw new Error(data.error || ('验证失败 (HTTP ' + resp.status + ')'));
              }
              return data;
            });
          })
          .then(function (data) {
            try {
              if (data && data.token) {
                localStorage.setItem('sc_token', data.token);
              }
            } catch (_) {}
            var sep = window.location.pathname.indexOf('?') >= 0 ? '&' : '?';
            window.location.replace(window.location.pathname + sep + '_t=' + Date.now() + (window.location.hash || ''));
          })
          .catch(function (err) {
            if (err && err.name === 'AbortError') {
              showErr('登录请求超时，请检查网关连接后重试');
            } else {
              showErr((err && err.message) || '验证失败，请重试');
            }
            btn.disabled = false;
            btn.textContent = '登录控制台';
          })
          .finally(function () {
            if (timer) clearTimeout(timer);
          });
      });
    })();
  </script>
</body>
</html>`

// ───────────────────────── 内部工具 ─────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
