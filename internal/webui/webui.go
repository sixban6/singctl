// Package webui 提供 singctl 的 Web 管理界面。
//
// 设计原则:
//   - 非侵入:所有"动作"通过重新执行 singctl 自身子命令完成,复用既有 CLI 逻辑;
//   - 零依赖:仅使用 Go 标准库,前端资源内嵌,适配 OpenWrt 等嵌入式系统;
//   - 单任务:同一时刻只允许一个动作执行,避免并发写配置冲突。
package webui

import (
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

	"singctl/internal/logger"
	"singctl/internal/util/netinfo"
)

// sessionCookieName 持久化 Cookie 键名,用于 Safari/PWA 独立沙盒免密免登
const SessionCookieName = "singctl_session"

//go:embed static
var staticFS embed.FS

// Options Web 服务配置
type Options struct {
	ConfigPath            string                  // singctl 配置文件路径
	SingBoxConfigPath     string                  // 可选：测试/定制 sing-box config.json 路径（留空使用 constant.SingBoxConfigFile）
	SingBoxWorkConfigPath string                  // 可选：测试/定制沙盒副本 config.json 路径
	Listen                string                  // 监听地址,如 ":8090"
	Password              string                  // 可选的访问口令(空=不启用鉴权,建议仅在可信内网使用)
	Version               string                  // singctl 版本号
	OnReady               func(listenAddr string) // Listen 成功后的回调(后台子进程用于就绪握手)
}

// Server Web 管理服务
type Server struct {
	opts Options

	Mux *http.ServeMux

	// iOS 配置生成缓存: 实时生成需拉订阅(秒级), 缓存让 SFI 同步/重复扫码瞬时返回
	iosMu       sync.Mutex
	iosCacheKey string // singctl.yaml 的 path|mtime|size 指纹
	iosCacheVal string

	cfgMu        sync.Mutex
	auditLimiter *auditRateLimiter

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
}

// New 创建 Web 服务
func New(opts Options) *Server {
	s := &Server{
		opts:         opts,
		Mux:          http.NewServeMux(),
		auditLimiter: newAuditRateLimiter(),
	}

	// 静态资源（统一受 WebUI 口令鉴权保护）
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	s.Mux.Handle("/", s.authOnly(fileServer))

	// 只读 API
	s.Mux.HandleFunc("GET /api/status", s.guard(s.handleStatus))
	s.Mux.HandleFunc("GET /api/health", s.guard(s.handleHealth))
	s.Mux.HandleFunc("GET /api/config", s.guard(s.handleConfigGet))
	s.Mux.HandleFunc("PUT /api/config", s.guard(s.handleConfigPut))
	s.Mux.HandleFunc("GET /api/config/raw", s.guard(s.handleConfigRawGet))
	s.Mux.HandleFunc("PUT /api/config/raw", s.guard(s.handleConfigRawPut))
	s.Mux.HandleFunc("GET /api/cache", s.guard(s.handleCache))
	s.Mux.HandleFunc("GET /api/logs", s.guard(s.handleLogs))

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
	s.Mux.HandleFunc("POST /api/sbconfig/restore", s.guard(s.handleSbConfigRestore))
	s.Mux.HandleFunc("GET /api/traffic-routing", s.guard(s.handleTrafficRoutingGet))
	s.Mux.HandleFunc("PUT /api/traffic-routing", s.guard(s.handleTrafficRoutingPut))

	// 看门狗守护与策略组容灾控制 API
	s.Mux.HandleFunc("GET /api/watchdog", s.guard(s.handleWatchdogGet))
	s.Mux.HandleFunc("PUT /api/watchdog/config", s.guard(s.handleWatchdogConfigPut))
	s.Mux.HandleFunc("POST /api/watchdog/patrol", s.guard(s.handleWatchdogPatrolPost))

	// 局域网设备行为审计与双层一键拉黑 API
	s.Mux.HandleFunc("GET /api/audit", s.guard(s.handleAuditGet))
	s.Mux.HandleFunc("GET /api/audit/ai-config", s.guard(s.handleAuditAIConfigGet))
	s.Mux.HandleFunc("POST /api/audit/ai-config", s.guard(s.handleAuditAIConfigPost))
	s.Mux.HandleFunc("POST /api/audit/ai-review", s.guard(s.handleAuditAIReviewPost))
	s.Mux.HandleFunc("POST /api/audit/block", s.guard(s.handleAuditBlock))
	s.Mux.HandleFunc("POST /api/audit/unblock", s.guard(s.handleAuditUnblock))
	s.Mux.HandleFunc("POST /api/audit/whitelist", s.guard(s.handleAuditWhitelist))

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
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	if s.opts.OnReady != nil {
		s.opts.OnReady(ln.Addr().String())
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

// setAuthCookie 若客户端未携带或携带无效 Cookie, 在通过鉴权后下发 30 天持久化 Cookie
func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request) {
	token := s.SessionToken()
	if token == "" {
		return
	}
	if c, err := r.Cookie(SessionCookieName); err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(token)) == 1 {
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

// guard 包装器:统一鉴权、反爬虫头注入、JSON 错误输出、方法校验
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="SingCtl WebUI"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
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

// authOnly 仅鉴权(用于静态资源,不校验 Content-Type)
func (s *Server) authOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="SingCtl WebUI"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.setAuthCookie(w, r)
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

// ───────────────────────── 内部工具 ─────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
