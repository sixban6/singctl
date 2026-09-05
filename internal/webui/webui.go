// Package webui 提供 singctl 的 Web 管理界面。
//
// 设计原则:
//   - 非侵入:所有"动作"通过重新执行 singctl 自身子命令完成,复用既有 CLI 逻辑;
//   - 零依赖:仅使用 Go 标准库,前端资源内嵌,适配 OpenWrt 等嵌入式系统;
//   - 单任务:同一时刻只允许一个动作执行,避免并发写配置冲突。
package webui

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"

	"singctl/internal/logger"
)

//go:embed static
var staticFS embed.FS

// Options Web 服务配置
type Options struct {
	ConfigPath string                  // singctl 配置文件路径
	Listen     string                  // 监听地址,如 ":8090"
	Password   string                  // 可选的访问口令(空=不启用鉴权,建议仅在可信内网使用)
	Version    string                  // singctl 版本号
	OnReady    func(listenAddr string) // Listen 成功后的回调(后台子进程用于就绪握手)
}

// Server Web 管理服务
type Server struct {
	opts Options

	mux *http.ServeMux

	// iOS 配置生成缓存: 实时生成需拉订阅(秒级), 缓存让 SFI 同步/重复扫码瞬时返回
	iosMu       sync.Mutex
	iosCacheKey string // singctl.yaml 的 path|mtime|size 指纹
	iosCacheVal string
}

// New 创建 Web 服务
func New(opts Options) *Server {
	s := &Server{opts: opts, mux: http.NewServeMux()}

	// 静态资源(同样受鉴权保护;不限方法,避免与 /clash/* 全方法代理模式冲突)
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	s.mux.Handle("/", s.authOnly(fileServer))

	// 只读 API
	s.mux.HandleFunc("GET /api/status", s.guard(s.handleStatus))
	s.mux.HandleFunc("GET /api/health", s.guard(s.handleHealth))
	s.mux.HandleFunc("GET /api/config", s.guard(s.handleConfigGet))
	s.mux.HandleFunc("PUT /api/config", s.guard(s.handleConfigPut))
	s.mux.HandleFunc("GET /api/config/raw", s.guard(s.handleConfigRawGet))
	s.mux.HandleFunc("PUT /api/config/raw", s.guard(s.handleConfigRawPut))
	s.mux.HandleFunc("GET /api/cache", s.guard(s.handleCache))
	s.mux.HandleFunc("GET /api/logs", s.guard(s.handleLogs))

	// iOS(sing-box App) 配置下载: 支持扫码 ?password= 鉴权(同时容忍尾斜杠)
	s.mux.HandleFunc("GET /api/gen/ios", s.guardIOSDownload(s.handleIOSConfig))
	s.mux.HandleFunc("GET /api/gen/ios/{$}", s.guardIOSDownload(s.handleIOSConfig))
	s.mux.HandleFunc("GET /api/gen/ios/url", s.guard(s.handleIOSConfigURL))

	// sing-box 配置文件编辑
	s.mux.HandleFunc("GET /api/sbconfig", s.guard(s.handleSbConfigGet))
	s.mux.HandleFunc("PUT /api/sbconfig", s.guard(s.handleSbConfigPut))
	s.mux.HandleFunc("POST /api/sbconfig/restore", s.guard(s.handleSbConfigRestore))

	// clash 控制面板与 API 反向代理(/clash/* 及根路径直通)
	s.setupClashProxy()

	// 动作 API(流式输出)
	s.mux.HandleFunc("POST /api/action", s.guard(s.handleAction))

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
	srv := &http.Server{Handler: s.mux}
	return srv.Serve(ln)
}

func (s *Server) printBanner(ln net.Listener) {
	logger.Success("SingCtl WebUI 已启动")
	for _, a := range formatListenURLs(ln.Addr().String()) {
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

// guard 包装器:统一鉴权、JSON 错误输出、方法校验
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="SingCtl WebUI"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// 轻量 CSRF 防护:写操作要求 JSON Content-Type(跨站表单无法伪造)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
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
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="SingCtl WebUI"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorized 校验 Basic Auth(可选)
func (s *Server) authorized(r *http.Request) bool {
	if s.opts.Password == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != "admin" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(pass), []byte(s.opts.Password)) == 1
}

// guardIOSDownload iOS 配置下载端点专用鉴权:
// 除 Basic Auth 外还接受 ?password= 查询参数 —— 手机扫码下载时 Safari 不便输入 Basic 凭据,
// 二维码 URL 会内嵌口令(与 Basic 口令同一秘密, 泄露面等价)
func (s *Server) guardIOSDownload(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Password != "" && !s.authorized(r) {
			q := r.URL.Query().Get("password")
			if subtle.ConstantTimeCompare([]byte(q), []byte(s.opts.Password)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
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
