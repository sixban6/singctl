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
	ConfigPath string // singctl 配置文件路径
	Listen     string // 监听地址,如 ":8090"
	Password   string // 可选的访问口令(空=不启用鉴权,建议仅在可信内网使用)
	Version    string // singctl 版本号
}

// Server Web 管理服务
type Server struct {
	opts Options

	mu       sync.Mutex // 保护 busy
	busy     bool       // 是否有动作正在执行
	actionTx string     // 当前执行中的动作名

	mux *http.ServeMux
}

// New 创建 Web 服务
func New(opts Options) *Server {
	s := &Server{opts: opts, mux: http.NewServeMux()}

	// 静态资源(同样受鉴权保护)
	staticContent, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(staticContent))
	s.mux.Handle("GET /", s.authOnly(fileServer))

	// 只读 API
	s.mux.HandleFunc("GET /api/status", s.guard(s.handleStatus))
	s.mux.HandleFunc("GET /api/health", s.guard(s.handleHealth))
	s.mux.HandleFunc("GET /api/config", s.guard(s.handleConfigGet))
	s.mux.HandleFunc("PUT /api/config", s.guard(s.handleConfigPut))
	s.mux.HandleFunc("GET /api/config/raw", s.guard(s.handleConfigRawGet))
	s.mux.HandleFunc("PUT /api/config/raw", s.guard(s.handleConfigRawPut))
	s.mux.HandleFunc("GET /api/cache", s.guard(s.handleCache))
	s.mux.HandleFunc("GET /api/logs", s.guard(s.handleLogs))

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

	s.printBanner(ln)
	srv := &http.Server{Handler: s.mux}
	return srv.Serve(ln)
}

func (s *Server) printBanner(ln net.Listener) {
	logger.Success("SingCtl WebUI 已启动")
	addrs := listenAddresses(ln)
	for _, a := range addrs {
		logger.Info("  ➜  http://%s", a)
	}
	if s.opts.Password == "" {
		logger.Warn("  ⚠  未设置访问口令,请确保仅暴露在可信内网(建议 --password 或 SINGCTL_WEB_PASSWORD)")
	}
}

// listenAddresses 返回适合展示的访问地址(优先内网 IP)
func listenAddresses(ln net.Listener) []string {
	port := "8090"
	if addr, ok := ln.Addr().(*net.TCPAddr); ok && addr.Port != 0 {
		port = itoa(addr.Port)
	}

	var lan, loopback string
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, a := range addrs {
				if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
					if lan == "" {
						lan = ipnet.IP.String()
					}
				}
			}
		}
	}
	loopback = "127.0.0.1"

	var out []string
	if lan != "" {
		out = append(out, lan+":"+port)
	}
	out = append(out, loopback+":"+port)
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
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

// ───────────────────────── 内部工具 ─────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
