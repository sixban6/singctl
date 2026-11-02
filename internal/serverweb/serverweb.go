package serverweb

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
	"singctl/internal/util/netinfo"
)

//go:embed static
var staticFS embed.FS

const sessionCookieName = "singctl_server_session"

// Options 服务端 Web 界面配置
type Options struct {
	ConfigPath string
	Listen     string
	Username   string
	Password   string
	Version    string
	OnReady    func(listenAddr string)
}

// Server 服务端 Web 实例
type Server struct {
	opts       Options
	mux        *http.ServeMux
	mu         sync.RWMutex
	sessions   map[string]time.Time
	sessionsMu sync.RWMutex
	limiter    *IPLimiter
}

// New 创建服务端 Web 实例
func New(opts Options) *Server {
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
		}
	}
	if opts.Listen == "" {
		opts.Listen = "127.0.0.1:8092"
	}
	if opts.Username == "" {
		opts.Username = "singctl"
	}

	s := &Server{
		opts:     opts,
		mux:      http.NewServeMux(),
		sessions: make(map[string]time.Time),
		limiter:  NewIPLimiter(3, 10*time.Minute, 15*time.Minute),
	}

	// 静态单页面：放行静态资源，敏感 API 均受 guard 保护
	staticContent, err := fs.Sub(staticFS, "static")
	if err == nil {
		fileServer := http.FileServer(http.FS(staticContent))
		s.mux.Handle("/", fileServer)
	}

	// 运维核心 API (全部需要授权)
	s.mux.HandleFunc("GET /api/server/status", s.guard(s.handleStatus))
	s.mux.HandleFunc("GET /api/server/nodes", s.guard(s.handleNodes))
	s.mux.HandleFunc("GET /api/server/subscriptions", s.guard(s.handleSubscriptions))
	s.mux.HandleFunc("POST /api/server/action", s.guard(s.handleAction))
	s.mux.HandleFunc("POST /api/server/service/action", s.guard(s.handleServiceAction))
	s.mux.HandleFunc("GET /api/server/service/logs", s.guard(s.handleServiceLogs))
	s.mux.HandleFunc("GET /api/server/service/config", s.guard(s.handleServiceConfig))
	s.mux.HandleFunc("PUT /api/server/service/config", s.guard(s.handleUpdateServiceConfig))
	s.mux.HandleFunc("GET /api/server/net/return", s.guard(s.handleNetReturn))
	s.mux.HandleFunc("POST /api/server/net/return", s.guard(s.handleNetReturn))
	s.mux.HandleFunc("POST /api/server/bbr", s.guard(s.handleEnableBBR))
	s.mux.HandleFunc("GET /api/server/warp/diagnose", s.guard(s.handleWarpDiagnose))
	s.mux.HandleFunc("POST /api/server/path/regenerate", s.guard(s.handleRegeneratePath))
	s.mux.HandleFunc("PUT /api/server/sni", s.guard(s.handleUpdateSNI))
	s.mux.HandleFunc("PUT /api/server/cf-token", s.guard(s.handleUpdateCFToken))
	s.mux.HandleFunc("PUT /api/server/credentials", s.guard(s.handleUpdateCredentials))
	s.mux.HandleFunc("GET /api/server/logs/stream", s.guard(s.handleLogsSSE))
	s.mux.HandleFunc("GET /api/server/session/url", s.guard(s.handleSessionURL))
	s.mux.HandleFunc("GET /api/server/bans", s.guard(s.handleListBans))
	s.mux.HandleFunc("POST /api/server/unban", s.handleUnban)

	// 认证 API (公开访问)
	s.mux.HandleFunc("POST /api/server/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/server/logout", s.handleLogout)

	return s
}

// ListenAndServe 启动 HTTP 服务
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.opts.Listen)
	if err != nil {
		return err
	}
	if s.opts.OnReady != nil {
		s.opts.OnReady(ln.Addr().String())
	}

	logger.Success("SingCtl 服务端管理面板已启动")
	logger.Info("  ➜  http://%s", ln.Addr().String())

	srv := &http.Server{Handler: s.mux}
	return srv.Serve(ln)
}

func (s *Server) getUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.opts.Username != "" {
		return s.opts.Username
	}
	return "singctl"
}

func (s *Server) getPassword() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opts.Password
}

// sessionToken 生成 HMAC-SHA256 安全会话 Token (混合用户名与密码)
func (s *Server) sessionToken() string {
	pass := s.getPassword()
	user := s.getUsername()
	if pass == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("singctl-server-session-salt-v2"))
	mac.Write([]byte(user + ":" + pass))
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *Server) touchSession(token string) {
	if token == "" {
		return
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.sessions[token] = time.Now()
}

func (s *Server) isSessionValid(token string) bool {
	if token == "" {
		return false
	}
	s.sessionsMu.RLock()
	defer s.sessionsMu.RUnlock()
	last, ok := s.sessions[token]
	if !ok {
		// 如果刚启动不久且符合当前 token，允许首次 touch 注册
		return true
	}
	// 2 小时空闲超时
	return time.Since(last) < 2*time.Hour
}

func (s *Server) deleteSession(token string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	delete(s.sessions, token)
}

func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request) {
	token := s.sessionToken()
	if token == "" {
		return
	}
	s.touchSession(token)

	// 纯 Session Cookie (不设置 MaxAge 与 Expires，浏览器/手机标签页关闭即自动清除)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) authorized(r *http.Request) bool {
	expectedPass := s.getPassword()
	if expectedPass == "" {
		return true
	}
	expectedToken := s.sessionToken()
	expectedUser := s.getUsername()

	// 1. Session Cookie (必须在 2 小时活跃期内)
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
		if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(expectedToken)) == 1 {
			if s.isSessionValid(cookie.Value) {
				s.touchSession(cookie.Value)
				return true
			}
		}
	}

	// 2. Bearer Header
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1 {
			if s.isSessionValid(token) {
				s.touchSession(token)
				return true
			}
		}
	}

	// 3. URL Query Token / Password
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		if subtle.ConstantTimeCompare([]byte(qToken), []byte(expectedToken)) == 1 {
			return true
		}
	}
	if qPass := r.URL.Query().Get("password"); qPass != "" {
		if subtle.ConstantTimeCompare([]byte(qPass), []byte(expectedPass)) == 1 {
			return true
		}
	}

	// 4. HTTP Basic Auth
	user, pass, ok := r.BasicAuth()
	if ok && user == expectedUser {
		if subtle.ConstantTimeCompare([]byte(pass), []byte(expectedPass)) == 1 {
			return true
		}
	}

	return false
}

func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeJSONError(w, http.StatusUnauthorized, "未授权访问，请先登录")
			return
		}
		s.setAuthCookie(w, r)
		next(w, r)
	}
}

// ───────────────────────── 核心 API ─────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	adminPath := cfg.Server.GetWebAdminPath()
	httpsURL := ""
	if subDomain != "" && adminPath != "" {
		httpsURL = fmt.Sprintf("https://%s%s/", subDomain, adminPath)
	}

	caddyRunning := checkServiceRunning("caddy")
	singboxRunning := checkServiceRunning("sing-box")
	substoreRunning := checkDockerRunning("sub-store")
	warpRunning := checkServiceRunning("wireproxy") || checkServiceRunning("warp-svc")

	status := map[string]any{
		"version":      s.opts.Version,
		"authEnabled":  s.getPassword() != "",
		"sessionToken": s.sessionToken(),
		"system":       getSystemMetrics(),
		"admin": map[string]any{
			"username": s.getUsername(),
			"path":     adminPath,
			"httpsUrl": httpsURL,
			"port":     cfg.Server.GetWebAdminPort(),
		},
		"services": map[string]any{
			"caddy": map[string]any{
				"running": caddyRunning,
				"pid":     getServicePID("caddy"),
				"uptime":  getServiceUptime("caddy"),
			},
			"singbox": map[string]any{
				"running": singboxRunning,
				"pid":     getServicePID("sing-box"),
				"uptime":  getServiceUptime("sing-box"),
			},
			"substore": map[string]any{
				"running": substoreRunning,
				"id":      getDockerContainerID("sub-store"),
			},
			"warp": map[string]any{
				"running":   warpRunning,
				"pid":       getServicePID("wireproxy"),
				"socksPort": 40000,
			},
		},
		"config": map[string]any{
			"nodeDomain":     cfg.Server.GetNodeDomain(),
			"substoreDomain": cfg.Server.GetSubstoreDomain(),
			"nodeTag":        cfg.Server.NodeTag,
			"sni":            cfg.Server.Sni,
			"hasCFToken":     cfg.Server.CFDNSKey != "",
		},
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "初始化服务端实例失败: "+err.Error())
		return
	}
	_ = sbs.LoadExistingCredentials()

	sbt := deploy.NewSubstore(cfg, "")
	adminURL, _ := sbt.GetAdminURL()
	vercelURL, _ := sbt.GetVercelAdminURL()

	res := map[string]any{
		"hy2": map[string]any{
			"link":     sbs.ShareLinkHy2,
			"port":     443,
			"protocol": "hysteria2",
			"domain":   cfg.Server.GetNodeDomain(),
		},
		"vless": map[string]any{
			"link":     sbs.ShareLinkVless,
			"port":     443,
			"protocol": "vless",
			"sni":      cfg.Server.Sni,
		},
		"substore": map[string]any{
			"adminUrl":  adminURL,
			"vercelUrl": vercelURL,
		},
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	sbs, _ := deploy.NewSingBoxServer(cfg)
	if sbs != nil {
		_ = sbs.LoadExistingCredentials()
	}

	sbt := deploy.NewSubstore(cfg, "")
	adminURL, _ := sbt.GetAdminURL()
	vercelURL, _ := sbt.GetVercelAdminURL()
	ssKey, _ := sbt.GetSubstoreKey()

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}

	rawSubURL := fmt.Sprintf("https://%s/download/collection/all", subDomain)
	if ssKey != "" {
		rawSubURL = fmt.Sprintf("https://%s/%s/download/collection/all", subDomain, ssKey)
	}

	// 各客户端直连导入 Scheme 深度链接
	importLinks := map[string]string{
		"shadowrocket": "sub://" + base64.StdEncoding.EncodeToString([]byte(rawSubURL+"?target=Shadowrocket")),
		"clash":        "clash://install-config?url=" + url.QueryEscape(rawSubURL+"?target=ClashMeta"),
		"singbox":      "sing-box://import-remote-profile?url=" + url.QueryEscape(rawSubURL+"?target=Sing-Box"),
		"surge":        "surge:///install-config?url=" + url.QueryEscape(rawSubURL+"?target=Surge"),
		"loon":         "loon://import?url=" + url.QueryEscape(rawSubURL+"?target=Loon"),
	}

	res := map[string]any{
		"substoreKey":       ssKey,
		"substoreAdminUrl":  adminURL,
		"substoreVercelUrl": vercelURL,
		"subscriptionUrl":   rawSubURL,
		"importLinks":       importLinks,
		"nodes": map[string]any{
			"hy2": map[string]any{
				"link":   sbs.ShareLinkHy2,
				"domain": cfg.Server.GetNodeDomain(),
				"port":   443,
			},
			"vless": map[string]any{
				"link": sbs.ShareLinkVless,
				"sni":  cfg.Server.Sni,
				"port": 443,
			},
		},
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	action := strings.ToLower(strings.TrimSpace(body.Action))
	service := strings.ToLower(strings.TrimSpace(body.Service))

	if action != "start" && action != "stop" && action != "restart" && action != "reload" {
		writeJSONError(w, http.StatusBadRequest, "不支持的动作: "+action)
		return
	}

	var cmdErr error
	switch service {
	case "caddy":
		if action == "reload" {
			cmdErr = exec.Command("caddy", "reload", "--config", "/etc/caddy/Caddyfile").Run()
			if cmdErr != nil {
				cmdErr = exec.Command("systemctl", "reload", "caddy").Run()
			}
		} else {
			cmdErr = exec.Command("systemctl", action, "caddy").Run()
		}
	case "singbox":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("systemctl", action, "sing-box").Run()
	case "substore":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("docker", action, "sub-store").Run()
	case "warp":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("systemctl", action, "wireproxy").Run()
		if cmdErr != nil {
			cmdErr = exec.Command("systemctl", action, "warp-svc").Run()
		}
	case "all":
		_ = exec.Command("systemctl", "restart", "sing-box").Run()
		_ = exec.Command("systemctl", "restart", "caddy").Run()
		_ = exec.Command("docker", "restart", "sub-store").Run()
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	default:
		writeJSONError(w, http.StatusBadRequest, "未知服务: "+service)
		return
	}

	if cmdErr != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("执行 %s %s 失败: %v", service, action, cmdErr))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("服务 %s 动作 %s 执行成功", service, action),
	})
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	// 兼容老 handleAction 接口
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	switch body.Action {
	case "restart-caddy":
		_ = exec.Command("systemctl", "restart", "caddy").Run()
	case "restart-singbox":
		_ = exec.Command("systemctl", "restart", "sing-box").Run()
	case "restart-substore":
		_ = exec.Command("docker", "restart", "sub-store").Run()
	case "restart-warp":
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	default:
		writeJSONError(w, http.StatusBadRequest, "未知操作: "+body.Action)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "操作执行成功"})
}

func (s *Server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	linesStr := strings.TrimSpace(r.URL.Query().Get("lines"))
	lines := 100
	if n, err := strconv.Atoi(linesStr); err == nil && n > 0 && n <= 500 {
		lines = n
	}

	var output []byte
	var err error

	switch service {
	case "caddy":
		output, err = exec.Command("journalctl", "-u", "caddy", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	case "singbox":
		output, err = exec.Command("journalctl", "-u", "sing-box", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	case "substore":
		output, err = exec.Command("docker", "logs", "--tail", strconv.Itoa(lines), "sub-store").CombinedOutput()
	case "warp":
		output, err = exec.Command("journalctl", "-u", "wireproxy", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
		if err != nil || len(output) == 0 {
			output, _ = exec.Command("journalctl", "-u", "warp-svc", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
		}
	default:
		output, err = exec.Command("journalctl", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	}

	if err != nil && len(output) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": service,
			"logs":    fmt.Sprintf("读取日志失败或无日志: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"logs":    string(output),
	})
}

func (s *Server) handleServiceConfig(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	var path string
	switch service {
	case "singbox":
		path = "/etc/sing-box/config.json"
	case "caddy":
		path = "/etc/caddy/Caddyfile"
	case "warp":
		path = "/etc/wireproxy/wireproxy.conf"
	default:
		writeJSONError(w, http.StatusBadRequest, "未知服务配置")
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("无法读取配置文件 %s: %v", path, err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"path":    path,
		"content": string(content),
	})
}

func (s *Server) handleUpdateServiceConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求格式")
		return
	}

	service := strings.TrimSpace(body.Service)
	content := strings.TrimSpace(body.Content)
	if content == "" {
		writeJSONError(w, http.StatusBadRequest, "配置内容不能为空")
		return
	}

	var path string
	switch service {
	case "singbox":
		path = "/etc/sing-box/config.json"
		var js json.RawMessage
		if err := json.Unmarshal([]byte(content), &js); err != nil {
			writeJSONError(w, http.StatusBadRequest, "sing-box 配置必须是合法的 JSON 格式: "+err.Error())
			return
		}
	case "caddy":
		path = "/etc/caddy/Caddyfile"
		tmpFile := "/tmp/Caddyfile.validate"
		if err := os.WriteFile(tmpFile, []byte(content), 0644); err == nil {
			defer os.Remove(tmpFile)
			cmd := exec.Command("caddy", "validate", "--config", tmpFile, "--adapter", "caddyfile")
			if out, err := cmd.CombinedOutput(); err != nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("Caddy 语法校验失败: %s", string(out)))
				return
			}
		}
	case "warp":
		path = "/etc/wireproxy/wireproxy.conf"
	default:
		writeJSONError(w, http.StatusBadRequest, "不支持编辑此服务配置: "+service)
		return
	}

	// 备份现有配置
	if old, err := os.ReadFile(path); err == nil {
		_ = os.WriteFile(path+".bak", old, 0644)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}

	// 自动重载/重启对应服务
	switch service {
	case "caddy":
		_ = exec.Command("caddy", "reload", "--config", path).Run()
	case "singbox":
		_ = exec.Command("systemctl", "restart", "sing-box").Run()
	case "warp":
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("服务 %s 配置文件已成功保存并重新加载", service),
	})
}

func (s *Server) handleNetReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	summary, err := netdiag.RunReturnRoute(ctx, 3)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "三网回程测试失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleWarpDiagnose(w http.ResponseWriter, r *http.Request) {
	res := diagnoseWARP()
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRegeneratePath(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	newPath := config.GenerateRandomAdminPath()
	cfg.Server.WebAdmin.Path = newPath
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存新随机路径失败: "+err.Error())
		return
	}

	// 重新渲染 Caddyfile 并热重载
	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("重新应用 Caddyfile 警告: %v", err)
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	newHTTPS := fmt.Sprintf("https://%s%s/", subDomain, newPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "全新隐蔽访问路径已生成并生效",
		"path":     newPath,
		"httpsUrl": newHTTPS,
	})
}

func (s *Server) handleUpdateSNI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SNI string `json:"sni"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SNI) == "" {
		writeJSONError(w, http.StatusBadRequest, "SNI 域名不能为空")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	cfg.Server.Sni = strings.TrimSpace(body.SNI)
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	// 1. 同步更新 Caddy Layer4 路由配置
	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("更新 Caddy SNI 警告: %v", err)
	}

	// 2. 更新 sing-box Reality 配置并重启
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err == nil {
		_ = sbs.LoadExistingCredentials()
		_ = sbs.DeploySingbox()

		// 3. 同步更新 Sub-Store 节点订阅
		sbt := deploy.NewSubstore(cfg, "")
		_ = sbt.UpdateSubstoreConfig(sbs)
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Reality SNI 已成功更新为 " + cfg.Server.Sni + " 并自动重载服务与订阅",
		"sni":     cfg.Server.Sni,
	})
}

func (s *Server) handleEnableBBR(w http.ResponseWriter, r *http.Request) {
	if err := deploy.EnableBBR(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "启用 TCP BBR 失败: "+err.Error())
		return
	}
	bbrOk := isBBREnabled()
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Google TCP BBR 拥塞控制算法已成功开启并立即生效",
		"bbr":     bbrOk,
	})
}

func (s *Server) handleUpdateCFToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" {
		writeJSONError(w, http.StatusBadRequest, "Cloudflare Token 不能为空")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	cfg.Server.CFDNSKey = strings.TrimSpace(body.Token)
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	if err := deploy.RotateCloudflareToken(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "轮换 Token 失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Cloudflare Token 已成功更新并重载 Caddy"})
}

func (s *Server) handleLogsSSE(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service == "" {
		service = "sing-box"
	}
	if service != "sing-box" && service != "caddy" && service != "wireproxy" {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	cmd := exec.CommandContext(r.Context(), "journalctl", "-u", service, "-n", "80", "-f", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(w, "data: 读取日志失败: %v\n\n", err)
		flusher.Flush()
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(w, "data: 启动日志进程失败: %v\n\n", err)
		flusher.Flush()
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "data: %s\n\n", line)
		flusher.Flush()
	}
	_ = cmd.Wait()
}

func (s *Server) handleSessionURL(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	subDomain := ""
	adminPath := ""
	if err == nil && cfg != nil {
		subDomain = cfg.Server.GetSubstoreDomain()
		if subDomain == "" {
			subDomain = cfg.Server.GetNodeDomain()
		}
		adminPath = cfg.Server.GetWebAdminPath()
	}

	targetURL := ""
	if subDomain != "" && adminPath != "" {
		targetURL = fmt.Sprintf("https://%s%s/", subDomain, adminPath)
	} else {
		lanIP := "127.0.0.1"
		if ni, err := netinfo.Get(); err == nil && ni.LANIPv4 != "" {
			lanIP = ni.LANIPv4
		}
		_, port, err := net.SplitHostPort(s.opts.Listen)
		if err != nil || port == "" {
			port = "8092"
		}
		targetURL = fmt.Sprintf("http://%s:%s/", lanIP, port)
	}

	token := s.sessionToken()
	writeJSON(w, http.StatusOK, map[string]string{
		"url":   targetURL,
		"token": token,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := GetClientIP(r)

	// 1. 防暴力破解：检查当前 IP 是否正处于封禁期
	if remaining, banned := s.limiter.CheckBan(clientIP); banned {
		mins := int(remaining.Minutes()) + 1
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
		writeJSONError(w, http.StatusTooManyRequests, fmt.Sprintf("密码错误已达 3 次，该 IP (%s) 已被安全封锁，请在 %d 分钟后再试", clientIP, mins))
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	user := s.getUsername()
	pass := s.getPassword()

	if pass != "" {
		inputUser := strings.TrimSpace(body.Username)
		userMatch := inputUser == "" || subtle.ConstantTimeCompare([]byte(inputUser), []byte(user)) == 1
		passMatch := subtle.ConstantTimeCompare([]byte(body.Password), []byte(pass)) == 1

		if !userMatch || !passMatch {
			banned, remaining, fails := s.limiter.RecordFailure(clientIP)
			if banned {
				mins := int(remaining.Minutes()) + 1
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
				writeJSONError(w, http.StatusTooManyRequests, fmt.Sprintf("密码错误已达 3 次，该 IP (%s) 已被安全封锁，请在 %d 分钟后再试", clientIP, mins))
				return
			}
			remainingAttempts := s.limiter.maxAttempts - fails
			writeJSONError(w, http.StatusUnauthorized, fmt.Sprintf("用户名或密码错误 (还剩 %d 次尝试机会)", remainingAttempts))
			return
		}
	}

	// 登录成功，重置当前 IP 失败计数并颁发会话凭据
	s.limiter.RecordSuccess(clientIP)
	s.setAuthCookie(w, r)
	token := s.sessionToken()
	writeJSON(w, http.StatusOK, map[string]any{
		"token":    token,
		"username": user,
		"message":  "登录成功",
	})
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	// 安全校验：仅允许本机 127.0.0.1 来源，或携带有效管理员凭据
	clientIP := GetClientIP(r)
	if !isWhitelisted(clientIP) && !s.authorized(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var body struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	targetIP := strings.TrimSpace(body.IP)
	if targetIP == "" {
		targetIP = "all"
	}

	s.limiter.Unban(targetIP)
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  fmt.Sprintf("已成功解封 IP: %s", targetIP),
		"unbanned": targetIP,
	})
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans := s.limiter.ListBans()
	banList := make([]map[string]any, 0, len(bans))
	for ip, rem := range bans {
		banList = append(banList, map[string]any{
			"ip":               ip,
			"remainingSeconds": int(rem.Seconds()),
			"remainingMinutes": int(rem.Minutes()) + 1,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bans": banList,
	})
}

func (s *Server) handleUpdateCredentials(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		NewUsername     string `json:"newUsername"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 数据")
		return
	}

	currentPass := s.getPassword()
	if currentPass != "" && subtle.ConstantTimeCompare([]byte(body.CurrentPassword), []byte(currentPass)) != 1 {
		writeJSONError(w, http.StatusForbidden, "当前管理密码错误，禁止修改")
		return
	}

	newPassword := strings.TrimSpace(body.NewPassword)
	// 严格校验新密码：至少 8 位，包含大写、小写、数字
	if !validatePasswordRules(newPassword) {
		writeJSONError(w, http.StatusBadRequest, "新管理密码需至少 8 位且必须同时包含大写字母、小写字母和数字")
		return
	}

	newUsername := strings.TrimSpace(body.NewUsername)
	if newUsername == "" {
		newUsername = s.getUsername()
	}
	if strings.EqualFold(newUsername, "admin") {
		writeJSONError(w, http.StatusBadRequest, "管理账号禁止使用通用的 admin，请设置个性化用户名")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置文件失败: "+err.Error())
		return
	}

	cfg.Server.WebAdmin.Username = newUsername
	cfg.Server.WebAdmin.Password = newPassword
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}

	s.mu.Lock()
	s.opts.Username = newUsername
	s.opts.Password = newPassword
	s.mu.Unlock()

	s.setAuthCookie(w, r)
	newToken := s.sessionToken()

	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "账号与密码修改成功，新凭据已生效",
		"username": newUsername,
		"token":    newToken,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		s.deleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "已安全退出登录"})
}

// ───────────────────────── 辅助工具与指标 ─────────────────────────

func validatePasswordRules(pass string) bool {
	if len(pass) < 8 {
		return false
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range pass {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasUpper && hasLower && hasDigit
}

func getSystemMetrics() map[string]any {
	m := map[string]any{
		"bbr":    isBBREnabled(),
		"uptime": getSystemUptime(),
	}

	// 内存
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, available uint64
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				switch fields[0] {
				case "MemTotal:":
					total, _ = strconv.ParseUint(fields[1], 10, 64)
				case "MemAvailable:":
					available, _ = strconv.ParseUint(fields[1], 10, 64)
				}
			}
		}
		if total > 0 {
			used := total - available
			m["memTotalMB"] = total / 1024
			m["memUsedMB"] = used / 1024
			m["memUsagePercent"] = fmt.Sprintf("%.1f%%", float64(used)/float64(total)*100)
		}
	}

	// 系统负载
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			m["loadAvg"] = fmt.Sprintf("%s, %s, %s", fields[0], fields[1], fields[2])
			m["load1"] = fields[0]
			m["load5"] = fields[1]
			m["load15"] = fields[2]
		}
	}

	// 磁盘空间
	out, err := exec.Command("df", "-h", "/").Output()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) >= 2 {
			fields := strings.Fields(lines[1])
			if len(fields) >= 5 {
				m["diskUsed"] = fields[2]
				m["diskTotal"] = fields[1]
				m["diskPercent"] = fields[4]
			}
		}
	}

	return m
}

func getSystemUptime() string {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) > 0 {
		secs, _ := strconv.ParseFloat(fields[0], 64)
		dur := (time.Duration(secs) * time.Second).Round(time.Minute)
		return dur.String()
	}
	return ""
}

func getServicePID(name string) string {
	out, err := exec.Command("systemctl", "show", "--property", "MainPID", "--value", name).Output()
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(out))
	if pid == "0" {
		return ""
	}
	return pid
}

func getServiceUptime(name string) string {
	out, err := exec.Command("systemctl", "show", "--property", "ActiveEnterTimestamp", "--value", name).Output()
	if err != nil {
		return ""
	}
	val := strings.TrimSpace(string(out))
	if val == "" {
		return ""
	}
	t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", val)
	if err != nil {
		return val
	}
	return time.Since(t).Round(time.Second).String()
}

func getDockerContainerID(containerName string) string {
	out, err := exec.Command("docker", "inspect", "-f", "{{.Id}}", containerName).Output()
	if err != nil {
		return ""
	}
	raw := strings.TrimSpace(string(out))
	if len(raw) > 12 {
		return raw[:12]
	}
	return raw
}

func checkServiceRunning(name string) bool {
	cmd := exec.Command("systemctl", "is-active", name)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out)) == "active"
}

func checkDockerRunning(containerName string) bool {
	cmd := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", containerName)
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

func isBBREnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(data)), "bbr")
}

func diagnoseWARP() map[string]any {
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			Proxy: func(req *http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:40000")
			},
		},
	}
	start := time.Now()
	resp, err := client.Get("https://cloudflare.com/cdn-cgi/trace")
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return map[string]any{
			"connected": false,
			"error":     err.Error(),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	trace := string(body)

	res := map[string]any{
		"connected": true,
		"latencyMs": latency,
		"warp":      "off",
	}
	for _, line := range strings.Split(trace, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			k, v := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			switch k {
			case "ip":
				res["ip"] = v
			case "loc":
				res["loc"] = v
			case "warp":
				res["warp"] = v
			}
		}
	}
	return res
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
