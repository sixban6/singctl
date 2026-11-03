package serverweb

import (
	"bufio"
	"context"
	"crypto/rand"
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
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
	"singctl/internal/subhub"
	"singctl/internal/util/netinfo"
)

//go:embed static
var staticFS embed.FS

const sessionCookieName = "singctl_server_session"

// Options 服务端 Web 界面配置
type Options struct {
	ConfigPath    string
	SubStoreDir   string // (可选) SubHub 数据存储目录，默认 /etc/sub-store
	BanFilePath   string // (可选) 防爆破封禁列表存储文件 (默认: <ConfigDir>/.serverweb_bans.json)
	AuditFilePath string // (可选) 管理操作审计日志存储文件 (默认: <ConfigDir>/.serverweb_audit.json)
	Listen        string
	Username      string
	Password      string
	Version       string
	OnReady       func(listenAddr string)
}

// Server 服务端 Web 实例
type Server struct {
	opts               Options
	mux                *http.ServeMux
	subStore           *subhub.Store
	mu                 sync.RWMutex
	sessions           map[string]sessionRecord
	sessionsMu         sync.Mutex
	limiter            *IPLimiter
	audit              *AuditManager
	geo                *IPGeoResolver
	passwordPendingAck bool
	gatewayToken       string
	cliToken           string
}

type sessionRecord struct {
	created time.Time
	last    time.Time
}

const (
	sessionIdleTTL     = 2 * time.Hour
	sessionAbsoluteTTL = 12 * time.Hour
	maxActiveSessions  = 50
)

func resolveBanFilePath(opts Options) string {
	if opts.BanFilePath != "" {
		return opts.BanFilePath
	}
	return ResolveBanFilePath(opts.ConfigPath)
}

// ResolveBanFilePath 返回指定配置文件对应的防爆破封禁持久化文件路径
func ResolveBanFilePath(configPath string) string {
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), ".serverweb_bans.json")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/.serverweb_bans.json"
	}
	return ""
}

// ResolveCLITokenPath 返回本机 root CLI 管理令牌文件路径 (0600)
func ResolveCLITokenPath(configPath string) string {
	if configPath != "" {
		return filepath.Join(filepath.Dir(configPath), ".serverweb_cli.token")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/.serverweb_cli.token"
	}
	return ""
}

func ensureCLIToken(tokenPath string) string {
	if strings.TrimSpace(tokenPath) == "" {
		return ""
	}
	if raw, err := os.ReadFile(tokenPath); err == nil {
		tok := strings.TrimSpace(string(raw))
		if len(tok) >= 32 {
			_ = os.Chmod(tokenPath, 0600)
			return tok
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	tok := hex.EncodeToString(buf)
	_ = os.MkdirAll(filepath.Dir(tokenPath), 0700)
	if err := os.WriteFile(tokenPath, []byte(tok+"\n"), 0600); err != nil {
		return ""
	}
	_ = os.Chmod(tokenPath, 0600)
	return tok
}

func resolveAuditFilePath(opts Options) string {
	if opts.AuditFilePath != "" {
		return opts.AuditFilePath
	}
	if opts.ConfigPath != "" {
		return filepath.Join(filepath.Dir(opts.ConfigPath), ".serverweb_audit.json")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/.serverweb_audit.json"
	}
	return ""
}

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

	s := &Server{
		opts:               opts,
		mux:                http.NewServeMux(),
		subStore:           subhub.NewStore(opts.SubStoreDir, ""),
		sessions:           make(map[string]sessionRecord),
		limiter:            NewIPLimiter(3, 10*time.Minute, 15*time.Minute, banFile),
		audit:              NewAuditManager(auditFile),
		geo:                NewIPGeoResolver(),
		passwordPendingAck: pendingAck,
		gatewayToken:       gatewayToken,
		cliToken:           cliToken,
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
	s.mux.HandleFunc("POST /api/server/subscriptions/sources", s.guard(s.handleUpsertSubscriptionSource))
	s.mux.HandleFunc("DELETE /api/server/subscriptions/sources", s.guard(s.handleDeleteSubscriptionSource))
	s.mux.HandleFunc("POST /api/server/subscriptions/rotate-key", s.guard(s.handleRotateSubscriptionKey))
	s.mux.HandleFunc("GET /api/server/subscriptions/preview", s.guard(s.handlePreviewSubscription))
	s.mux.HandleFunc("POST /api/server/action", s.guard(s.handleAction))
	s.mux.HandleFunc("POST /api/server/service/action", s.guard(s.handleServiceAction))
	s.mux.HandleFunc("GET /api/server/service/check-update", s.guard(s.handleCheckServiceUpdate))
	s.mux.HandleFunc("POST /api/server/service/upgrade", s.guard(s.handleUpgradeService))
	s.mux.HandleFunc("GET /api/server/service/logs", s.guard(s.handleServiceLogs))
	s.mux.HandleFunc("GET /api/server/service/config", s.guard(s.handleServiceConfig))
	s.mux.HandleFunc("PUT /api/server/service/config", s.guard(s.handleUpdateServiceConfig))
	s.mux.HandleFunc("GET /api/server/net/return", s.guard(s.handleNetReturn))
	s.mux.HandleFunc("POST /api/server/net/return", s.guard(s.handleNetReturn))
	s.mux.HandleFunc("POST /api/server/bbr", s.guard(s.handleEnableBBR))
	s.mux.HandleFunc("GET /api/server/warp/diagnose", s.guard(s.handleWarpDiagnose))
	s.mux.HandleFunc("POST /api/server/path/regenerate", s.guard(s.handleRegeneratePath))
	s.mux.HandleFunc("POST /api/server/mask-site/regenerate", s.guard(s.handleRegenerateMaskSite))
	s.mux.HandleFunc("PUT /api/server/sni", s.guard(s.handleUpdateSNI))
	s.mux.HandleFunc("PUT /api/server/cf-token", s.guard(s.handleUpdateCFToken))
	s.mux.HandleFunc("PUT /api/server/credentials", s.guard(s.handleUpdateCredentials))
	s.mux.HandleFunc("POST /api/server/credentials/ack", s.guard(s.handleAckCredentials))
	s.mux.HandleFunc("GET /api/server/logs/stream", s.guard(s.handleLogsSSE))
	s.mux.HandleFunc("GET /api/server/session/url", s.guard(s.handleSessionURL))
	s.mux.HandleFunc("GET /api/server/bans", s.guard(s.handleListBans))
	s.mux.HandleFunc("POST /api/server/unban", s.guard(s.handleUnban))
	s.mux.HandleFunc("GET /api/server/audit-logs", s.guard(s.handleListAuditLogs))
	s.mux.HandleFunc("GET /api/server/doctor", s.guard(s.handleDoctor))
	s.mux.HandleFunc("GET /api/server/diagnose/unlock", s.guard(s.handleUnlockDiagnose))

	// 认证 API (公开访问)
	s.mux.HandleFunc("POST /api/server/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/server/logout", s.handleLogout)

	return s
}

// ListenAndServe 启动 HTTP 服务
func (s *Server) ListenAndServe() error {
	if strings.TrimSpace(s.getPassword()) == "" {
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

func (s *Server) pendingAck() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.passwordPendingAck
}

// GatewayToken 返回当前 Caddy -> ServerWeb 内部网关校验令牌
func (s *Server) GatewayToken() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gatewayToken
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil || host == "" {
		host = remoteAddr
	}
	return isWhitelisted(host)
}

func (s *Server) issueSession() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	id := hex.EncodeToString(buf)
	now := time.Now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.pruneExpiredSessionsLocked(now)
	s.sessions[id] = sessionRecord{created: now, last: now}
	return id
}

func (s *Server) pruneExpiredSessionsLocked(now time.Time) {
	for id, rec := range s.sessions {
		if now.Sub(rec.created) >= sessionAbsoluteTTL || now.Sub(rec.last) >= sessionIdleTTL {
			delete(s.sessions, id)
		}
	}
	for len(s.sessions) >= maxActiveSessions {
		var oldestID string
		var oldestTime time.Time
		for id, rec := range s.sessions {
			if oldestID == "" || rec.last.Before(oldestTime) {
				oldestID = id
				oldestTime = rec.last
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.sessions, oldestID)
	}
}

func (s *Server) useSession(id string) bool {
	if id == "" {
		return false
	}
	now := time.Now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	rec, ok := s.sessions[id]
	if !ok {
		return false
	}
	if now.Sub(rec.created) >= sessionAbsoluteTTL || now.Sub(rec.last) >= sessionIdleTTL {
		delete(s.sessions, id)
		return false
	}
	rec.last = now
	s.sessions[id] = rec
	return true
}

func (s *Server) sessionAlive(id string) bool {
	if id == "" {
		return false
	}
	now := time.Now()
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	rec, ok := s.sessions[id]
	if !ok {
		return false
	}
	return now.Sub(rec.created) < sessionAbsoluteTTL && now.Sub(rec.last) < sessionIdleTTL
}

func (s *Server) deleteSession(id string) {
	if id == "" {
		return
	}
	s.sessionsMu.Lock()
	delete(s.sessions, id)
	s.sessionsMu.Unlock()
}

func (s *Server) revokeAllSessions() {
	s.sessionsMu.Lock()
	s.sessions = make(map[string]sessionRecord)
	s.sessionsMu.Unlock()
}

func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && s.sessionAlive(c.Value) {
		return
	}
	id := s.issueSession()
	if id == "" {
		return
	}
	secure := r.TLS != nil || strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) authorized(r *http.Request) bool {
	if s.getPassword() == "" {
		return false
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil && s.useSession(cookie.Value) {
		return true
	}

	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if s.useSession(token) {
			return true
		}
		if s.cliToken != "" && isLoopbackRemote(r.RemoteAddr) &&
			subtle.ConstantTimeCompare([]byte(token), []byte(s.cliToken)) == 1 {
			return true
		}
	}

	user, pass, ok := r.BasicAuth()
	if ok && subtle.ConstantTimeCompare([]byte(user), []byte(s.getUsername())) == 1 {
		if config.VerifyPassword(s.getPassword(), pass) {
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
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
				return
			}
		}
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
	substoreRunning := checkServiceRunning("singctl-sub") || subhub.IsRunning()
	warpRunning := checkServiceRunning("wireproxy") || checkServiceRunning("warp-svc")

	caddyVer := deploy.GetInstalledCaddyVersion()
	singboxVer := deploy.GetInstalledSingBoxVersion()
	substoreVer := deploy.GetInstalledSubstoreVersion()
	warpVer := deploy.GetInstalledWarpVersion()

	substoreAdminURL := ""
	sbt := deploy.NewSubstore(cfg, "")
	if adminURL, err := sbt.GetAdminURL(); err == nil && adminURL != "" {
		substoreAdminURL = adminURL
	} else if vercelURL, err := sbt.GetVercelAdminURL(); err == nil && vercelURL != "" {
		substoreAdminURL = vercelURL
	}

	status := map[string]any{
		"version":     s.opts.Version,
		"authEnabled": s.getPassword() != "",
		"system":      getSystemMetrics(),
		"admin": map[string]any{
			"username": s.getUsername(),
			"path":     adminPath,
			"httpsUrl": httpsURL,
			"port":     cfg.Server.GetWebAdminPort(),
		},
		"services": map[string]any{
			"caddy": map[string]any{
				"running": caddyRunning,
				"version": caddyVer,
				"pid":     getServicePID("caddy"),
				"uptime":  getServiceUptime("caddy"),
			},
			"singbox": map[string]any{
				"running": singboxRunning,
				"version": singboxVer,
				"pid":     getServicePID("sing-box"),
				"uptime":  getServiceUptime("sing-box"),
			},
			"substore": map[string]any{
				"running": substoreRunning,
				"version": substoreVer,
				"pid":     getServicePID("singctl-sub"),
				"uptime":  getServiceUptime("singctl-sub"),
				"engine":  "native-go",
			},
			"warp": map[string]any{
				"running":   warpRunning,
				"version":   warpVer,
				"pid":       getServicePID("wireproxy"),
				"socksPort": 40000,
			},
		},
		"config": map[string]any{
			"nodeDomain":       cfg.Server.GetNodeDomain(),
			"substoreDomain":   cfg.Server.GetSubstoreDomain(),
			"substoreAdminUrl": substoreAdminURL,
			"nodeTag":          cfg.Server.NodeTag,
			"sni":              cfg.Server.Sni,
			"hasCFToken":       cfg.Server.CFDNSKey != "",
		},
	}
	if s.audit != nil {
		rawLogs := s.audit.List()
		enriched := make([]map[string]any, 0, len(rawLogs))
		for _, entry := range rawLogs {
			item := map[string]any{
				"time":   entry.Time,
				"action": entry.Action,
				"ip":     entry.IP,
			}
			if s.geo != nil {
				geo := s.geo.Resolve(entry.IP)
				item["geo"] = geo.Geo
				item["isp"] = geo.ISP
				item["country"] = geo.Country
				item["countryCode"] = geo.CountryCode
				item["flag"] = geo.Flag
			}
			enriched = append(enriched, item)
		}
		status["auditLogs"] = enriched
	}
	if s.pendingAck() && !config.IsHashedPassword(s.getPassword()) {
		status["initialCredentials"] = map[string]any{
			"pending":  true,
			"username": s.getUsername(),
			"password": s.getPassword(),
		}
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

	var hy2Link, vlessLink string
	sbs, _ := deploy.NewSingBoxServer(cfg)
	if sbs != nil {
		_ = sbs.LoadExistingCredentials()
		hy2Link = sbs.ShareLinkHy2
		vlessLink = sbs.ShareLinkVless
	}

	sbt := deploy.NewSubstore(cfg, "")
	adminURL, _ := sbt.GetAdminURL()
	ssKey, err := s.subStore.GetKey()
	if err != nil || ssKey == "" {
		ssKey, _ = sbt.GetSubstoreKey()
	}
	if ssKey == "" {
		ssKey, _ = s.subStore.EnsureKey()
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}

	rawSubURL := fmt.Sprintf("https://%s/download/collection/all", subDomain)
	if ssKey != "" {
		rawSubURL = fmt.Sprintf("https://%s/%s/download/collection/all", subDomain, ssKey)
	}

	sources, err := s.subStore.ListSources()
	if err != nil || sources == nil {
		sources = []subhub.SourceItem{}
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
		"engine":            "native-go",
		"substoreKey":       ssKey,
		"substoreAdminUrl":  adminURL,
		"substoreVercelUrl": "",
		"subscriptionUrl":   rawSubURL,
		"importLinks":       importLinks,
		"sources":           sources,
		"nodes": map[string]any{
			"hy2": map[string]any{
				"link":   hy2Link,
				"domain": cfg.Server.GetNodeDomain(),
				"port":   443,
			},
			"vless": map[string]any{
				"link": vlessLink,
				"sni":  cfg.Server.Sni,
				"port": 443,
			},
		},
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpsertSubscriptionSource(w http.ResponseWriter, r *http.Request) {
	var in subhub.SourceUpsertInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求: "+err.Error())
		return
	}
	item, err := s.subStore.UpsertSource(r.Context(), in)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r, fmt.Sprintf("保存聚合订阅源 [%s (%s)]", item.DisplayName, item.Source))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "订阅源已保存并实时加入聚合节点池",
		"source":  item,
	})
}

func (s *Server) handleDeleteSubscriptionSource(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		var body struct {
			Name string `json:"name"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		name = strings.TrimSpace(body.Name)
	}
	if err := s.subStore.DeleteSource(name); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.recordAudit(r, fmt.Sprintf("删除聚合订阅源 [%s]", name))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "订阅源已成功移除",
	})
}

func (s *Server) handleRotateSubscriptionKey(w http.ResponseWriter, r *http.Request) {
	newKey, err := s.subStore.RotateKey()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "轮换订阅密钥失败: "+err.Error())
		return
	}

	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg != nil {
		if err := deploy.SyncCaddyfile(cfg); err != nil {
			logger.Warn("轮换订阅密钥后同步 Caddyfile 警告: %v", err)
		}
	}

	subDomain := ""
	if cfg != nil {
		subDomain = cfg.Server.GetSubstoreDomain()
		if subDomain == "" {
			subDomain = cfg.Server.GetNodeDomain()
		}
	}
	newSubURL := ""
	if subDomain != "" {
		newSubURL = fmt.Sprintf("https://%s/%s/download/collection/all", subDomain, newKey)
	}

	s.recordAudit(r, "轮换客户端聚合订阅访问密钥")
	writeJSON(w, http.StatusOK, map[string]any{
		"message":         "订阅访问密钥已成功轮换，旧订阅链接已立即失效",
		"substoreKey":     newKey,
		"subscriptionUrl": newSubURL,
	})
}

func (s *Server) handlePreviewSubscription(w http.ResponseWriter, r *http.Request) {
	qTarget := strings.TrimSpace(r.URL.Query().Get("target"))
	if qTarget == "" {
		qTarget = "ClashMeta"
	}
	target := subhub.DetectTarget(qTarget, r.URL.Query().Get("raw"), "")

	bundle, err := s.subStore.ResolveCollection(r.Context(), "all")
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "解析聚合节点池失败: "+err.Error())
		return
	}

	renderOpts := subhub.RenderOptions{
		Target:   target,
		Platform: r.URL.Query().Get("platform"),
	}
	if cfg, err := config.Load(s.opts.ConfigPath); err == nil && cfg != nil {
		renderOpts.MirrorURL = cfg.GitHub.MirrorURL
		renderOpts.UpMbps = cfg.Hy2.Up
		renderOpts.DownMbps = cfg.Hy2.Down
		subDomain := cfg.Server.GetSubstoreDomain()
		if subDomain == "" {
			subDomain = cfg.Server.GetNodeDomain()
		}
		if key, kErr := s.subStore.GetKey(); kErr == nil && key != "" && subDomain != "" {
			renderOpts.RequestURL = fmt.Sprintf("https://%s/%s/download/collection/all?target=%s", subDomain, key, qTarget)
		}
	}

	res, err := subhub.RenderBundle(r.Context(), bundle, renderOpts)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":      string(res.Format),
		"filename":    res.Filename,
		"contentType": res.ContentType,
		"nodeCount":   len(bundle.Nodes),
		"content":     string(res.Body),
	})
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
	case "substore", "singctl-sub", "subhub":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("systemctl", action, "singctl-sub").Run()
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
		_ = exec.Command("systemctl", "restart", "singctl-sub").Run()
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	default:
		writeJSONError(w, http.StatusBadRequest, "未知服务: "+service)
		return
	}

	if cmdErr != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("执行 %s %s 失败: %v", service, action, cmdErr))
		return
	}
	s.recordAudit(r, fmt.Sprintf("执行服务操作 [%s -> %s]", service, action))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("服务 %s 动作 %s 执行成功", service, action),
	})
}

func (s *Server) handleCheckServiceUpdate(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	if service == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少检查目标服务名称 (service)")
		return
	}

	cfg, _ := config.Load(s.opts.ConfigPath)
	res, err := deploy.CheckComponentUpdate(service, cfg)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpgradeService(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Service) == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少升级目标服务名称")
		return
	}

	target := strings.ToLower(strings.TrimSpace(body.Service))
	cfg, _ := config.Load(s.opts.ConfigPath)
	results, err := deploy.UpgradeComponent(target, cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "组件升级失败: "+err.Error())
		return
	}

	msg := "组件已成功平滑更新"
	if len(results) == 1 {
		msg = results[0].Message
	} else if len(results) > 1 {
		msg = fmt.Sprintf("已成功平滑更新 %d 个核心服务组件", len(results))
	}

	s.recordAudit(r, fmt.Sprintf("平滑升级组件 [%s]", target))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": msg,
		"results": results,
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
		_ = exec.Command("systemctl", "restart", "singctl-sub").Run()
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
	case "substore", "singctl-sub", "subhub":
		output, err = exec.Command("journalctl", "-u", "singctl-sub", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
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

// writeConfigBackup 把旧配置写成 0600 的时间戳备份，只保留最近 3 份。
func writeConfigBackup(path string, content []byte) error {
	bak := fmt.Sprintf("%s.%d.bak", path, time.Now().UnixNano())
	if err := os.WriteFile(bak, content, 0600); err != nil {
		return err
	}
	if err := os.Chmod(bak, 0600); err != nil {
		return err
	}
	pruneConfigBackups(path, 3)
	return nil
}

func pruneConfigBackups(path string, keep int) {
	if keep < 1 {
		keep = 1
	}
	matches, _ := filepath.Glob(path + ".*.bak")
	legacy := path + ".bak"
	if st, err := os.Stat(legacy); err == nil && !st.IsDir() {
		matches = append(matches, legacy)
	}
	sort.Slice(matches, func(i, j int) bool {
		si, errI := os.Stat(matches[i])
		sj, errJ := os.Stat(matches[j])
		if errI != nil || errJ != nil {
			return matches[i] > matches[j]
		}
		if !si.ModTime().Equal(sj.ModTime()) {
			return si.ModTime().After(sj.ModTime())
		}
		return matches[i] > matches[j]
	})
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
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
		tmp, err := os.CreateTemp("", "caddyfile-validate-*.caddy")
		if err == nil {
			tmpName := tmp.Name()
			defer os.Remove(tmpName)
			_ = tmp.Chmod(0600)
			_, _ = tmp.WriteString(content)
			_ = tmp.Close()
			cmd := exec.Command("caddy", "validate", "--config", tmpName, "--adapter", "caddyfile")
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
		_ = writeConfigBackup(path, old)
	}

	mode := os.FileMode(0600)
	if service == "caddy" {
		mode = 0640
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}
	_ = os.Chmod(path, mode)
	if service == "caddy" {
		if g, err := user.LookupGroup("caddy"); err == nil {
			if gid, convErr := strconv.Atoi(g.Gid); convErr == nil {
				_ = os.Chown(path, 0, gid)
			}
		}
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

	s.recordAudit(r, fmt.Sprintf("修改并保存 %s 服务配置", service))
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
	s.mu.Lock()
	s.gatewayToken = config.DeriveGatewayToken(newPath)
	s.mu.Unlock()

	// 重新渲染 Caddyfile 并热重载
	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("重新应用 Caddyfile 警告: %v", err)
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	newHTTPS := fmt.Sprintf("https://%s%s/", subDomain, newPath)

	s.recordAudit(r, fmt.Sprintf("重新生成随机安全管理路径为 [%s]", newPath))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "全新隐蔽访问路径已生成并生效",
		"path":     newPath,
		"httpsUrl": newHTTPS,
	})
}

func (s *Server) handleRegenerateMaskSite(w http.ResponseWriter, r *http.Request) {
	meta, err := deploy.RegenerateMaskSite()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "重新生成伪装站点失败: "+err.Error())
		return
	}

	s.recordAudit(r, "重新生成随机伪装站")
	writeJSON(w, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("已成功重新生成伪装博客：%s（作者：%s，主题：%s）", meta.BlogTitle, meta.AuthorName, meta.Category),
		"meta":    meta,
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

	s.recordAudit(r, fmt.Sprintf("更新 Reality SNI 伪装域名为 [%s]", cfg.Server.Sni))
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
	s.recordAudit(r, "启用 Google TCP BBR 加速")
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

	s.recordAudit(r, "轮换 Cloudflare API Token")
	writeJSON(w, http.StatusOK, map[string]string{"message": "Cloudflare Token 已成功更新并重载 Caddy"})
}

func (s *Server) handleLogsSSE(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	if service == "" {
		service = "sing-box"
	}
	if service == "substore" || service == "subhub" {
		service = "singctl-sub"
	}
	if service != "sing-box" && service != "caddy" && service != "wireproxy" && service != "singctl-sub" {
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

	writeJSON(w, http.StatusOK, map[string]string{
		"url": targetURL,
	})
}

func (s *Server) getClientIPAndSeedGeo(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	if isWhitelisted(host) {
		gw := s.GatewayToken()
		if gw != "" {
			gotGW := strings.TrimSpace(r.Header.Get("X-Singctl-Gateway"))
			if subtle.ConstantTimeCompare([]byte(gotGW), []byte(gw)) == 1 {
				ip := GetClientIP(r)
				if s.geo != nil {
					if country := strings.TrimSpace(r.Header.Get("X-Geo-Country")); country != "" {
						s.geo.SeedCountry(ip, country)
					}
				}
				return ip
			}
			// 未携带合法 Caddy 网关凭证的直连回环请求：忽略伪造的 X-Real-IP / X-Geo-Country，并纳入独立限流桶
			return "loopback-direct"
		}
	}

	ip := GetClientIP(r)
	if s.geo != nil && gwAllowedForGeo(host, s.GatewayToken(), r) {
		if country := strings.TrimSpace(r.Header.Get("X-Geo-Country")); country != "" {
			s.geo.SeedCountry(ip, country)
		}
	}
	return ip
}

func gwAllowedForGeo(host, gw string, r *http.Request) bool {
	if !isWhitelisted(host) {
		return false
	}
	if gw == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.Header.Get("X-Singctl-Gateway"))), []byte(gw)) == 1
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIPAndSeedGeo(r)

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
	inputUser := strings.TrimSpace(body.Username)
	userMatch := inputUser == "" || subtle.ConstantTimeCompare([]byte(inputUser), []byte(user)) == 1
	passMatch := pass != "" && config.VerifyPassword(pass, body.Password)

	if !userMatch || !passMatch {
		banned, remaining, fails := s.limiter.RecordFailure(clientIP)
		if banned {
			mins := int(remaining.Minutes()) + 1
			s.recordAudit(r, fmt.Sprintf("连续密码错误 %d 次，触发封锁 %d 分钟", fails, mins))
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
			writeJSONError(w, http.StatusTooManyRequests, fmt.Sprintf("密码错误已达 3 次，该 IP (%s) 已被安全封锁，请在 %d 分钟后再试", clientIP, mins))
			return
		}
		remainingAttempts := s.limiter.maxAttempts - fails
		s.recordAudit(r, fmt.Sprintf("登录失败 (密码错误，剩余尝试机会 %d 次)", remainingAttempts))
		writeJSONError(w, http.StatusUnauthorized, fmt.Sprintf("用户名或密码错误 (还剩 %d 次尝试机会)", remainingAttempts))
		return
	}

	s.limiter.RecordSuccess(clientIP)
	s.setAuthCookie(w, r)
	s.recordAudit(r, fmt.Sprintf("管理员 [%s] 登录成功", user))
	writeJSON(w, http.StatusOK, map[string]any{
		"username": user,
		"message":  "登录成功",
	})
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	targetIP := strings.TrimSpace(body.IP)
	if targetIP == "" {
		targetIP = "all"
	}

	s.limiter.Unban(targetIP)
	s.recordAudit(r, fmt.Sprintf("解除 IP 封禁: %s", targetIP))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  fmt.Sprintf("已成功解封 IP: %s", targetIP),
		"unbanned": targetIP,
	})
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	bans := s.limiter.ListBans()
	banList := make([]map[string]any, 0, len(bans))
	for ip, rem := range bans {
		item := map[string]any{
			"ip":               ip,
			"remainingSeconds": int(rem.Seconds()),
			"remainingMinutes": int(rem.Minutes()) + 1,
		}
		if s.geo != nil {
			geo := s.geo.Resolve(ip)
			item["geo"] = geo.Geo
			item["isp"] = geo.ISP
			item["country"] = geo.Country
			item["countryCode"] = geo.CountryCode
			item["flag"] = geo.Flag
		}
		banList = append(banList, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bans": banList,
	})
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	var rawLogs []AuditEntry
	if s.audit != nil {
		rawLogs = s.audit.List()
	} else {
		rawLogs = []AuditEntry{}
	}
	logs := make([]map[string]any, 0, len(rawLogs))
	for _, entry := range rawLogs {
		item := map[string]any{
			"time":   entry.Time,
			"action": entry.Action,
			"ip":     entry.IP,
		}
		if s.geo != nil {
			geo := s.geo.Resolve(entry.IP)
			item["geo"] = geo.Geo
			item["isp"] = geo.ISP
			item["country"] = geo.Country
			item["countryCode"] = geo.CountryCode
			item["flag"] = geo.Flag
		}
		logs = append(logs, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"logs": logs,
	})
}

func (s *Server) recordAudit(r *http.Request, action string) {
	if s.audit != nil {
		s.audit.Record(s.getClientIPAndSeedGeo(r), action)
	}
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load(s.opts.ConfigPath)
	report := doctor.RunServerDoctor(cfg)
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleUnlockDiagnose(w http.ResponseWriter, r *http.Request) {
	report := doctor.CheckMediaUnlock()
	writeJSON(w, http.StatusOK, report)
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
	if currentPass != "" && !config.VerifyPassword(currentPass, body.CurrentPassword) {
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

	hashedPassword, err := config.HashPassword(newPassword)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "密码加密失败: "+err.Error())
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置文件失败: "+err.Error())
		return
	}

	cfg.Server.WebAdmin.Username = newUsername
	cfg.Server.WebAdmin.Password = hashedPassword
	cfg.Server.WebAdmin.PasswordPendingAck = false
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}

	s.mu.Lock()
	s.opts.Username = newUsername
	s.opts.Password = hashedPassword
	s.passwordPendingAck = false
	s.mu.Unlock()

	s.revokeAllSessions()
	s.setAuthCookie(w, r)

	s.recordAudit(r, fmt.Sprintf("修改管理账号为 [%s] 并更新管理密码", newUsername))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "账号与密码修改成功，新凭据已生效",
		"username": newUsername,
	})
}

func (s *Server) handleAckCredentials(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置文件失败")
		return
	}
	hashedPass := s.getPassword()
	if plain := strings.TrimSpace(cfg.Server.WebAdmin.Password); plain != "" && !config.IsHashedPassword(plain) {
		if h, hashErr := config.HashPassword(plain); hashErr == nil {
			cfg.Server.WebAdmin.Password = h
			hashedPass = h
		}
	}
	cfg.Server.WebAdmin.PasswordPendingAck = false
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}
	s.mu.Lock()
	if hashedPass != "" {
		s.opts.Password = hashedPass
	}
	s.passwordPendingAck = false
	s.mu.Unlock()
	s.recordAudit(r, "在面板确认已保存初始密码")
	writeJSON(w, http.StatusOK, map[string]string{"message": "已确认密码保存，密码已单向哈希加密存储"})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.recordAudit(r, "管理员退出登录")
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

func checkServiceRunning(name string) bool {
	cmd := exec.Command("systemctl", "is-active", name)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out)) == "active"
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
