// 文件职责：承载客户端 WebUI 多通道鉴权（Cookie/Bearer/Query/BasicAuth）、防爆破限流与会话接口。
package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/httpx"
	"singctl/internal/common/netx"
)

func (s *Server) currentPassword() string {
	if p := s.passwordPtr.Load(); p != nil {
		return *p
	}
	return s.opts.Password
}

func (s *Server) setPasswordRuntime(pw string) {
	cp := pw
	s.passwordPtr.Store(&cp)
}

// SessionToken 根据访问口令派生无状态持久化 Token (HMAC-SHA256)
func (s *Server) SessionToken() string {
	pw := s.currentPassword()
	if pw == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte("singctl-webui-session-salt-v1"))
	mac.Write([]byte(pw))
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

// clientWebCSP 严格限制浏览器脚本、框架与出站连接，仅放行同源接口及 DNS/IP 测漏探针域名。
const clientWebCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; frame-src 'self' http: https:; connect-src 'self' https://ipv4.geojs.io https://ipv6.geojs.io https://myip.ipip.net https://*.edns.ip-api.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

func applyClientSecurityHeaders(w http.ResponseWriter, csp string) {
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if csp != "" {
		w.Header().Set("Content-Security-Policy", csp)
	}
}

// guard 包装器:统一鉴权、反爬虫与严格 CSP 安全头注入、JSON 错误输出、方法校验
func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.RecordRequestActivity()
		applyClientSecurityHeaders(w, clientWebCSP)
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
		if strings.HasSuffix(r.URL.Path, "/stream") || r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/event-stream") {
			next(w, r)
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				s.invalidateStatusCache()
			}
			return
		}
		httpx.ServeGzip(w, r, next)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			s.invalidateStatusCache()
		}
	}
}

// authOnly 仅鉴权(用于静态资源,不校验 Content-Type)。
//  1. 首页 `/` 与 `/index.html` 强制 `Cache-Control: no-store`，消除自更新后浏览器缓存旧 index.html 导致白屏；
//  2. 未授权访问首页时返回 401 + 自包含口令登录页（不发 WWW-Authenticate），兼容 Safari/PWA/移动端。
func (s *Server) authOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.RecordRequestActivity()
		if !s.authorized(r) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			if (r.Method == http.MethodGet || r.Method == http.MethodHead) && (r.URL.Path == "/" || r.URL.Path == "/index.html") {
				applyClientSecurityHeaders(w, embeddedLoginCSP)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				if r.Method != http.MethodHead {
					_, _ = w.Write([]byte(embeddedLoginHTML))
				}
				return
			}
			applyClientSecurityHeaders(w, clientWebCSP)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		applyClientSecurityHeaders(w, clientWebCSP)
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
	pw := s.currentPassword()
	if pw == "" {
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
		if subtle.ConstantTimeCompare([]byte(qPass), []byte(pw)) == 1 {
			return true
		}
	}

	// 4. 标准 HTTP Basic Auth (admin / password)
	user, pass, ok := r.BasicAuth()
	if ok && user == "admin" {
		if subtle.ConstantTimeCompare([]byte(pass), []byte(pw)) == 1 {
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
	s.RecordRequestActivity()
	applyClientSecurityHeaders(w, clientWebCSP)
	w.Header().Set("Cache-Control", "no-store")

	authed := s.authorized(r)
	if authed {
		s.setAuthCookie(w, r)
	}
	resp := map[string]any{
		"ok":            true,
		"authRequired":  s.currentPassword() != "",
		"authenticated": authed,
	}
	if authed && s.opts.Version != "" {
		resp["version"] = s.opts.Version
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleAuthLogin 内嵌口令登录接口：恒定时间校验口令、同 IP 限流防爆破，成功后下发 30 天 HttpOnly Cookie 及会话 Token
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	applyClientSecurityHeaders(w, clientWebCSP)
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

	curPW := s.currentPassword()
	if curPW == "" {
		if s.loginLimiter != nil {
			s.loginLimiter.reset(clientIP)
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": ""})
		return
	}

	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(curPW)) != 1 {
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

// handleAuthPasswordPut 支持在不中断当前登录态的前提下设置或更新 0600 落盘的 WebUI 访问口令。
func (s *Server) handleAuthPasswordPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CurrentPassword string `json:"currentPassword"`
		Password        string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	curPW := s.currentPassword()
	if curPW != "" && subtle.ConstantTimeCompare([]byte(body.CurrentPassword), []byte(curPW)) != 1 {
		writeJSONError(w, http.StatusForbidden, "当前访问口令校验未通过")
		return
	}

	if strings.ContainsAny(body.Password, "\r\n\x00") {
		writeJSONError(w, http.StatusBadRequest, "访问口令包含非法换行或控制字符")
		return
	}
	if body.Password != "" && (len(body.Password) < 6 || len(body.Password) > 128) {
		writeJSONError(w, http.StatusBadRequest, "访问口令长度须在 6～128 位之间")
		return
	}

	pwPath := WebPasswordFilePath(s.opts.ConfigPath)
	if err := WriteWebPasswordFile(pwPath, body.Password); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "持久化 WebUI 口令文件失败: "+err.Error())
		return
	}
	s.setPasswordRuntime(body.Password)
	if body.Password != "" {
		s.issueAuthCookie(w)
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"authRequired": body.Password != "",
		"token":        s.SessionToken(),
	})
}

// handleLogout 登出并清理 Cookie
func (s *Server) handleLogout(w http.ResponseWriter, _ *http.Request) {
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
func (s *Server) handleSessionURL(w http.ResponseWriter, _ *http.Request) {
	lanIP := "127.0.0.1"
	if ni, err := netx.Get(); err == nil && ni.LANIPv4 != "" {
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
