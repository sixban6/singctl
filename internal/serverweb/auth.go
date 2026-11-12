package serverweb

import (
	"cmp"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/util/netinfo"
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

func resolveSniffFilePath(opts Options) string {
	if opts.ConfigPath != "" {
		return filepath.Join(filepath.Dir(opts.ConfigPath), ".serverweb_sniff.json")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/.serverweb_sniff.json"
	}
	return ""
}

func resolveGeoFilePath(opts Options) string {
	if opts.ConfigPath != "" {
		return filepath.Join(filepath.Dir(opts.ConfigPath), ".serverweb_geo_cache.json")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/.serverweb_geo_cache.json"
	}
	return ""
}

func (s *Server) GetUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.opts.Username != "" {
		return s.opts.Username
	}
	return "singctl"
}

func (s *Server) GetPassword() string {
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

func (s *Server) IssueSession() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	id := hex.EncodeToString(buf)
	now := time.Now()
	s.SessionsMu.Lock()
	defer s.SessionsMu.Unlock()
	s.pruneExpiredSessionsLocked(now)
	s.Sessions[id] = SessionRecord{Created: now, Last: now}
	return id
}

func (s *Server) pruneExpiredSessionsLocked(now time.Time) {
	for id, rec := range s.Sessions {
		if now.Sub(rec.Created) >= sessionAbsoluteTTL || now.Sub(rec.Last) >= sessionIdleTTL {
			delete(s.Sessions, id)
		}
	}
	for len(s.Sessions) >= MaxActiveSessions {
		var oldestID string
		var oldestTime time.Time
		for id, rec := range s.Sessions {
			if oldestID == "" || rec.Last.Before(oldestTime) {
				oldestID = id
				oldestTime = rec.Last
			}
		}
		if oldestID == "" {
			break
		}
		delete(s.Sessions, oldestID)
	}
}

func (s *Server) useSession(id string) bool {
	if id == "" {
		return false
	}
	now := time.Now()
	s.SessionsMu.Lock()
	defer s.SessionsMu.Unlock()
	rec, ok := s.Sessions[id]
	if !ok {
		return false
	}
	if now.Sub(rec.Created) >= sessionAbsoluteTTL || now.Sub(rec.Last) >= sessionIdleTTL {
		delete(s.Sessions, id)
		return false
	}
	rec.Last = now
	s.Sessions[id] = rec
	return true
}

func (s *Server) sessionAlive(id string) bool {
	if id == "" {
		return false
	}
	now := time.Now()
	s.SessionsMu.Lock()
	defer s.SessionsMu.Unlock()
	rec, ok := s.Sessions[id]
	if !ok {
		return false
	}
	return now.Sub(rec.Created) < sessionAbsoluteTTL && now.Sub(rec.Last) < sessionIdleTTL
}

func (s *Server) deleteSession(id string) {
	if id == "" {
		return
	}
	s.SessionsMu.Lock()
	delete(s.Sessions, id)
	s.SessionsMu.Unlock()
}

func (s *Server) revokeAllSessions() {
	s.SessionsMu.Lock()
	s.Sessions = make(map[string]SessionRecord)
	s.SessionsMu.Unlock()
}

func (s *Server) setAuthCookie(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil && s.sessionAlive(c.Value) {
		return
	}
	id := s.IssueSession()
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
	if s.GetPassword() == "" {
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
	if ok && subtle.ConstantTimeCompare([]byte(user), []byte(s.GetUsername())) == 1 {
		if config.VerifyPassword(s.GetPassword(), pass) {
			return true
		}
	}
	return false
}

func (s *Server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientIP := s.getClientIPAndSeedGeo(r)
		if !s.authorized(r) {
			if s.sniff != nil && clientIP != "" && clientIP != "loopback-direct" {
				s.sniff.Observe(clientIP, "Web 管理路径嗅探", "observing", 1)
			}
			writeJSONError(w, http.StatusUnauthorized, "未授权访问，请先登录")
			return
		}
		if s.sniff != nil && clientIP != "" && clientIP != "loopback-direct" {
			s.sniff.MarkTrustedClientIPs(clientIP)
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

func (s *Server) recordAudit(r *http.Request, action string) {
	if s.audit != nil {
		s.audit.Record(s.getClientIPAndSeedGeo(r), action)
	}
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := s.getClientIPAndSeedGeo(r)

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
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	_ = json.NewDecoder(r.Body).Decode(&body)

	user := s.GetUsername()
	pass := s.GetPassword()
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

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP       string `json:"ip"`
		Target   string `json:"target"`
		Node     string `json:"node"`
		ViewNode string `json:"viewNode"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	targetIP := strings.TrimSpace(cmp.Or(body.IP, body.Target))
	if targetIP == "" {
		targetIP = "all"
	}
	nodeScope := cmp.Or(strings.TrimSpace(body.Node), "all")
	viewScope := cmp.Or(strings.TrimSpace(body.ViewNode), nodeScope)

	s.limiter.Unban(targetIP)
	appliedNodes := 1
	canonicalTarget := targetIP
	if s.sniff != nil {
		if unblocked, n, err := s.sniff.UnblockTargetForNode(r.Context(), targetIP, nodeScope); err == nil {
			canonicalTarget = unblocked
			if n > 0 {
				appliedNodes = n
			}
		} else if targetIP != "all" && targetIP != "*" {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	s.recordAudit(r, fmt.Sprintf("全链路解除封禁 [%s] (范围: %s, 生效主机: %d 台)", canonicalTarget, nodeScope, appliedNodes))
	resp := map[string]any{
		"message":      fmt.Sprintf("已全链路解除封禁: %s（同步清理防火墙与限流表，共 %d 台主机）", canonicalTarget, appliedNodes),
		"unbanned":     canonicalTarget,
		"appliedNodes": appliedNodes,
	}
	if s.sniff != nil {
		resp["summary"] = s.sniff.SnapshotForNode(r.Context(), viewScope, false)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	details := s.limiter.ListBanDetails()
	banList := make([]map[string]any, 0, len(details))
	loginFailCount := 0
	manualSniffCount := 0
	for _, d := range details {
		if d.Source == BanSourceManualSniff {
			manualSniffCount++
		} else {
			loginFailCount++
		}
		item := map[string]any{
			"ip":               d.IP,
			"remainingSeconds": int(d.Remaining.Seconds()),
			"remainingMinutes": int(d.Remaining.Minutes()) + 1,
			"remainingText":    FormatDurationCN(d.Remaining),
			"bannedUntil":      d.BannedUntil.Local().Format("2006-01-02 15:04:05"),
			"failCount":        d.FailCount,
			"source":           d.Source,
			"sourceLabel":      d.SourceLabel,
			"reason":           d.Reason,
		}
		if s.geo != nil {
			geo := s.geo.Resolve(d.IP)
			item["geo"] = geo.Geo
			item["isp"] = geo.ISP
			item["country"] = geo.Country
			item["countryCode"] = geo.CountryCode
			item["flag"] = geo.Flag
		}
		banList = append(banList, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bans":             banList,
		"loginFailCount":   loginFailCount,
		"manualSniffCount": manualSniffCount,
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
			"time":     entry.Time,
			"action":   entry.Action,
			"ip":       entry.IP,
			"category": ClassifyAuditCategory(entry.Action),
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

	currentPass := s.GetPassword()
	if currentPass != "" && !config.VerifyPassword(currentPass, body.CurrentPassword) {
		writeJSONError(w, http.StatusForbidden, "当前管理密码错误，禁止修改")
		return
	}

	newPassword := strings.TrimSpace(body.NewPassword)
	if !validatePasswordRules(newPassword) {
		writeJSONError(w, http.StatusBadRequest, "新管理密码需至少 8 位且必须同时包含大写字母、小写字母和数字")
		return
	}

	newUsername := strings.TrimSpace(body.NewUsername)
	if newUsername == "" {
		newUsername = s.GetUsername()
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
	hashedPass := s.GetPassword()
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
