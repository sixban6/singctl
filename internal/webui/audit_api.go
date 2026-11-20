package webui

import (
	"cmp"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
	"singctl/internal/daemon"
)

// auditRateLimiter 针对审计与拉黑接口提供轻量滑动窗口防爬虫/防高频扫描限流。
type auditRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*ipWindow
}

type ipWindow struct {
	count   int
	resetAt time.Time
}

func newAuditRateLimiter() *auditRateLimiter {
	return &auditRateLimiter{
		windows: make(map[string]*ipWindow),
	}
}

func (l *auditRateLimiter) allow(r *http.Request, scope string, maxPerMin int) bool {
	if l == nil {
		return true
	}
	// 拦截典型恶意爬虫与批量扫描器 User-Agent
	ua := strings.ToLower(strings.TrimSpace(r.Header.Get("User-Agent")))
	for _, bot := range []string{"sqlmap", "nikto", "masscan", "zgrab", "nmap", "nuclei", "dirbuster", "gobuster", "scrapy", "petalbot", "bytespider", "semrushbot", "ahrefsbot"} {
		if strings.Contains(ua, bot) {
			return false
		}
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	key := scope + "|" + host

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.windows) > 512 {
		for k, v := range l.windows {
			if now.After(v.resetAt) {
				delete(l.windows, k)
			}
		}
	}

	win, ok := l.windows[key]
	if !ok || now.After(win.resetAt) {
		l.windows[key] = &ipWindow{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	win.count++
	return win.count <= maxPerMin
}

// handleAuditGet 返回局域网设备行为审计报告（支持 ?device=...&suspicious=1&ai=1&format=csv|json）。
func (s *Server) handleAuditGet(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "read", 180) {
		writeJSONError(w, http.StatusTooManyRequests, "请求过于频繁或触发反爬虫保护，请稍后再试")
		return
	}

	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	q := r.URL.Query()
	exportFormat := strings.ToLower(strings.TrimSpace(q.Get("format")))
	limit := -1 // WebUI 与导出默认返回全量明细，支持前端表格无限滚动与本地秒级筛选
	if exportFormat == "" {
		if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
			if parsed, err := strconv.Atoi(rawLimit); err == nil && parsed > 0 {
				limit = parsed
			}
		}
	}

	callerHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || callerHost == "" {
		callerHost = strings.TrimSpace(r.RemoteAddr)
	}

	opts := audit.CollectOptions{
		DeviceFilter: strings.TrimSpace(q.Get("device")),
		OnlySuspect:  q.Get("suspicious") == "1" || q.Get("suspicious") == "true",
		EnableAI:     q.Get("ai") == "1" || q.Get("ai") == "true" || exportFormat != "",
		CallerIP:     callerHost,
		Limit:        limit,
		SortBy:       strings.ToLower(strings.TrimSpace(q.Get("sort"))),
		SortAsc:      strings.EqualFold(strings.TrimSpace(q.Get("dir")), "asc"),
	}

	var rep *audit.Report
	if s.auditCollector != nil {
		rep = s.auditCollector.CollectWithConfig(r.Context(), cfg, opts)
	} else {
		rep = audit.NewCollector(cfg).Collect(r.Context(), opts)
	}

	ts := time.Now().Format("20060102-150405")
	switch exportFormat {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="singctl-audit-`+ts+`.csv"`)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_ = rep.WriteCSV(w)
		return
	case "json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="singctl-audit-`+ts+`.json"`)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return
	default:
		writeJSON(w, http.StatusOK, rep)
	}
}

func (s *Server) newAuditEnforcer(cfg *config.Config) *audit.Enforcer {
	enforcer := audit.NewEnforcer(cfg, s.opts.ConfigPath)
	if strings.TrimSpace(s.opts.SingBoxConfigPath) != "" ||
		strings.TrimSpace(s.opts.SingBoxWorkConfigPath) != "" ||
		strings.TrimSpace(s.opts.AdGuardConfigPath) != "" {
		enforcer.SetStoragePaths(s.opts.SingBoxConfigPath, s.opts.SingBoxWorkConfigPath, s.opts.AdGuardConfigPath)
	}
	return enforcer
}

type auditBlockRequest struct {
	Target   string `json:"target"`
	SourceIP string `json:"sourceIp"`
	Reason   string `json:"reason"`
}

// handleAuditBlock 执行一键双层拉黑（Sing-Box 路由阻断 + AdGuard Home DNS 黑名单 + 立即掐断活跃连接）。
func (s *Server) handleAuditBlock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditBlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "target 不能为空")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.Block(r.Context(), req.Target, req.SourceIP, req.Reason)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}

// handleAuditUnblock 从 Sing-Box 与 AdGuard Home DNS 黑名单中一键解封目标。
func (s *Server) handleAuditUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditBlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "target 不能为空")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusBadRequest, "加载配置文件失败")
		return
	}

	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.Unblock(r.Context(), req.Target, req.SourceIP)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}

type auditPCDNBlockRequest struct {
	Enabled bool `json:"enabled"`
}

// handleAuditPCDNBlock 一键切换内置默认防 PCDN 规则集的开启/关闭状态（持久落盘并热重载 sing-box）。
func (s *Server) handleAuditPCDNBlock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditPCDNBlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.SetPCDNBlock(r.Context(), req.Enabled)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"pcdnBlockEnabled":  req.Enabled,
		"target":            res.Target,
		"configSaved":       res.ConfigSaved,
		"singboxSynced":     res.SingBoxSynced,
		"killedConnections": res.KilledConnections,
		"message":           res.Message,
	})
}

type auditWhitelistRequest struct {
	Action string `json:"action"` // "add" | "remove"
	Target string `json:"target"`
}

// handleAuditWhitelist 管理设备行为审计的信任放行白名单（写入 singctl.yaml audit.whitelist，0600 权限）。
func (s *Server) handleAuditWhitelist(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditWhitelistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	if strings.TrimSpace(req.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "target 不能为空")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	enforcer := audit.NewEnforcer(cfg, s.opts.ConfigPath)
	action := strings.ToLower(cmp.Or(strings.TrimSpace(req.Action), "add"))
	switch action {
	case "add":
		normalized, err := enforcer.WhitelistAdd(req.Target)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"target":    normalized,
			"whitelist": cfg.Audit.Whitelist,
			"message":   "已将 " + normalized + " 加入审计信任白名单 (自动豁免告警)",
		})
	case "remove", "delete", "rm":
		normalized, err := enforcer.WhitelistRemove(req.Target)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"target":    normalized,
			"whitelist": cfg.Audit.Whitelist,
			"message":   "已将 " + normalized + " 移出审计信任白名单",
		})
	default:
		writeJSONError(w, http.StatusBadRequest, "不支持的 action 参数 (支持 add / remove)")
	}
}

type auditAIConfigPayload struct {
	BaseURL         string `json:"baseUrl"`
	APIKey          string `json:"apiKey"`
	Model           string `json:"model"`
	SuggestedLANURL string `json:"suggestedLanUrl,omitempty"`
}

// handleAuditAIConfigGet 返回当前配置的 AI 网关地址、密钥与模型（默认 antigravity/gemini-3.8-flash）。
func (s *Server) handleAuditAIConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	callerHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || callerHost == "" {
		callerHost = strings.TrimSpace(r.RemoteAddr)
	}
	suggested := "http://127.0.0.1:3425/v1"
	if ip := net.ParseIP(callerHost); ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		suggested = "http://" + net.JoinHostPort(ip.String(), "3425") + "/v1"
	}

	writeJSON(w, http.StatusOK, auditAIConfigPayload{
		BaseURL:         strings.TrimSpace(cfg.Audit.AI.Endpoint),
		APIKey:          strings.TrimSpace(cfg.Audit.AI.APIKey),
		Model:           cmp.Or(strings.TrimSpace(cfg.Audit.AI.Model), "antigravity/gemini-3.8-flash"),
		SuggestedLANURL: suggested,
	})
}

// handleAuditAIConfigPost 保存用户自定义的 AI 网关请求地址 BaseURL、网关密钥与访问模型至 singctl.yaml (0600)。
func (s *Server) handleAuditAIConfigPost(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditAIConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	cfg.Audit.AI.Endpoint = strings.TrimSpace(req.BaseURL)
	cfg.Audit.AI.APIKey = strings.TrimSpace(req.APIKey)
	cfg.Audit.AI.Model = cmp.Or(strings.TrimSpace(req.Model), "antigravity/gemini-3.8-flash")
	cfg.Audit.AI.Enabled = cfg.Audit.AI.Endpoint != "" || cfg.Audit.AI.APIKey != ""

	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存 AI 网关配置失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": "AI 网关配置已保存生效",
		"model":   cfg.Audit.AI.Model,
	})
}

// handleAuditAIModelsPost 动态连接用户填写（或自动探测）的 AI 网关拉取可用模型列表，失败时优雅降级供前端手动输入。
func (s *Server) handleAuditAIModelsPost(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req struct {
		BaseURL string `json:"baseUrl"`
		APIKey  string `json:"apiKey"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	baseURL := strings.TrimSpace(req.BaseURL)
	apiKey := strings.TrimSpace(req.APIKey)
	if apiKey == "" && (baseURL == "" || baseURL == strings.TrimSpace(cfg.Audit.AI.Endpoint)) {
		apiKey = strings.TrimSpace(cfg.Audit.AI.APIKey)
	}

	callerHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || callerHost == "" {
		callerHost = strings.TrimSpace(r.RemoteAddr)
	}

	// 注意：此处若前端刻意清空了 BaseURL，则按空 BaseURL 走 :3425 自动探测，不被旧配置覆盖
	aiCfg := config.AuditAIConfig{
		Enabled:  true,
		Endpoint: baseURL,
		APIKey:   apiKey,
	}
	advisor := audit.NewAdvisor(aiCfg)
	if baseURL == "" {
		// 显式清空 Endpoint 以允许拉取默认探测网关模型（防止环境变量在用户自定义测探时干扰，但保留未填时的合理回退）
	}
	models, resolvedURL, fetchErr := advisor.FetchAvailableModels(r.Context(), callerHost)
	if fetchErr != nil || len(models) == 0 {
		errMsg := "未能自动获取模型列表，请手动填写模型名称"
		if fetchErr != nil {
			errMsg = fetchErr.Error()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"models": []string{},
			"error":  errMsg,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"models":      models,
		"resolvedUrl": resolvedURL,
	})
}

type auditAIReviewRequest struct {
	Flows []audit.FlowRecord `json:"flows"`
	Force bool               `json:"force,omitempty"`
}

// handleAuditAIReviewPost 针对前端传入的一批连接记录（最多 12 条/批）执行 L2 AI 深度研判，支持全量渐进式分批点亮与单行按需研判。
func (s *Server) handleAuditAIReviewPost(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "ai", 300) {
		writeJSONError(w, http.StatusTooManyRequests, "AI 研判请求过于频繁，请稍后再试")
		return
	}

	var req auditAIReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	callerHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || callerHost == "" {
		callerHost = strings.TrimSpace(r.RemoteAddr)
	}

	advisor := audit.NewAdvisor(cfg.Audit.AI)
	results, usedRemote := advisor.ReviewFlowBatch(r.Context(), req.Flows, callerHost, req.Force)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"usedRemote": usedRemote,
		"results":    results,
	})
}

// handleAuditCloseConnections 临时断开单条流或全部活跃连接，促使客户端立即重新握手走新节点或策略组。
func (s *Server) handleAuditCloseConnections(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req audit.CloseConnectionsRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	if !req.All && len(req.ConnIDs) == 0 && strings.TrimSpace(req.Target) == "" {
		writeJSONError(w, http.StatusBadRequest, "请指定要断开的连接 ID、目标域名或 all=true")
		return
	}

	collector := s.auditCollector
	if collector == nil {
		collector = audit.NewCollector(nil)
	}
	res, err := collector.CloseConnections(r.Context(), req)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "断开活跃连接失败: "+err.Error())
		return
	}

	msg := "已触发断开所有活跃连接，后续请求将重新选路"
	if !res.All {
		if res.Closed > 0 {
			msg = "已断开 " + strconv.Itoa(res.Closed) + " 条活跃连接"
		} else {
			msg = "相关连接已自然结束或关闭"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"closed":  res.Closed,
		"all":     res.All,
		"message": msg,
	})
}
