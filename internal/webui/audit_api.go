// 文件职责：提供局域网设备行为审计报告导出、一键双层拉黑/解封、上行限速与 L2 AI 研判接口。
package webui

import (
	"cmp"
	"context"
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
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

// AuditRateLimiter 针对审计与拉黑接口提供轻量滑动窗口防爬虫/防高频扫描限流。
type AuditRateLimiter struct {
	mu      sync.Mutex
	windows map[string]*ipWindow
}

type ipWindow struct {
	count   int
	resetAt time.Time
}

// NewAuditRateLimiter 创建滑动窗口限流器实例。
func NewAuditRateLimiter() *AuditRateLimiter {
	return &AuditRateLimiter{
		windows: make(map[string]*ipWindow),
	}
}

// Allow 判断请求在给定 scope 内是否未超出每分钟配额且未命中恶意扫描器特征。
func (l *AuditRateLimiter) Allow(r *http.Request, scope string, maxPerMin int) bool {
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

func (s *Server) collectDefaultAuditReport(ctx context.Context) (*audit.Report, error) {
	cfg := s.readConfigOrEmpty()
	opts := audit.CollectOptions{
		Limit:  -1,
		SortBy: "active",
	}
	if s.auditCollector != nil {
		return s.auditCollector.CollectWithConfig(ctx, cfg, opts), nil
	}
	return audit.NewCollector(cfg).Collect(ctx, opts), nil
}

func (s *Server) invalidateAuditCache() {
	if s.auditCache != nil {
		s.auditCache.Invalidate()
	}
}

func isDefaultWebUIAuditQuery(exportFormat string, opts audit.CollectOptions, fresh bool) bool {
	if fresh || exportFormat != "" || opts.DeviceFilter != "" || opts.OnlySuspect || opts.EnableAI || opts.Limit != -1 || opts.SortAsc {
		return false
	}
	return opts.SortBy == "" || opts.SortBy == "active"
}

// handleAuditGet 返回局域网设备行为审计报告（支持 ?device=...&suspicious=1&ai=1&format=csv|json）。
func (s *Server) handleAuditGet(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "read", 180) {
		writeJSONError(w, http.StatusTooManyRequests, "请求过于频繁或触发反爬虫保护，请稍后再试")
		return
	}

	cfg := s.readConfigOrEmpty()

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
	if s.auditCache != nil && isDefaultWebUIAuditQuery(exportFormat, opts, q.Get("fresh") == "1") {
		if cached, cErr := s.auditCache.Get(r.Context()); cErr == nil && cached != nil {
			rep = cached
		}
	}
	if rep == nil {
		if s.auditCollector != nil {
			rep = s.auditCollector.CollectWithConfig(r.Context(), cfg, opts)
		} else {
			rep = audit.NewCollector(cfg).Collect(r.Context(), opts)
		}
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
	if !s.auditLimiter.Allow(r, "write", 120) {
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

	cfg := s.loadMutableConfig()

	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.Block(r.Context(), req.Target, req.SourceIP, req.Reason)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateConfigStore()
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}

type auditBlockBatchRequest struct {
	Items []audit.BlockBatchItem `json:"items"`
}

// handleAuditBlockBatch 执行原子批量拉黑（单次持久化 + 单次 sing-box/DNS 热重载 + 存量连接批量斩断）。
func (s *Server) handleAuditBlockBatch(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 60) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditBlockBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	if len(req.Items) == 0 {
		writeJSONError(w, http.StatusBadRequest, "items 不能为空")
		return
	}
	if len(req.Items) > 100 {
		writeJSONError(w, http.StatusBadRequest, "单次批量拉黑最多支持 100 条目标")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.BlockBatch(r.Context(), req.Items)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateConfigStore()
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}

// handleAuditUnblock 从 Sing-Box 与 AdGuard Home DNS 黑名单中一键解封目标。
func (s *Server) handleAuditUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
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

	snap, err := s.loadConfigSnapshot()
	if err != nil || snap == nil {
		writeJSONError(w, http.StatusBadRequest, "加载配置文件失败")
		return
	}
	cfg := snap.Clone()

	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.Unblock(r.Context(), req.Target, req.SourceIP)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateConfigStore()
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}

type auditPCDNBlockRequest struct {
	Enabled bool `json:"enabled"`
}

// handleAuditPCDNBlock 一键切换内置默认防 PCDN 规则集的开启/关闭状态（持久落盘并热重载 sing-box）。
func (s *Server) handleAuditPCDNBlock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
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

	cfg := s.loadMutableConfig()

	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.SetPCDNBlock(r.Context(), req.Enabled)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateConfigStore()
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
	if !s.auditLimiter.Allow(r, "write", 120) {
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

	cfg := s.loadMutableConfig()
	oldManaged := singbox.EffectiveAdBlockWhitelist(cfg)

	enforcer := audit.NewEnforcer(cfg, s.opts.ConfigPath)
	action := strings.ToLower(cmp.Or(strings.TrimSpace(req.Action), "add"))
	syncDomainWhitelist := func(target string, allow bool) {
		dom, ok := singbox.NormalizeWhitelistDomain(target)
		if !ok {
			return
		}
		if eng := s.newDNSRegistry(cfg).ActiveEngine(); eng != nil && eng.IsInstalled() {
			if err := eng.SetWhitelist(r.Context(), dom, allow); err != nil {
				logger.Warn("[Audit] 同步审计白名单至本地 DNS 引擎失败 (%s): %v", dom, err)
			}
		}
		newManaged := singbox.EffectiveAdBlockWhitelist(cfg)
		if err := s.syncSingBoxAdBlockWhitelist(r.Context(), oldManaged, newManaged); err != nil {
			logger.Warn("[Audit] 热同步审计白名单至 sing-box 失败 (%s): %v", dom, err)
		}
		_ = daemon.NotifyReload()
	}

	switch action {
	case "add":
		normalized, err := enforcer.WhitelistAdd(req.Target)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.invalidateConfigStore()
		syncDomainWhitelist(normalized, true)
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
		s.invalidateConfigStore()
		syncDomainWhitelist(normalized, false)
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
	cfg := s.readConfigOrEmpty()

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
	if !s.auditLimiter.Allow(r, "write", 120) {
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

	cfg := s.loadMutableConfig()

	cfg.Audit.AI.Endpoint = strings.TrimSpace(req.BaseURL)
	cfg.Audit.AI.APIKey = strings.TrimSpace(req.APIKey)
	cfg.Audit.AI.Model = cmp.Or(strings.TrimSpace(req.Model), "antigravity/gemini-3.8-flash")
	cfg.Audit.AI.Enabled = cfg.Audit.AI.Endpoint != "" || cfg.Audit.AI.APIKey != ""

	if err := s.saveConfig(cfg); err != nil {
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
	if !s.auditLimiter.Allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req struct {
		BaseURL string `json:"baseUrl"`
		APIKey  string `json:"apiKey"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	cfg := s.readConfigOrEmpty()

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
	if !s.auditLimiter.Allow(r, "ai", 300) {
		writeJSONError(w, http.StatusTooManyRequests, "AI 研判请求过于频繁，请稍后再试")
		return
	}

	var req auditAIReviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	cfg := s.readConfigOrEmpty()

	callerHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || callerHost == "" {
		callerHost = strings.TrimSpace(r.RemoteAddr)
	}

	advisor := audit.NewAdvisor(cfg.Audit.AI)
	results, usedRemote := advisor.ReviewFlowBatch(r.Context(), req.Flows, callerHost, req.Force)
	s.invalidateAuditCache()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"usedRemote": usedRemote,
		"results":    results,
	})
}

// handleAuditCloseConnections 临时断开单条流或全部活跃连接，促使客户端立即重新握手走新节点或策略组。
func (s *Server) handleAuditCloseConnections(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
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
	s.invalidateAuditCache()

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

type auditThrottleRequest struct {
	Target   string `json:"target"`
	Port     int    `json:"port"`
	RateKBps int    `json:"rateKbps"`
	Comment  string `json:"comment"`
}

// handleAuditThrottle 配置单目标“限速不拉黑”策略（rateKbps <= 0 解除限速），落盘 0600 并实时下发 nftables 隔离限速表。
func (s *Server) handleAuditThrottle(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditThrottleRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()

	normTarget, _, err := audit.NormalizeThrottleTarget(cfg, req.Target, req.Port)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	action := "throttled"
	var msg string
	if req.RateKBps <= 0 {
		action = "removed"
		removed := audit.RemoveThrottleRule(cfg, normTarget, req.Port)
		if !removed && req.Port > 0 {
			removed = audit.RemoveThrottleRule(cfg, normTarget, 0)
		}
		if removed {
			msg = "已解除 " + normTarget + " 的上行限速"
		} else {
			msg = normTarget + " 当前未启用上行限速"
		}
	} else {
		rule, err := audit.UpsertThrottleRule(cfg, config.AuditThrottleRule{
			Target:   normTarget,
			Port:     req.Port,
			RateKBps: req.RateKBps,
			Comment:  strings.TrimSpace(req.Comment),
		})
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		portSuffix := ""
		if rule.Port > 0 {
			portSuffix = ":" + strconv.Itoa(rule.Port)
		}
		msg = "已设置 " + rule.Target + portSuffix + " 上行限速 " + strconv.Itoa(rule.RateKBps) + " KB/s（不断网）"
	}

	if strings.TrimSpace(s.opts.ConfigPath) != "" {
		if saveErr := s.saveConfig(cfg); saveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+saveErr.Error())
			return
		}
	}

	applyRes := audit.ApplyThrottleRules(r.Context(), cfg)
	if applyRes.Message != "" {
		msg = msg + "；" + applyRes.Message
	}
	_ = daemon.NotifyReload()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"action":      action,
		"target":      normTarget,
		"port":        req.Port,
		"rateKbps":    req.RateKBps,
		"throttles":   cfg.Audit.Throttles,
		"applyResult": applyRes,
		"message":     msg,
	})
}

type auditDeviceAccessRequest struct {
	DeviceIP      string `json:"deviceIp"`
	AllowOverseas *bool  `json:"allowOverseas"`
}

// handleAuditDeviceAccess 切换单个局域网设备的外网分流权限（true=正常分流, false=强制全部走 Direct + dns_local）。
func (s *Server) handleAuditDeviceAccess(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 120) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditDeviceAccessRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil || req.AllowOverseas == nil {
		writeJSONError(w, http.StatusBadRequest, "请求参数无效：缺少 deviceIp 或 allowOverseas 布尔开关")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	enforcer := s.newAuditEnforcer(cfg)
	res, err := enforcer.SetDeviceOverseasAccess(r.Context(), req.DeviceIP, *req.AllowOverseas)
	if err != nil {
		if res != nil && res.ConfigSaved && s.cfgStore != nil {
			s.cfgStore.Set(cfg)
		} else {
			s.invalidateConfigStore()
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if s.cfgStore != nil {
		s.cfgStore.Set(cfg)
	}
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}
