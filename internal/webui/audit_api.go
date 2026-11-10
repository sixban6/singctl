package webui

import (
	"cmp"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"singctl/internal/audit"
	"singctl/internal/config"
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

func (l *auditRateLimiter) allow(r *http.Request, maxPerMin int) bool {
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

	win, ok := l.windows[host]
	if !ok || now.After(win.resetAt) {
		l.windows[host] = &ipWindow{count: 1, resetAt: now.Add(time.Minute)}
		return true
	}
	win.count++
	return win.count <= maxPerMin
}

// handleAuditGet 返回局域网设备行为审计报告（支持 ?device=...&suspicious=1&ai=1&format=csv|json）。
func (s *Server) handleAuditGet(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, 60) {
		writeJSONError(w, http.StatusTooManyRequests, "请求过于频繁或触发反爬虫保护，请稍后再试")
		return
	}

	cfg, _ := config.Load(s.opts.ConfigPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	q := r.URL.Query()
	exportFormat := strings.ToLower(strings.TrimSpace(q.Get("format")))
	limit := 100
	if exportFormat == "csv" || exportFormat == "json" {
		limit = 0 // 导出明细时不截断条数，返回全量流记录
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
	}

	collector := audit.NewCollector(cfg)
	rep := collector.Collect(r.Context(), opts)

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

type auditBlockRequest struct {
	Target   string `json:"target"`
	SourceIP string `json:"sourceIp"`
	Reason   string `json:"reason"`
}

// handleAuditBlock 执行一键双层拉黑（Sing-Box 路由阻断 + AdGuard Home DNS 黑名单 + 立即掐断活跃连接）。
func (s *Server) handleAuditBlock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, 30) {
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

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}

	enforcer := audit.NewEnforcer(cfg, s.opts.ConfigPath)
	res, err := enforcer.Block(r.Context(), req.Target, req.SourceIP, req.Reason)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleAuditUnblock 从 Sing-Box 与 AdGuard Home DNS 黑名单中一键解封目标。
func (s *Server) handleAuditUnblock(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, 30) {
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

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusBadRequest, "加载配置文件失败")
		return
	}

	enforcer := audit.NewEnforcer(cfg, s.opts.ConfigPath)
	res, err := enforcer.Unblock(r.Context(), req.Target, req.SourceIP)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
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
	if !s.auditLimiter.allow(r, 30) {
		writeJSONError(w, http.StatusTooManyRequests, "操作过于频繁，请稍后再试")
		return
	}

	var req auditAIConfigPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}

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

type auditAIReviewRequest struct {
	Flows []audit.FlowRecord `json:"flows"`
}

// handleAuditAIReviewPost 针对前端传入的一批连接记录（最多 12 条/批）执行 L2 AI 深度研判，支持全量渐进式分批点亮与单行按需研判。
func (s *Server) handleAuditAIReviewPost(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.allow(r, 180) {
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
	results, usedRemote := advisor.ReviewFlowBatch(r.Context(), req.Flows, callerHost)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"usedRemote": usedRemote,
		"results":    results,
	})
}
