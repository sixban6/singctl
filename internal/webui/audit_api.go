package webui

import (
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

// handleAuditGet 返回局域网设备行为审计报告（支持 ?device=...&suspicious=1&ai=1）。
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
	opts := audit.CollectOptions{
		DeviceFilter: strings.TrimSpace(q.Get("device")),
		OnlySuspect:  q.Get("suspicious") == "1" || q.Get("suspicious") == "true",
		EnableAI:     q.Get("ai") == "1" || q.Get("ai") == "true",
		Limit:        100,
	}

	collector := audit.NewCollector(cfg)
	rep := collector.Collect(r.Context(), opts)
	writeJSON(w, http.StatusOK, rep)
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
