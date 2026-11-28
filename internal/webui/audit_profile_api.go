// 文件职责：提供单台局域网设备行为画像查询与手动 AI 画像总结 HTTP 接口。
package webui

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"singctl/internal/audit"
)

func parseProfileRange(raw string) audit.DeviceProfileRange {
	if strings.EqualFold(strings.TrimSpace(raw), string(audit.ProfileRange7d)) {
		return audit.ProfileRange7d
	}
	return audit.ProfileRange24h
}

func (s *Server) handleAuditDeviceProfileGet(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "read", 180) {
		writeJSONError(w, http.StatusTooManyRequests, "请求过于频繁或触发反爬虫保护，请稍后再试")
		return
	}

	q := r.URL.Query()
	rawIP := strings.TrimSpace(q.Get("ip"))
	if parsed := net.ParseIP(rawIP); parsed == nil {
		writeJSONError(w, http.StatusBadRequest, "请提供有效的局域网设备 IP (?ip=...)")
		return
	}
	rng := parseProfileRange(q.Get("range"))

	cfg := s.readConfigOrEmpty()
	collector := s.auditCollector
	if collector == nil {
		collector = audit.NewCollector(cfg)
	}
	prof := collector.BuildDeviceProfile(r.Context(), cfg, rawIP, rng)
	writeJSON(w, http.StatusOK, prof)
}

type auditDeviceProfileAIRequest struct {
	DeviceIP string `json:"deviceIp"`
	Range    string `json:"range,omitempty"`
}

func (s *Server) handleAuditDeviceProfileAIPost(w http.ResponseWriter, r *http.Request) {
	if !s.auditLimiter.Allow(r, "write", 60) {
		writeJSONError(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
		return
	}

	var req auditDeviceProfileAIRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求体")
		return
	}
	rawIP := strings.TrimSpace(req.DeviceIP)
	if parsed := net.ParseIP(rawIP); parsed == nil {
		writeJSONError(w, http.StatusBadRequest, "请提供有效的局域网设备 IP")
		return
	}

	callerHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil || callerHost == "" {
		callerHost = strings.TrimSpace(r.RemoteAddr)
	}

	cfg := s.readConfigOrEmpty()
	collector := s.auditCollector
	if collector == nil {
		collector = audit.NewCollector(cfg)
	}
	prof := collector.BuildDeviceProfile(r.Context(), cfg, rawIP, parseProfileRange(req.Range))
	summary := audit.NewAdvisor(cfg.Audit.AI).SummarizeDeviceProfile(r.Context(), prof, callerHost)
	writeJSON(w, http.StatusOK, summary)
}
