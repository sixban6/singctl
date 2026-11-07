package serverweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"singctl/internal/telemetry"
)

func (s *Server) collectEnrichedTelemetry(r *http.Request) telemetry.Snapshot {
	snap := s.telemetry.Collect(r.Context())
	if s.sniff != nil {
		clientIP := s.getClientIPAndSeedGeo(r)
		if clientIP != "" && clientIP != "loopback-direct" {
			s.sniff.MarkTrustedClientIPs(clientIP)
		}
		snap.Sniffing = s.sniff.Snapshot(r.Context(), snap.ActiveClientIPs...)
	}
	return snap
}

func (s *Server) handleTelemetrySnapshot(w http.ResponseWriter, r *http.Request) {
	snap := s.collectEnrichedTelemetry(r)
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleTelemetrySSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	sendFrame := func() bool {
		snap := s.collectEnrichedTelemetry(r)
		raw, err := json.Marshal(snap)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", raw); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	if !sendFrame() {
		return
	}

	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if !sendFrame() {
				return
			}
		}
	}
}

func (s *Server) handleEnableTelemetry(w http.ResponseWriter, r *http.Request) {
	changed, addr, _, err := telemetry.EnsureConfigTelemetry(s.opts.SingBoxConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "启用实时流量遥测失败: "+err.Error())
		return
	}
	if changed {
		if runErr := exec.Command("systemctl", "restart", "sing-box").Run(); runErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "已写入遥测配置，但重启 sing-box 失败: "+runErr.Error())
			return
		}
		time.Sleep(350 * time.Millisecond)
	}
	s.recordAudit(r, fmt.Sprintf("启用 sing-box 本地回环流量遥测 (%s)", addr))
	snap := s.telemetry.Collect(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "实时流量与分流遥测已无损开启（未变更任何节点密码与密钥）",
		"changed":  changed,
		"snapshot": snap,
	})
}
