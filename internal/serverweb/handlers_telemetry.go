// 文件职责：提供实时流量遥测快照、SSE 帧级合并推送与无损开启遥测接口，在控制面边界组合嗅探摘要字段。
package serverweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"singctl/internal/sniff"
	"singctl/internal/telemetry"
)

// EnrichedTelemetrySnapshot 在控制面边界组合底层遥测快照与嗅探态势摘要，保持前端 JSON 100% 兼容且解除 telemetry 对 sniff 的耦合。
type EnrichedTelemetrySnapshot struct {
	telemetry.Snapshot
	Sniffing *sniff.Summary `json:"sniffing,omitempty"`
}

type sseFrameCache struct {
	mu          sync.Mutex
	cachedAt    time.Time
	cachedFrame []byte
}

func (s *Server) markRequestClientTrusted(r *http.Request) {
	if s.sniff == nil {
		return
	}
	clientIP := s.getClientIPAndSeedGeo(r)
	if clientIP != "" && clientIP != "loopback-direct" {
		s.sniff.MarkTrustedClientIPs(clientIP)
	}
}

func (s *Server) collectEnrichedTelemetry(r *http.Request) EnrichedTelemetrySnapshot {
	snap := s.telemetry.Collect(r.Context())
	out := EnrichedTelemetrySnapshot{Snapshot: snap}
	if s.sniff != nil {
		s.markRequestClientTrusted(r)
		summary := s.sniff.Snapshot(r.Context(), snap.ActiveClientIPs...)
		out.Sniffing = &summary
	}
	return out
}

func (s *Server) handleTelemetrySnapshot(w http.ResponseWriter, r *http.Request) {
	snap := s.collectEnrichedTelemetry(r)
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) getOrBuildTelemetrySSEFrame(r *http.Request) ([]byte, error) {
	s.markRequestClientTrusted(r)

	s.caches.sse.mu.Lock()
	defer s.caches.sse.mu.Unlock()
	if len(s.caches.sse.cachedFrame) > 0 && time.Since(s.caches.sse.cachedAt) < 900*time.Millisecond {
		return s.caches.sse.cachedFrame, nil
	}
	snap := s.collectEnrichedTelemetry(r)
	raw, err := json.Marshal(snap)
	if err != nil {
		return nil, err
	}
	s.caches.sse.cachedFrame = raw
	s.caches.sse.cachedAt = time.Now()
	return raw, nil
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
		raw, err := s.getOrBuildTelemetrySSEFrame(r)
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
		if runErr := s.serviceMgr().Restart(context.Background(), "sing-box"); runErr != nil {
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
