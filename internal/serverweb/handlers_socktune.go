// 文件职责：提供服务端 QUIC/UDP Socket 缓冲区与 BBR/FQ 状态探测及防断连异步重载 Caddy 一键优化接口。
package serverweb

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"singctl/internal/common/httpx"
	"singctl/internal/common/socktune"
	"singctl/internal/logger"
)

const defaultCaddyAsyncRestartDelay = 600 * time.Millisecond

func (s *Server) sockTuneEnv() socktune.Env {
	if s != nil {
		if env := s.snapshotDeps().SockTuneEnv; env != nil {
			return *env
		}
	}
	return socktune.Env{}
}

func (s *Server) caddyRestartDelay() time.Duration {
	if s != nil {
		if d := s.snapshotDeps().CaddyAsyncRestartDelayForTest; d != nil && *d > 0 {
			return *d
		}
	}
	return defaultCaddyAsyncRestartDelay
}

func (s *Server) handleGetSocketTune(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, socktune.Inspect(socktune.ProfileServer, s.sockTuneEnv()))
}

func (s *Server) handleApplySocketTune(w http.ResponseWriter, r *http.Request) {
	type reqBody struct {
		DefaultPreset string `json:"defaultPreset"`
		RmemMax       int    `json:"rmemMax"`
		WmemMax       int    `json:"wmemMax"`
		RmemDefault   int    `json:"rmemDefault"`
		WmemDefault   int    `json:"wmemDefault"`
		EnableBBR     *bool  `json:"enableBbr"`
		RestartCaddy  *bool  `json:"restartCaddy"`
	}
	body, ok := decodeBodyJSON[reqBody](w, r, httpx.DefaultMaxBodyBytes, true, "Socket 缓冲调优请求格式无效")
	if !ok {
		return
	}

	applyReq := socktune.ApplyRequest{
		DefaultPreset: body.DefaultPreset,
		RmemMax:       body.RmemMax,
		WmemMax:       body.WmemMax,
		RmemDefault:   body.RmemDefault,
		WmemDefault:   body.WmemDefault,
		EnableBBR:     body.EnableBBR,
	}

	res, err := socktune.Apply(r.Context(), socktune.ProfileServer, applyReq, s.sockTuneEnv())
	if err != nil {
		switch {
		case errors.Is(err, socktune.ErrInvalidRequest),
			errors.Is(err, socktune.ErrUnsupported),
			errors.Is(err, socktune.ErrReadOnlyKernel):
			writeJSONError(w, http.StatusBadRequest, err.Error())
		default:
			writeJSONError(w, http.StatusInternalServerError, "应用 Socket 缓冲优化失败: "+err.Error())
		}
		return
	}

	wantRestart := body.RestartCaddy == nil || *body.RestartCaddy
	asyncCaddyRestart := wantRestart && (res.DefaultBufferChanged || (body.RestartCaddy != nil && *body.RestartCaddy))

	msg := "QUIC/UDP Socket 缓冲与 BBR/FQ 优化已成功写入并生效"
	if asyncCaddyRestart {
		msg = "优化参数已立即生效，Caddy 将在 1 秒内平滑重载以更新 UDP 默认缓冲"
	}

	s.invalidateStatusCaches()
	s.recordAudit(r, fmt.Sprintf("优化服务端 QUIC/UDP Socket 缓冲 [%s]", strings.Join(res.Actions, "; ")))

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   res.OK,
		"message":              msg,
		"actions":              res.Actions,
		"warnings":             res.Warnings,
		"defaultBufferChanged": res.DefaultBufferChanged,
		"restartRecommended":   res.RestartRecommended,
		"asyncCaddyRestart":    asyncCaddyRestart,
		"status":               res.Status,
	})

	if asyncCaddyRestart {
		// 先完整冲刷 HTTP 200 响应再延迟重启 Caddy，防止面板本身经 Caddy :443 反代访问时出现连接中断误报
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		s.scheduleAsyncCaddyRestart(r.Context(), s.caddyRestartDelay())
	}
}

func (s *Server) scheduleAsyncCaddyRestart(reqCtx context.Context, delay time.Duration) {
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	bgCtx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), 25*time.Second)
	mgr := s.serviceMgr()
	go func() {
		defer cancel()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-bgCtx.Done():
			return
		case <-timer.C:
		}
		if err := mgr.Restart(bgCtx, "caddy"); err != nil {
			logger.Warn("[SockTune] 异步重载 Caddy 失败: %v", err)
		}
		s.invalidateStatusCaches()
	}()
}
