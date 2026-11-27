// 文件职责：提供 OpenWrt Wi-Fi 体检、按需信道干扰扫描、一键安全优化与高并发底盘加速的薄 HTTP 控制器（联动 SafeCommit 自动回滚与短周期单飞缓存）。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"singctl/internal/safecommit"
	"singctl/internal/wifiopt"
)

func (s *Server) wifiOptService() *wifiopt.Service {
	if s.opts.WifiOptServiceForTest != nil {
		return s.opts.WifiOptServiceForTest
	}
	return wifiopt.NewService(wifiopt.Env{})
}

func (s *Server) invalidateWifiCache() {
	if s.wifiCache != nil {
		s.wifiCache.Invalidate()
	}
	if s.statusCache != nil {
		s.statusCache.Invalidate()
	}
}

func (s *Server) handleWifiOverviewGet(w http.ResponseWriter, r *http.Request) {
	if s.wifiCache != nil && r.URL.Query().Get("fresh") != "1" {
		if ov, err := s.wifiCache.Get(r.Context()); err == nil && ov != nil {
			writeJSON(w, http.StatusOK, ov)
			return
		}
	}
	ov, err := s.wifiOptService().Overview(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取 Wi-Fi 状态与体检信息失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleWifiScanPost(w http.ResponseWriter, r *http.Request) {
	res, err := s.wifiOptService().Scan(r.Context())
	if err != nil {
		if errors.Is(err, wifiopt.ErrUnsupported) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "扫描周边无线信道失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleWifiApplyPost(w http.ResponseWriter, r *http.Request) {
	var req wifiopt.ApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	svc := s.wifiOptService()
	if req.DryRun {
		res, err := svc.Apply(r.Context(), req)
		if err != nil {
			writeWifiApplyError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}

	// 先做 DryRun 预检，避免无效入参触发 SafeCommit 武装
	preReq := req
	preReq.DryRun = true
	preview, err := svc.Apply(r.Context(), preReq)
	if err != nil {
		writeWifiApplyError(w, err)
		return
	}
	if len(preview.Changes) == 0 {
		ov, _ := svc.Overview(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":       true,
			"action":   req.Action,
			"summary":  preview.Summary,
			"changes":  preview.Changes,
			"reloaded": false,
			"overview": ov,
		})
		return
	}

	s.wifiApplyMu.Lock()
	defer s.wifiApplyMu.Unlock()

	reason := "Wi-Fi 安全调优: " + cmp.Or(strings.TrimSpace(req.Action), "optimize")
	scState, scErr := s.armSafeCommitWithExtraSnapshots(r.Context(), req.TTLSec, reason, map[string]string{
		"uci_wireless": "/etc/config/wireless",
	})
	if scErr != nil {
		if errors.Is(scErr, safecommit.ErrInvalidTTL) {
			writeJSONError(w, http.StatusBadRequest, scErr.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "武装防失联安全回滚保险丝失败，已中止写入: "+scErr.Error())
		return
	}

	res, err := svc.Apply(r.Context(), req)
	if err != nil {
		// 后端即时网桥自检失败已完成自动回滚，解除本次无效保险丝防止重复回滚
		_, _ = s.safeCommitManager().Confirm(scState.Token)
		s.invalidateWifiCache()
		writeWifiApplyError(w, err)
		return
	}

	s.invalidateWifiCache()
	ov, _ := svc.Overview(r.Context())

	res.SafeCommitToken = scState.Token
	res.SafeCommitTTLSec = scState.TTLSec

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               res.OK,
		"action":           res.Action,
		"summary":          res.Summary,
		"changes":          res.Changes,
		"reloaded":         res.Reloaded,
		"bridgeVerified":   res.BridgeVerified,
		"bridgeWaitMs":     res.BridgeWaitMs,
		"warnings":         res.Warnings,
		"safeCommitToken":  res.SafeCommitToken,
		"safeCommitTtlSec": res.SafeCommitTTLSec,
		"safeCommit":       s.safeCommitStatusPayload(s.readConfigOrEmpty()),
		"overview":         ov,
	})
}

func (s *Server) handleWifiChassisPost(w http.ResponseWriter, r *http.Request) {
	var req wifiopt.ChassisApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	res, err := s.wifiOptService().ApplyChassis(r.Context(), req)
	if err != nil {
		if errors.Is(err, wifiopt.ErrInvalidRequest) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "应用高并发底盘加速失败: "+err.Error())
		return
	}
	s.invalidateWifiCache()
	writeJSON(w, http.StatusOK, res)
}

func writeWifiApplyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, wifiopt.ErrInvalidRequest),
		errors.Is(err, wifiopt.ErrUnsupported),
		errors.Is(err, wifiopt.ErrRadioNotFound),
		errors.Is(err, wifiopt.ErrInterfaceNotFound):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	default:
		writeJSONError(w, http.StatusInternalServerError, err.Error())
	}
}

// wifiOverviewLoader 供 swrcache 单飞缓存复用。
func (s *Server) wifiOverviewLoader(ctx context.Context) (*wifiopt.Overview, error) {
	return s.wifiOptService().Overview(ctx)
}
