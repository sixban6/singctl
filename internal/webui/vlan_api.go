// 文件职责：提供 OpenWrt 本机原生 VLAN 子网隔离与透明代理联动的 HTTP 路由薄控制器（自动接入 Safe Commit 回滚保险丝）。
package webui

import (
	"cmp"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"singctl/internal/constant"
	"singctl/internal/safecommit"
	"singctl/internal/vlan"
)

func (s *Server) vlanService() *vlan.Service {
	if s.opts.VLANServiceForTest != nil {
		return s.opts.VLANServiceForTest
	}
	return vlan.NewService(vlan.Env{})
}

func vlanSnapshotFiles() map[string]string {
	return map[string]string{
		"uci_network":       "/etc/config/network",
		"uci_dhcp":          "/etc/config/dhcp",
		"uci_wireless":      "/etc/config/wireless",
		"uci_firewall":      "/etc/config/firewall",
		"vlan_proxy_bypass": constant.VLANProxyBypassFile,
	}
}

func callerIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (s *Server) handleVLANOverviewGet(w http.ResponseWriter, r *http.Request) {
	ov, err := s.vlanService().Overview(r.Context(), callerIPFromRequest(r))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取 VLAN 拓扑概览失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleVLANPreviewPost(w http.ResponseWriter, r *http.Request) {
	var req vlan.SaveSegmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	res, err := s.vlanService().PreviewSave(r.Context(), callerIPFromRequest(r), req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成 VLAN 变更预览失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleVLANApplyPost(w http.ResponseWriter, r *http.Request) {
	var req vlan.SaveSegmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	caller := callerIPFromRequest(r)
	svc := s.vlanService()
	preview, err := svc.PreviewSave(r.Context(), caller, req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "预检 VLAN 变更失败: "+err.Error())
		return
	}
	if !preview.Valid {
		writeJSONError(w, http.StatusBadRequest, cmp.Or(strings.Join(preview.Errors, "；"), "VLAN 配置校验未通过"))
		return
	}

	reason := "VLAN 子网变更: " + cmp.Or(strings.TrimSpace(req.DisplayName), strings.TrimSpace(req.ID))
	scState, scErr := s.armSafeCommitWithExtraSnapshots(r.Context(), req.TTLSec, reason, vlanSnapshotFiles())
	if scErr != nil {
		if errors.Is(scErr, safecommit.ErrInvalidTTL) {
			writeJSONError(w, http.StatusBadRequest, scErr.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "武装防失联安全回滚保险丝失败，已中止写入: "+scErr.Error())
		return
	}

	res, err := svc.ApplySave(r.Context(), caller, req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "应用 VLAN 配置失败: "+err.Error())
		return
	}
	res.SafeCommitToken = scState.Token
	res.SafeCommitTTLSec = scState.TTLSec

	ov, _ := svc.Overview(r.Context(), caller)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                res.OK,
		"segmentId":         res.SegmentID,
		"plainSummary":      res.PlainSummary,
		"uciCommands":       res.UCICommands,
		"warnings":          res.Warnings,
		"upstreamRouteHint": res.UpstreamRouteHint,
		"safeCommitToken":   res.SafeCommitToken,
		"safeCommitTtlSec":  res.SafeCommitTTLSec,
		"safeCommit":        s.safeCommitStatusPayload(s.readConfigOrEmpty()),
		"overview":          ov,
	})
}

func (s *Server) handleVLANDeletePreviewPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	res, err := s.vlanService().PreviewDelete(r.Context(), callerIPFromRequest(r), body.ID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成 VLAN 删除预览失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleVLANDelete(w http.ResponseWriter, r *http.Request) {
	segID := strings.TrimSpace(r.PathValue("id"))
	caller := callerIPFromRequest(r)
	svc := s.vlanService()

	preview, err := svc.PreviewDelete(r.Context(), caller, segID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "预检 VLAN 删除失败: "+err.Error())
		return
	}
	if !preview.Valid {
		writeJSONError(w, http.StatusBadRequest, cmp.Or(strings.Join(preview.Errors, "；"), "不允许删除该网络分段"))
		return
	}

	scState, scErr := s.armSafeCommitWithExtraSnapshots(r.Context(), 0, "删除 VLAN 子网: "+segID, vlanSnapshotFiles())
	if scErr != nil {
		writeJSONError(w, http.StatusInternalServerError, "武装防失联安全回滚保险丝失败，已中止删除: "+scErr.Error())
		return
	}

	res, err := svc.ApplyDelete(r.Context(), caller, segID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "删除 VLAN 子网失败: "+err.Error())
		return
	}
	res.SafeCommitToken = scState.Token
	res.SafeCommitTTLSec = scState.TTLSec

	ov, _ := svc.Overview(r.Context(), caller)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":               res.OK,
		"segmentId":        res.SegmentID,
		"plainSummary":     res.PlainSummary,
		"uciCommands":      res.UCICommands,
		"safeCommitToken":  res.SafeCommitToken,
		"safeCommitTtlSec": res.SafeCommitTTLSec,
		"safeCommit":       s.safeCommitStatusPayload(s.readConfigOrEmpty()),
		"overview":         ov,
	})
}
