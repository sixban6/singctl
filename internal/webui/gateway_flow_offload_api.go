// 文件职责：提供宿主机软硬件流量卸载状态探测与在线热开关 Web API，并在重载防火墙后自动保活主旁路由规则。
package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/gateway"
	"singctl/internal/vlan"
)

type gatewayFlowOffloadPutRequest struct {
	Enabled          *bool `json:"enabled"`
	SafeCommit       bool  `json:"safeCommit,omitempty"`
	SafeCommitTtlSec int   `json:"safeCommitTtlSec,omitempty"`
}

func (s *Server) probeGatewayFlowOffloadStatus(ctx context.Context) gateway.FlowOffloadStatus {
	if s.opts.FlowOffloadProberForTest != nil {
		return s.opts.FlowOffloadProberForTest(ctx)
	}
	if runtime.GOOS != "linux" {
		return gateway.FlowOffloadStatus{Supported: false}
	}
	return gateway.ProbeFlowOffloadStatus(ctx, gateway.FlowOffloadDeps{})
}

func (s *Server) applyGatewayFlowOffload(ctx context.Context, cfg *config.Config, enable bool) (gateway.FlowOffloadApplyResult, error) {
	if s.opts.FlowOffloadApplyForTest != nil {
		return s.opts.FlowOffloadApplyForTest(ctx, enable)
	}
	res, err := gateway.ApplyFlowOffload(ctx, enable, gateway.FlowOffloadDeps{})
	if err != nil {
		return gateway.FlowOffloadApplyResult{}, err
	}

	if runtime.GOOS == "linux" && cfg != nil {
		if cfg.Gateway.EffectiveMode() == gateway.ModeMain && strings.TrimSpace(cfg.Gateway.SideRouterIP) != "" {
			if dnsRules := vlan.ReadDNSBypassRules(constant.VLANDNSBypassFile); len(dnsRules) > 0 {
				_ = vlan.SyncRuntimeDNSBypass(ctx, constant.VLANDNSBypassFile, dnsRules)
			}
			sideSpec := vlan.ReadSideRouteSpec(constant.VLANSideRoutesFile)
			if cfg.EffectiveWorkMode() == config.WorkModeDelegated || len(sideSpec.CIDRs) > 0 {
				sideSpec.SideRouterIP = strings.TrimSpace(cfg.Gateway.SideRouterIP)
				_ = vlan.SyncRuntimeSideRoutes(ctx, constant.VLANSideRoutesFile, sideSpec)
			}
		} else if cfg.Gateway.IsSideRouter() && daemon.IsSingBoxRunning() {
			_ = gateway.NewController().Apply(ctx, cfg.Gateway)
		}
	}

	return res, nil
}

func (s *Server) handleGatewayFlowOffloadPut(w http.ResponseWriter, r *http.Request) {
	var body gatewayFlowOffloadPutRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	if body.Enabled == nil {
		writeJSONError(w, http.StatusBadRequest, "缺少必需参数 enabled (true/false)")
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.readConfigOrEmpty()
	if body.SafeCommit {
		if _, err := s.armSafeCommit(r.Context(), body.SafeCommitTtlSec, "软硬件流量卸载切换"); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	res, err := s.applyGatewayFlowOffload(r.Context(), cfg, *body.Enabled)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "切换流量卸载失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"enabled":           res.Enabled,
		"appliedLive":       res.AppliedLive,
		"rebootRequired":    res.RebootRequired,
		"restoredBackup":    res.RestoredBackup,
		"actions":           res.Actions,
		"message":           res.Message,
		"flowOffloadStatus": res.Status,
	})
}
