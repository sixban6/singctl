// 文件职责：提供客户端 WebUI 分层防 DNS 绕过策略接口（GET/POST /api/dns/bypass-guard）及 sing-box 无感热同步。
package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

type dnsBypassGuardPostRequest struct {
	Enabled         *bool           `json:"enabled"`
	Layers          map[string]bool `json:"layers,omitempty"`
	AppGroups       map[string]bool `json:"appGroups,omitempty"`
	ExemptSourceIPs []string        `json:"exemptSourceIps"`
}

func (s *Server) syncSingBoxDNSBypassGuard(ctx context.Context, cfg *config.Config) error {
	sbPath := s.sbConfigPath()
	rawBytes, err := os.ReadFile(sbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	updated, changed, err := singbox.ApplyDNSBypassGuardToConfigJSON(string(rawBytes), cfg)
	if err != nil || !changed {
		return err
	}
	return singbox.ApplyLiveSingBoxConfig(ctx, sbPath, s.sbWorkConfigPath(), updated, "bypassguard")
}

func (s *Server) handleDNSBypassGuardGet(w http.ResponseWriter, _ *http.Request) {
	cfg := s.readConfigOrEmpty()
	writeJSON(w, http.StatusOK, singbox.InspectDNSBypassGuardStatus(cfg))
}

func (s *Server) handleDNSBypassGuardPost(w http.ResponseWriter, r *http.Request) {
	var body dnsBypassGuardPostRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	normExempt, err := config.NormalizeExemptSourceIPs(body.ExemptSourceIPs)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	normAppGroups := make(map[string]bool, len(body.AppGroups))
	for rawID, on := range body.AppGroups {
		id := strings.ToLower(strings.TrimSpace(rawID))
		if !config.IsKnownDNSBypassAppGroup(id) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("未知的 App HTTPDNS 分组: %q", rawID))
			return
		}
		normAppGroups[id] = on
	}

	var oldManagedWL []string
	var wechatChanged bool
	var nextSnap singbox.DNSBypassGuardSnapshot

	_, txErr := s.updateConfigTx(configTxOptions{
		InvalidateIOS: true,
		LiveApply: func(cfg *config.Config) error {
			if err := s.syncSingBoxDNSBypassGuard(r.Context(), cfg); err != nil {
				return &apiStatusError{status: http.StatusBadGateway, msg: "热同步 sing-box 防绕过策略失败: " + err.Error()}
			}
			if wechatChanged {
				newManagedWL := singbox.EffectiveAdBlockWhitelist(cfg)
				if wlErr := s.syncSingBoxAdBlockWhitelist(r.Context(), oldManagedWL, newManagedWL); wlErr != nil {
					logger.Warn("[DNS] 同步微信白名单互斥状态失败: %v", wlErr)
				}
				if eng := s.newDNSRegistry(cfg).ActiveEngine(); eng != nil && eng.IsInstalled() {
					_ = eng.SyncCommonConfig(r.Context())
				}
			}
			nextSnap = singbox.InspectDNSBypassGuardStatus(cfg)
			return nil
		},
	}, func(cfg *config.Config) error {
		prevWeChat := singbox.IsWeChatHTTPDNSRejectActive(cfg)
		oldManagedWL = singbox.EffectiveAdBlockWhitelist(cfg)

		nextBG := cfg.DNS.BypassGuard.Clone()
		if body.Enabled != nil {
			v := *body.Enabled
			nextBG.Enabled = &v
		}
		if body.Layers != nil {
			for k, v := range body.Layers {
				val := v
				switch strings.ToLower(strings.TrimSpace(k)) {
				case "dotdoq", "dot_doq":
					nextBG.Layers.DoTDoQ = &val
				case "publicdoh", "public_doh":
					nextBG.Layers.PublicDoH = &val
				case "sdkhttpdns", "sdk_httpdns":
					nextBG.Layers.SDKHTTPDNS = &val
				case "apphttpdns", "app_httpdns":
					nextBG.Layers.AppHTTPDNS = &val
				default:
					return &apiStatusError{status: http.StatusBadRequest, msg: fmt.Sprintf("未知的防绕过层级: %q", k)}
				}
			}
		}
		if len(normAppGroups) > 0 {
			if nextBG.AppGroups == nil {
				nextBG.AppGroups = make(map[string]bool, len(normAppGroups))
			}
			for id, on := range normAppGroups {
				nextBG.AppGroups[id] = on
			}
		}
		nextBG.ExemptSourceIPs = normExempt
		cfg.DNS.BypassGuard = nextBG
		wechatChanged = prevWeChat != singbox.IsWeChatHTTPDNSRejectActive(cfg)
		return nil
	})
	if txErr != nil {
		writePartialSaveError(w, txErr)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"bypassGuard": nextSnap,
	})
}
