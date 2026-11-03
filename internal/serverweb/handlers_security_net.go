package serverweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/netdiag"
)

func (s *Server) handleNetReturn(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	summary, err := netdiag.RunReturnRoute(ctx, 3)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "三网回程测试失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleWarpDiagnose(w http.ResponseWriter, r *http.Request) {
	res := diagnoseWARP()
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleRegeneratePath(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	newPath := config.GenerateRandomAdminPath()
	cfg.Server.WebAdmin.Path = newPath
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存新随机路径失败: "+err.Error())
		return
	}
	s.mu.Lock()
	s.gatewayToken = config.DeriveGatewayToken(newPath)
	s.mu.Unlock()

	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("重新应用 Caddyfile 警告: %v", err)
	}

	subDomain := cfg.Server.GetSubstoreDomain()
	if subDomain == "" {
		subDomain = cfg.Server.GetNodeDomain()
	}
	newHTTPS := fmt.Sprintf("https://%s%s/", subDomain, newPath)

	s.recordAudit(r, fmt.Sprintf("重新生成随机安全管理路径为 [%s]", newPath))
	writeJSON(w, http.StatusOK, map[string]any{
		"message":  "全新隐蔽访问路径已生成并生效",
		"path":     newPath,
		"httpsUrl": newHTTPS,
	})
}

func (s *Server) handleRegenerateMaskSite(w http.ResponseWriter, r *http.Request) {
	meta, err := deploy.RegenerateMaskSite()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "重新生成伪装站点失败: "+err.Error())
		return
	}

	s.recordAudit(r, "重新生成随机伪装站")
	writeJSON(w, http.StatusOK, map[string]any{
		"message": fmt.Sprintf("已成功重新生成伪装博客：%s（作者：%s，主题：%s）", meta.BlogTitle, meta.AuthorName, meta.Category),
		"meta":    meta,
	})
}

func (s *Server) handleUpdateSNI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SNI string `json:"sni"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.SNI) == "" {
		writeJSONError(w, http.StatusBadRequest, "SNI 域名不能为空")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	cfg.Server.Sni = strings.TrimSpace(body.SNI)
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	if err := deploy.DeployCaddy(cfg); err != nil {
		logger.Warn("更新 Caddy SNI 警告: %v", err)
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err == nil {
		_ = sbs.LoadExistingCredentials()
		_ = sbs.DeploySingbox()

		sbt := deploy.NewSubstore(cfg, "")
		_ = sbt.UpdateSubstoreConfig(sbs)
	}

	s.recordAudit(r, fmt.Sprintf("更新 Reality SNI 伪装域名为 [%s]", cfg.Server.Sni))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Reality SNI 已成功更新为 " + cfg.Server.Sni + " 并自动重载服务与订阅",
		"sni":     cfg.Server.Sni,
	})
}

func (s *Server) handleEnableBBR(w http.ResponseWriter, r *http.Request) {
	if err := deploy.EnableBBR(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "启用 TCP BBR 失败: "+err.Error())
		return
	}
	bbrOk := isBBREnabled()
	s.recordAudit(r, "启用 Google TCP BBR 加速")
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Google TCP BBR 拥塞控制算法已成功开启并立即生效",
		"bbr":     bbrOk,
	})
}

func (s *Server) handleUpdateCFToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Token) == "" {
		writeJSONError(w, http.StatusBadRequest, "Cloudflare Token 不能为空")
		return
	}

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}

	cfg.Server.CFDNSKey = strings.TrimSpace(body.Token)
	if err := config.Save(s.opts.ConfigPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	if err := deploy.RotateCloudflareToken(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "轮换 Token 失败: "+err.Error())
		return
	}

	s.recordAudit(r, "轮换 Cloudflare API Token")
	writeJSON(w, http.StatusOK, map[string]string{"message": "Cloudflare Token 已成功更新并重载 Caddy"})
}

func (s *Server) handleDoctor(w http.ResponseWriter, r *http.Request) {
	cfg, _ := config.Load(s.opts.ConfigPath)
	report := doctor.RunServerDoctor(cfg)
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleUnlockDiagnose(w http.ResponseWriter, r *http.Request) {
	report := doctor.CheckMediaUnlock()
	writeJSON(w, http.StatusOK, report)
}
