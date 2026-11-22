// 文件职责：提供客户端 WebUI 统一双引擎防劫持 DNS (/api/dns/* 与 /api/adguard/* 兼容别名) 接口与 SmartDNS 审计日志采集循环。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/localdns"
)

func (s *Server) newDNSRegistry(cfg *config.Config) *localdns.Registry {
	var readMem func() (sysinfo.MemInfo, error)
	if s.opts.AdGuardMemInfoForTest != nil {
		fn := s.opts.AdGuardMemInfoForTest
		readMem = func() (sysinfo.MemInfo, error) {
			return fn(), nil
		}
	}

	deps := localdns.EngineDeps{
		ConfigPath:              s.opts.ConfigPath,
		SaveConfig:              s.saveConfig,
		SingBoxConfigPath:       cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile),
		SingBoxWorkConfigPath:   s.opts.SingBoxWorkConfigPath,
		AdGuardBinPath:          s.opts.AdGuardBinPath,
		AdGuardConfigPath:       s.opts.AdGuardConfigPath,
		SmartDNSBinPath:         s.opts.SmartDNSBinPath,
		SmartDNSConfigFile:      s.opts.SmartDNSConfigPath,
		SmartDNSRulesDir:        s.opts.SmartDNSRulesDir,
		SmartDNSAuditLogPath:    s.opts.SmartDNSAuditLogPath,
		ServiceMgr:              s.opts.LocalDNSServiceMgr,
		ReadMemInfo:             readMem,
		ReadDiskSpace:           s.opts.DiskSpaceForTest,
		SkipProbeForTest:        s.opts.SkipAdGuardProbeForTest,
		ProbeUpstreamListFunc:   s.opts.DNSProbeUpstreamForTest,
		ProbeDNSFunc:            s.opts.LocalDNSProbeDNSForTest,
		ProbeResolutionFunc:     s.opts.LocalDNSProbeResForTest,
		SyncSingBoxDNSLocalFunc: s.opts.LocalDNSSyncSingBoxDNSLocalForTest,
		NowFunc:                 s.now,
		SmartDNSStats:           s.smartDNSStatsRing,
		SmartDNSTailer:          s.smartDNSTailer,
	}
	return localdns.NewRegistry(cfg, deps)
}

func (s *Server) runDNSTelemetryLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg := s.readConfigOrEmpty()
		reg := s.newDNSRegistry(cfg)
		active := reg.ActiveEngine()
		if active != nil && active.ID() == constant.DNSEngineSmartDNS && active.IsInstalled() {
			reg.DrainSmartDNSAuditLog()
		}
	}
}

func (s *Server) dnsStatusSummary(ctx context.Context) map[string]any {
	cfg := s.readConfigOrEmpty()
	return s.newDNSRegistry(cfg).StatusSummary(ctx)
}

func (s *Server) handleDNSOverviewGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	reg := s.newDNSRegistry(cfg)
	writeJSON(w, http.StatusOK, reg.Overview(r.Context()))
}

func (s *Server) handleDNSCredentialsGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	reg := s.newDNSRegistry(cfg)
	eng := reg.ActiveEngine()
	if cm, ok := eng.(localdns.CredentialManager); ok {
		creds, err := cm.Credentials(r.Context())
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, creds)
		return
	}
	// 非 AdGuard 活跃时仍兼容返回已存 AdGuard 面板凭据（空值安全）
	if aghEng, ok := reg.Get(constant.DNSEngineAdGuard); ok {
		if cm, isCM := aghEng.(localdns.CredentialManager); isCM {
			if creds, err := cm.Credentials(r.Context()); err == nil {
				writeJSON(w, http.StatusOK, creds)
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, localdns.CredentialsInfo{})
}

func (s *Server) handleDNSCredentialsResetPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	reg := s.newDNSRegistry(cfg)
	aghEng, ok := reg.Get(constant.DNSEngineAdGuard)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "当前环境未注册 AdGuard Home 凭据管理模块")
		return
	}
	cm, ok := aghEng.(localdns.CredentialManager)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "当前引擎不支持重置面板凭据")
		return
	}
	creds, err := cm.ResetCredentials(r.Context(), body.Username)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateConfigStore()
	writeJSON(w, http.StatusOK, creds)
}

func (s *Server) handleDNSConfigPreviewGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	reg := s.newDNSRegistry(cfg)
	eng := reg.ActiveEngine()
	if eng == nil {
		writeJSONError(w, http.StatusNotFound, "未找到活跃的防劫持 DNS 引擎")
		return
	}
	preview, err := eng.ConfigPreview(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, preview)
}

func (s *Server) handleDNSEngineSwitchPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		localdns.SwitchRequest
		SafeCommit       bool `json:"safeCommit,omitempty"`
		SafeCommitTTLSec int  `json:"safeCommitTtlSec,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	body.NonInteractive = true

	if body.SafeCommit {
		if _, err := s.armSafeCommit(r.Context(), body.SafeCommitTTLSec, "DNS 引擎切换"); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	reg := s.newDNSRegistry(cfg)
	res, err := reg.SwitchEngine(r.Context(), body.SwitchRequest)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.invalidateIOSCache()
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleDNSProtectionPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled         bool `json:"enabled"`
		DurationMinutes int  `json:"durationMinutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	if err := eng.SetProtection(r.Context(), body.Enabled, body.DurationMinutes); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDNSCacheClearPost(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	if err := eng.ClearCache(r.Context()); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDNSProbePost(w http.ResponseWriter, r *http.Request) {
	cfg := s.readConfigOrEmpty()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	report := eng.ProbeUpstreams(r.Context(), "qq.com")
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) handleDNSUpstreamsPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Upstreams    []string `json:"upstreams"`
		UpstreamMode string   `json:"upstreamMode"`
		ResetDefault bool     `json:"resetDefault"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	res, err := eng.SetUpstreams(r.Context(), body.Upstreams, body.UpstreamMode, body.ResetDefault)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"upstreams":         res.Upstreams,
		"upstreamMode":      res.UpstreamMode,
		"upstreamModeLabel": cmp.Or(res.UpstreamModeLabel, adguard.UpstreamModeDescription(res.UpstreamMode)),
		"notes":             res.Notes,
	})
}

func (s *Server) handleDNSWhitelistPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Action string `json:"action"` // "add" | "remove"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	allow := strings.ToLower(strings.TrimSpace(body.Action)) != "remove"

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	if err := eng.SetWhitelist(r.Context(), body.Domain, allow); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDNSRewritesPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"` // "add" | "delete"
		Domain string `json:"domain"`
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	switch strings.ToLower(strings.TrimSpace(body.Action)) {
	case "delete", "remove":
		if err := eng.DeleteRewrite(r.Context(), body.Domain, body.Answer); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		if err := eng.AddRewrite(r.Context(), body.Domain, body.Answer); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDNSFiltersPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action  string `json:"action"` // "toggle" | "add" | "remove" | "refresh"
		URL     string `json:"url"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	eng := s.newDNSRegistry(cfg).ActiveEngine()
	switch strings.ToLower(strings.TrimSpace(body.Action)) {
	case "refresh":
		if err := eng.RefreshFilters(r.Context()); err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
	case "remove", "delete":
		if err := eng.RemoveFilter(r.Context(), body.URL); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "add":
		if err := eng.SetFilterState(r.Context(), body.URL, body.Name, true); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	default: // "toggle"
		if err := eng.SetFilterState(r.Context(), body.URL, body.Name, body.Enabled); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
