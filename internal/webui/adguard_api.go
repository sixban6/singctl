package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/singbox"
	"singctl/internal/util/netinfo"
)

func (s *Server) newAdGuardManager(cfg *config.Config) *adguard.Manager {
	mgr := adguard.NewManager(cfg, s.opts.ConfigPath)
	mgr.SetPathsForTest(s.opts.AdGuardBinPath, s.opts.AdGuardConfigPath)
	return mgr
}

func (s *Server) adguardBinPath() string {
	return cmp.Or(strings.TrimSpace(s.opts.AdGuardBinPath), constant.AdGuardInstallPath)
}

func (s *Server) adguardConfigFilePath() string {
	return cmp.Or(strings.TrimSpace(s.opts.AdGuardConfigPath), constant.AdGuardConfigFile)
}

func (s *Server) cachedAdGuardVersion(binPath string) string {
	info, err := os.Stat(binPath)
	if err != nil || info.IsDir() {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", binPath, info.ModTime().UnixNano(), info.Size())

	s.aghVerMu.Lock()
	if s.aghVerBinKey == key && s.aghVerCached != "" {
		ver := s.aghVerCached
		s.aghVerMu.Unlock()
		return ver
	}
	s.aghVerMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	out, err := exec.CommandContext(ctx, binPath, "--version").Output()
	cancel()
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(string(out))

	s.aghVerMu.Lock()
	s.aghVerBinKey = key
	s.aghVerCached = ver
	s.aghVerMu.Unlock()
	return ver
}

// adguardStatusSummary 返回轻量级 AdGuard Home 顶栏与总览卡片状态快照（控制在毫秒级，不阻塞 /api/status）。
func (s *Server) adguardStatusSummary() map[string]any {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	binPath := s.adguardBinPath()
	aghCfgPath := s.adguardConfigFilePath()

	installed := false
	if binPath != "" {
		if info, statErr := os.Stat(binPath); statErr == nil && !info.IsDir() {
			installed = true
		}
	}

	dnsPort := cfg.DNS.GetDNSPort()
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(dnsPort))
	webAddr := adguard.ReadCurrentHTTPAddress(aghCfgPath)
	if webAddr == "" {
		lanIP := "127.0.0.1"
		if ni, niErr := netinfo.Get(); niErr == nil && ni.LANIPv4 != "" {
			lanIP = ni.LANIPv4
		}
		webAddr = net.JoinHostPort(lanIP, strconv.Itoa(cfg.DNS.GetWebPort()))
	}

	dnsHealthy := false
	webHealthy := false
	version := ""
	if installed {
		dnsHealthy = adguard.ProbeDNS(dnsAddr, 300*time.Millisecond) == nil
		webHealthy = adguard.ProbeTCPPort(webAddr, 250*time.Millisecond)
		version = s.cachedAdGuardVersion(binPath)
	}
	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	singboxLinked, _ := singbox.InspectSingBoxDNSLocal(sbCfgPath)

	return map[string]any{
		"supported":     adguard.IsSupportedPlatform(),
		"installed":     installed,
		"enabled":       cfg.DNS.IsEnabled(),
		"running":       dnsHealthy || webHealthy,
		"dnsHealthy":    dnsHealthy,
		"webHealthy":    webHealthy,
		"singboxLinked": singboxLinked,
		"version":       version,
		"dnsAddr":       dnsAddr,
		"webUrl":        "http://" + webAddr,
	}
}

func (s *Server) syncAdGuardSubWhitelistAsync(cfg *config.Config) {
	if cfg == nil || len(cfg.Subs) == 0 {
		return
	}
	var urls []string
	for _, sub := range cfg.Subs {
		if strings.TrimSpace(sub.URL) != "" {
			urls = append(urls, sub.URL)
		}
	}
	if len(urls) == 0 {
		return
	}
	cfgCopy := *cfg
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.newAdGuardManager(&cfgCopy).SyncSubscriptionWhitelist(ctx, urls)
	}()
}

// handleAdGuardOverviewGet 返回 AdGuard Home 完整工作台快照。
func (s *Server) handleAdGuardOverviewGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	sbCfgPath := cmp.Or(strings.TrimSpace(s.opts.SingBoxConfigPath), constant.SingBoxConfigFile)
	linked, _ := singbox.InspectSingBoxDNSLocal(sbCfgPath)

	mgr := s.newAdGuardManager(cfg)
	snap := mgr.Overview(r.Context(), linked)
	writeJSON(w, http.StatusOK, snap)
}

// handleAdGuardCredentialsGet 仅在用户主动点开「原生面板与凭据」抽屉时返回登录凭据。
func (s *Server) handleAdGuardCredentialsGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	st := s.newAdGuardManager(cfg).Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"webUrl":   st.WebURL,
		"username": st.Username,
		"password": st.Password,
	})
}

// handleAdGuardCredentialsResetPost 一键轮换 16 位高强度随机密码并无损同步至 AdGuardHome.yaml。
func (s *Server) handleAdGuardCredentialsResetPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	mgr := s.newAdGuardManager(cfg)
	user, pass, err := mgr.ResetCredentials(body.Username)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	st := mgr.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"webUrl":   st.WebURL,
		"username": user,
		"password": pass,
	})
}

// handleAdGuardProtectionPost 切换去广告规则保护状态（支持临时暂停 5/30/60 分钟，不断网）。
func (s *Server) handleAdGuardProtectionPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled         bool `json:"enabled"`
		DurationMinutes int  `json:"durationMinutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	if err := s.newAdGuardManager(cfg).SetProtection(r.Context(), body.Enabled, body.DurationMinutes); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdGuardCacheClearPost 清空 AdGuard Home 本地 DNS 缓存。
func (s *Server) handleAdGuardCacheClearPost(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	if err := s.newAdGuardManager(cfg).ClearCache(r.Context()); err != nil {
		writeJSONError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdGuardProbePost 实测本地防劫持引擎及加密 DoH 上游端到端解析延迟。
func (s *Server) handleAdGuardProbePost(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.DNS.GetDNSPort()))
	if err := adguard.ProbeDNS(dnsAddr, 1200*time.Millisecond); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"healthy": false,
			"dnsAddr": dnsAddr,
			"error":   fmt.Sprintf("本地引擎 %s 未响应: %v", dnsAddr, err),
		})
		return
	}
	ips, elapsed, err := adguard.ProbeUpstreamResolution(dnsAddr, "qq.com", 3500*time.Millisecond)
	if err != nil || len(ips) == 0 {
		errMsg := "上游未返回有效 IP"
		if err != nil {
			errMsg = err.Error()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"healthy": false,
			"dnsAddr": dnsAddr,
			"error":   "加密 DoH 上游解析异常: " + errMsg,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"healthy":   true,
		"dnsAddr":   dnsAddr,
		"domain":    "qq.com",
		"resolved":  ips[0],
		"latencyMs": elapsed.Milliseconds(),
	})
}

// handleAdGuardWhitelistPost 一键加入或移除域名放行白名单。
func (s *Server) handleAdGuardWhitelistPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Action string `json:"action"` // "add" | "remove"
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	allow := strings.ToLower(strings.TrimSpace(body.Action)) != "remove"
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	if err := s.newAdGuardManager(cfg).SetDomainWhitelist(r.Context(), body.Domain, allow); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdGuardRewritesPost 管理内网自定义域名解析重写规则。
func (s *Server) handleAdGuardRewritesPost(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"` // "add" | "delete"
		Domain string `json:"domain"`
		Answer string `json:"answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	mgr := s.newAdGuardManager(cfg)
	switch strings.ToLower(strings.TrimSpace(body.Action)) {
	case "delete", "remove":
		if err := mgr.DeleteRewrite(r.Context(), body.Domain, body.Answer); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	default:
		if err := mgr.AddRewrite(r.Context(), body.Domain, body.Answer); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleAdGuardFiltersPost 管理去广告规则库（启用/停用预设、新增自定义订阅、删除、立即更新）。
func (s *Server) handleAdGuardFiltersPost(w http.ResponseWriter, r *http.Request) {
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
	cfg, err := config.Load(s.opts.ConfigPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
	mgr := s.newAdGuardManager(cfg)
	switch strings.ToLower(strings.TrimSpace(body.Action)) {
	case "refresh":
		if err := mgr.RefreshFilters(r.Context()); err != nil {
			writeJSONError(w, http.StatusBadGateway, err.Error())
			return
		}
	case "remove", "delete":
		if err := mgr.RemoveFilter(r.Context(), body.URL); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "add":
		if err := mgr.SetFilterState(r.Context(), body.URL, body.Name, true); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	default: // "toggle"
		if err := mgr.SetFilterState(r.Context(), body.URL, body.Name, body.Enabled); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
