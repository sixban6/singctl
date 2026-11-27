// 文件职责：提供客户端 WebUI 核心组件自动更新开关 API（GET/PUT /api/system/auto-update）。
package webui

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
)

type autoUpdateComponentDTO struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Enabled        bool   `json:"enabled"`
	Installed      bool   `json:"installed"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	LatestVersion  string `json:"latestVersion,omitempty"`
	LastCheckedAt  string `json:"lastCheckedAt,omitempty"`
	LastUpdatedAt  string `json:"lastUpdatedAt,omitempty"`
	Status         string `json:"status,omitempty"`
	Message        string `json:"message,omitempty"`
	LastError      string `json:"lastError,omitempty"`
}

type autoUpdateStatusDTO struct {
	SingCtl       bool                     `json:"singctl"`
	SingBox       bool                     `json:"singbox"`
	AdGuardHome   bool                     `json:"adguardHome"`
	Tailscale     bool                     `json:"tailscale"`
	IntervalHours int                      `json:"intervalHours"`
	DaemonRunning bool                     `json:"daemonRunning"`
	Components    []autoUpdateComponentDTO `json:"components"`
}

func (s *Server) buildAutoUpdateStatusDTO(cfg *config.Config) autoUpdateStatusDTO {
	if cfg == nil {
		cfg = &config.Config{}
	}
	au := cfg.Watchdog.AutoUpdate
	snap := daemon.LoadRuntimeSnapshot()
	snapMap := snap.AutoUpdate

	sbInstalled, sbVersion := false, ""
	aghInstalled, aghVersion := false, ""
	tsInstalled, tsVersion := false, ""
	if !s.opts.SkipAdGuardProbeForTest {
		sbSummary := singboxStatus()
		sbInstalled, _ = sbSummary["installed"].(bool)
		sbVersion, _ = sbSummary["version"].(string)

		aghInstalled = adguard.IsInstalled()
		if aghInstalled {
			aghVersion = strings.TrimSpace(adguard.CachedBinaryVersion(constant.AdGuardInstallPath))
		}

		if _, err := exec.LookPath("tailscale"); err == nil {
			tsInstalled = true
			tsSummary := s.tailscaleStatus(s.opts.ConfigPath)
			tsVersion, _ = tsSummary["version"].(string)
		}
	}

	scVer := strings.TrimSpace(s.opts.Version)
	if scVer != "" && scVer != "dev" && !strings.HasPrefix(scVer, "v") {
		scVer = "v" + scVer
	}

	mkItem := func(id, name, desc string, enabled, installed bool, curVer string) autoUpdateComponentDTO {
		st := snapMap[id]
		return autoUpdateComponentDTO{
			ID:             id,
			Name:           name,
			Description:    desc,
			Enabled:        enabled,
			Installed:      installed,
			CurrentVersion: cmp.Or(strings.TrimSpace(curVer), st.CurrentVersion),
			LatestVersion:  st.LatestVersion,
			LastCheckedAt:  st.LastCheckedAt,
			LastUpdatedAt:  st.LastUpdatedAt,
			Status:         cmp.Or(st.Status, "idle"),
			Message:        st.Message,
			LastError:      st.LastError,
		}
	}

	return autoUpdateStatusDTO{
		SingCtl:       au.SingCtl,
		SingBox:       au.SingBox,
		AdGuardHome:   au.AdGuardHome,
		Tailscale:     au.Tailscale,
		IntervalHours: au.EffectiveIntervalHours(),
		DaemonRunning: daemon.IsDaemonRunning(),
		Components: []autoUpdateComponentDTO{
			mkItem(
				daemon.AutoUpdateComponentSingCtl,
				"SingCtl 本体",
				"自动识别完整版 / -lite 并校验 SHA-256，升级后平滑重启看门狗与 WebUI（不中断代理）",
				au.SingCtl,
				true,
				scVer,
			),
			mkItem(
				daemon.AutoUpdateComponentSingBox,
				"sing-box 内核",
				"升级前备份旧版并执行 sing-box check 预校验，失败自动回滚；托管模式自动跳过",
				au.SingBox,
				sbInstalled,
				sbVersion,
			),
			mkItem(
				daemon.AutoUpdateComponentAdGuard,
				"AdGuard Home",
				"仅检测到新版本时无损升级并重启，保留既有过滤规则与凭据；未安装自动跳过",
				au.AdGuardHome,
				aghInstalled,
				aghVersion,
			),
			mkItem(
				daemon.AutoUpdateComponentTailscale,
				"Tailscale",
				"通过闪存与平台安全预检后移交脱离式切换器升级，连通性失败自动回滚旧版",
				au.Tailscale,
				tsInstalled,
				tsVersion,
			),
		},
	}
}

func (s *Server) handleAutoUpdateGet(w http.ResponseWriter, _ *http.Request) {
	cfg := s.readConfigOrEmpty()
	writeJSON(w, http.StatusOK, s.buildAutoUpdateStatusDTO(cfg))
}

func (s *Server) handleAutoUpdatePut(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SingCtl       *bool `json:"singctl"`
		SingBox       *bool `json:"singbox"`
		AdGuardHome   *bool `json:"adguardHome"`
		Tailscale     *bool `json:"tailscale"`
		IntervalHours *int  `json:"intervalHours"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求参数无效: "+err.Error())
		return
	}
	if req.SingCtl == nil && req.SingBox == nil && req.AdGuardHome == nil && req.Tailscale == nil && req.IntervalHours == nil {
		writeJSONError(w, http.StatusBadRequest, "请求参数无效：至少需要提供一个自动更新开关或周期字段")
		return
	}
	if req.IntervalHours != nil {
		h := *req.IntervalHours
		if h != 0 && (h < config.MinAutoUpdateIntervalHours || h > config.MaxAutoUpdateIntervalHours) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("检查周期必须在 %d~%d 小时之间（或填 0 使用默认 %d 小时）",
				config.MinAutoUpdateIntervalHours, config.MaxAutoUpdateIntervalHours, config.DefaultAutoUpdateIntervalHours))
			return
		}
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	nextCfg := s.loadMutableConfig()
	au := nextCfg.Watchdog.AutoUpdate
	if req.SingCtl != nil {
		au.SingCtl = *req.SingCtl
	}
	if req.SingBox != nil {
		au.SingBox = *req.SingBox
	}
	if req.AdGuardHome != nil {
		au.AdGuardHome = *req.AdGuardHome
	}
	if req.Tailscale != nil {
		au.Tailscale = *req.Tailscale
	}
	if req.IntervalHours != nil {
		au.IntervalHours = *req.IntervalHours
	}
	if !au.AnyEnabled() && req.IntervalHours == nil {
		au.IntervalHours = 0
	}
	nextCfg.Watchdog.AutoUpdate = au

	if err := s.saveConfig(nextCfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存 singctl.yaml 自动更新设置失败: "+err.Error())
		return
	}
	daemon.NotifyReload()

	enabledCount := 0
	for _, v := range []bool{au.SingCtl, au.SingBox, au.AdGuardHome, au.Tailscale} {
		if v {
			enabledCount++
		}
	}
	msg := "已关闭全部组件自动更新"
	if enabledCount > 0 {
		msg = fmt.Sprintf("组件自动更新配置已保存（已启用 %d/4 项，每 %d 小时巡检）", enabledCount, au.EffectiveIntervalHours())
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"message": msg,
		"status":  s.buildAutoUpdateStatusDTO(nextCfg),
	})
}
