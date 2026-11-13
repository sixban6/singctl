package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
)

type watchdogFailoverDTO struct {
	Enabled            bool     `json:"enabled"`
	Groups             []string `json:"groups"`
	IsDefaultGroups    bool     `json:"is_default_groups"`
	DefaultGroups      []string `json:"default_groups"`
	PatrolInterval     int      `json:"patrol_interval"`
	ProbeTimeoutMs     int      `json:"probe_timeout_ms"`
	ConfirmRetries     int      `json:"confirm_retries"`
	AutoFailback       bool     `json:"auto_failback"`
	FailbackCooldown   int      `json:"failback_cooldown"`
	MaxFailbackDelayMs int      `json:"max_failback_delay_ms"`
	ProbeURLs          []string `json:"probe_urls"`
	IsDefaultProbeURLs bool     `json:"is_default_probe_urls"`
}

type watchdogConfigDTO struct {
	Interval        int                 `json:"interval"`
	ConfirmWait     int                 `json:"confirm_wait"`
	MaxRestarts     int                 `json:"max_restarts"`
	SubSyncEnabled  bool                `json:"sub_sync_enabled"`
	SubSyncInterval int                 `json:"sub_sync_interval"`
	Failover        watchdogFailoverDTO `json:"failover"`
}

func buildWatchdogConfigDTO(cfg *config.Config) watchdogConfigDTO {
	if cfg == nil {
		cfg = &config.Config{}
	}
	wd := cfg.Watchdog
	interval := wd.Interval
	if interval <= 0 {
		interval = 180
	}
	confirmWait := wd.ConfirmWait
	if confirmWait <= 0 {
		confirmWait = 30
	}
	maxRestarts := wd.MaxRestarts
	if maxRestarts <= 0 {
		maxRestarts = 3
	}
	subSyncEnabled := wd.SubSyncInterval >= 0
	subSyncInterval := wd.SubSyncInterval
	if subSyncInterval <= 0 {
		subSyncInterval = 600
	}

	fo := wd.Failover
	effGroups := fo.EffectiveGroups()
	effURLs := fo.EffectiveProbeURLs()
	cooldownSec := 180
	if fo.FailbackCooldown > 0 {
		cooldownSec = fo.FailbackCooldown
	}

	return watchdogConfigDTO{
		Interval:        interval,
		ConfirmWait:     confirmWait,
		MaxRestarts:     maxRestarts,
		SubSyncEnabled:  subSyncEnabled,
		SubSyncInterval: subSyncInterval,
		Failover: watchdogFailoverDTO{
			Enabled:            fo.IsEnabled(),
			Groups:             effGroups,
			IsDefaultGroups:    len(fo.Groups) == 0 || slices.Equal(effGroups, config.DefaultWatchdogFailoverGroups),
			DefaultGroups:      slices.Clone(config.DefaultWatchdogFailoverGroups),
			PatrolInterval:     int(fo.EffectivePatrolInterval().Seconds()),
			ProbeTimeoutMs:     int(fo.EffectiveProbeTimeout().Milliseconds()),
			ConfirmRetries:     fo.EffectiveConfirmRetries(),
			AutoFailback:       fo.AutoFailbackEnabled(),
			FailbackCooldown:   cooldownSec,
			MaxFailbackDelayMs: fo.EffectiveMaxFailbackDelayMs(),
			ProbeURLs:          effURLs,
			IsDefaultProbeURLs: len(fo.ProbeURLs) == 0 || slices.Equal(effURLs, config.DefaultWatchdogProbeURLs),
		},
	}
}

func (s *Server) buildWatchdogReport(cfg *config.Config) map[string]any {
	dto := buildWatchdogConfigDTO(cfg)
	snap := daemon.LoadRuntimeSnapshot()
	running := daemon.IsDaemonRunning()
	pid := 0
	if running {
		if p, err := daemon.ReadDaemonPid(); err == nil {
			pid = p
		}
	}
	limiter := daemon.NewRestartLimiterFromState(dto.MaxRestarts)

	logPath := daemon.GetDaemonLogPath()
	var logSize int64
	if fi, err := os.Stat(logPath); err == nil {
		logSize = fi.Size()
	}

	stale := running && daemon.IsDaemonBinaryStale()
	curVer := strings.TrimPrefix(strings.TrimSpace(s.opts.Version), "v")
	dmVer := strings.TrimPrefix(strings.TrimSpace(snap.DaemonVersion), "v")
	versionMismatch := running && (stale || (curVer != "" && curVer != "dev" && dmVer != "" && dmVer != "dev" && curVer != dmVer))

	// 快速查询当前 Clash Selector 列表（1.5s 超时，sing-box 未运行时不阻塞）
	var selectorGroups []daemon.SelectorGroupSummary
	if daemon.IsSingBoxRunning() {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		if list, err := daemon.InspectClashSelectors(
			ctx,
			singbox.ClashAPIEndpoints(),
			singbox.ClashAPISecret(),
			dto.Failover.Groups,
			snap.ActiveFailovers,
		); err == nil {
			selectorGroups = list
		}
		cancel()
	}

	// 若 sing-box 在线且处于默认策略组模式，则按实际存在的 Selector 自动对齐，避免展示不存在的历史分组
	if len(selectorGroups) > 0 && dto.Failover.IsDefaultGroups {
		liveSet := make(map[string]bool, len(selectorGroups))
		liveNames := make([]string, 0, len(selectorGroups))
		for _, g := range selectorGroups {
			liveSet[g.Name] = true
			liveNames = append(liveNames, g.Name)
		}
		var synced []string
		for _, g := range dto.Failover.Groups {
			if liveSet[g] {
				synced = append(synced, g)
			}
		}
		if len(synced) == 0 {
			synced = liveNames
		}
		dto.Failover.Groups = synced
		dto.Failover.DefaultGroups = slices.Clone(synced)
		for i := range selectorGroups {
			selectorGroups[i].Watched = slices.Contains(synced, selectorGroups[i].Name)
		}
	}

	aghInfo := map[string]any{
		"supported": runtime.GOOS == "linux",
		"enabled":   cfg != nil && cfg.DNS.IsEnabled(),
		"installed": false,
		"healthy":   false,
	}
	if runtime.GOOS == "linux" && cfg != nil {
		installed := adguard.IsInstalled()
		aghInfo["installed"] = installed
		if installed {
			st := adguard.NewManager(cfg, s.opts.ConfigPath).Status()
			aghInfo["healthy"] = st.DNSHealthy
		}
	}

	return map[string]any{
		"daemon": map[string]any{
			"running":         running,
			"pid":             pid,
			"daemonVersion":   snap.DaemonVersion,
			"singctlVersion":  s.opts.Version,
			"staleBinary":     stale,
			"versionMismatch": versionMismatch,
			"startedAt":       snap.StartedAt,
			"restarts":        limiter.GetRestartCount(),
			"maxRestarts":     limiter.GetMaxRestarts(),
			"totalRestarts":   limiter.GetTotalRestarts(),
			"logPath":         logPath,
			"logSizeBytes":    logSize,
			"logMaxBytes":     daemon.MaxDaemonLogBytes,
		},
		"config":         dto,
		"runtime":        snap,
		"selectorGroups": selectorGroups,
		"adguard":        aghInfo,
	}
}

func (s *Server) handleWatchdogGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(configPathFor(s))
	if err != nil {
		cfg = &config.Config{}
	}
	writeJSON(w, http.StatusOK, s.buildWatchdogReport(cfg))
}

type watchdogConfigUpdateReq struct {
	Interval        *int `json:"interval"`
	ConfirmWait     *int `json:"confirm_wait"`
	MaxRestarts     *int `json:"max_restarts"`
	SubSyncEnabled  *bool `json:"sub_sync_enabled"`
	SubSyncInterval *int `json:"sub_sync_interval"`
	Failover        *struct {
		Enabled            *bool    `json:"enabled"`
		Groups             []string `json:"groups"`
		HasGroups          bool     `json:"has_groups"`
		PatrolInterval     *int     `json:"patrol_interval"`
		ProbeTimeoutMs     *int     `json:"probe_timeout_ms"`
		ConfirmRetries     *int     `json:"confirm_retries"`
		AutoFailback       *bool    `json:"auto_failback"`
		FailbackCooldown   *int     `json:"failback_cooldown"`
		MaxFailbackDelayMs *int     `json:"max_failback_delay_ms"`
		ProbeURLs          []string `json:"probe_urls"`
		HasProbeURLs       bool     `json:"has_probe_urls"`
	} `json:"failover"`
}

func (s *Server) handleWatchdogConfigPut(w http.ResponseWriter, r *http.Request) {
	var req watchdogConfigUpdateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	cfgPath := configPathFor(s)
	cfg, err := config.Load(cfgPath)
	if err != nil || cfg == nil {
		cfg = &config.Config{
			Watchdog: config.WatchdogConfig{
				Interval:        180,
				ConfirmWait:     30,
				MaxRestarts:     3,
				SubSyncInterval: 600,
			},
		}
	}

	if req.Interval != nil {
		cfg.Watchdog.Interval = min(max(15, *req.Interval), 86400)
	}
	if req.ConfirmWait != nil {
		cfg.Watchdog.ConfirmWait = min(max(5, *req.ConfirmWait), 600)
	}
	if req.MaxRestarts != nil {
		cfg.Watchdog.MaxRestarts = min(max(1, *req.MaxRestarts), 50)
	}
	if req.SubSyncEnabled != nil {
		if !*req.SubSyncEnabled {
			cfg.Watchdog.SubSyncInterval = -1
		} else {
			iv := 600
			if req.SubSyncInterval != nil && *req.SubSyncInterval > 0 {
				iv = min(max(60, *req.SubSyncInterval), 86400)
			} else if cfg.Watchdog.SubSyncInterval > 0 {
				iv = cfg.Watchdog.SubSyncInterval
			}
			cfg.Watchdog.SubSyncInterval = iv
		}
	} else if req.SubSyncInterval != nil {
		if *req.SubSyncInterval < 0 {
			cfg.Watchdog.SubSyncInterval = -1
		} else {
			cfg.Watchdog.SubSyncInterval = min(max(60, *req.SubSyncInterval), 86400)
		}
	}

	if req.Failover != nil {
		fo := &cfg.Watchdog.Failover
		if req.Failover.Enabled != nil {
			if *req.Failover.Enabled {
				fo.Enabled = nil // 默认即为开启，省略字段保持 YAML 清爽
			} else {
				v := false
				fo.Enabled = &v
			}
		}
		if req.Failover.HasGroups || req.Failover.Groups != nil {
			var cleaned []string
			for _, g := range req.Failover.Groups {
				g = strings.TrimSpace(g)
				if g != "" && !slices.Contains(cleaned, g) {
					cleaned = append(cleaned, g)
				}
			}
			if len(cleaned) == 0 || slices.Equal(cleaned, config.DefaultWatchdogFailoverGroups) {
				fo.Groups = nil
			} else {
				fo.Groups = cleaned
			}
		}
		if req.Failover.PatrolInterval != nil {
			v := min(max(10, *req.Failover.PatrolInterval), 3600)
			if v == 300 {
				fo.PatrolInterval = 0
			} else {
				fo.PatrolInterval = v
			}
		}
		if req.Failover.ProbeTimeoutMs != nil {
			v := min(max(500, *req.Failover.ProbeTimeoutMs), 15000)
			if v == 2800 {
				fo.ProbeTimeoutMs = 0
			} else {
				fo.ProbeTimeoutMs = v
			}
		}
		if req.Failover.ConfirmRetries != nil {
			v := min(max(0, *req.Failover.ConfirmRetries), 5)
			switch v {
			case 0:
				fo.ConfirmRetries = -1 // 显式不复测
			case 1:
				fo.ConfirmRetries = 0 // 默认复测 1 次
			default:
				fo.ConfirmRetries = v
			}
		}
		if req.Failover.AutoFailback != nil {
			if !*req.Failover.AutoFailback {
				fo.FailbackCooldown = -1
			} else {
				cd := 180
				if req.Failover.FailbackCooldown != nil && *req.Failover.FailbackCooldown >= 0 {
					cd = min(max(10, *req.Failover.FailbackCooldown), 86400)
				} else if fo.FailbackCooldown > 0 {
					cd = fo.FailbackCooldown
				}
				if cd == 180 {
					fo.FailbackCooldown = 0
				} else {
					fo.FailbackCooldown = cd
				}
			}
		} else if req.Failover.FailbackCooldown != nil {
			if *req.Failover.FailbackCooldown < 0 {
				fo.FailbackCooldown = -1
			} else {
				cd := min(max(10, *req.Failover.FailbackCooldown), 86400)
				if cd == 180 {
					fo.FailbackCooldown = 0
				} else {
					fo.FailbackCooldown = cd
				}
			}
		}
		if req.Failover.MaxFailbackDelayMs != nil {
			v := min(max(100, *req.Failover.MaxFailbackDelayMs), 5000)
			if v == 600 {
				fo.MaxFailbackDelayMs = 0
			} else {
				fo.MaxFailbackDelayMs = v
			}
		}
		if req.Failover.HasProbeURLs || req.Failover.ProbeURLs != nil {
			var urls []string
			for _, raw := range req.Failover.ProbeURLs {
				u := strings.TrimSpace(raw)
				if u == "" {
					continue
				}
				parsed, pErr := url.Parse(u)
				if pErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
					writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("无效的探测 URL %q（需以 http:// 或 https:// 开头）", u))
					return
				}
				if !slices.Contains(urls, u) {
					urls = append(urls, u)
				}
			}
			if len(urls) == 0 || slices.Equal(urls, config.DefaultWatchdogProbeURLs) {
				fo.ProbeURLs = nil
			} else {
				fo.ProbeURLs = urls
			}
		}
	}

	if err := backupConfig(cfgPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := config.Save(cfgPath, cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}

	reloaded := daemon.NotifyReload()
	if !cfg.Watchdog.Failover.IsEnabled() {
		daemon.UpdateRuntimeState(func(snap *daemon.DaemonRuntimeSnapshot) {
			snap.ActiveFailovers = nil
		})
	}

	resp := s.buildWatchdogReport(cfg)
	resp["ok"] = true
	resp["daemonReloaded"] = reloaded
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleWatchdogPatrolPost(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败")
		return
	}
	if !daemon.IsSingBoxRunning() {
		writeJSONError(w, http.StatusBadRequest, "sing-box 未运行，无法执行策略组容灾探测")
		return
	}

	if daemon.IsDaemonRunning() {
		daemon.NotifyReload()
		time.Sleep(800 * time.Millisecond)
	} else {
		st := daemon.NewGroupFailoverState()
		st.ApplyConfig(cfg.Watchdog.Failover)
		st.ConfirmRetries = 0
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		st.Patrol(ctx, singbox.ClashAPIEndpoints(), singbox.ClashAPISecret())
		cancel()
		nowStr := time.Now().Format(time.DateTime)
		active := st.ActiveSnapshot()
		daemon.UpdateRuntimeState(func(snap *daemon.DaemonRuntimeSnapshot) {
			snap.LastFailoverAt = nowStr
			snap.ActiveFailovers = active
		})
	}

	resp := s.buildWatchdogReport(cfg)
	resp["ok"] = true
	writeJSON(w, http.StatusOK, resp)
}
