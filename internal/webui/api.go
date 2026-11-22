// 文件职责：提供客户端 WebUI 状态概览、健康检查、singctl.yaml 结构化与源码读写、iOS 配置生成及备份原语。
package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/firewall"
	"singctl/internal/singbox"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"
	"singctl/internal/util/os"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ───────────────────────── 状态 ─────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	var (
		host map[string]any
		sb   map[string]any
		dm   map[string]any
		agh  map[string]any
		ts   map[string]any
		fw   firewall.QuickStatus
		gw   map[string]any
		cfg  map[string]any
	)

	var wg sync.WaitGroup
	wg.Add(8)
	go func() { defer wg.Done(); host = hostInfo() }()
	go func() { defer wg.Done(); sb = singboxStatus() }()
	go func() { defer wg.Done(); dm = s.daemonStatusSummary() }()
	go func() { defer wg.Done(); agh = s.adguardStatusSummary() }()
	go func() { defer wg.Done(); ts = s.tailscaleStatus(s.opts.ConfigPath) }()
	go func() { defer wg.Done(); fw = firewallStatus() }()
	go func() { defer wg.Done(); gw = s.gatewayStatusSummary() }()
	go func() { defer wg.Done(); cfg = s.configSummary(s.opts.ConfigPath) }()
	wg.Wait()

	status := map[string]any{
		"singctlVersion": s.opts.Version,
		"authEnabled":    s.opts.Password != "",
		"sessionToken":   s.SessionToken(),
		"host":           host,
		"singbox":        sb,
		"daemon":         dm,
		"adguard":        agh,
		"tailscale":      ts,
		"firewall":       fw,
		"gateway":        gw,
		"config":         cfg,
	}
	writeJSON(w, http.StatusOK, status)
}

// daemonStatusSummary 汇总看门狗守护与故障切换摘要（供概览卡片与顶栏轮询展示）
func (s *Server) daemonStatusSummary() map[string]any {
	maxRestartsCfg := 0
	failoverEnabled := true
	if loaded, err := s.loadConfigSnapshot(); err == nil && loaded != nil {
		maxRestartsCfg = loaded.Watchdog.MaxRestarts
		failoverEnabled = loaded.Watchdog.Failover.IsEnabled()
	}
	running := daemon.IsDaemonRunning()
	limiter := daemon.NewRestartLimiterFromState(maxRestartsCfg)
	snap := daemon.LoadRuntimeSnapshot()
	stale := running && daemon.IsDaemonBinaryStale()
	curVer := strings.TrimPrefix(strings.TrimSpace(s.opts.Version), "v")
	dmVer := strings.TrimPrefix(strings.TrimSpace(snap.DaemonVersion), "v")
	versionMismatch := running && (stale || (curVer != "" && curVer != "dev" && dmVer != "" && dmVer != "dev" && curVer != dmVer))

	return map[string]any{
		"running":             running,
		"restarts":            limiter.GetRestartCount(),
		"maxRestarts":         limiter.GetMaxRestarts(),
		"totalRestarts":       limiter.GetTotalRestarts(),
		"logPath":             daemon.GetDaemonLogPath(),
		"daemonVersion":       snap.DaemonVersion,
		"staleBinary":         stale,
		"versionMismatch":     versionMismatch,
		"lastHealthAt":        snap.LastHealthAt,
		"lastHealthOK":        snap.LastHealthOK,
		"failoverEnabled":     failoverEnabled,
		"activeFailoverCount": len(snap.ActiveFailovers),
	}
}

func hostInfo() map[string]any {
	hostname, _ := os.Hostname()
	lanIP := ""
	if ni, err := netinfo.Get(); err == nil && ni.LANIPv4 != "" {
		lanIP = ni.LANIPv4
	}
	return map[string]any{
		"hostname": hostname,
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"openwrt":  isOpenWrtSystem(),
		"lanIP":    lanIP,
	}
}

func isOpenWrtSystem() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	_, err := os.Stat("/etc/openwrt_version")
	return err == nil
}

func singboxStatus() map[string]any {
	installed := fileExists(constant.SingBoxInstallDir)
	if !installed {
		if _, err := exec.LookPath("sing-box"); err == nil {
			installed = true
		}
	}

	version := ""
	if v, err := shortCommand(3*time.Second, constant.SingBoxInstallDir, "version"); err == nil {
		if parsed, err := singbox.ParseSingBoxVersionOutput(v); err == nil {
			version = parsed
		}
	}

	return map[string]any{
		"running":      daemon.IsSingBoxRunning(),
		"installed":    installed,
		"version":      version,
		"configExists": fileExists(constant.SingBoxConfigFile),
		"configPath":   constant.SingBoxConfigFile,
	}
}

func (s *Server) tailscaleStatus(configPath string) map[string]any {
	// OpenWrt 装在 /usr/sbin,发行版常在 /usr/bin,桌面端在 /usr/local/bin
	binPath := ""
	for _, c := range []string{"/usr/sbin/tailscale", "/usr/bin/tailscale", "/usr/local/bin/tailscale"} {
		if fileExists(c) {
			binPath = c
			break
		}
	}
	if binPath == "" {
		if p, err := exec.LookPath("tailscale"); err == nil {
			binPath = p
		}
	}

	version := ""
	if binPath != "" {
		if out, err := shortCommand(3*time.Second, binPath, "version"); err == nil {
			if v, err := tailscale.ParseVersionOutput(out); err == nil {
				version = v
			}
		}
	}

	// 权威判定:`tailscale status --json` 能连通后端即 daemon 在运行,
	// 并拿到 BackendState(Running/NeedsLogin/Stopped...)与当前启动模式。
	// 注:不能用 pgrep -x 检测 —— busybox 1.36.1 上实测无法匹配 tailscaled(见 osutil.PgrepMatch)。
	daemonUp, backendState, mode, acceptRoutes, liveSubnets := queryTailscaleBackend(binPath)
	if !daemonUp && binPath == "" {
		// CLI 不存在时退化为进程检测(子串匹配,兼容 busybox)
		daemonUp = osutil.PgrepMatch("tailscaled")
	}

	authKeySet := false
	subnets := ""
	var cfg *config.Config
	var err error
	if configPath == configPathFor(s) {
		cfg, err = s.loadConfigSnapshot()
	} else {
		cfg, err = config.Load(configPath)
	}
	if err == nil && cfg != nil {
		authKeySet = strings.TrimSpace(cfg.Tailscale.AuthKey) != ""
		subnets = strings.TrimSpace(cfg.Tailscale.Subnets)
	}
	if subnets == "" && liveSubnets != "" {
		subnets = liveSubnets
	}

	return map[string]any{
		"installed":    binPath != "",
		"running":      daemonUp,
		"state":        backendState,
		"mode":         mode,
		"acceptRoutes": acceptRoutes,
		"subnets":      subnets,
		"version":      version,
		"authKeySet":   authKeySet,
	}
}

// queryTailscaleBackend 通过 `tailscale status --json` 判定 daemon 是否存活及其后端状态，并读取 LocalAPI prefs 中的 RouteAll。
// daemon 存活时返回 (true, BackendState, mode, acceptRoutes, liveSubnets);不可达返回 (false, "", "", false, "")。
// 实测退出码:daemon 在(含 Stopped/NeedsLogin)rc=0,daemon 不在 rc=1。
// 同时从 Self 提取启动模式: AdvertisedRoutes(广播的非默认子网路由) + ExitNodeOption(出口节点)。
func queryTailscaleBackend(binPath string) (bool, string, string, bool, string) {
	if binPath == "" {
		return false, "", "", false, ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binPath, "status", "--json").Output()
	if err != nil {
		return false, "", "", false, ""
	}
	var st struct {
		BackendState string `json:"BackendState"`
		Self         struct {
			AdvertisedRoutes []string `json:"AdvertisedRoutes"`
			ExitNodeOption   bool     `json:"ExitNodeOption"`
		} `json:"Self"`
	}
	if json.Unmarshal(out, &st) != nil || st.BackendState == "" {
		return false, "", "", false, ""
	}
	// 过滤出非默认网关路由（排除 0.0.0.0/0 与 ::/0，仅保留广播的 LAN 子网）。
	var lanRoutes []string
	for _, r := range st.Self.AdvertisedRoutes {
		trimmed := strings.TrimSpace(r)
		if trimmed == "" || trimmed == "0.0.0.0/0" || trimmed == "::/0" {
			continue
		}
		lanRoutes = append(lanRoutes, trimmed)
	}
	// 与 WebUI 启动模式选项对应: ""(或client)/router/exit/gateway(router+exit)
	mode := ""
	hasRoutes := len(lanRoutes) > 0
	switch {
	case st.Self.ExitNodeOption && hasRoutes:
		mode = "gateway"
	case st.Self.ExitNodeOption:
		mode = "exit"
	case hasRoutes:
		mode = "router"
	}
	acceptRoutes := queryTailscaleAcceptRoutes(ctx, binPath)
	return true, st.BackendState, mode, acceptRoutes, strings.Join(lanRoutes, ", ")
}

var tailscaleLocalHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext: func(dCtx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(dCtx, "unix", tailscale.DefaultTailscaledSocket)
		},
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	},
	Timeout: 2 * time.Second,
}

func queryTailscaleAcceptRoutes(ctx context.Context, binPath string) bool {
	// 优先直连 tailscaled LocalAPI /localapi/v0/prefs（兼容精简版无 debug CLI 场景）。
	if req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local-tailscaled.sock/localapi/v0/prefs", nil); err == nil {
		if resp, err := tailscaleLocalHTTPClient.Do(req); err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var prefs struct {
					RouteAll bool `json:"RouteAll"`
				}
				decErr := json.NewDecoder(resp.Body).Decode(&prefs)
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
				if decErr == nil {
					return prefs.RouteAll
				}
			} else {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16*1024))
			}
		}
	}
	// 回退 CLI: tailscale debug prefs
	if out, err := exec.CommandContext(ctx, binPath, "debug", "prefs").Output(); err == nil {
		var prefs struct {
			RouteAll bool `json:"RouteAll"`
		}
		if json.Unmarshal(out, &prefs) == nil {
			return prefs.RouteAll
		}
	}
	return false
}

func firewallStatus() firewall.QuickStatus {
	return firewall.InspectQuickStatus()
}

func (s *Server) configSummary(path string) map[string]any {
	summary := map[string]any{
		"path":   path,
		"exists": fileExists(path),
		"subs":   []map[string]any{},
	}
	var cfg *config.Config
	var err error
	if path == configPathFor(s) {
		cfg, err = s.loadConfigSnapshot()
	} else {
		cfg, err = config.Load(path)
	}
	if err != nil {
		summary["error"] = err.Error()
		return summary
	}
	subs := make([]map[string]any, 0, len(cfg.Subs))
	for _, sub := range cfg.Subs {
		subs = append(subs, map[string]any{
			"name":    sub.Name,
			"urlHint": MaskURL(sub.URL),
		})
	}
	summary["subs"] = subs
	return summary
}

func MaskURL(u string) string {
	if u == "" {
		return ""
	}
	// 订阅 URL 含 token 凭据且域名本身就是敏感信息(机场站点),
	// 概览页只保留协议, 其余全部遮蔽; 订阅名称已足以识别服务商
	parsed, err := url.Parse(u)
	if err != nil {
		return "******"
	}
	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://******"
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// shortCommand 执行命令并返回输出(超时则返回错误)
func shortCommand(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// ───────────────────────── 健康检测 ─────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfigSnapshot()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}
	monitor := daemon.NewMonitor(cfg)
	result := monitor.CheckHealth()
	writeJSON(w, http.StatusOK, map[string]any{
		"healthy":      result.Healthy,
		"dnsOK":        result.DNSOK,
		"failedReason": result.FailedReason,
		"details":      result.Details,
		"checkTime":    result.CheckTime.Format(time.DateTime),
	})
}

// ───────────────────────── 配置(结构化) ─────────────────────────

type SubDTO struct {
	Name          string              `json:"name"`
	URL           string              `json:"url"`
	SkipTlsVerify bool                `json:"skip_tls_verify"`
	RemoveEmoji   bool                `json:"remove_emoji"`
	Include       *string             `json:"include,omitempty"`
	Exclude       *string             `json:"exclude,omitempty"`
	Rename        []config.RenameRule `json:"rename,omitempty"`
}

type ConfigDTO struct {
	Subs []SubDTO `json:"subs"`

	GitHub struct {
		MirrorURL string `json:"mirror_url"`
	} `json:"github"`

	Hy2 struct {
		Up   int `json:"up"`
		Down int `json:"down"`
	} `json:"hy2"`

	Tailscale struct {
		AuthKey  string `json:"auth_key"`
		UseBuild bool   `json:"use_build"`
		Subnets  string `json:"subnets"`
	} `json:"tailscale"`

	Server struct {
		SBDomain string `json:"sb_domain"`
		CFDNSKey string `json:"cf_dns_key"`
		Sni      string `json:"sni"`
	} `json:"server"`
}

func configPathFor(s *Server) string { return s.opts.ConfigPath }

func (s *Server) handleConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfigSnapshot()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	var dto ConfigDTO
	for _, sub := range cfg.Subs {
		item := SubDTO{
			Name:          sub.Name,
			URL:           sub.URL,
			SkipTlsVerify: sub.SkipTlsVerify,
			RemoveEmoji:   sub.RemoveEmoji,
			Rename:        sub.Rename,
		}
		if sub.Include != "" {
			inc := sub.Include
			item.Include = &inc
		}
		if sub.Exclude != "" {
			exc := sub.Exclude
			item.Exclude = &exc
		}
		dto.Subs = append(dto.Subs, item)
	}
	dto.GitHub.MirrorURL = cfg.GitHub.MirrorURL
	dto.Hy2.Up = cfg.Hy2.Up
	dto.Hy2.Down = cfg.Hy2.Down
	dto.Tailscale.AuthKey = cfg.Tailscale.AuthKey
	dto.Tailscale.UseBuild = cfg.Tailscale.UseBuild
	dto.Tailscale.Subnets = cfg.Tailscale.Subnets
	dto.Server.SBDomain = cfg.Server.SBDomain
	dto.Server.CFDNSKey = cfg.Server.CFDNSKey
	dto.Server.Sni = cfg.Server.Sni

	writeJSON(w, http.StatusOK, map[string]any{
		"path":   configPathFor(s),
		"config": dto,
	})
}

func (s *Server) handleConfigPut(w http.ResponseWriter, r *http.Request) {
	var dto ConfigDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// 基于现有配置合并更新，避免丢失 custom_rules、watchdog、server 高级字段等非表单项
	cfg := s.loadMutableConfig()
	dto.ApplyTo(cfg)

	// 有订阅时做完整校验;允许暂存空订阅(首次使用)
	if len(cfg.Subs) > 0 {
		if err := cfg.ValidateSubs(); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if err := backupConfig(configPathFor(s)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	s.invalidateIOSCache()
	s.syncAdGuardSubWhitelistAsync(cfg)
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (dto ConfigDTO) ApplyTo(cfg *config.Config) {
	applySubsToConfig(dto.Subs, cfg)
	cfg.GitHub.MirrorURL = strings.TrimSpace(dto.GitHub.MirrorURL)
	cfg.Hy2.Up = dto.Hy2.Up
	cfg.Hy2.Down = dto.Hy2.Down
	cfg.Tailscale.AuthKey = strings.TrimSpace(dto.Tailscale.AuthKey)
	cfg.Tailscale.UseBuild = dto.Tailscale.UseBuild
	cfg.Tailscale.Subnets = strings.TrimSpace(dto.Tailscale.Subnets)
	cfg.Server.SBDomain = strings.TrimSpace(dto.Server.SBDomain)
	cfg.Server.CFDNSKey = strings.TrimSpace(dto.Server.CFDNSKey)
	cfg.Server.Sni = strings.TrimSpace(dto.Server.Sni)
}

func applySubsToConfig(subDTOs []SubDTO, cfg *config.Config) {
	prevByName := make(map[string]config.Subscription, len(cfg.Subs))
	prevByURL := make(map[string]config.Subscription, len(cfg.Subs))
	for _, old := range cfg.Subs {
		if old.Name != "" {
			prevByName[old.Name] = old
		}
		if old.URL != "" {
			prevByURL[old.URL] = old
		}
	}

	cfg.Subs = make([]config.Subscription, 0, len(subDTOs))
	for _, sub := range subDTOs {
		name := strings.TrimSpace(sub.Name)
		u := strings.TrimSpace(sub.URL)
		prev, ok := prevByName[name]
		if !ok || name == "" {
			prev, ok = prevByURL[u]
		}

		next := config.Subscription{
			Name:          name,
			URL:           u,
			SkipTlsVerify: sub.SkipTlsVerify,
			RemoveEmoji:   sub.RemoveEmoji,
		}
		if ok {
			next.Include = prev.Include
			next.Exclude = prev.Exclude
			next.Rename = prev.Rename
		}
		if sub.Include != nil {
			next.Include = strings.TrimSpace(*sub.Include)
		}
		if sub.Exclude != nil {
			next.Exclude = strings.TrimSpace(*sub.Exclude)
		}
		if sub.Rename != nil {
			next.Rename = sub.Rename
		}
		cfg.Subs = append(cfg.Subs, next)
	}
}

// ───────────────────────── 配置(原文 YAML) ─────────────────────────

func (s *Server) handleConfigRawGet(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(configPathFor(s))
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "读取配置失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": configPathFor(s), "content": string(data)})
}

func (s *Server) handleConfigRawPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	// 先校验 YAML 语法与结构,再落盘
	var cfg config.Config
	if err := yaml.Unmarshal([]byte(body.Content), &cfg); err != nil {
		writeJSONError(w, http.StatusBadRequest, "YAML 语法错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if err := backupConfig(configPathFor(s)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	// 0600 原子写入: 配置含订阅地址、auth_key 等敏感信息
	if err := atomicWriteFile0600(configPathFor(s), []byte(body.Content)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入配置失败: "+err.Error())
		return
	}
	s.invalidateConfigStore()
	s.invalidateIOSCache()
	s.syncAdGuardSubWhitelistAsync(&cfg)
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ───────────────────── iOS (sing-box App) 配置下载 ─────────────────────

// iosGenerate 生成 iOS 目标配置(可注入以便测试; 避免单测真实拉取订阅)
var IOSGenerate = func(cfg *config.Config) (string, error) {
	return singbox.NewConfigGenerator(cfg).GenerateForPlatform(singbox.PlatformIOS)
}

// handleIOSConfig 生成并返回 iOS 配置文件(作为附件下载)。
// 以 singctl.yaml 的 mtime+size 为指纹缓存生成结果: 实时生成需拉订阅(秒级),
// 缓存让 SFI 远程配置同步与重复扫码瞬时返回; 配置变更后自动失效。
func (s *Server) handleIOSConfig(w http.ResponseWriter, r *http.Request) {
	cfgPath := configPathFor(s)
	cacheKey := ""
	if fi, err := os.Stat(cfgPath); err == nil {
		cacheKey = fmt.Sprintf("%s|%d|%d", cfgPath, fi.ModTime().UnixNano(), fi.Size())
		if gfi, gErr := os.Stat(config.GroupsPathForConfig(cfgPath)); gErr == nil {
			cacheKey += fmt.Sprintf("|g:%d|%d", gfi.ModTime().UnixNano(), gfi.Size())
		}
	}

	s.iosMu.Lock()
	if cacheKey != "" && cacheKey == s.iosCacheKey && s.iosCacheVal != "" {
		content := s.iosCacheVal
		s.iosMu.Unlock()
		s.writeIOSConfig(w, content)
		return
	}
	s.iosMu.Unlock()

	cfg, err := s.loadConfigSnapshot()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "读取配置失败: "+err.Error())
		return
	}
	if err := cfg.ValidateSubs(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "订阅未配置: "+err.Error())
		return
	}
	configJSON, err := IOSGenerate(cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成 iOS 配置失败: "+err.Error())
		return
	}
	// 双保险: 防止未来生成逻辑变化后把本地路径规则集发给 iPhone
	if err := singbox.CheckIOSCompatibility(configJSON); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if cacheKey != "" {
		s.iosMu.Lock()
		s.iosCacheKey, s.iosCacheVal = cacheKey, configJSON
		s.iosMu.Unlock()
	}
	s.writeIOSConfig(w, configJSON)
}

// writeIOSConfig 以附件形式输出 iOS 配置
func (s *Server) writeIOSConfig(w http.ResponseWriter, configJSON string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="singctl-ios.json"`)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(configJSON))
}

// handleIOSConfigURL 返回手机可直接访问的下载地址（携带签名 ?token=，避免 URL 明文口令）及 SFI 一键导入链接
func (s *Server) handleIOSConfigURL(w http.ResponseWriter, r *http.Request) {
	ni, err := netinfo.Get()
	if err != nil || ni.LANIPv4 == "" {
		writeJSONError(w, http.StatusInternalServerError, "无法获取局域网 IP: "+err.Error())
		return
	}
	_, port, err := net.SplitHostPort(s.opts.Listen)
	if err != nil || port == "" {
		writeJSONError(w, http.StatusInternalServerError, "无法解析监听端口: "+s.opts.Listen)
		return
	}
	targetURL := fmt.Sprintf("http://%s:%s/api/gen/ios", ni.LANIPv4, port)
	if tok := s.SessionToken(); tok != "" {
		targetURL += "?token=" + url.QueryEscape(tok)
	}
	importURL := "sing-box://import-remote-profile?url=" + url.QueryEscape(targetURL)
	writeJSON(w, http.StatusOK, map[string]string{
		"url":       targetURL,
		"importUrl": importURL,
	})
}

// backupConfig 保存前备份(保留最近 3 份)
func backupConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	backup := fmt.Sprintf("%s.webui-bak-%s", path, time.Now().Format("20060102-150405"))
	if err := os.WriteFile(backup, data, 0600); err != nil {
		return err
	}
	// 清理多余备份
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	matches, _ := filepath.Glob(filepath.Join(dir, base+".webui-bak-*"))
	sort.Strings(matches)
	if len(matches) > 3 {
		for _, m := range matches[:len(matches)-3] {
			_ = os.Remove(m)
		}
	}
	return nil
}
