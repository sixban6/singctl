// 文件职责：提供客户端 WebUI 状态概览、健康检查、singctl.yaml 结构化与源码读写、iOS 配置生成及备份原语。
package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/common/netx"
	"singctl/internal/common/proc"
	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/firewall"
	"singctl/internal/safecommit"
	"singctl/internal/singbox"
	"singctl/internal/tailscale"
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
		sc   safecommit.StatusReport
		as   daemon.AutoStartStatus
	)

	var wg sync.WaitGroup
	wg.Add(10)
	go func() { defer wg.Done(); host = s.hostInfo() }()
	go func() { defer wg.Done(); sb = singboxStatus() }()
	go func() { defer wg.Done(); dm = s.daemonStatusSummary() }()
	go func() { defer wg.Done(); agh = s.dnsStatusSummary(r.Context()) }()
	go func() { defer wg.Done(); ts = s.tailscaleStatus(s.opts.ConfigPath) }()
	go func() { defer wg.Done(); fw = firewallStatus() }()
	go func() { defer wg.Done(); gw = s.gatewayStatusSummary() }()
	go func() { defer wg.Done(); cfg = s.configSummary(s.opts.ConfigPath) }()
	go func() { defer wg.Done(); sc = s.safeCommitManager().Status() }()
	go func() { defer wg.Done(); as = s.autoStartStatusSummary(r.Context()) }()
	wg.Wait()

	status := map[string]any{
		"singctlVersion": s.opts.Version,
		"authEnabled":    s.opts.Password != "",
		"sessionToken":   s.SessionToken(),
		"host":           host,
		"singbox":        sb,
		"daemon":         dm,
		"dns":            agh,
		"adguard":        agh,
		"tailscale":      ts,
		"firewall":       fw,
		"gateway":        gw,
		"config":         cfg,
		"safeCommit":     sc,
		"autoStart":      as,
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

func (s *Server) collectHostTelemetry() sysinfo.HostTelemetry {
	if s.opts.TelemetryDeps != nil {
		return sysinfo.CollectHostTelemetryWithDeps(s.cpuSampler, *s.opts.TelemetryDeps)
	}
	return sysinfo.CollectHostTelemetry(s.cpuSampler)
}

func (s *Server) hostInfo() map[string]any {
	hostname, _ := os.Hostname()
	lanIP := ""
	if ni, err := netx.Get(); err == nil && ni.LANIPv4 != "" {
		lanIP = ni.LANIPv4
	}
	return map[string]any{
		"hostname":  hostname,
		"os":        runtime.GOOS,
		"arch":      runtime.GOARCH,
		"openwrt":   isOpenWrtSystem(),
		"lanIP":     lanIP,
		"telemetry": s.collectHostTelemetry(),
	}
}

func isOpenWrtSystem() bool {
	return sysinfo.IsOpenWrt()
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
	authKeySet := false
	subnets := ""
	var (
		cfg *config.Config
		err error
	)
	if configPath == configPathFor(s) {
		cfg, err = s.loadConfigSnapshot()
	} else {
		cfg, err = config.Load(configPath)
	}
	if err == nil && cfg != nil {
		authKeySet = strings.TrimSpace(cfg.Tailscale.AuthKey) != ""
		subnets = strings.TrimSpace(cfg.Tailscale.Subnets)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tailscale.InspectHostStatus(ctx, tailscale.HostStatusOptions{
		AuthKeyConfigured: authKeySet,
		ConfiguredSubnets: subnets,
		DaemonProcProbe: func() bool {
			return proc.PgrepMatch("tailscaled")
		},
	})
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

	_, err := s.updateConfigTx(configTxOptions{SyncAdGuard: true}, func(cfg *config.Config) error {
		dto.ApplyTo(cfg)
		if len(cfg.Subs) > 0 {
			if valErr := cfg.ValidateSubs(); valErr != nil {
				return &apiStatusError{status: http.StatusBadRequest, msg: sanitizeSubErrorText(valErr)}
			}
		}
		return nil
	})
	if err != nil {
		writePartialSaveError(w, err)
		return
	}
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
		writeJSONError(w, http.StatusBadRequest, "订阅未配置: "+sanitizeSubErrorText(err))
		return
	}
	genFn := s.opts.IOSGenerator
	if genFn == nil {
		genFn = IOSGenerate
	}
	configJSON, err := genFn(cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "生成 iOS 配置失败: "+sanitizeSubErrorText(err))
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
	ni, err := netx.Get()
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
