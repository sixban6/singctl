package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
	ruleset_snapshot "singctl/internal/singbox/ruleset_snapshot"
	"singctl/internal/tailscale"
	"singctl/internal/util/netinfo"

	"gopkg.in/yaml.v3"
)

// ───────────────────────── 状态 ─────────────────────────

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{
		"singctlVersion": s.opts.Version,
		"host":           hostInfo(),
		"singbox":        singboxStatus(),
		"daemon":         daemonStatus(s.watchdogMaxRestarts()),
		"tailscale":      tailscaleStatus(s.opts.ConfigPath),
		"firewall":       firewallStatus(),
		"config":         configSummary(s.opts.ConfigPath),
	}
	writeJSON(w, http.StatusOK, status)
}

// watchdogMaxRestarts 从配置读取看门狗每小时重启上限（用于状态展示）
func (s *Server) watchdogMaxRestarts() int {
	if cfg, err := config.Load(s.opts.ConfigPath); err == nil {
		return cfg.Watchdog.MaxRestarts
	}
	return 0
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

	// 控制面板地址(与生成器逻辑保持一致)
	panelHost := "127.0.0.1"
	if runtime.GOOS == "linux" {
		if ni, err := netinfo.Get(); err == nil && ni.LANIPv4 != "" {
			panelHost = ni.LANIPv4
		}
	}

	return map[string]any{
		"running":      daemon.IsSingBoxRunning(),
		"installed":    installed,
		"version":      version,
		"configExists": fileExists(constant.SingBoxConfigFile),
		"configPath":   constant.SingBoxConfigFile,
		"panelURL":     fmt.Sprintf("http://%s:9090/ui", panelHost),
	}
}

func daemonStatus(cfgMaxRestarts int) map[string]any {
	running := daemon.IsDaemonRunning()
	restarts, maxRestarts := 0, 0
	if running {
		// 从持久化状态恢复真实计数（看门狗每次重启都会落盘）
		limiter := daemon.NewRestartLimiterFromState(cfgMaxRestarts)
		restarts = limiter.GetRestartCount()
		maxRestarts = limiter.GetMaxRestarts()
	}
	return map[string]any{
		"running":         running,
		"restarts":        restarts,
		"maxRestarts":     maxRestarts,
		"logPath":         daemon.GetDaemonLogPath(),
		"watchdogLogPath": daemon.GetWatchdogLogPath(),
	}
}

func tailscaleStatus(configPath string) map[string]any {
	binPath := ""
	if p, err := exec.LookPath("tailscale"); err == nil {
		binPath = p
	} else if fileExists("/usr/bin/tailscale") {
		binPath = "/usr/bin/tailscale"
	}

	version := ""
	if binPath != "" {
		if out, err := shortCommand(3*time.Second, binPath, "version"); err == nil {
			if v, err := tailscale.ParseVersionOutput(out); err == nil {
				version = v
			}
		}
	}

	running := false
	if runtime.GOOS != "windows" {
		running = exec.Command("pgrep", "-x", "tailscaled").Run() == nil
	}

	authKeySet := false
	if cfg, err := config.Load(configPath); err == nil {
		authKeySet = strings.TrimSpace(cfg.Tailscale.AuthKey) != ""
	}

	return map[string]any{
		"installed":  binPath != "",
		"running":    running,
		"version":    version,
		"authKeySet": authKeySet,
	}
}

func firewallStatus() map[string]any {
	if runtime.GOOS != "linux" {
		return map[string]any{"supported": false, "enabled": false}
	}
	enabled := fileExists(constant.SingBoxNftablesFile) ||
		fileExists(constant.FirewallSystemdService) ||
		fileExists(constant.FirewallInitdScript)
	return map[string]any{"supported": true, "enabled": enabled}
}

func configSummary(path string) map[string]any {
	summary := map[string]any{
		"path":   path,
		"exists": fileExists(path),
		"subs":   []map[string]any{},
	}
	cfg, err := config.Load(path)
	if err != nil {
		summary["error"] = err.Error()
		return summary
	}
	subs := make([]map[string]any, 0, len(cfg.Subs))
	for _, sub := range cfg.Subs {
		subs = append(subs, map[string]any{
			"name":    sub.Name,
			"urlHint": maskURL(sub.URL),
		})
	}
	summary["subs"] = subs
	return summary
}

func maskURL(u string) string {
	if u == "" {
		return ""
	}
	if len(u) <= 28 {
		return u[:8] + "…" + u[len(u)-6:]
	}
	return u[:18] + "…" + u[len(u)-10:]
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
	cfg, err := config.Load(configPathFor(s))
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

type subDTO struct {
	Name          string `json:"name"`
	URL           string `json:"url"`
	SkipTlsVerify bool   `json:"skip_tls_verify"`
	RemoveEmoji   bool   `json:"remove_emoji"`
}

type configDTO struct {
	Subs []subDTO `json:"subs"`

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
	cfg, err := config.Load(configPathFor(s))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	var dto configDTO
	for _, sub := range cfg.Subs {
		dto.Subs = append(dto.Subs, subDTO{
			Name:          sub.Name,
			URL:           sub.URL,
			SkipTlsVerify: sub.SkipTlsVerify,
			RemoveEmoji:   sub.RemoveEmoji,
		})
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
	var dto configDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	cfg := dto.toConfig()

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
	if err := config.Save(configPathFor(s), cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (dto configDTO) toConfig() *config.Config {
	cfg := &config.Config{}
	for _, sub := range dto.Subs {
		cfg.Subs = append(cfg.Subs, config.Subscription{
			Name:          strings.TrimSpace(sub.Name),
			URL:           strings.TrimSpace(sub.URL),
			SkipTlsVerify: sub.SkipTlsVerify,
			RemoveEmoji:   sub.RemoveEmoji,
		})
	}
	cfg.GitHub.MirrorURL = strings.TrimSpace(dto.GitHub.MirrorURL)
	cfg.Hy2.Up = dto.Hy2.Up
	cfg.Hy2.Down = dto.Hy2.Down
	cfg.Tailscale.AuthKey = strings.TrimSpace(dto.Tailscale.AuthKey)
	cfg.Tailscale.UseBuild = dto.Tailscale.UseBuild
	cfg.Tailscale.Subnets = strings.TrimSpace(dto.Tailscale.Subnets)
	cfg.Server.SBDomain = strings.TrimSpace(dto.Server.SBDomain)
	cfg.Server.CFDNSKey = strings.TrimSpace(dto.Server.CFDNSKey)
	cfg.Server.Sni = strings.TrimSpace(dto.Server.Sni)
	return cfg
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

	if err := backupConfig(configPathFor(s)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份配置失败: "+err.Error())
		return
	}
	// 0600:配置含订阅地址、auth_key 等敏感信息
	if err := os.WriteFile(configPathFor(s), []byte(body.Content), 0600); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入配置失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
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

// preserveMode 返回目标文件应使用的权限(存在则保持原样,否则 0600)
func preserveMode(path string) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return 0600
}

// ───────────────────── sing-box 配置文件(config.json) ─────────────────────

// sbconfigBackups 返回按时间倒序的备份文件基名列表
func sbconfigBackups(path string) []string {
	matches, _ := filepath.Glob(path + ".webui-bak-*")
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, filepath.Base(m))
	}
	return out
}

// lookPathFunc 可注入的命令查找函数(测试用)
var lookPathFunc = exec.LookPath

// singboxBinaryPath 返回 sing-box 可执行文件路径(未安装则返回空)
func singboxBinaryPath() string {
	if fileExists(constant.SingBoxInstallDir) {
		return constant.SingBoxInstallDir
	}
	if p, err := lookPathFunc("sing-box"); err == nil {
		return p
	}
	return ""
}

// checkSingBoxConfig 用 sing-box check 校验配置内容(15s 超时)
func checkSingBoxConfig(exe, content string) error {
	tmp, err := os.CreateTemp("", "sbcheck-*.json")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return fmt.Errorf("写入临时文件失败: %w", err)
	}
	tmp.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "check", "-c", tmp.Name()).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 800 {
			msg = msg[:800] + "…"
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func (s *Server) handleSbConfigGet(w http.ResponseWriter, r *http.Request) {
	path := constant.SingBoxConfigFile
	content := ""
	data, err := os.ReadFile(path)
	exists := err == nil
	if exists {
		content = string(data)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":      path,
		"exists":    exists,
		"content":   content,
		"backups":   sbconfigBackups(path),
		"checkable": singboxBinaryPath() != "",
	})
}

func (s *Server) handleSbConfigPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	// JSON 语法校验
	if !json.Valid([]byte(body.Content)) {
		writeJSONError(w, http.StatusBadRequest, "内容不是合法的 JSON")
		return
	}

	// 有 sing-box 可执行文件时做语义校验,把住“改坏配置”这道门
	checked := false
	if exe := singboxBinaryPath(); exe != "" {
		if err := checkSingBoxConfig(exe, body.Content); err != nil {
			writeJSONError(w, http.StatusBadRequest, "sing-box check 未通过: "+err.Error())
			return
		}
		checked = true
	}

	path := constant.SingBoxConfigFile
	if err := backupConfig(path); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份失败: "+err.Error())
		return
	}
	if err := os.WriteFile(path, []byte(body.Content), preserveMode(path)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked": checked})
}

func (s *Server) handleSbConfigRestore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	// 防路径穿越:只允许本目录下、以备份前缀命名的基名
	path := constant.SingBoxConfigFile
	prefix := filepath.Base(path) + ".webui-bak-"
	name := filepath.Base(body.Name)
	if name == "" || !strings.HasPrefix(name, prefix) {
		writeJSONError(w, http.StatusBadRequest, "非法的备份名称")
		return
	}

	src := filepath.Join(filepath.Dir(path), name)
	data, err := os.ReadFile(src)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "读取备份失败: "+err.Error())
		return
	}
	if !json.Valid(data) {
		writeJSONError(w, http.StatusBadRequest, "备份内容不是合法的 JSON")
		return
	}

	if err := backupConfig(path); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份当前配置失败: "+err.Error())
		return
	}
	if err := os.WriteFile(path, data, preserveMode(path)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入失败: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ───────────────────────── 规则集缓存 ─────────────────────────

func (s *Server) handleCache(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.Load(configPathFor(s))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "加载配置失败: "+err.Error())
		return
	}

	entries := singbox.CacheStatus(singbox.LocalizeOptions{MirrorURL: cfg.GitHub.MirrorURL})
	snap := ruleset_snapshot.Load()

	list := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		state := "ok"
		if !e.FileOK {
			if e.InSnapshot {
				state = "snapshot"
			} else {
				state = "missing"
			}
		}
		list = append(list, map[string]any{
			"tag":        e.Tag,
			"format":     e.Format,
			"updatedAt":  e.UpdatedAt,
			"fileOK":     e.FileOK,
			"inSnapshot": e.InSnapshot,
			"state":      state,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"cacheDir":      singbox.RuleSetCacheDir(),
		"snapshotCount": snap.Count(),
		"snapshotTime":  snap.GeneratedAt(),
		"entries":       list,
	})
}

// ───────────────────────── 日志 ─────────────────────────

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		name = "daemon"
	}
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &tail); err != nil || n != 1 || tail <= 0 || tail > 5000 {
			tail = 200
		}
	}

	var path string
	switch name {
	case "watchdog":
		path = daemon.GetWatchdogLogPath()
	default:
		name = "daemon"
		path = daemon.GetDaemonLogPath()
	}

	content := ""
	if data, err := os.ReadFile(path); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) > tail {
			lines = lines[len(lines)-tail:]
		}
		content = strings.Join(lines, "\n")
	} else {
		content = "(日志文件不存在,启动相应服务后才会生成)"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name":    name,
		"path":    path,
		"tail":    tail,
		"content": content,
	})
}
