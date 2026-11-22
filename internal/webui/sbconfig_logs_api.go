// 文件职责：提供客户端 WebUI sing-box config.json 校验保存/备份还原、规则集缓存列表及多组件日志查看清理接口。
package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/common/fsx"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
	ruleset_snapshot "singctl/internal/singbox/ruleset_snapshot"
	"slices"
	"sort"
	"strings"
	"time"
)

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
var LookPathFunc = exec.LookPath

// singboxBinaryPath 返回 sing-box 可执行文件路径(未安装则返回空)
func singboxBinaryPath() string {
	if fileExists(constant.SingBoxInstallDir) {
		return constant.SingBoxInstallDir
	}
	if p, err := LookPathFunc("sing-box"); err == nil {
		return p
	}
	return ""
}

func (s *Server) singboxBinaryPath() string {
	if s.opts.SingBoxLookPath != nil {
		if p, err := s.opts.SingBoxLookPath("sing-box"); err == nil {
			return p
		}
		return ""
	}
	return singboxBinaryPath()
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
	path := s.sbConfigPath()
	content := ""
	data, err := os.ReadFile(path)
	exists := err == nil
	if exists {
		content = string(data)
	}
	preserveManual := true
	if cfg, cfgErr := s.loadConfigSnapshot(); cfgErr == nil && cfg != nil {
		preserveManual = cfg.Watchdog.ShouldPreserveManualConfig()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"path":                 path,
		"exists":               exists,
		"content":              content,
		"backups":              sbconfigBackups(path),
		"checkable":            s.singboxBinaryPath() != "",
		"preserveManualConfig": preserveManual,
	})
}

func atomicWriteFile0600(path string, data []byte) error {
	return fsx.WriteAtomic0600(path, data)
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

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// 有 sing-box 可执行文件时做语义校验,把住“改坏配置”这道门
	checked := false
	if exe := s.singboxBinaryPath(); exe != "" {
		if err := checkSingBoxConfig(exe, body.Content); err != nil {
			writeJSONError(w, http.StatusBadRequest, "sing-box check 未通过: "+err.Error())
			return
		}
		checked = true
	}

	path := s.sbConfigPath()
	singbox.EnsureInitialBaseSnapshot(path)
	if err := backupConfig(path); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份失败: "+err.Error())
		return
	}
	if err := atomicWriteFile0600(path, []byte(body.Content)); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入失败: "+err.Error())
		return
	}
	if err := singbox.SyncSandboxWorkConfig(r.Context(), path, s.sbWorkConfigPath(), body.Content, ".webui.tmp"); err != nil {
		writeJSONError(w, http.StatusBadRequest, "同步沙盒配置失败: "+err.Error())
		return
	}
	singbox.ReloadSingBoxProcess()
	s.invalidateIOSCache()
	s.invalidateClashCache()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked": checked})
}

func (s *Server) handleSbConfigPreservePut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Preserve bool `json:"preserve"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg := s.loadMutableConfig()
	cfg.Watchdog.SetPreserveManualConfig(body.Preserve)
	if err := s.saveConfig(cfg); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置失败: "+err.Error())
		return
	}
	_ = daemon.NotifyReload()
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                   true,
		"preserveManualConfig": cfg.Watchdog.ShouldPreserveManualConfig(),
	})
}

func (s *Server) handleSbConfigRestore(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// 防路径穿越:只允许本目录下、以备份前缀命名的基名
	path := s.sbConfigPath()
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
	checked := false
	if exe := s.singboxBinaryPath(); exe != "" {
		if err := checkSingBoxConfig(exe, string(data)); err != nil {
			writeJSONError(w, http.StatusBadRequest, "备份配置 sing-box check 未通过: "+err.Error())
			return
		}
		checked = true
	}

	if err := backupConfig(path); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "备份当前配置失败: "+err.Error())
		return
	}
	if err := atomicWriteFile0600(path, data); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "写入失败: "+err.Error())
		return
	}
	if err := singbox.SyncSandboxWorkConfig(r.Context(), path, s.sbWorkConfigPath(), string(data), ".webui.tmp"); err != nil {
		writeJSONError(w, http.StatusBadRequest, "同步沙盒配置失败: "+err.Error())
		return
	}
	singbox.ReloadSingBoxProcess()
	s.invalidateIOSCache()
	s.invalidateClashCache()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "checked": checked})
}

// ───────────────────────── 规则集缓存 ─────────────────────────

func (s *Server) handleCache(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfigSnapshot()
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

func resolveClientLogTarget(name string) (canonicalName, path string, eventsOnly bool) {
	switch name {
	case "watchdog", "events":
		return "events", daemon.GetDaemonLogPath(), true
	case "webui":
		return "webui", WebLogPath(), false
	default:
		return "daemon", daemon.GetDaemonLogPath(), false
	}
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &tail); err != nil || n != 1 || tail <= 0 || tail > 5000 {
			tail = 200
		}
	}

	name, path, eventsOnly := resolveClientLogTarget(name)

	content := ""
	if data, err := os.ReadFile(path); err == nil {
		var lines []string
		for line := range strings.SplitSeq(strings.TrimRight(string(data), "\n"), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			// 过滤旧版本遗留的订阅比对噪音行
			if daemon.IsLegacyDaemonSpamLine(line) {
				continue
			}
			if eventsOnly && !daemon.IsKeyWatchdogLogLine(line) {
				continue
			}
			lines = append(lines, line)
		}
		if len(lines) > tail {
			lines = lines[len(lines)-tail:]
		}
		slices.Reverse(lines)
		if len(lines) == 0 {
			if eventsOnly {
				content = "(暂无看门狗/容灾/热同步事件记录，运行平稳)"
			} else {
				content = "(暂无日志记录)"
			}
		} else {
			content = strings.Join(lines, "\n")
		}
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

func (s *Server) handleLogsClear(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = strings.TrimSpace(r.URL.Query().Get("name"))
	}

	canonicalName, path, _ := resolveClientLogTarget(name)
	// 就地 truncate 保持 inode 不变，确保持续 O_APPEND 写入的 dm/web 守护进程无缝从 0 偏移续写。
	if err := os.Truncate(path, 0); err != nil && !os.IsNotExist(err) {
		writeJSONError(w, http.StatusInternalServerError, "清空日志失败: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"name":    canonicalName,
		"path":    path,
		"message": "日志已清空",
	})
}
