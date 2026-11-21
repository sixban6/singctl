package serverweb

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/updater"
	"singctl/internal/util/file"
)

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	action := strings.ToLower(strings.TrimSpace(body.Action))
	service := strings.ToLower(strings.TrimSpace(body.Service))

	if action != "start" && action != "stop" && action != "restart" && action != "reload" {
		writeJSONError(w, http.StatusBadRequest, "不支持的动作: "+action)
		return
	}

	var cmdErr error
	mgr := s.serviceMgr()
	if service == "all" {
		for _, comp := range deploy.ServerRegistry().All() {
			_ = mgr.Restart(context.Background(), comp.UnitName())
		}
	} else {
		comp, err := deploy.ServerRegistry().Resolve(service)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "未知服务: "+service)
			return
		}
		cmdErr = comp.ExecuteServiceAction(
			context.Background(),
			action,
			mgr,
			s.activeCmdRunner(),
			s.resolveServiceConfigPath(comp.ID(), ""),
		)
	}

	if cmdErr != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("执行 %s %s 失败: %v", service, action, cmdErr))
		return
	}
	s.invalidateStatusCaches()
	s.recordAudit(r, fmt.Sprintf("执行服务操作 [%s -> %s]", service, action))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("服务 %s 动作 %s 执行成功", service, action),
	})
}

func (s *Server) handleCheckServiceUpdate(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	if service == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少检查目标服务名称 (service)")
		return
	}

	cfg, _ := config.Load(s.opts.ConfigPath)
	res, err := deploy.CheckComponentUpdate(service, cfg)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if res.Component == "singctl" && (res.CurrentVersion == "" || res.CurrentVersion == "unknown") && s.opts.Version != "" {
		curr := strings.TrimPrefix(strings.TrimSpace(s.opts.Version), "v")
		res.CurrentVersion = curr
		res.HasUpdate = deploy.IsNewerVersion(curr, res.LatestVersion)
		if res.HasUpdate {
			res.Message = fmt.Sprintf("发现 SingCtl 新版本: v%s (当前: v%s)", res.LatestVersion, curr)
		} else {
			res.Message = fmt.Sprintf("SingCtl 主程序与 SubHub 已是最新版本 (v%s)", curr)
		}
	}

	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleUpgradeService(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Service) == "" {
		writeJSONError(w, http.StatusBadRequest, "缺少升级目标服务名称")
		return
	}

	target := strings.ToLower(strings.TrimSpace(body.Service))
	cfg, _ := config.Load(s.opts.ConfigPath)

	if target == "singctl" || target == "subhub" || target == "substore" {
		mirror := ""
		if cfg != nil {
			mirror = cfg.GitHub.MirrorURL
		}
		oldVer := cmp.Or(strings.TrimPrefix(strings.TrimSpace(s.opts.Version), "v"), deploy.GetInstalledSubhubVersion())
		checkRes, _ := deploy.CheckComponentUpdate("singctl", cfg)
		if checkRes != nil && checkRes.LatestVersion != "" && !deploy.IsNewerVersion(oldVer, checkRes.LatestVersion) {
			msg := fmt.Sprintf("SingCtl 当前已是最新版本 (v%s)，无需重复更新", oldVer)
			writeJSON(w, http.StatusOK, map[string]any{
				"message": msg,
				"results": []*deploy.UpgradeResult{{
					Component:   "singctl",
					DisplayName: "SingCtl 主程序 (WebUI + SubHub)",
					OldVersion:  oldVer,
					NewVersion:  oldVer,
					Message:     msg,
					Updated:     false,
				}},
			})
			return
		}

		up := updater.New(mirror, "")
		if err := up.UpdateSelf(s.opts.ConfigPath, oldVer); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "SingCtl 自更新失败: "+err.Error())
			return
		}
		newVer := deploy.GetInstalledSubhubVersion()
		if checkServiceRunning("singctl-sub") {
			_ = s.serviceMgr().Restart(context.Background(), "singctl-sub")
		}
		msg := fmt.Sprintf("SingCtl 已平滑升级至 %s，后台面板将在 1 秒后自动热重启", cmp.Or(newVer, "最新版"))
		s.invalidateStatusCaches()
		s.recordAudit(r, fmt.Sprintf("平滑自升级 SingCtl 主程序 [%s -> %s]", oldVer, cmp.Or(newVer, "latest")))
		writeJSON(w, http.StatusOK, map[string]any{
			"message":       msg,
			"willRestartUI": true,
			"results": []*deploy.UpgradeResult{{
				Component:   "singctl",
				DisplayName: "SingCtl 主程序 (WebUI + SubHub)",
				OldVersion:  oldVer,
				NewVersion:  cmp.Or(newVer, oldVer),
				Message:     msg,
				Updated:     true,
			}},
		})
		time.AfterFunc(1200*time.Millisecond, func() {
			_ = RestartService()
		})
		return
	}

	results, err := deploy.UpgradeComponent(target, cfg)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "组件升级失败: "+err.Error())
		return
	}

	msg := "组件已成功平滑更新"
	if len(results) == 1 {
		msg = results[0].Message
	} else if len(results) > 1 {
		msg = fmt.Sprintf("已成功平滑更新 %d 个核心服务组件", len(results))
	}

	s.invalidateStatusCaches()
	s.recordAudit(r, fmt.Sprintf("平滑升级组件 [%s]", target))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": msg,
		"results": results,
	})
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	targetName, hasPrefix := strings.CutPrefix(strings.TrimSpace(body.Action), "restart-")
	if !hasPrefix {
		writeJSONError(w, http.StatusBadRequest, "未知操作: "+body.Action)
		return
	}
	comp, err := deploy.ServerRegistry().Resolve(targetName)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "未知操作: "+body.Action)
		return
	}
	_ = comp.ExecuteServiceAction(context.Background(), "restart", s.serviceMgr(), s.activeCmdRunner(), "")
	s.invalidateStatusCaches()
	writeJSON(w, http.StatusOK, map[string]string{"message": "操作执行成功"})
}

func (s *Server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	linesStr := strings.TrimSpace(r.URL.Query().Get("lines"))
	lines := 100
	if n, err := strconv.Atoi(linesStr); err == nil && n > 0 && n <= 500 {
		lines = n
	}

	logCtx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	var (
		output []byte
		err    error
	)
	if comp, resErr := deploy.ServerRegistry().Resolve(service); resErr == nil {
		output, err = exec.CommandContext(logCtx, "journalctl", "-u", comp.UnitName(), "--since", "-24h", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	} else {
		output, err = exec.CommandContext(logCtx, "journalctl", "--since", "-24h", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	}

	if err != nil && len(output) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"service": service,
			"logs":    fmt.Sprintf("读取日志失败或无日志: %v", err),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"logs":    string(output),
	})
}

func (s *Server) handleLogsSSE(w http.ResponseWriter, r *http.Request) {
	rawService := cmp.Or(strings.TrimSpace(r.URL.Query().Get("service")), "singbox")
	comp, resErr := deploy.ServerRegistry().Resolve(rawService)
	if resErr != nil {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}
	unitName := comp.UnitName()

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	cmd := exec.CommandContext(r.Context(), "journalctl", "-u", unitName, "-n", "80", "-f", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(w, "data: 读取日志失败: %v\n\n", err)
		flusher.Flush()
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(w, "data: 启动日志进程失败: %v\n\n", err)
		flusher.Flush()
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintf(w, "data: %s\n\n", line)
		flusher.Flush()
	}
	_ = cmd.Wait()
}

func (s *Server) handleServiceConfig(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	comp, err := deploy.ServerRegistry().Resolve(service)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "未知服务配置")
		return
	}
	cfgComp, ok := comp.(component.Configurable)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "未知服务配置")
		return
	}
	target, err := cfgComp.ResolveConfigTarget(s.resolveServiceConfigPath(comp.ID(), ""))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	content, err := os.ReadFile(target.PrimaryPath)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("无法读取配置文件 %s: %v", target.PrimaryPath, err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"path":    target.PrimaryPath,
		"content": string(content),
	})
}

func WriteConfigBackup(path string, content []byte) error {
	bak := fmt.Sprintf("%s.%d.bak", path, time.Now().UnixNano())
	if err := os.WriteFile(bak, content, 0600); err != nil {
		return err
	}
	if err := os.Chmod(bak, 0600); err != nil {
		return err
	}
	pruneConfigBackups(path, 3)
	return nil
}

func pruneConfigBackups(path string, keep int) {
	if keep < 1 {
		keep = 1
	}
	matches, _ := filepath.Glob(path + ".*.bak")
	legacy := path + ".bak"
	if st, err := os.Stat(legacy); err == nil && !st.IsDir() {
		matches = append(matches, legacy)
	}
	sort.Slice(matches, func(i, j int) bool {
		si, errI := os.Stat(matches[i])
		sj, errJ := os.Stat(matches[j])
		if errI != nil || errJ != nil {
			return matches[i] > matches[j]
		}
		if !si.ModTime().Equal(sj.ModTime()) {
			return si.ModTime().After(sj.ModTime())
		}
		return matches[i] > matches[j]
	})
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
}

func (s *Server) handleUpdateServiceConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Service string `json:"service"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的请求格式")
		return
	}

	service := strings.TrimSpace(body.Service)
	content := strings.TrimSpace(body.Content)
	if content == "" {
		writeJSONError(w, http.StatusBadRequest, "配置内容不能为空")
		return
	}

	comp, resErr := deploy.ServerRegistry().Resolve(service)
	if resErr != nil {
		writeJSONError(w, http.StatusBadRequest, "不支持编辑此服务配置: "+service)
		return
	}
	cfgComp, ok := comp.(component.Configurable)
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "不支持编辑此服务配置: "+service)
		return
	}
	target, targetErr := cfgComp.ResolveConfigTarget(s.resolveServiceConfigPath(comp.ID(), ""))
	if targetErr != nil {
		writeJSONError(w, http.StatusInternalServerError, targetErr.Error())
		return
	}

	sbOverride := ""
	if s != nil {
		sbOverride = s.singBoxBinOverride
	}
	if valErr := cfgComp.ValidateConfig(r.Context(), content, s.activeCmdRunner(), sbOverride); valErr != nil {
		writeJSONError(w, http.StatusBadRequest, valErr.Error())
		return
	}

	oldBytes, hadOld := os.ReadFile(target.PrimaryPath)
	if hadOld == nil {
		_ = WriteConfigBackup(target.PrimaryPath, oldBytes)
	}
	oldMirrors := make(map[string][]byte, len(target.MirrorPaths))
	for _, mp := range target.MirrorPaths {
		if b, mErr := os.ReadFile(mp); mErr == nil {
			oldMirrors[mp] = b
		}
	}

	if err := writeConfigAtomically(target.PrimaryPath, []byte(content), target.FileMode); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}
	for _, mp := range target.MirrorPaths {
		if _, exists := oldMirrors[mp]; exists {
			_ = writeConfigAtomically(mp, []byte(content), target.FileMode)
		}
	}
	cfgComp.ApplyOwnership(target.PrimaryPath)

	reloadErr := cfgComp.ReloadAfterSave(context.Background(), target.PrimaryPath, s.serviceMgr(), s.activeCmdRunner(), s.canRunSystemctl())
	if reloadErr != nil && hadOld == nil {
		_ = writeConfigAtomically(target.PrimaryPath, oldBytes, target.FileMode)
		for mp, prev := range oldMirrors {
			_ = writeConfigAtomically(mp, prev, target.FileMode)
		}
		_ = cfgComp.ReloadAfterSave(context.Background(), target.PrimaryPath, s.serviceMgr(), s.activeCmdRunner(), s.canRunSystemctl())
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("服务 %s 重载失败 (%v)，已自动回滚至原配置确保不断连", service, reloadErr))
		return
	}

	s.recordAudit(r, fmt.Sprintf("修改并保存 %s 服务配置", service))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("服务 %s 配置文件已通过预检、安全保存并重新加载", service),
	})
}

func writeConfigAtomically(path string, data []byte, mode os.FileMode) error {
	return file.WriteAtomic(path, data, mode)
}
