package serverweb

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/deploy"
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
	switch service {
	case "caddy":
		if action == "reload" {
			cmdErr = exec.Command("caddy", "reload", "--config", "/etc/caddy/Caddyfile").Run()
			if cmdErr != nil {
				cmdErr = exec.Command("systemctl", "reload", "caddy").Run()
			}
		} else {
			cmdErr = exec.Command("systemctl", action, "caddy").Run()
		}
	case "singbox":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("systemctl", action, "sing-box").Run()
	case "subhub":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("systemctl", action, "singctl-sub").Run()
	case "warp":
		if action == "reload" {
			action = "restart"
		}
		cmdErr = exec.Command("systemctl", action, "wireproxy").Run()
		if cmdErr != nil {
			cmdErr = exec.Command("systemctl", action, "warp-svc").Run()
		}
	case "all":
		_ = exec.Command("systemctl", "restart", "sing-box").Run()
		_ = exec.Command("systemctl", "restart", "caddy").Run()
		_ = exec.Command("systemctl", "restart", "singctl-sub").Run()
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	default:
		writeJSONError(w, http.StatusBadRequest, "未知服务: "+service)
		return
	}

	if cmdErr != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("执行 %s %s 失败: %v", service, action, cmdErr))
		return
	}
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

	s.recordAudit(r, fmt.Sprintf("平滑升级组件 [%s]", target))
	writeJSON(w, http.StatusOK, map[string]any{
		"message": msg,
		"results": results,
	})

	for _, res := range results {
		if res != nil && res.Component == "subhub" && res.Updated {
			_ = exec.Command("sh", "-c", "sleep 2 && singctl sr web restart >/dev/null 2>&1").Start()
			break
		}
	}
}

func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "无效的 JSON 请求")
		return
	}

	switch body.Action {
	case "restart-caddy":
		_ = exec.Command("systemctl", "restart", "caddy").Run()
	case "restart-singbox":
		_ = exec.Command("systemctl", "restart", "sing-box").Run()
	case "restart-subhub":
		_ = exec.Command("systemctl", "restart", "singctl-sub").Run()
	case "restart-warp":
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	default:
		writeJSONError(w, http.StatusBadRequest, "未知操作: "+body.Action)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "操作执行成功"})
}

func (s *Server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	service := strings.TrimSpace(r.URL.Query().Get("service"))
	linesStr := strings.TrimSpace(r.URL.Query().Get("lines"))
	lines := 100
	if n, err := strconv.Atoi(linesStr); err == nil && n > 0 && n <= 500 {
		lines = n
	}

	var output []byte
	var err error

	switch service {
	case "caddy":
		output, err = exec.Command("journalctl", "-u", "caddy", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	case "singbox":
		output, err = exec.Command("journalctl", "-u", "sing-box", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	case "subhub":
		output, err = exec.Command("journalctl", "-u", "singctl-sub", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
	case "warp":
		output, err = exec.Command("journalctl", "-u", "wireproxy", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
		if err != nil || len(output) == 0 {
			output, _ = exec.Command("journalctl", "-u", "warp-svc", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
		}
	default:
		output, err = exec.Command("journalctl", "-n", strconv.Itoa(lines), "--no-pager").CombinedOutput()
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
	service := r.URL.Query().Get("service")
	if service == "" {
		service = "sing-box"
	}
	if service == "subhub" {
		service = "singctl-sub"
	}
	if service != "sing-box" && service != "caddy" && service != "wireproxy" && service != "singctl-sub" {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	cmd := exec.CommandContext(r.Context(), "journalctl", "-u", service, "-n", "80", "-f", "--no-pager")
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
	var path string
	switch service {
	case "singbox":
		path = "/etc/sing-box/config.json"
	case "caddy":
		path = "/etc/caddy/Caddyfile"
	case "warp":
		path = "/etc/wireproxy/wireproxy.conf"
	default:
		writeJSONError(w, http.StatusBadRequest, "未知服务配置")
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("无法读取配置文件 %s: %v", path, err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"service": service,
		"path":    path,
		"content": string(content),
	})
}

func writeConfigBackup(path string, content []byte) error {
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

	var path string
	switch service {
	case "singbox":
		path = "/etc/sing-box/config.json"
		var js json.RawMessage
		if err := json.Unmarshal([]byte(content), &js); err != nil {
			writeJSONError(w, http.StatusBadRequest, "sing-box 配置必须是合法的 JSON 格式: "+err.Error())
			return
		}
	case "caddy":
		path = "/etc/caddy/Caddyfile"
		tmp, err := os.CreateTemp("", "caddyfile-validate-*.caddy")
		if err == nil {
			tmpName := tmp.Name()
			defer os.Remove(tmpName)
			_ = tmp.Chmod(0600)
			_, _ = tmp.WriteString(content)
			_ = tmp.Close()
			cmd := exec.Command("caddy", "validate", "--config", tmpName, "--adapter", "caddyfile")
			if out, err := cmd.CombinedOutput(); err != nil {
				writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("Caddy 语法校验失败: %s", string(out)))
				return
			}
		}
	case "warp":
		path = "/etc/wireproxy/wireproxy.conf"
	default:
		writeJSONError(w, http.StatusBadRequest, "不支持编辑此服务配置: "+service)
		return
	}

	if old, err := os.ReadFile(path); err == nil {
		_ = writeConfigBackup(path, old)
	}

	mode := os.FileMode(0600)
	if service == "caddy" {
		mode = 0640
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "保存配置文件失败: "+err.Error())
		return
	}
	_ = os.Chmod(path, mode)
	if service == "caddy" {
		if g, err := user.LookupGroup("caddy"); err == nil {
			if gid, convErr := strconv.Atoi(g.Gid); convErr == nil {
				_ = os.Chown(path, 0, gid)
			}
		}
	}

	switch service {
	case "caddy":
		_ = exec.Command("caddy", "reload", "--config", path).Run()
	case "singbox":
		_ = exec.Command("systemctl", "restart", "sing-box").Run()
	case "warp":
		_ = exec.Command("systemctl", "restart", "wireproxy").Run()
	}

	s.recordAudit(r, fmt.Sprintf("修改并保存 %s 服务配置", service))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("服务 %s 配置文件已成功保存并重新加载", service),
	})
}
