package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// actionTimeout 单个动作最长执行时间(安装/更新含下载,放宽到 30 分钟)
const actionTimeout = 30 * time.Minute

// ansiRe 匹配终端颜色转义序列
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// actionDef 动作定义:name → CLI 参数
type ActionDef struct {
	Title string
	Build func(params map[string]any) []string
}

// actions 动作白名单。所有动作都通过重新执行 singctl 自身完成,
// 与命令行行为完全一致,不侵入既有逻辑。
var Actions = map[string]ActionDef{
	// sing-box 客户端
	"sb-start":   {Title: "启动 sing-box", Build: fixed("sb", "start")},
	"sb-stop":    {Title: "停止 sing-box", Build: fixed("sb", "stop")},
	"sb-restart": {Title: "重启 sing-box", Build: fixed("sb", "restart")},
	"sb-gen":     {Title: "生成 sing-box 配置", Build: fixed("sb", "gen")},
	"sb-install": {Title: "安装 sing-box", Build: fixed("sb", "install")},
	"sb-update":  {Title: "更新 sing-box", Build: fixed("sb", "update")},

	// 规则集缓存
	"cache-update": {Title: "刷新规则集缓存", Build: fixed("sb", "cache", "update")},
	"cache-clear":  {Title: "清空规则集缓存", Build: fixed("sb", "cache", "clear")},

	// 守护进程
	"dm-start":   {Title: "启动守护进程", Build: fixed("dm", "start")},
	"dm-stop":    {Title: "停止守护进程", Build: fixed("dm", "stop")},
	"dm-restart": {Title: "重启守护进程", Build: fixed("dm", "restart")},

	// Tailscale
	"ts-start":   {Title: "启动 Tailscale", Build: TsStartArgs},
	"ts-stop":    {Title: "停止 Tailscale", Build: fixed("ts", "stop")},
	"ts-install": {Title: "安装 Tailscale", Build: fixed("ts", "install")},
	"ts-update":  {Title: "更新 Tailscale", Build: fixed("ts", "update")},

	// 防火墙
	"fw-enable":  {Title: "启用防火墙加固", Build: fixed("fw", "enable")},
	"fw-disable": {Title: "禁用防火墙加固", Build: fixed("fw", "disable")},

	// 本地防劫持 DNS (AdGuard Home)
	"dns-install":   {Title: "安装并启用防劫持 DNS (AdGuard Home)", Build: fixed("dns", "install", "--non-interactive")},
	"dns-update":    {Title: "更新 AdGuard Home 核心版本", Build: fixed("dns", "install", "--non-interactive", "--force")},
	"dns-start":     {Title: "启用防劫持 DNS 并接管 sing-box", Build: fixed("dns", "start")},
	"dns-stop":      {Title: "安全停用防劫持 DNS (自动回退内置加密 DNS)", Build: fixed("dns", "stop")},
	"dns-restart":   {Title: "重启 AdGuard Home 服务", Build: fixed("dns", "restart")},
	"dns-uninstall": {Title: "安全卸载 AdGuard Home", Build: DnsUninstallArgs},

	// 工具
	"update-self": {Title: "更新 singctl 自身", Build: fixed("update", "self")},
	"speedtest":   {Title: "带宽测速", Build: fixed("ut", "testbd")},
}

func fixed(args ...string) func(map[string]any) []string {
	return func(map[string]any) []string { return args }
}

// tsStartArgs 将 Web 参数映射为 ts start 的命令行参数
func TsStartArgs(p map[string]any) []string {
	args := []string{"ts", "start"}
	mode := paramString(p, "mode")
	switch mode {
	case "client", "router", "exit", "gateway":
		args = append(args, "--mode", mode)
	case "":
		// 未选模式时支持显式布尔组合
		if paramBool(p, "exitNode") {
			args = append(args, "--exit-node")
		}
		if paramBool(p, "router") {
			args = append(args, "--router")
		}
	}
	if paramBool(p, "acceptRoutes") {
		args = append(args, "--accept-routes")
	}
	return args
}

// DnsUninstallArgs 将 Web 参数映射为 dns uninstall 命令行参数
func DnsUninstallArgs(p map[string]any) []string {
	args := []string{"dns", "uninstall"}
	if paramBool(p, "purge") {
		args = append(args, "--purge")
	}
	return args
}

func paramString(p map[string]any, key string) string {
	if v, ok := p[key].(string); ok {
		return strings.TrimSpace(strings.ToLower(v))
	}
	return ""
}

func paramBool(p map[string]any, key string) bool {
	if v, ok := p[key].(bool); ok {
		return v
	}
	return false
}

// busyFlag 原子标记当前是否有动作在执行
var busyFlag atomic.Bool

// handleAction 执行动作并以 NDJSON 流式返回输出
//
// 协议(每行一个 JSON 对象):
//
//	{"t":"start","title":"...","cmd":"singctl sb start"}
//	{"t":"out","line":"2025/01/01 [INFO] ..."}
//	{"t":"exit","code":0}
func (s *Server) handleAction(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string         `json:"name"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	def, ok := Actions[body.Name]
	if !ok {
		writeJSONError(w, http.StatusBadRequest, "未知动作: "+body.Name)
		return
	}

	// 同一时刻只允许一个动作
	if !busyFlag.CompareAndSwap(false, true) {
		writeJSONError(w, http.StatusConflict, "已有任务在执行中,请稍候")
		return
	}
	defer busyFlag.Store(false)

	exe, err := resolveOnDiskExecutable()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "定位 singctl 可执行文件失败: "+err.Error())
		return
	}

	args := append([]string{"--config", s.opts.ConfigPath}, def.Build(body.Params)...)

	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = append(os.Environ(), "TERM=dumb", "SINGCTL_FROM_WEBUI=1")

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	stream := NewNDJSONWriter(w)
	cmd.Stdout = stream
	cmd.Stderr = stream

	stream.write(map[string]any{
		"t":     "start",
		"title": def.Title,
		"cmd":   "singctl " + strings.Join(def.Build(body.Params), " "),
	})

	waitErr := cmd.Run()

	code := 0
	if waitErr != nil {
		code = 1
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	restarting := false
	if body.Name == "update-self" && code == 0 && stream.sawSelfUpdated {
		restarting = true
		stream.emitLine("[INFO] 🔄 正在自动热重启 WebUI 服务以应用新版本，页面将在 3 秒后自动刷新...")
	}
	stream.write(map[string]any{"t": "exit", "code": code, "restarting": restarting})
	if restarting {
		ScheduleDetachedRestart(s.opts.ConfigPath, s.opts.Listen, s.opts.Password)
	}
}

// ndjsonWriter 将子进程输出按行转为 NDJSON 事件并立即刷新
type ndjsonWriter struct {
	w              http.ResponseWriter
	flush          func()
	buf            []byte
	sawSelfUpdated bool
}

func NewNDJSONWriter(w http.ResponseWriter) *ndjsonWriter {
	flush := func() {}
	if f, ok := w.(http.Flusher); ok {
		flush = f.Flush
	}
	return &ndjsonWriter{w: w, flush: flush}
}

func (nw *ndjsonWriter) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_, _ = nw.w.Write(append(b, '\n'))
	nw.flush()
}

func (nw *ndjsonWriter) Write(p []byte) (int, error) {
	nw.buf = append(nw.buf, p...)
	for {
		i := indexByte(nw.buf, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimRight(string(nw.buf[:i]), "\r")
		nw.buf = nw.buf[i+1:]
		nw.emitLine(line)
	}
	// 处理无换行的尾部输出(如进度条)
	if len(nw.buf) > 0 && len(nw.buf) < 4096 {
		// 留在缓冲区等待更多数据
		return len(p), nil
	} else if len(nw.buf) >= 4096 {
		nw.emitLine(string(nw.buf))
		nw.buf = nil
	}
	return len(p), nil
}

func (nw *ndjsonWriter) emitLine(line string) {
	line = ansiRe.ReplaceAllString(line, "")
	if strings.TrimSpace(line) == "" {
		return
	}
	if strings.Contains(line, "SingCtl updated successfully") {
		nw.sawSelfUpdated = true
	}
	nw.write(map[string]any{"t": "out", "line": line})
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
