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
type actionDef struct {
	title string
	build func(params map[string]any) []string
}

// actions 动作白名单。所有动作都通过重新执行 singctl 自身完成,
// 与命令行行为完全一致,不侵入既有逻辑。
var actions = map[string]actionDef{
	// sing-box 客户端
	"sb-start":   {title: "启动 sing-box", build: fixed("sb", "start")},
	"sb-stop":    {title: "停止 sing-box", build: fixed("sb", "stop")},
	"sb-restart": {title: "重启 sing-box", build: fixed("sb", "restart")},
	"sb-gen":     {title: "生成 sing-box 配置", build: fixed("sb", "gen")},
	"sb-install": {title: "安装 sing-box", build: fixed("sb", "install")},
	"sb-update":  {title: "更新 sing-box", build: fixed("sb", "update")},

	// 规则集缓存
	"cache-update": {title: "刷新规则集缓存", build: fixed("sb", "cache", "update")},
	"cache-clear":  {title: "清空规则集缓存", build: fixed("sb", "cache", "clear")},

	// 守护进程
	"dm-start": {title: "启动守护进程", build: fixed("dm", "start")},
	"dm-stop":  {title: "停止守护进程", build: fixed("dm", "stop")},

	// Tailscale
	"ts-start":   {title: "启动 Tailscale", build: tsStartArgs},
	"ts-stop":    {title: "停止 Tailscale", build: fixed("ts", "stop")},
	"ts-install": {title: "安装 Tailscale", build: fixed("ts", "install")},
	"ts-update":  {title: "更新 Tailscale", build: fixed("ts", "update")},

	// 防火墙
	"fw-enable":  {title: "启用防火墙加固", build: fixed("fw", "enable")},
	"fw-disable": {title: "禁用防火墙加固", build: fixed("fw", "disable")},

	// 工具
	"update-self": {title: "更新 singctl 自身", build: fixed("update", "self")},
	"speedtest":   {title: "带宽测速", build: fixed("ut", "testbd")},
}

func fixed(args ...string) func(map[string]any) []string {
	return func(map[string]any) []string { return args }
}

// tsStartArgs 将 Web 参数映射为 ts start 的命令行参数
func tsStartArgs(p map[string]any) []string {
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

	def, ok := actions[body.Name]
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

	exe, err := os.Executable()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "定位 singctl 可执行文件失败: "+err.Error())
		return
	}

	args := append([]string{"--config", s.opts.ConfigPath}, def.build(body.Params)...)

	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = append(os.Environ(), "TERM=dumb")

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	stream := newNDJSONWriter(w)
	cmd.Stdout = stream
	cmd.Stderr = stream

	stream.write(map[string]any{
		"t":     "start",
		"title": def.title,
		"cmd":   "singctl " + strings.Join(def.build(body.Params), " "),
	})

	waitErr := cmd.Run()

	code := 0
	if waitErr != nil {
		code = 1
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	stream.write(map[string]any{"t": "exit", "code": code})
}

// ndjsonWriter 将子进程输出按行转为 NDJSON 事件并立即刷新
type ndjsonWriter struct {
	w     http.ResponseWriter
	flush func()
	buf   []byte
}

func newNDJSONWriter(w http.ResponseWriter) *ndjsonWriter {
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
