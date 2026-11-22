// 文件职责：提供客户端 WebUI 流式 CLI 动作白名单编排、实例级并发互斥锁与 NDJSON 实时输出器。
package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/tailscale"
)

const defaultHandoffShutdownDelay = 300 * time.Millisecond

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
	"ts-update":  {Title: "零失联更新 Tailscale", Build: TsUpdateArgs},

	// 防火墙
	"fw-enable":  {Title: "启用防火墙加固", Build: fixed("fw", "enable")},
	"fw-disable": {Title: "禁用防火墙加固", Build: fixed("fw", "disable")},

	// 本地防劫持 DNS 双引擎统一控制（SmartDNS / AdGuard Home）
	"dns-install":   {Title: "安装并启用防劫持 DNS 引擎", Build: DnsInstallArgs},
	"dns-switch":    {Title: "零断网切换防劫持 DNS 引擎", Build: DnsSwitchArgs},
	"dns-update":    {Title: "更新防劫持 DNS 引擎核心版本", Build: DnsUpdateArgs},
	"dns-start":     {Title: "启用防劫持 DNS 并接管 sing-box", Build: DnsStartArgs},
	"dns-stop":      {Title: "安全停用外部防劫持 DNS (自动回退 sing-box 纯 IP 加密 DoH)", Build: DnsStopArgs},
	"dns-restart":   {Title: "重启防劫持 DNS 服务", Build: DnsRestartArgs},
	"dns-uninstall": {Title: "安全卸载外部防劫持 DNS 引擎", Build: DnsUninstallArgs},

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
	if p != nil {
		if raw, hasAccept := p["acceptRoutes"]; hasAccept {
			if b, ok := raw.(bool); ok {
				if b {
					args = append(args, "--accept-routes")
				} else {
					args = append(args, "--accept-routes=false")
				}
			}
		}
	}
	if paramBool(p, "reconfigure") {
		args = append(args, "--reconfigure")
	}
	return args
}

// TsUpdateArgs 将 Web 参数映射为 ts update 命令行参数（强制 --no-wait 交由脱离进程执行）
func TsUpdateArgs(p map[string]any) []string {
	args := []string{"ts", "update", "--no-wait"}
	if paramBool(p, "force") {
		args = append(args, "--force")
	}
	return args
}

func appendValidDNSEngineArg(args []string, p map[string]any) []string {
	if eng := paramString(p, "engine"); eng != "" && config.IsValidDNSEngine(eng) {
		args = append(args, "--engine", eng)
	}
	return args
}

// DnsInstallArgs 将 Web 参数映射为 dns install 命令行参数（支持 engine / force / forceLowMemory）。
func DnsInstallArgs(p map[string]any) []string {
	args := []string{"dns", "install", "--non-interactive"}
	args = appendValidDNSEngineArg(args, p)
	if paramBool(p, "force") {
		args = append(args, "--force")
	}
	if paramBool(p, "forceLowMemory") {
		args = append(args, "--force-low-memory")
	}
	return args
}

// DnsSwitchArgs 将 Web 参数映射为 dns switch 命令行参数（用于流式输出下载、验活与零断网切换进度）。
func DnsSwitchArgs(p map[string]any) []string {
	eng := paramString(p, "engine")
	if eng == "" || !config.IsValidDNSEngine(eng) {
		eng = constant.DNSEngineAuto
	}
	args := []string{"dns", "switch", "--engine", eng}
	if paramBool(p, "forceLowMemory") {
		args = append(args, "--force-low-memory")
	}
	return args
}

// DnsUpdateArgs 将 Web 参数映射为 dns install --force 命令行参数（支持 engine / forceLowMemory）。
func DnsUpdateArgs(p map[string]any) []string {
	args := []string{"dns", "install", "--non-interactive", "--force"}
	args = appendValidDNSEngineArg(args, p)
	if paramBool(p, "forceLowMemory") {
		args = append(args, "--force-low-memory")
	}
	return args
}

// DnsStartArgs 将 Web 参数映射为 dns start 命令行参数。
func DnsStartArgs(p map[string]any) []string {
	return appendValidDNSEngineArg([]string{"dns", "start"}, p)
}

// DnsStopArgs 将 Web 参数映射为 dns stop 命令行参数。
func DnsStopArgs(p map[string]any) []string {
	return appendValidDNSEngineArg([]string{"dns", "stop"}, p)
}

// DnsRestartArgs 将 Web 参数映射为 dns restart 命令行参数。
func DnsRestartArgs(p map[string]any) []string {
	return appendValidDNSEngineArg([]string{"dns", "restart"}, p)
}

// DnsUninstallArgs 将 Web 参数映射为 dns uninstall 命令行参数。
func DnsUninstallArgs(p map[string]any) []string {
	args := appendValidDNSEngineArg([]string{"dns", "uninstall"}, p)
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

func (s *Server) resolveExecutable() (string, error) {
	if exe := strings.TrimSpace(s.opts.ExecutablePath); exe != "" {
		return exe, nil
	}
	return resolveOnDiskExecutable()
}

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

	// 同一服务实例同一时刻只允许一个动作
	if !s.actionBusy.CompareAndSwap(false, true) {
		writeJSONError(w, http.StatusConflict, "已有任务在执行中,请稍候")
		return
	}
	defer s.actionBusy.Store(false)

	exe, err := s.resolveExecutable()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "定位 singctl 可执行文件失败: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")

	stream := NewNDJSONWriter(w)
	builtArgs := def.Build(body.Params)
	stream.write(map[string]any{
		"t":     "start",
		"title": def.Title,
		"cmd":   "singctl " + strings.Join(builtArgs, " "),
	})

	// 防劫持 DNS 引擎前置硬件护栏：零子进程开销直接透传中文保护提示
	if body.Name == "dns-install" || body.Name == "dns-update" || body.Name == "dns-switch" {
		targetEng := paramString(body.Params, "engine")
		forceLowMem := paramBool(body.Params, "forceLowMemory")
		cfg := s.readConfigOrEmpty()

		if (body.Name == "dns-install" || body.Name == "dns-update") && (targetEng == "" || targetEng == constant.DNSEngineAdGuard) && !forceLowMem {
			if warn := s.newAdGuardManager(cfg).LowMemoryGuardWarning(); warn != "" {
				stream.emitLine("[ERROR] 🛡️ " + warn)
				stream.write(map[string]any{
					"t":                "exit",
					"code":             1,
					"restarting":       false,
					"lowMemoryBlocked": true,
					"lowMemoryWarning": warn,
				})
				return
			}
		} else if targetEng == constant.DNSEngineAdGuard || targetEng == constant.DNSEngineSmartDNS {
			reg := s.newDNSRegistry(cfg)
			sel := reg.ResolveSelection()
			elig := sel.Eligibility[targetEng]
			installed := reg.InstalledMap()[targetEng]
			if !installed && (elig.DiskBlocked || (elig.MemoryBlocked && !forceLowMem)) {
				warn := elig.BlockedReason
				stream.emitLine("[ERROR] 🛡️ " + warn)
				stream.write(map[string]any{
					"t":                "exit",
					"code":             1,
					"restarting":       false,
					"lowMemoryBlocked": elig.MemoryBlocked && !elig.DiskBlocked,
					"lowMemoryWarning": warn,
				})
				return
			}
		}
	}

	args := append([]string{"--config", s.opts.ConfigPath}, builtArgs...)
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Env = BuildCleanSubprocessEnv("TERM=dumb", "SINGCTL_FROM_WEBUI=1")
	cmd.Stdout = stream
	cmd.Stderr = stream

	waitErr := cmd.Run()

	code := 0
	if waitErr != nil {
		code = 1
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		}
	}
	selfUpdateRestart := body.Name == "update-self" && code == 0 && stream.sawSelfUpdated
	handoffToUnified := s.shouldHandoffToUnifiedDaemon(body.Name, code)
	restarting := selfUpdateRestart || handoffToUnified
	if selfUpdateRestart {
		stream.emitLine("[INFO] 🔄 正在自动热重启 WebUI 服务以应用新版本，页面将在 3 秒后自动刷新...")
	} else if handoffToUnified {
		stream.emitLine("[INFO] 🔄 守护进程已启用单进程合体模式，独立 WebUI 将优雅让渡端口，页面即将自动重连...")
	}
	tailscaleSwapping := body.Name == "ts-update" && code == 0 && stream.sawTailscaleSwapHandoff
	stream.write(map[string]any{
		"t":                 "exit",
		"code":              code,
		"restarting":        restarting,
		"tailscaleSwapping": tailscaleSwapping,
	})
	if selfUpdateRestart {
		ScheduleDetachedRestart(s.opts.ConfigPath, s.opts.Listen, s.opts.Password)
	} else if handoffToUnified {
		delay := s.opts.HandoffShutdownDelay
		if delay <= 0 {
			delay = defaultHandoffShutdownDelay
		}
		go func() {
			time.Sleep(delay)
			s.RequestShutdown()
		}()
	}
}

func (s *Server) shouldHandoffToUnifiedDaemon(actionName string, code int) bool {
	if code != 0 {
		return false
	}
	switch actionName {
	case "sb-start", "sb-restart", "dm-start", "dm-restart":
	default:
		return false
	}
	if s.opts.EmbeddedInDaemon || os.Getenv("SINGCTL_DAEMONIZED") == "1" {
		return false
	}
	if s.opts.UnifiedHandoffCheck != nil {
		return s.opts.UnifiedHandoffCheck()
	}
	if _, ok := daemon.ReadWebEmbeddedState(); ok {
		return true
	}
	return daemon.IsDaemonRunning() && daemon.IsLowMemoryDevice()
}

// ndjsonWriter 将子进程输出按行转为 NDJSON 事件并立即刷新
type ndjsonWriter struct {
	w                       http.ResponseWriter
	flush                   func()
	buf                     []byte
	sawSelfUpdated          bool
	sawTailscaleSwapHandoff bool
}

func NewNDJSONWriter(w http.ResponseWriter) *ndjsonWriter {
	flush := func() {}
	if f, ok := w.(http.Flusher); ok {
		flush = f.Flush
	}
	return &ndjsonWriter{w: w, flush: flush}
}

// SawTailscaleSwapHandoff 返回是否检测到 Tailscale 零失联热切换接力标记。
func (nw *ndjsonWriter) SawTailscaleSwapHandoff() bool {
	return nw != nil && nw.sawTailscaleSwapHandoff
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
	if strings.Contains(line, tailscale.TailscaleSwapHandoffMarker) {
		nw.sawTailscaleSwapHandoff = true
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
