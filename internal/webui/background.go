package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"singctl/internal/logger"
	"singctl/internal/platform/servicemgr"
	"singctl/internal/updater"
	"singctl/internal/util/file"
)

// 后台运行机制与 daemon 包的看门狗一致:
//   - 父进程以硬链接原子创建状态文件作为互斥锁(防并发 start)
//   - fork 自身 + SINGCTL_WEB_BACKGROUND=1 环境变量标记(防二次 fork)
//   - 子进程 Listen 成功后覆写状态文件并通过 fd3 命名管道回传就绪信号
//     (父进程因此能确认端口真的绑定成功,失败如实报错)
//   - 停止时按 PID + 命令行特征校验后 SIGTERM → 等待 → SIGKILL 兜底

const (
	envWebBackground = "SINGCTL_WEB_BACKGROUND"
	envWebReadyFd    = "SINGCTL_WEB_READY_FD"
	webReadyFd       = 3
	WebStateName     = "singctl-web.pid"
	webLogName       = "singctl-web.log"
)

// WebState 后台运行状态文件内容（含运行配置路径与可选口令以保障热重启/CLI 自更新不丢鉴权，强制 0600 权限）
type WebState struct {
	Pid        int    `json:"pid"`
	Listen     string `json:"listen"`
	ConfigPath string `json:"config_path,omitempty"`
	Password   string `json:"password,omitempty"`
}

var (
	ErrWebAlreadyRunning = errors.New("webui already running")
	// 测试钩子
	WebStatePathOverride   string
	WebLogPathOverride     string
	ExecutablePathOverride string
	webProcMatchesOverride func(pid int) bool
)

// WebStatePath 状态文件路径
func WebStatePath() string {
	if WebStatePathOverride != "" {
		return WebStatePathOverride
	}
	if v := strings.TrimSpace(os.Getenv("SINGCTL_WEB_STATE_PATH")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), WebStateName)
	}
	return filepath.Join("/tmp", WebStateName)
}

// WebLogPath 后台运行日志路径
func WebLogPath() string {
	if WebLogPathOverride != "" {
		return WebLogPathOverride
	}
	if v := strings.TrimSpace(os.Getenv("SINGCTL_WEB_LOG_PATH")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), webLogName)
	}
	return filepath.Join("/tmp", webLogName)
}

// IsBackgroundChild 当前进程是否为新版 StartBackground 派生的合法后台守护子进程。
// 关键升级自愈兼容：旧版 (<= v1.14.126，如 v1.14.120) 网页点击「检查并更新 singctl」时，
// 旧版 ScheduleDetachedRestart 会误将父进程的 SINGCTL_WEB_BACKGROUND=1 遗传给新版 `singctl web start`，
// 但旧版并未注入 SINGCTL_WEB_READY_FD 且将输出重定向到了 /dev/null。
// 此处检测到缺少 SINGCTL_WEB_READY_FD 时自动剥离残留标记并返回 false，
// 让新版无缝走正规 StartBackground 守护化流程（重建 0600 状态锁、恢复 /tmp/singctl-web.log 日志与原口令）。
func IsBackgroundChild() bool {
	if os.Getenv(envWebBackground) != "1" {
		return false
	}
	if strings.TrimSpace(os.Getenv(envWebReadyFd)) == "" {
		_ = os.Unsetenv(envWebBackground)
		return false
	}
	return true
}

// NormalizeLegacyWildcardListen 将旧版状态文件中由内核展开的 "[::]:8090" 归一化回通用通配 ":8090"，
// 防止软路由禁用 IPv6 后热重启绑定失败。
func NormalizeLegacyWildcardListen(listen string) string {
	s := strings.TrimSpace(listen)
	if strings.HasPrefix(s, "[::]:") {
		return ":" + strings.TrimPrefix(s, "[::]:")
	}
	return s
}

// BuildCleanSubprocessEnv 构造干净的子进程环境变量：
// 强制剥离后台标记（SINGCTL_WEB_BACKGROUND / SINGCTL_WEB_READY_FD / SINGCTL_FROM_WEBUI），
// 并对传入的 extra (KEY=VAL) 去重覆写；若传入 KEY=（空值）亦可显式移除父环境同名键。
func BuildCleanSubprocessEnv(extra ...string) []string {
	stripKeys := map[string]struct{}{
		envWebBackground:     {},
		envWebReadyFd:        {},
		"SINGCTL_FROM_WEBUI": {},
	}
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" {
			stripKeys[k] = struct{}{}
		}
	}

	base := os.Environ()
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, drop := stripKeys[k]; drop {
			continue
		}
		out = append(out, kv)
	}
	for _, kv := range extra {
		if k, _, ok := strings.Cut(kv, "="); ok && k != "" {
			out = append(out, kv)
		}
	}
	return out
}

func buildRestartEnv(password string) []string {
	if password != "" {
		return BuildCleanSubprocessEnv("SINGCTL_WEB_PASSWORD=" + password)
	}
	// 显式剥离旧密码环境变量，避免已清空口令的场景被父环境残留污染
	base := BuildCleanSubprocessEnv("SINGCTL_WEB_PASSWORD=")
	return slices.DeleteFunc(base, func(kv string) bool {
		return kv == "SINGCTL_WEB_PASSWORD="
	})
}

// ───────────────────────── 状态文件 ─────────────────────────

func ReadWebState() (WebState, error) {
	data, err := os.ReadFile(WebStatePath())
	if err != nil {
		return WebState{}, err
	}
	var st WebState
	if err := json.Unmarshal(data, &st); err != nil {
		return WebState{}, err
	}
	return st, nil
}

// WriteWebStateAtomic 原子写入状态文件（强制 0600 权限，先写临时文件再 rename）
func WriteWebStateAtomic(st WebState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return file.WriteAtomic0600(WebStatePath(), b)
}

// AcquireWebLock 以硬链接原子创建状态文件作为互斥锁（0600 权限）。
// 实现：先写临时文件再 os.Link —— 目标存在时原子失败，避免 O_EXCL
// “先建空文件后写内容”的窗口期被并发者误判为残留锁清除。
// 文件已存在时:PID 存活且命令行含 web → 已在运行;否则视为残留锁清除后重试一次。
func AcquireWebLock(st WebState) error {
	b, _ := json.Marshal(st)
	target := WebStatePath()
	tmp := fmt.Sprintf("%s.new-%d", target, os.Getpid())
	defer os.Remove(tmp)

	for attempt := 0; attempt < 2; attempt++ {
		if err := os.WriteFile(tmp, b, 0600); err != nil {
			return fmt.Errorf("failed to write web state tmp: %w", err)
		}
		_ = os.Chmod(tmp, 0600)
		err := os.Link(tmp, target)
		if err == nil {
			return nil // 赢得锁
		}
		if !os.IsExist(err) {
			return fmt.Errorf("failed to claim web state: %w", err)
		}

		old, rerr := ReadWebState()
		if rerr == nil && WebProcMatches(old.Pid) {
			return ErrWebAlreadyRunning
		}
		_ = os.Remove(target)
	}
	return ErrWebAlreadyRunning
}

// ───────────────────────── 进程校验 ─────────────────────────

// webProcMatches 判断 PID 是否为运行中的 WebUI 进程。
// 看门狗与 WebUI 同为 singctl 可执行文件,无法只靠进程名区分,
// 因此校验完整命令行中是否含 web/w 子命令参数(防 PID 回绕误杀无关进程)。
func WebProcMatches(pid int) bool {
	if webProcMatchesOverride != nil {
		return webProcMatchesOverride(pid)
	}
	if !ProcessAlive(pid) {
		return false
	}

	hasWebArg := func(args []string) bool {
		for _, a := range args {
			if a == "web" || a == "w" {
				return true
			}
		}
		return false
	}

	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			return hasWebArg(strings.Split(strings.TrimRight(string(b), "\x00"), "\x00"))
		}
		return false
	}
	if runtime.GOOS == "darwin" {
		out, err := outputWebCmdTimeout(defaultWebProbeTimeout, "ps", "-p", strconv.Itoa(pid), "-o", "command=")
		if err != nil {
			return false
		}
		return hasWebArg(strings.Fields(string(out)))
	}
	// Windows 无法低成本校验,保守放行
	return true
}

func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	// Linux: /proc/<pid>/stat 状态字段 Z=僵尸(已退出未被收尸,对存活判定而言就是已死)
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) {
				return b[i+2] != 'Z'
			}
		}
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if proc.Signal(syscall.Signal(0)) != nil {
		return false
	}
	// macOS:用 ps 判僵尸
	if runtime.GOOS == "darwin" {
		if out, err := outputWebCmdTimeout(defaultWebProbeTimeout, "ps", "-p", strconv.Itoa(pid), "-o", "stat="); err == nil {
			return !strings.Contains(strings.TrimSpace(string(out)), "Z")
		}
	}
	return true
}

// ───────────────────────── 子进程侧 ─────────────────────────

// ChildReadyWithOptions 子进程就绪回调：记录完整启动参数（优先保留用户原始 Listen 如 :8090，
// 避免被内核展开的 [::]:8090 覆盖导致无 IPv6 环境重启失败），清理自身后台标记环境变量，
// 并仅在确认 fd3 为真实 FIFO 管道时写入握手字节。
func ChildReadyWithOptions(opts Options, actualListen string) {
	listen := strings.TrimSpace(opts.Listen)
	if listen == "" || strings.HasSuffix(listen, ":0") {
		listen = actualListen
	}
	_ = WriteWebStateAtomic(WebState{
		Pid:        os.Getpid(),
		Listen:     listen,
		ConfigPath: opts.ConfigPath,
		Password:   opts.Password,
	})

	// 立即清除当前 WebUI 守护进程自身的后台标记环境变量，防止后续任何子进程误继承
	_ = os.Unsetenv(envWebBackground)
	_ = os.Unsetenv(envWebReadyFd)

	if runtime.GOOS == "windows" {
		return
	}
	notifyReadyPipe(webReadyFd)
}

// InstallChildSignalCleanup 子进程安装信号清理:退出前移除状态文件。
func InstallChildSignalCleanup() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-ch
		_ = os.Remove(WebStatePath())
		os.Exit(0)
	}()
}

// ───────────────────────── 父进程侧 ─────────────────────────

// StartBackground 后台启动 WebUI(父进程路径)。
func StartBackground(opts Options) error {
	opts.Listen = NormalizeLegacyWildcardListen(opts.Listen)
	if err := AcquireWebLock(WebState{
		Pid:        os.Getpid(),
		Listen:     opts.Listen,
		ConfigPath: opts.ConfigPath,
		Password:   opts.Password,
	}); err != nil {
		if errors.Is(err, ErrWebAlreadyRunning) {
			if st, rerr := ReadWebState(); rerr == nil {
				logger.Error("WebUI 已在后台运行 (pid=%d, %s)", st.Pid, st.Listen)
			} else {
				logger.Error("WebUI 已在后台运行")
			}
		}
		return err
	}

	// Intentional bare exec.Command: detached background WebUI child must outlive StartBackground().
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	extraEnv := []string{
		envWebBackground + "=1",
		envWebReadyFd + "=" + strconv.Itoa(webReadyFd),
	}
	if opts.Password != "" {
		extraEnv = append(extraEnv, "SINGCTL_WEB_PASSWORD="+opts.Password)
	}
	cmd.Env = BuildCleanSubprocessEnv(extraEnv...)
	setWebSpawnAttrs(cmd)

	// 日志落盘（0600 权限）;stdin/stdout/stderr 重定向
	logFile, err := os.OpenFile(WebLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		_ = os.Remove(WebStatePath())
		return fmt.Errorf("failed to open webui log: %w", err)
	}
	defer logFile.Close()

	devNull := os.DevNull
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	nullFile, err := os.OpenFile(devNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdin = nullFile
		defer nullFile.Close()
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Unix: fd3 就绪管道
	var readyR *os.File
	if runtime.GOOS != "windows" {
		r, w, perr := os.Pipe()
		if perr == nil {
			readyR = r
			cmd.ExtraFiles = []*os.File{w}
		}
	}

	if err := cmd.Start(); err != nil {
		_ = os.Remove(WebStatePath())
		logger.Error("后台启动失败: %v", err)
		return fmt.Errorf("failed to start background webui: %w", err)
	}

	if readyR == nil {
		// Windows / 管道不可用:无法握手,乐观返回
		logger.Success("WebUI 已在后台启动 (pid=%d)", cmd.Process.Pid)
		return nil
	}
	// 父进程关闭写端,子进程退出时 Read 才会收到 EOF
	_ = cmd.ExtraFiles[0].Close()

	rerr := waitWebReady(readyR, 15*time.Second)
	_ = readyR.Close()
	if rerr != nil {
		_ = cmd.Process.Kill()
		_ = os.Remove(WebStatePath())
		logger.Error("WebUI 后台启动失败,详见日志: %s (%v)", WebLogPath(), rerr)
		return fmt.Errorf("webui background start failed: %w", rerr)
	}

	st, serr := ReadWebState()
	if serr != nil {
		logger.Success("WebUI 已在后台启动 (pid=%d)", cmd.Process.Pid)
		return nil
	}
	logger.Success("WebUI 已在后台启动 (pid=%d)", st.Pid)
	for _, u := range FormatListenURLs(st.Listen) {
		logger.Info("  ➜  http://%s", u)
	}
	if opts.Password == "" {
		logger.Warn("  ⚠  未设置访问口令,请确保仅暴露在可信内网(建议 --password 或 SINGCTL_WEB_PASSWORD)")
	}
	logger.Info("停止: singctl web stop   日志: %s", WebLogPath())
	return nil
}

var errWebChildDied = errors.New("webui child exited during startup")

func waitWebReady(r *os.File, timeout time.Duration) error {
	ch := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		n, err := r.Read(buf)
		switch {
		case n > 0 && buf[0] == 1:
			ch <- nil
		case err != nil:
			ch <- errWebChildDied
		default:
			ch <- errWebChildDied
		}
	}()
	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for webui ready signal")
	}
}

// ListenURLs 把监听地址转成可访问的 URL 列表(导出版,供 cmd 层展示)
func ListenURLs(listen string) []string { return FormatListenURLs(listen) }

// formatListenURLs 把监听地址转成可访问的 URL 列表(通配地址展开为 LAN/loopback)
func FormatListenURLs(listen string) []string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return []string{listen}
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "[::]" {
		return []string{net.JoinHostPort(host, port)}
	}
	var out []string
	if lan := lanIPv4(); lan != "" {
		out = append(out, lan+":"+port)
	}
	return append(out, "127.0.0.1:"+port)
}

// ───────────────────────── 停止 / 状态 ─────────────────────────

// StopWeb 停止后台 WebUI。返回是否真的执行了停止( false = 本来就没在运行)。
func StopWeb() (bool, error) {
	st, err := ReadWebState()
	if err != nil {
		return false, nil // 状态文件不存在 → 未在运行
	}

	if !WebProcMatches(st.Pid) {
		// PID 已死或被无关进程复用 → 残留文件,清理即可
		_ = os.Remove(WebStatePath())
		return false, nil
	}

	proc, perr := os.FindProcess(st.Pid)
	if perr != nil {
		_ = os.Remove(WebStatePath())
		return false, nil
	}
	send := func(sig syscall.Signal) {
		if runtime.GOOS == "windows" {
			_ = proc.Kill()
			return
		}
		_ = proc.Signal(sig)
	}

	send(syscall.SIGTERM)
	if !waitWebExit(st.Pid, 5*time.Second) {
		send(syscall.SIGKILL)
		waitWebExit(st.Pid, 3*time.Second)
	}
	_ = os.Remove(WebStatePath())
	return true, nil
}

func waitWebExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !ProcessAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !ProcessAlive(pid)
}

// WebStatus 查询后台运行状态
func WebStatus() (WebState, bool) {
	st, err := ReadWebState()
	if err != nil {
		return WebState{}, false
	}
	return st, WebProcMatches(st.Pid)
}

// isProcdManagedWeb 判断是否由 OpenWrt procd (/etc/init.d/singctl-web) 托管运行
func isProcdManagedWeb() bool {
	if runtime.GOOS != "linux" || WebStatePathOverride != "" {
		return false
	}
	fi, err := os.Stat("/etc/init.d/singctl-web")
	if err != nil || fi.IsDir() {
		return false
	}
	return runWebCmdTimeout(defaultWebProbeTimeout, nil, nil, nil, "/etc/init.d/singctl-web", "running") == nil
}

// isSystemdManagedWeb 判断是否由 Linux systemd (singctl-web.service) 托管运行
func isSystemdManagedWeb() bool {
	if runtime.GOOS != "linux" || WebStatePathOverride != "" {
		return false
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	return servicemgr.NewSystemd(nil).IsActive(context.Background(), "singctl-web")
}

// IsWebRunningOrManaged 判断客户端 WebUI 是否正在运行（含 web start 守护、OpenWrt procd 或 systemd 托管）
func IsWebRunningOrManaged() bool {
	if _, running := WebStatus(); running {
		return true
	}
	return isProcdManagedWeb() || isSystemdManagedWeb()
}

// resolveOnDiskExecutable 定位磁盘上最新的 singctl 可执行文件路径（剥离 Linux /proc/self/exe 的 " (deleted)" 或 ".backup" 后缀）
func resolveOnDiskExecutable() (string, error) {
	if ExecutablePathOverride != "" {
		return ExecutablePathOverride, nil
	}
	return updater.ResolveExecutablePath()
}

// buildRestartArgs 根据指定监听/配置或历史状态构造重启 `singctl web start` 的命令行参数
func buildRestartArgs(st WebState, configPath string, preferredListen string) []string {
	listen := cmp.Or(strings.TrimSpace(preferredListen), strings.TrimSpace(st.Listen), ":8090")
	cfgPath := cmp.Or(strings.TrimSpace(configPath), strings.TrimSpace(st.ConfigPath))
	args := make([]string, 0, 6)
	if cfgPath != "" {
		args = append(args, "--config", cfgPath)
	}
	args = append(args, "web", "start", "-l", listen)
	return args
}

// RestartWeb 停止当前运行的客户端 WebUI 并使用磁盘上的最新二进制重新拉起（供 CLI `singctl update self` 或 `singctl web restart` 调用）
func RestartWeb(configPath string) error {
	if isProcdManagedWeb() {
		return runWebCmdTimeout(defaultWebRestartTimeout, BuildCleanSubprocessEnv(), os.Stdout, os.Stderr, "/etc/init.d/singctl-web", "restart")
	}
	if isSystemdManagedWeb() {
		return servicemgr.NewSystemd(nil).Restart(context.Background(), "singctl-web")
	}

	st, running := WebStatus()
	if !running {
		return nil
	}
	exe, err := resolveOnDiskExecutable()
	if err != nil {
		return err
	}
	args := buildRestartArgs(st, configPath, st.Listen)
	if _, err := StopWeb(); err != nil {
		return err
	}
	return runWebCmdTimeout(defaultWebRestartTimeout, buildRestartEnv(st.Password), os.Stdout, os.Stderr, exe, args...)
}

// attachDetachedStdio 将异步热重启子进程的输入输出与当前 HTTP 会话彻底解耦，并把启动/错误日志追加至 WebLogPath
func attachDetachedStdio(cmd *exec.Cmd) (cleanup func()) {
	var closers []*os.File
	devNull := os.DevNull
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	if nf, err := os.OpenFile(devNull, os.O_RDWR, 0); err == nil {
		cmd.Stdin = nf
		closers = append(closers, nf)
	}
	if lf, err := os.OpenFile(WebLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		cmd.Stdout = lf
		cmd.Stderr = lf
		closers = append(closers, lf)
	}
	return func() {
		for _, f := range closers {
			_ = f.Close()
		}
	}
}

// ScheduleDetachedRestart 供 WebUI 内部触发 `update-self` 成功后异步热重启自身：
// 先让当前 HTTP 响应流完整返回给浏览器，1 秒后由脱离后台标记的独立会话子进程执行平滑重启。
// 自动兼容 OpenWrt procd、Linux systemd、singctl web start 守护进程、前台直跑及 Windows。
func ScheduleDetachedRestart(configPath string, listen string, password string) {
	st, _ := WebStatus()
	effectiveCfg := cmp.Or(strings.TrimSpace(configPath), strings.TrimSpace(st.ConfigPath))
	effectiveListen := cmp.Or(strings.TrimSpace(listen), strings.TrimSpace(st.Listen), ":8090")
	effectivePassword := cmp.Or(password, st.Password)

	if runtime.GOOS == "windows" {
		exe, err := resolveOnDiskExecutable()
		if err != nil || exe == "" {
			return
		}
		oldPid := strconv.Itoa(os.Getpid())
		winScript := `ping -n 2 127.0.0.1 >NUL 2>&1 & "%SINGCTL_RESTART_EXE%" web stop >NUL 2>&1 & taskkill /PID %SINGCTL_RESTART_OLDPID% /F >NUL 2>&1 & if defined SINGCTL_RESTART_CFG ("%SINGCTL_RESTART_EXE%" --config "%SINGCTL_RESTART_CFG%" web start -l "%SINGCTL_RESTART_LISTEN%") else ("%SINGCTL_RESTART_EXE%" web start -l "%SINGCTL_RESTART_LISTEN%")`
		// Intentional bare exec.Command: detached async restart helper must survive parent exit.
		cmd := exec.Command("cmd.exe", "/C", winScript)
		env := buildRestartEnv(effectivePassword)
		env = append(env,
			"SINGCTL_RESTART_EXE="+exe,
			"SINGCTL_RESTART_OLDPID="+oldPid,
			"SINGCTL_RESTART_CFG="+effectiveCfg,
			"SINGCTL_RESTART_LISTEN="+effectiveListen,
		)
		cmd.Env = env
		setWebSpawnAttrs(cmd)
		cleanup := attachDetachedStdio(cmd)
		defer cleanup()
		_ = cmd.Start()
		return
	}

	var cmd *exec.Cmd
	// Intentional bare exec.Command: detached async restart helper must survive parent HTTP process shutdown.
	switch {
	case isProcdManagedWeb():
		cmd = exec.Command("/bin/sh", "-c", "sleep 1; exec /etc/init.d/singctl-web restart")
		cmd.Env = BuildCleanSubprocessEnv()
	case isSystemdManagedWeb():
		cmd = exec.Command("/bin/sh", "-c", "sleep 1; exec systemctl restart singctl-web")
		cmd.Env = BuildCleanSubprocessEnv()
	default:
		exe, err := resolveOnDiskExecutable()
		if err != nil || exe == "" {
			return
		}
		startArgs := buildRestartArgs(st, effectiveCfg, effectiveListen)
		oldPid := strconv.Itoa(os.Getpid())
		// 严格遵循 POSIX / OpenWrt BusyBox ash 语法，所有动态参数经位置参数 ($1, $2, "$@") 传递，零命令注入风险
		posixScript := `exe="$1"; oldpid="$2"; shift 2; sleep 1; "$exe" web stop >/dev/null 2>&1 || true; if [ -n "$oldpid" ] && kill -0 "$oldpid" 2>/dev/null; then kill "$oldpid" 2>/dev/null || true; i=0; while [ "$i" -lt 30 ] && kill -0 "$oldpid" 2>/dev/null; do sleep 0.1 2>/dev/null || sleep 1; i=$((i + 1)); done; fi; exec "$@"`
		shArgs := make([]string, 0, 6+len(startArgs))
		shArgs = append(shArgs, "-c", posixScript, "--", exe, oldPid, exe)
		shArgs = append(shArgs, startArgs...)
		cmd = exec.Command("/bin/sh", shArgs...)
		cmd.Env = buildRestartEnv(effectivePassword)
	}

	setWebSpawnAttrs(cmd)
	cleanup := attachDetachedStdio(cmd)
	defer cleanup()
	_ = cmd.Start()
}
