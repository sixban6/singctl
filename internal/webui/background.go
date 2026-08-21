package webui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"singctl/internal/logger"
)

// 后台运行机制与 daemon 包的看门狗一致:
//   - 父进程以 O_EXCL 原子创建状态文件作为互斥锁(防并发 start)
//   - fork 自身 + SINGCTL_WEB_BACKGROUND=1 环境变量标记(防二次 fork)
//   - 子进程 Listen 成功后覆写状态文件并通过 fd3 回传就绪信号
//     (父进程因此能确认端口真的绑定成功,失败如实报错)
//   - 停止时按 PID + 命令行特征校验后 SIGTERM → 等待 → SIGKILL 兜底

const (
	envWebBackground = "SINGCTL_WEB_BACKGROUND"
	webReadyFd       = 3
	webStateName     = "singctl-web.pid"
	webLogName       = "singctl-web.log"
)

// webState 后台运行状态文件内容
type webState struct {
	Pid    int    `json:"pid"`
	Listen string `json:"listen"`
}

var (
	errWebAlreadyRunning = errors.New("webui already running")
	// 测试钩子
	webStatePathOverride   string
	webProcMatchesOverride func(pid int) bool
)

// WebStatePath 状态文件路径
func WebStatePath() string {
	if webStatePathOverride != "" {
		return webStatePathOverride
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), webStateName)
	}
	return filepath.Join("/tmp", webStateName)
}

// WebLogPath 后台运行日志路径
func WebLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), webLogName)
	}
	return filepath.Join("/tmp", webLogName)
}

// IsBackgroundChild 当前进程是否为后台子进程
func IsBackgroundChild() bool {
	return os.Getenv(envWebBackground) == "1"
}

// ───────────────────────── 状态文件 ─────────────────────────

func readWebState() (webState, error) {
	data, err := os.ReadFile(WebStatePath())
	if err != nil {
		return webState{}, err
	}
	var st webState
	if err := json.Unmarshal(data, &st); err != nil {
		return webState{}, err
	}
	return st, nil
}

// writeWebStateAtomic 原子写入状态文件(先写临时文件再 rename,避免读到半截内容)
func writeWebStateAtomic(st webState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	path := WebStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// acquireWebLock 以硬链接原子创建状态文件作为互斥锁。
// 实现：先写临时文件再 os.Link —— 目标存在时原子失败，避免 O_EXCL
// “先建空文件后写内容”的窗口期被并发者误判为残留锁清除。
// 文件已存在时:PID 存活且命令行含 web → 已在运行;否则视为残留锁清除后重试一次。
func acquireWebLock(st webState) error {
	b, _ := json.Marshal(st)
	target := WebStatePath()
	tmp := fmt.Sprintf("%s.new-%d", target, os.Getpid())
	defer os.Remove(tmp)

	for attempt := 0; attempt < 2; attempt++ {
		if err := os.WriteFile(tmp, b, 0644); err != nil {
			return fmt.Errorf("failed to write web state tmp: %w", err)
		}
		err := os.Link(tmp, target)
		if err == nil {
			return nil // 赢得锁
		}
		if !os.IsExist(err) {
			return fmt.Errorf("failed to claim web state: %w", err)
		}

		old, rerr := readWebState()
		if rerr == nil && webProcMatches(old.Pid) {
			return errWebAlreadyRunning
		}
		_ = os.Remove(target)
	}
	return errWebAlreadyRunning
}

// ───────────────────────── 进程校验 ─────────────────────────

// webProcMatches 判断 PID 是否为运行中的 WebUI 进程。
// 看门狗与 WebUI 同为 singctl 可执行文件,无法只靠进程名区分,
// 因此校验完整命令行中是否含 web/w 子命令参数(防 PID 回绕误杀无关进程)。
func webProcMatches(pid int) bool {
	if webProcMatchesOverride != nil {
		return webProcMatchesOverride(pid)
	}
	if !processAlive(pid) {
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
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
		if err != nil {
			return false
		}
		return hasWebArg(strings.Fields(string(out)))
	}
	// Windows 无法低成本校验,保守放行
	return true
}

func processAlive(pid int) bool {
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
		if out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "stat=").Output(); err == nil {
			return !strings.Contains(strings.TrimSpace(string(out)), "Z")
		}
	}
	return true
}

// ───────────────────────── 子进程侧 ─────────────────────────

// ChildReady 子进程就绪回调:覆写状态文件(带上真实监听地址)并通知父进程。
func ChildReady(listenAddr string) {
	_ = writeWebStateAtomic(webState{Pid: os.Getpid(), Listen: listenAddr})

	if runtime.GOOS == "windows" {
		return
	}
	f := os.NewFile(webReadyFd, "webui-ready")
	if f == nil {
		return
	}
	_, _ = f.Write([]byte{1})
	_ = f.Close()
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
	if err := acquireWebLock(webState{Pid: os.Getpid(), Listen: opts.Listen}); err != nil {
		if errors.Is(err, errWebAlreadyRunning) {
			if st, rerr := readWebState(); rerr == nil {
				logger.Error("WebUI 已在后台运行 (pid=%d, %s)", st.Pid, st.Listen)
			} else {
				logger.Error("WebUI 已在后台运行")
			}
		}
		return err
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), envWebBackground+"=1")
	setWebSpawnAttrs(cmd)

	// 日志落盘;stdin/stdout/stderr 重定向
	logFile, err := os.OpenFile(WebLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

	st, serr := readWebState()
	if serr != nil {
		logger.Success("WebUI 已在后台启动 (pid=%d)", cmd.Process.Pid)
		return nil
	}
	logger.Success("WebUI 已在后台启动 (pid=%d)", st.Pid)
	for _, u := range formatListenURLs(st.Listen) {
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
func ListenURLs(listen string) []string { return formatListenURLs(listen) }

// formatListenURLs 把监听地址转成可访问的 URL 列表(通配地址展开为 LAN/loopback)
func formatListenURLs(listen string) []string {
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
	st, err := readWebState()
	if err != nil {
		return false, nil // 状态文件不存在 → 未在运行
	}

	if !webProcMatches(st.Pid) {
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
		if !processAlive(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !processAlive(pid)
}

// WebStatus 查询后台运行状态
func WebStatus() (webState, bool) {
	st, err := readWebState()
	if err != nil {
		return webState{}, false
	}
	return st, webProcMatches(st.Pid)
}
