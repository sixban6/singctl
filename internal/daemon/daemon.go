package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

// envDaemonized 环境变量标记：子进程以此识别自己已经完成后台化，
// 避免依赖 Getppid()==1 这种有竞态的判断方式（父进程可能尚未退出）。
const envDaemonized = "SINGCTL_DAEMONIZED"

// readyFd 子进程向父进程回传就绪信号的管道 fd
const readyFd = 3

// Daemon 守护进程
type Daemon struct {
	config  *config.Config
	monitor *Monitor
	limiter *RestartLimiter
	singbox *singbox.SingBox
	ctx     context.Context
	cancel  context.CancelFunc
	logFile *os.File
}

// NewDaemon 创建守护进程
func NewDaemon(cfg *config.Config) *Daemon {
	ctx, cancel := context.WithCancel(context.Background())

	limiter := NewRestartLimiterWithMax(cfg.Watchdog.MaxRestarts)

	return &Daemon{
		config:  cfg,
		monitor: NewMonitor(cfg),
		limiter: limiter,
		singbox: singbox.New(cfg),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start 启动守护进程。
//
// 前台路径（用户执行 dm start 的进程）：
//  1. 以 O_EXCL 原子抢占 PID 锁，防止并发启动分裂出孤儿守护
//  2. fork 自身到后台（带 SINGCTL_DAEMONIZED=1 标记）
//  3. 通过管道等待子进程就绪信号后再返回，启动失败能如实报错
//
// 子进程路径（环境变量已标记）：初始化日志/PID → 通知父进程 → 进入监控循环。
func (d *Daemon) Start() error {
	if os.Getenv(envDaemonized) == "1" {
		// 子进程：父进程已持有 PID 锁并写入其 PID，这里用原子写覆盖为自己的
		return d.runForeground()
	}

	// 前台：抢占互斥锁（已运行则直接报错）
	if err := acquirePidLock(); err != nil {
		if errors.Is(err, errDaemonAlreadyRunning) {
			logger.Error("daemon already running")
		}
		return err
	}

	return d.spawn()
}

// runForeground 子进程主体：初始化并进入监控循环（阻塞）
func (d *Daemon) runForeground() error {
	// 设置日志文件（在通知父进程之前，保证就绪即日志可用）
	if err := d.setupLogFile(); err != nil {
		notifyParentReady(false)
		logger.Error("failed to setup log file: %v", err)
		return fmt.Errorf("failed to setup log file: %w", err)
	}

	// 用自己的 PID 覆盖 PID 文件（原子替换）
	if err := WritePidFile(); err != nil {
		notifyParentReady(false)
		logger.Error("failed to write pid file: %v", err)
		return fmt.Errorf("failed to write pid file: %w", err)
	}

	d.setupSignalHandler()

	logger.Success("Daemon started successfully (pid=%d, check every %ds)", os.Getpid(), d.config.Watchdog.Interval)

	// 通知父进程：守护进程已就绪
	notifyParentReady(true)

	return d.monitorLoop()
}

// spawn fork 后台子进程并等待就绪信号
func (d *Daemon) spawn() error {
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), envDaemonized+"=1")

	// 设置进程属性（跨平台处理）
	d.setProcAttrs(cmd)

	// 重定向标准输入输出到 /dev/null (Unix) 或 NUL (Windows)
	devNull := "/dev/null"
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	nullFile, err := os.OpenFile(devNull, os.O_RDWR, 0)
	if err != nil {
		_ = RemovePidFile()
		return err
	}
	defer nullFile.Close()

	cmd.Stdin = nullFile
	cmd.Stdout = nullFile
	cmd.Stderr = nullFile

	// Unix：通过 fd3 传递就绪管道，父进程据此判断子进程是否成功启动
	var readyR *os.File
	if runtime.GOOS != "windows" {
		var readyW *os.File
		readyR, readyW, err = os.Pipe()
		if err == nil {
			cmd.ExtraFiles = []*os.File{readyW}
		}
	}

	if err := cmd.Start(); err != nil {
		logger.Error("failed to daemonize: %v", err)
		_ = RemovePidFile()
		return fmt.Errorf("failed to daemonize: %w", err)
	}

	if readyR == nil {
		// Windows / 管道不可用：无法握手，维持旧行为（乐观返回）
		logger.Success("Daemon started in background (pid=%d)", cmd.Process.Pid)
		return nil
	}

	// 关闭父进程持有的写端，子进程退出时 Read 才会收到 EOF
	if extra := cmd.ExtraFiles; len(extra) > 0 {
		_ = extra[0].Close()
	}

	err = waitReady(readyR, 10*time.Second)
	_ = readyR.Close()
	switch {
	case err == nil:
		logger.Success("Daemon started in background (pid=%d)", cmd.Process.Pid)
		return nil
	case errors.Is(err, errChildDied):
		_ = RemovePidFile()
		logger.Error("daemon child exited during startup")
		return err
	default: // 超时：子进程可能仍在初始化，保留锁由其自行接管
		logger.Warn("daemon startup not confirmed within timeout; check %s", GetDaemonLogPath())
		return nil
	}
}

var errChildDied = errors.New("daemon child exited during startup")

// waitReady 阻塞等待子进程的就绪信号
func waitReady(r *os.File, timeout time.Duration) error {
	ch := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		n, err := r.Read(buf)
		switch {
		case n > 0 && buf[0] == 1:
			ch <- nil
		case n > 0:
			ch <- fmt.Errorf("unexpected ready signal: %d", buf[0])
		case err != nil:
			ch <- errChildDied
		default:
			ch <- errChildDied
		}
	}()

	select {
	case err := <-ch:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout waiting for daemon ready signal")
	}
}

// notifyParentReady 子进程通过 fd3 通知父进程初始化结果（fd 不存在时静默忽略）
func notifyParentReady(ok bool) {
	if runtime.GOOS == "windows" {
		return
	}
	f := os.NewFile(readyFd, "ready-pipe")
	if f == nil {
		return
	}
	b := []byte{0}
	if ok {
		b[0] = 1
	}
	_, _ = f.Write(b)
	_ = f.Close()
}

// Stop 停止守护进程
func (d *Daemon) Stop() error {
	return StopDaemon()
}

// Status 获取守护进程状态
func (d *Daemon) Status() MonitorStatus {
	return d.monitor.GetStatus()
}

// setupSignalHandler 设置信号处理器：仅取消 context，
// 由 monitorLoop 自然退出并执行 defer 清理（关闭日志、删除 PID 文件），
// 避免 os.Exit 跳过清理逻辑。
func (d *Daemon) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		logger.Info("Received signal %v, shutting down daemon...", sig)
		d.cancel()
	}()
}

// monitorLoop 监控循环
func (d *Daemon) monitorLoop() error {
	interval := time.Duration(d.config.Watchdog.Interval) * time.Second
	if interval <= 0 {
		interval = 3 * time.Minute
	}
	watchdogTicker := time.NewTicker(interval)

	defer func() {
		watchdogTicker.Stop()
		logger.Info("Daemon stopped")
		RemovePidFile()
		if d.logFile != nil {
			d.logFile.Close()
		}
	}()

	logger.Info("Daemon watchdog started (check interval: %s)", interval)

	for {
		select {
		case <-d.ctx.Done():
			return nil

		case <-watchdogTicker.C:
			d.runWatchdogCheck()
		}
	}
}

// runWatchdogCheck 健康检查：DNS + 进程，不健康则确认后 stop → start
func (d *Daemon) runWatchdogCheck() {
	// 第一轮检测
	result1 := d.monitor.CheckHealth()
	if result1.Healthy {
		return // 健康，一切正常
	}

	logger.Warn("[Watchdog] Health check failed (round 1): %s - %s, waiting %ds for confirmation...",
		result1.FailedReason, result1.Details, d.config.Watchdog.ConfirmWait)
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "DETECT",
		CheckResult:   result1,
		RestartResult: "-",
	})

	// 等待后进行第二轮确认
	select {
	case <-time.After(time.Duration(d.config.Watchdog.ConfirmWait) * time.Second):
	case <-d.ctx.Done():
		return
	}

	// 第二轮确认检测
	result2 := d.monitor.CheckHealth()
	if result2.Healthy {
		logger.Info("[Watchdog] Health recovered on confirmation check, no action needed")
		return
	}

	logger.Warn("[Watchdog] Health check confirmed unhealthy (round 2): %s - %s, preparing restart...",
		result2.FailedReason, result2.Details)
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "CONFIRM",
		CheckResult:   result2,
		RestartResult: "-",
	})

	// 执行 stop → start
	d.doRestart(result2, result2.FailedReason)
}

// restartSingBox 重启sing-box
func (d *Daemon) restartSingBox() error {
	// 首先生成配置（如果需要）
	if err := d.singbox.ValidateConfig(); err != nil {
		logger.Info("Current config is invalid, generating new config...")
		if err := d.singbox.GenerateConfig(); err != nil {
			return err
		}
	}

	// 启动sing-box
	return d.singbox.Start()
}

// doRestart 执行完整 stop → start 重启流程（带渐进退避 + 频率限制）
func (d *Daemon) doRestart(checkResult HealthCheckResult, reason string) {
	// 检查是否允许重启（频率限制）
	if !d.limiter.CanRestart() {
		logger.Error("[Watchdog] Restart limit exceeded (%d restarts in last hour), skipping auto-restart",
			d.limiter.GetMaxRestarts())
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "RESTART_BLOCKED",
			CheckResult:   checkResult,
			RestartResult: "rate limited",
		})
		return
	}

	// 渐进退避：连续重启次数越多，等待越久，给上游故障恢复留出时间
	if delay := d.limiter.GetRestartDelay(); delay > 0 {
		logger.Warn("[Watchdog] Backing off %s before restart (%d restarts in last hour)...",
			delay, d.limiter.GetRestartCount())
		select {
		case <-time.After(delay):
		case <-d.ctx.Done():
			return
		}
		// 退避期间计数窗口可能滑动（限额释放）也可能新增，重新校验
		if !d.limiter.CanRestart() {
			logger.Error("[Watchdog] Restart limit exceeded after backoff, skipping auto-restart")
			LogWatchdogEvent(WatchdogEvent{
				Time:          time.Now(),
				Action:        "RESTART_BLOCKED",
				CheckResult:   checkResult,
				RestartResult: "rate limited after backoff",
			})
			return
		}
	}

	logger.Warn("[Watchdog] Executing full restart: stop → start (reason: %s)", reason)

	// Stop (stop 脚本是幂等的，即使没有进程也不会出错)
	if err := d.singbox.Stop(); err != nil {
		logger.Error("[Watchdog] Stop failed: %v", err)
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "RESTART",
			CheckResult:   checkResult,
			RestartResult: fmt.Sprintf("stop failed: %v", err),
		})
		return
	}

	// 等待 2 秒确保清理完毕
	select {
	case <-time.After(2 * time.Second):
	case <-d.ctx.Done():
		return
	}

	// Start
	if err := d.restartSingBox(); err != nil {
		logger.Error("[Watchdog] Start failed: %v", err)
		LogWatchdogEvent(WatchdogEvent{
			Time:          time.Now(),
			Action:        "RESTART",
			CheckResult:   checkResult,
			RestartResult: fmt.Sprintf("start failed: %v", err),
		})
		return
	}

	// 记录重启成功
	d.limiter.RecordRestart()
	logger.Success("[Watchdog] sing-box restarted successfully (reason: %s)", reason)
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "RESTART",
		CheckResult:   checkResult,
		RestartResult: "success",
	})
}

// setupLogFile 设置日志文件。
//
// 注意：internal/logger 持有私有 *log.Logger 实例，标准库 log.SetOutput
// 对其无效，必须通过 logger.SetOutput 重定向，否则守护日志文件永远为空。
func (d *Daemon) setupLogFile() error {
	logPath := GetDaemonLogPath()

	// 确保日志目录存在
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// 打开日志文件
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	d.logFile = logFile

	// 日志写入文件（stdout 已被重定向到 /dev/null，无需重复输出）
	logger.SetOutput(logFile)
	// 文件中不需要 ANSI 颜色转义序列
	logger.SetColor(false)

	return nil
}
