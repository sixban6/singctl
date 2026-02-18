package daemon

import (
	"context"
	"fmt"
	"io"
	"log"
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

	return &Daemon{
		config:  cfg,
		monitor: NewMonitor(cfg),
		limiter: NewRestartLimiter(),
		singbox: singbox.New(cfg),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start 启动守护进程
func (d *Daemon) Start() error {
	// 检查是否已有守护进程运行
	if IsDaemonRunning() {
		logger.Error("daemon already running")
		return fmt.Errorf("daemon already running")
	}

	// 后台化进程
	if err := d.daemonize(); err != nil {
		return err
	}

	// 设置日志文件
	if err := d.setupLogFile(); err != nil {
		logger.Error("failed to setup log file: %v", err)
		return fmt.Errorf("failed to setup log file: %v", err)
	}

	// 写入PID文件
	if err := WritePidFile(); err != nil {
		logger.Error("failed to write pid file: %v", err)
		return fmt.Errorf("failed to write pid file: %v", err)
	}

	// 设置信号处理
	d.setupSignalHandler()

	// 启动监控循环
	logger.Success("Daemon started successfully")
	return d.monitorLoop()
}

// Stop 停止守护进程
func (d *Daemon) Stop() error {
	return StopDaemon()
}

// Status 获取守护进程状态
func (d *Daemon) Status() MonitorStatus {
	return d.monitor.GetStatus()
}

// daemonize 后台化进程
func (d *Daemon) daemonize() error {
	// 如果已经是守护进程，直接返回
	if os.Getppid() == 1 {
		return nil
	}

	// Fork到后台
	cmd := exec.Command(os.Args[0], os.Args[1:]...)

	// 设置进程属性（跨平台处理）
	d.setProcAttrs(cmd)

	// 重定向标准输入输出到 /dev/null (Unix) 或 NUL (Windows)
	devNull := "/dev/null"
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}

	nullFile, err := os.OpenFile(devNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}

	cmd.Stdin = nullFile
	cmd.Stdout = nullFile
	cmd.Stderr = nullFile

	// 启动后台进程
	if err := cmd.Start(); err != nil {
		logger.Error("failed to daemonize: %v", err)
		return fmt.Errorf("failed to daemonize: %v", err)
	}

	// 父进程退出
	os.Exit(0)
	return nil
}

// setupSignalHandler 设置信号处理器
func (d *Daemon) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		logger.Info("Received signal %v, shutting down daemon...", sig)
		d.shutdown()
	}()
}

// shutdown 优雅关闭守护进程
func (d *Daemon) shutdown() {
	logger.Info("Daemon shutting down...")

	// 取消监控循环
	d.cancel()

	// 删除PID文件
	RemovePidFile()

	logger.Success("Daemon stopped")
	os.Exit(0)
}

// monitorLoop 监控循环
func (d *Daemon) monitorLoop() error {
	// 单一看门狗定时器：每3分钟检查一次
	watchdogTicker := time.NewTicker(3 * time.Minute)

	defer func() {
		watchdogTicker.Stop()
		RemovePidFile()
		if d.logFile != nil {
			d.logFile.Close()
		}
	}()

	logger.Info("Daemon watchdog started (check interval: 3min)")

	for {
		select {
		case <-d.ctx.Done():
			logger.Info("Daemon watchdog stopped")
			return nil

		case <-watchdogTicker.C:
			d.checkNetwork()
		}
	}
}

// checkNetwork 网络看门狗：检查是否能上网，不能则执行 stop → start
// 逻辑很简单：能上网就没问题，不能上网就重启，不管 sing-box 在不在
func (d *Daemon) checkNetwork() {
	// 第一轮检测
	result1 := d.monitor.CheckInternetAccess()
	if result1.Accessible {
		return // 能上网，一切正常
	}

	logger.Warn("[Watchdog] Internet access check failed (round 1), waiting 30s for confirmation...")
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "DETECT",
		CheckResult:   result1,
		RestartResult: "-",
	})

	// 等待 30 秒后进行第二轮确认
	select {
	case <-time.After(30 * time.Second):
	case <-d.ctx.Done():
		return
	}

	// 第二轮确认检测
	result2 := d.monitor.CheckInternetAccess()
	if result2.Accessible {
		logger.Info("[Watchdog] Internet access recovered on confirmation check, no action needed")
		return
	}

	logger.Warn("[Watchdog] Internet access confirmed unreachable (round 2), preparing restart...")
	LogWatchdogEvent(WatchdogEvent{
		Time:          time.Now(),
		Action:        "CONFIRM",
		CheckResult:   result2,
		RestartResult: "-",
	})

	// 执行 stop → start
	d.doRestart(result2, "internet unreachable")
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

// doRestart 执行完整 stop → start 重启流程（带频率限制）
func (d *Daemon) doRestart(checkResult InternetCheckResult, reason string) {
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
	time.Sleep(2 * time.Second)

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

// setupLogFile 设置日志文件
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

	// 设置logger输出到文件和标准输出
	multiWriter := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(multiWriter)

	return nil
}
