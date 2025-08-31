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
	config   *config.Config
	monitor  *Monitor
	limiter  *RestartLimiter
	singbox  *singbox.SingBox
	ctx      context.Context
	cancel   context.CancelFunc
	logFile  *os.File
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
	return d.monitor.GetMonitorStatus()
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
	// 定时器
	procTicker := time.NewTicker(60 * time.Second)    // 进程检查：每60秒
	subTicker := time.NewTicker(5 * time.Minute)      // 订阅检查：每5分钟
	netTicker := time.NewTicker(10 * time.Minute)     // 网络检查：每10分钟
	
	defer func() {
		procTicker.Stop()
		subTicker.Stop() 
		netTicker.Stop()
		RemovePidFile()
		if d.logFile != nil {
			d.logFile.Close()
		}
	}()

	logger.Info("Daemon monitoring started")

	for {
		select {
		case <-d.ctx.Done():
			logger.Info("Daemon monitoring stopped")
			return nil

		case <-procTicker.C:
			d.checkAndRestartProcess()

		case <-subTicker.C:
			d.checkSubscriptions()

		case <-netTicker.C:
			d.checkNetwork()
		}
	}
}

// checkAndRestartProcess 检查并重启进程
func (d *Daemon) checkAndRestartProcess() {
	if IsSingBoxRunning() {
		return // 进程正常运行
	}

	// 检查是否允许重启
	if !d.limiter.CanRestart() {
		logger.Error("Restart limit exceeded (%d restarts in last hour), stopping daemon", 
			d.limiter.GetMaxRestarts())
		d.shutdown()
		return
	}

	// 获取重启延迟
	delay := d.limiter.GetRestartDelay()
	restartCount := d.limiter.GetRestartCount() + 1

	logger.Warn("sing-box stopped, restarting in %v... (attempt %d/%d)", 
		delay, restartCount, d.limiter.GetMaxRestarts())

	// 等待延迟时间
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-d.ctx.Done():
			return
		}
	}

	// 尝试重启
	if err := d.restartSingBox(); err != nil {
		logger.Error("Failed to restart sing-box: %v", err)
		return
	}

	// 记录重启
	d.limiter.RecordRestart()
	logger.Success("sing-box restarted successfully (attempt %d/%d)", 
		restartCount, d.limiter.GetMaxRestarts())
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

// checkSubscriptions 检查订阅状态
func (d *Daemon) checkSubscriptions() {
	healthy, failedSubs := d.monitor.CheckSubscriptionHealth()
	
	if !healthy && len(failedSubs) > 0 {
		logger.Warn("Subscription issues detected:")
		for _, sub := range failedSubs {
			logger.Warn("  - Unreachable: %s", sub)
		}
		logger.Info("Consider running 'singctl gen' to update configuration")
	}
}

// checkNetwork 检查网络连通性
func (d *Daemon) checkNetwork() {
	if !d.monitor.CheckNetworkConnectivity() {
		logger.Warn("Network connectivity issues detected")
	}
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