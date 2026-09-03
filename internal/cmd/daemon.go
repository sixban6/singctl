package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

// NewDaemonCommand creates the daemon command with subcommands
func NewDaemonCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "daemon",
		Aliases: []string{"dm"}, // 添加快捷命令 singctl dm
		Short:   "看门狗: 守护singbox(简写singctl dm)",
		Long:    "管理 singctl 守护进程，自动监控和重启 sing-box / Manage the singctl daemon for automatic sing-box monitoring and restart",
	}

	cmd.AddCommand(
		newDaemonStartCommand(),
		newDaemonStopCommand(),
		newDaemonStatusCommand(),
		newDaemonLogsCommand(),
	)

	return cmd
}

// newDaemonStartCommand creates daemon start subcommand
func newDaemonStartCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "启动守护进程 / Start the daemon",
		Long:  "启动 singctl 守护进程，监控 sing-box 进程并在需要时自动重启 / Start the singctl daemon to monitor sing-box process and automatically restart it when needed",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			d := daemon.NewDaemon(cfg)
			return d.Start()
		},
	}
}

// newDaemonStopCommand creates daemon stop subcommand
func newDaemonStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止守护进程 / Stop the daemon",
		Long:  "停止 singctl 守护进程 / Stop the singctl daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !daemon.IsDaemonRunning() {
				logger.Warn("Daemon is not running")
				return nil
			}

			if err := daemon.StopDaemon(); err != nil {
				return fmt.Errorf("failed to stop daemon: %w", err)
			}

			logger.Success("Daemon stopped successfully")
			return nil
		},
	}
}

// newDaemonStatusCommand creates daemon status subcommand
func newDaemonStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看守护进程状态 / Show daemon status",
		Long:  "查看 singctl 守护进程和被监控服务的当前状态 / Show the current status of the singctl daemon and monitored services",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			monitor := daemon.NewMonitor(cfg)
			status := monitor.GetStatus()

			// 显示状态信息
			logger.Info("Daemon Status:")
			logger.Info("├─ %s", status.String())

			// 显示重启限制器信息（从持久化状态恢复真实计数）
			if daemon.IsDaemonRunning() {
				limiter := daemon.NewRestartLimiterFromState(cfg.Watchdog.MaxRestarts)
				logger.Info("├─ Restarts: %d/%d (last hour)",
					limiter.GetRestartCount(), limiter.GetMaxRestarts())
			}

			// 显示看门狗日志路径
			logger.Info("├─ Watchdog log: %s", daemon.GetWatchdogLogPath())

			return nil
		},
	}
}

// newDaemonLogsCommand creates daemon logs subcommand
func newDaemonLogsCommand() *cobra.Command {
	var tail int
	var follow bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "查看守护进程日志 / Show daemon logs",
		Long:  "查看 singctl 守护进程日志 / Show the singctl daemon logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			logPath := daemon.GetDaemonLogPath()

			// 检查日志文件是否存在
			if _, err := os.Stat(logPath); os.IsNotExist(err) {
				logger.Warn("Log file does not exist: %s", logPath)
				logger.Info("Start the daemon to generate logs: singctl daemon start")
				return nil
			}

			// 读取日志文件
			content, err := os.ReadFile(logPath)
			if err != nil {
				return fmt.Errorf("failed to read log file: %w", err)
			}

			// 过滤空行后取末尾 tail 行(与 tail -n 行为一致)
			var nonEmpty []string
			for _, line := range strings.Split(string(content), "\n") {
				if strings.TrimSpace(line) != "" {
					nonEmpty = append(nonEmpty, line)
				}
			}
			if tail > 0 && len(nonEmpty) > tail {
				nonEmpty = nonEmpty[len(nonEmpty)-tail:]
			}

			// 输出日志内容
			for _, line := range nonEmpty {
				fmt.Println(line)
			}

			// follow 模式：持续跟踪新增日志（类似 tail -f）
			if follow {
				return followFile(cmd.Context(), logPath, int64(len(content)))
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "n", 100, "Number of lines to show from the end of the log")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output (like tail -f)")

	return cmd
}

// followFile 从 offset 起持续输出文件新增内容，直到日志被删除或收到中断信号(Ctrl+C)。
// 兼容日志轮转：检测到文件被截断/重建时从头重新读取。
func followFile(ctx context.Context, path string, offset int64) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // 日志被清理，结束跟踪
			}
			return fmt.Errorf("failed to open log file: %w", err)
		}

		info, err := f.Stat()
		if err != nil {
			f.Close()
			return fmt.Errorf("failed to stat log file: %w", err)
		}

		// 文件被轮转(截断或重建)：从头读取
		if info.Size() < offset {
			offset = 0
		}

		if info.Size() > offset {
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				f.Close()
				return fmt.Errorf("failed to seek log file: %w", err)
			}
			if _, err := io.Copy(os.Stdout, f); err != nil {
				f.Close()
				return fmt.Errorf("failed to read log file: %w", err)
			}
			offset = info.Size()
		}
		f.Close()
	}
}
