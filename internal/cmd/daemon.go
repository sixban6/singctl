package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
)

// NewDaemonCommand creates the daemon command with subcommands
func NewDaemonCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Daemon management commands",
		Long:  "Manage the singctl daemon for automatic sing-box monitoring and restart",
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
		Short: "Start the daemon",
		Long:  "Start the singctl daemon to monitor sing-box process and automatically restart it when needed",
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
		Short: "Stop the daemon",
		Long:  "Stop the singctl daemon",
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
		Short: "Show daemon status",
		Long:  "Show the current status of the singctl daemon and monitored services",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()
			
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			monitor := daemon.NewMonitor(cfg)
			status := monitor.GetQuickStatus() // 使用快速状态，不进行网络检查
			
			// 显示状态信息
			logger.Info("Daemon Status:")
			logger.Info("├─ %s", status.String())
			
			// 如果有重启限制器信息，也显示
			if daemon.IsDaemonRunning() {
				limiter := daemon.NewRestartLimiter()
				logger.Info("├─ Restarts: %d/%d (last hour)", 
					limiter.GetRestartCount(), limiter.GetMaxRestarts())
			}

			// 显示失败的订阅详情
			if len(status.FailedSubscriptions) > 0 {
				logger.Info("├─ Failed Subscriptions:")
				for _, sub := range status.FailedSubscriptions {
					logger.Info("│  └─ %s", sub)
				}
			}

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
		Short: "Show daemon logs",
		Long:  "Show the singctl daemon logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			logPath := daemon.GetDaemonLogPath()
			
			// 检查日志文件是否存在
			if _, err := os.Stat(logPath); os.IsNotExist(err) {
				logger.Warn("Log file does not exist: %s", logPath)
				logger.Info("Start the daemon to generate logs: singctl daemon start")
				return nil
			}

			// 读取日志文件
			content, err := ioutil.ReadFile(logPath)
			if err != nil {
				return fmt.Errorf("failed to read log file: %w", err)
			}

			lines := strings.Split(string(content), "\n")
			
			// 处理tail参数
			if tail > 0 && len(lines) > tail {
				lines = lines[len(lines)-tail:]
			}

			// 输出日志内容
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					fmt.Println(line)
				}
			}

			// TODO: 实现follow功能（类似tail -f）
			if follow {
				logger.Info("Follow mode not yet implemented")
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "n", 100, "Number of lines to show from the end of the log")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output (not yet implemented)")

	return cmd
}