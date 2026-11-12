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
func NewDaemonCommand(version ...string) *cobra.Command {
	ver := "dev"
	if len(version) > 0 && strings.TrimSpace(version[0]) != "" {
		ver = strings.TrimSpace(version[0])
	}

	cmd := &cobra.Command{
		Use:     "daemon",
		Aliases: []string{"dm"},
		Short:   "看门狗: 守护singbox(简写singctl dm)",
		Long:    "管理 singctl 守护进程，自动监控自愈 sing-box、策略组自动故障切换与订阅无感热同步",
	}

	cmd.AddCommand(
		newDaemonStartCommand(ver),
		newDaemonStopCommand(),
		newDaemonRestartCommand(),
		newDaemonStatusCommand(),
		newDaemonLogsCommand(),
	)

	return cmd
}

func newDaemonStartCommand(ver string) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "启动守护进程 / Start the daemon",
		Long:  "启动 singctl 守护进程，监控 sing-box 进程并在需要时自动重启与切换备选线路",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			d := daemon.NewDaemonWithMeta(cfg, configPath, ver)
			return d.Start()
		},
	}
}

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

func newDaemonRestartCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "restart",
		Short: "平滑重启守护进程(不中断 sing-box) / Restart the daemon seamlessly",
		Long:  "平滑重启 singctl 看门狗守护进程以加载新配置或新版本，不影响正在运行的 sing-box 代理连接",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()
			if err := daemon.RestartDaemon(configPath); err != nil {
				return fmt.Errorf("failed to restart daemon: %w", err)
			}
			logger.Success("Daemon restarted seamlessly")
			return nil
		},
	}
}

func newDaemonStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "查看守护进程状态 / Show daemon status",
		Long:  "查看 singctl 守护进程、故障切换与被监控服务的当前状态",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			monitor := daemon.NewMonitor(cfg)
			status := monitor.GetStatus()
			snap := daemon.LoadRuntimeSnapshot()

			logger.Info("Daemon Status:")
			if status.DaemonRunning {
				verTag := ""
				if snap.DaemonVersion != "" {
					verTag = " (" + snap.DaemonVersion + ")"
				}
				if daemon.IsDaemonBinaryStale() {
					verTag += " [待重启应用新版本]"
				}
				logger.Info("├─ Daemon: Running ✓%s", verTag)
			} else {
				logger.Info("├─ Daemon: Stopped ✗")
			}

			if status.ProcessRunning {
				logger.Info("├─ SingBox: Running ✓")
			} else {
				logger.Info("├─ SingBox: Stopped ✗")
			}

			foCfg := cfg.Watchdog.Failover
			if foCfg.IsEnabled() {
				if len(snap.ActiveFailovers) > 0 {
					var parts []string
					for _, a := range snap.ActiveFailovers {
						parts = append(parts, fmt.Sprintf("%s(%s->%s)", a.Group, a.Origin, a.Current))
					}
					logger.Info("├─ Group failover: Enabled (接管中: %s)", strings.Join(parts, ", "))
				} else {
					logger.Info("├─ Group failover: Enabled (%d groups watched, all primary healthy)", len(foCfg.EffectiveGroups()))
				}
			} else {
				logger.Info("├─ Group failover: Disabled")
			}

			if snap.LastHealthAt != "" {
				detail := snap.LastHealthDetail
				if detail != "" {
					logger.Info("├─ Last check: %s (%s)", snap.LastHealthAt, detail)
				} else {
					logger.Info("├─ Last check: %s", snap.LastHealthAt)
				}
			}

			limiter := daemon.NewRestartLimiterFromState(cfg.Watchdog.MaxRestarts)
			logger.Info("├─ Restarts: %d/%d (last hour)",
				limiter.GetRestartCount(), limiter.GetMaxRestarts())
			logger.Info("├─ Total restarts: %d", limiter.GetTotalRestarts())
			logger.Info("└─ Daemon log: %s", daemon.GetDaemonLogPath())

			return nil
		},
	}
}

func IsKeyWatchdogLogLine(line string) bool {
	return strings.Contains(line, "[WATCHDOG]") ||
		strings.Contains(line, "[GroupFailover]") ||
		strings.Contains(line, "[SubSync]") ||
		strings.Contains(line, "[RuleSet]") ||
		strings.Contains(line, "[Watchdog]") ||
		strings.Contains(line, "Daemon started") ||
		strings.Contains(line, "Daemon stopped") ||
		strings.Contains(line, "[WARN]") ||
		strings.Contains(line, "[ERROR]")
}

func newDaemonLogsCommand() *cobra.Command {
	var tail int
	var follow bool
	var eventsOnly bool

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "查看守护进程日志 / Show daemon logs",
		Long:  "查看 singctl 守护进程与看门狗事件日志",
		RunE: func(cmd *cobra.Command, args []string) error {
			logPath := daemon.GetDaemonLogPath()

			if _, err := os.Stat(logPath); os.IsNotExist(err) {
				logger.Warn("Log file does not exist: %s", logPath)
				logger.Info("Start the daemon to generate logs: singctl daemon start")
				return nil
			}

			content, err := os.ReadFile(logPath)
			if err != nil {
				return fmt.Errorf("failed to read log file: %w", err)
			}

			var nonEmpty []string
			for line := range strings.SplitSeq(string(content), "\n") {
				if strings.TrimSpace(line) == "" {
					continue
				}
				if eventsOnly && !IsKeyWatchdogLogLine(line) {
					continue
				}
				nonEmpty = append(nonEmpty, line)
			}
			if tail > 0 && len(nonEmpty) > tail {
				nonEmpty = nonEmpty[len(nonEmpty)-tail:]
			}

			for _, line := range nonEmpty {
				fmt.Println(line)
			}

			if follow {
				return followFile(cmd.Context(), logPath, int64(len(content)))
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&tail, "tail", "n", 100, "Number of lines to show from the end of the log")
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output (like tail -f)")
	cmd.Flags().BoolVarP(&eventsOnly, "events", "e", false, "Only show watchdog/failover/sync key events")

	return cmd
}

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
				return nil
			}
			return fmt.Errorf("failed to open log file: %w", err)
		}

		info, err := f.Stat()
		if err != nil {
			f.Close()
			return fmt.Errorf("failed to stat log file: %w", err)
		}

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
