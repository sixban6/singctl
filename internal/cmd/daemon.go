// 文件职责：提供看门狗守护进程 (`singctl daemon` / `singctl dm`) 的启停、平滑重启、状态与日志查看子命令。
package cmd

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"singctl/internal/common/sysinfo"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/webui"

	"github.com/spf13/cobra"
)

const (
	defaultWebHandoffTimeout      = 12 * time.Second
	defaultWebHandoffPollInterval = 100 * time.Millisecond
)

// DaemonStartDeps 显式注入守护进程启动时的宿主内存探测、环境变量、交接策略与路径覆盖（零全局状态篡改）。
type DaemonStartDeps struct {
	ReadMemInfo            func() (sysinfo.MemInfo, error)
	UnifiedEnvValue        *string
	WebListen              string
	WebPassword            string
	Paths                  daemon.Paths
	SkipSignalSetup        bool
	OnWebReady             func(listenAddr string)
	DeferWebHandoff        *bool
	IsStandaloneWebRunning func() bool
	StopStandaloneWeb      func() (bool, error)
	WebHandoffTimeout      time.Duration
	WebHandoffPollInterval time.Duration
}

// BuildUnifiedDaemon 装配守护进程实例；当命中低内存设备或 SINGCTL_UNIFIED_DAEMON=1 时自动内嵌共享 config.Store 的 WebUI。
func BuildUnifiedDaemon(cfg *config.Config, configPath, ver string, deps DaemonStartDeps) (*daemon.Daemon, bool) {
	readMem := deps.ReadMemInfo
	if readMem == nil {
		readMem = sysinfo.ReadMemInfo
	}
	mi, _ := readMem()

	envVal := os.Getenv(daemon.EnvUnifiedDaemon)
	if deps.UnifiedEnvValue != nil {
		envVal = *deps.UnifiedEnvValue
	}

	if !daemon.ShouldEnableUnifiedDaemon(mi, envVal) {
		if deps.Paths == (daemon.Paths{}) && !deps.SkipSignalSetup {
			return daemon.NewDaemonWithMeta(cfg, configPath, ver), false
		}
		d := daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
			ConfigPath:      configPath,
			Version:         ver,
			Paths:           deps.Paths,
			SkipSignalSetup: deps.SkipSignalSetup,
		})
		return d, false
	}

	listen := cmp.Or(strings.TrimSpace(deps.WebListen), strings.TrimSpace(os.Getenv("SINGCTL_WEB_LISTEN")))
	password := cmp.Or(deps.WebPassword, resolveWebPassword(""))
	isolatedTest := strings.TrimSpace(deps.Paths.WebEmbeddedFile) != ""
	if !isolatedTest {
		if prevSt, err := webui.ReadWebState(); err == nil {
			if listen == "" {
				listen = strings.TrimSpace(prevSt.Listen)
			}
			if password == "" {
				password = prevSt.Password
			}
		}
	}
	listen = webui.NormalizeLegacyWildcardListen(cmp.Or(listen, ":8090"))
	lowMem := true

	var d *daemon.Daemon
	d = daemon.NewDaemonWithOptions(cfg, daemon.DaemonOptions{
		ConfigPath:        configPath,
		Version:           ver,
		Paths:             deps.Paths,
		SkipSignalSetup:   deps.SkipSignalSetup,
		WebEmbeddedListen: listen,
		LowMemoryMode:     &lowMem,
		EmbeddedService: func(ctx context.Context, cfgStore *config.Store) error {
			srv := webui.New(webui.Options{
				ConfigPath:              configPath,
				ConfigStore:             cfgStore,
				AuditCollector:          d.AuditCollector(),
				SmartDNSStatsRing:       d.SmartDNSStatsRing(),
				SmartDNSTailer:          d.SmartDNSTailer(),
				NotifyDispatcher:        d.Notifier(),
				LowMemoryMode:           &lowMem,
				EmbeddedInDaemon:        true,
				Listen:                  listen,
				Password:                password,
				Version:                 ver,
				SkipAdGuardProbeForTest: deps.SkipSignalSetup,
				OnReady: func(actualAddr string) {
					d.RecordWebEmbeddedListen(actualAddr)
					if deps.OnWebReady != nil {
						deps.OnWebReady(actualAddr)
					}
				},
			})
			return serveEmbeddedWebWithHandoff(ctx, srv, deps, isolatedTest)
		},
	})
	return d, true
}

func shouldDeferWebHandoff(deps DaemonStartDeps) bool {
	if deps.DeferWebHandoff != nil {
		return *deps.DeferWebHandoff
	}
	return os.Getenv(daemon.EnvDeferWebHandoff) == "1" || os.Getenv(daemon.EnvFromWebUI) == "1"
}

func isAddrInUseError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address")
}

func serveEmbeddedWebWithHandoff(ctx context.Context, srv *webui.Server, deps DaemonStartDeps, isolatedTest bool) error {
	if isolatedTest && deps.IsStandaloneWebRunning == nil && deps.StopStandaloneWeb == nil {
		return srv.ServeContext(ctx)
	}

	isStandalone := deps.IsStandaloneWebRunning
	if isStandalone == nil {
		isStandalone = webui.IsStandaloneWebRunning
	}
	stopStandalone := deps.StopStandaloneWeb
	if stopStandalone == nil {
		stopStandalone = webui.StopWeb
	}

	deferHandoff := shouldDeferWebHandoff(deps)
	if !deferHandoff {
		_, _ = stopStandalone()
		return srv.ServeContext(ctx)
	}

	timeout := deps.WebHandoffTimeout
	if timeout <= 0 {
		timeout = defaultWebHandoffTimeout
	}
	pollInterval := deps.WebHandoffPollInterval
	if pollInterval <= 0 {
		pollInterval = defaultWebHandoffPollInterval
	}

	deadline := time.Now().Add(timeout)
	stoppedFallback := false

	if isStandalone() {
		logger.Info("[Daemon] 检测到由独立 WebUI 触发单进程合体，礼貌等待其推流结束并主动让渡端口（最长 %v）...", timeout)
		ticker := time.NewTicker(pollInterval)
		for isStandalone() {
			if !time.Now().Before(deadline) {
				logger.Warn("[Daemon] 等待独立 WebUI 优雅让渡端口超时（%v），执行兜底停止接管", timeout)
				_, _ = stopStandalone()
				stoppedFallback = true
				break
			}
			select {
			case <-ctx.Done():
				ticker.Stop()
				return ctx.Err()
			case <-ticker.C:
			}
		}
		ticker.Stop()
	}

	for {
		err := srv.ServeContext(ctx)
		if err == nil || ctx.Err() != nil {
			return err
		}
		if !isAddrInUseError(err) {
			return err
		}
		if time.Now().Before(deadline) {
			timer := time.NewTimer(pollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if !stoppedFallback {
			logger.Warn("[Daemon] 内嵌 WebUI 绑定端口仍被占用且超过交接等待上限（%v），执行兜底停止后重试", timeout)
			_, _ = stopStandalone()
			stoppedFallback = true
			continue
		}
		return err
	}
}

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

			d, unified := BuildUnifiedDaemon(cfg, configPath, ver, DaemonStartDeps{})
			if unified && os.Getenv("SINGCTL_DAEMONIZED") != "1" {
				logger.Info("检测到低内存设备，已启用单进程合体模式 (守护进程内嵌 WebUI)")
			}
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

			if emb, ok := daemon.ReadWebEmbeddedState(); ok {
				logger.Info("├─ WebUI: Embedded ✓ (%s, 低内存单进程合体模式)", emb.Listen)
			} else if status.DaemonRunning && snap.WebEmbedded {
				logger.Info("├─ WebUI: Embedded ✓ (%s, 低内存单进程合体模式)", cmp.Or(snap.WebEmbeddedListen, ":8090"))
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

// IsKeyWatchdogLogLine 判断日志行是否属于看门狗关键告警/容灾/同步事件（委托 daemon 权威实现）。
func IsKeyWatchdogLogLine(line string) bool {
	return daemon.IsKeyWatchdogLogLine(line)
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
