package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/fileutil"
	"singctl/internal/logger"
	"singctl/internal/updater"
)

// NewInfoCommand creates the info command
func NewInfoCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "配置信息",
		Long:  "Display sing-box installation path, configuration file path, singctl version and subscription information",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()
			return showSystemInfo(configPath, version)
		},
	}
}

func NewUpdateCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "update <target>",
		Short: "更新  ：更新singctl到最新版",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			switch args[0] {
			case "self":
				updater := updater.New(cfg.GitHub.MirrorURL, "https://github.com/sixban6/singctl")
				if err := updater.UpdateSelf(configPath); err != nil {
					return err
				}
				return nil
			default:
				return fmt.Errorf("unknown target: %s", args[0])
			}
		},
	}
}

func NewVersionCmd(Version string, BuildTime string, GitCommit string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "查询：查询singctl版本",
		Run: func(cmd *cobra.Command, args []string) {
			logger.Info("SingCtl %s", Version)
			logger.Info("Build Time: %s", BuildTime)
			logger.Info("Git Commit: %s", GitCommit)
		},
	}
}

func showSystemInfo(configPath, version string) error {
	// Header
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Success("           🎉 SINGCTL 系统信息 🎉")
	logger.Info("═══════════════════════════════════════════════════════════")

	// 1. Sing-box 信息
	logger.Info("")
	logger.Success("🎯 Sing-Box Information")
	logger.Info("───────────────────────────────────────────────────────────")

	// Sing-box 安装路径
	singboxPath := fileutil.GetSingBoxInstallDir()
	if _, err := os.Stat(singboxPath); err == nil {
		logger.Success("安装路径        : %s ✓", singboxPath)
	} else {
		logger.Warn("安装路径        : %s (不存在) ✗", singboxPath)
	}

	// Sing-box 配置文件路径
	singboxConfigPath := fileutil.GetSingboxConfigPath()
	if _, err := os.Stat(singboxConfigPath); err == nil {
		logger.Success("配置文件路径    : %s ✓", singboxConfigPath)
	} else {
		logger.Warn("配置文件路径    : %s (不存在) ✗", singboxConfigPath)
	}

	// 2. SingCtl 信息
	logger.Info("")
	logger.Success("🚀 SingCtl Information")
	logger.Info("───────────────────────────────────────────────────────────")

	logger.Success("版本            : %s ✓", version)

	// SingCtl 安装路径
	exePath, err := os.Executable()
	if err != nil {
		logger.Warn("安装路径        : 未知 ✗")
	} else {
		logger.Success("安装路径        : %s ✓", exePath)
	}

	// SingCtl 配置文件路径
	if _, err := os.Stat(configPath); err == nil {
		logger.Success("配置文件路径    : %s ✓", configPath)
	} else {
		logger.Warn("配置文件路径    : %s (不存在) ✗", configPath)
	}

	// 3. 守护进程信息
	logger.Info("")
	logger.Success("🤖 守护进程信息")
	logger.Info("───────────────────────────────────────────────────────────")

	if daemon.IsDaemonRunning() {
		logger.Success("守护进程状态    : 运行中 ✓")

		// 显示重启统计
		limiter := daemon.NewRestartLimiter()
		logger.Info("重启统计        : %d/%d (最近1小时)",
			limiter.GetRestartCount(), limiter.GetMaxRestarts())
	} else {
		logger.Warn("守护进程状态    : 未运行 ✗")
	}

	// 日志文件路径
	logPath := daemon.GetDaemonLogPath()
	if _, err := os.Stat(logPath); err == nil {
		logger.Success("日志文件路径    : %s ✓", logPath)
	} else {
		logger.Info("日志文件路径    : %s (未生成)", logPath)
	}

	// 4. 订阅连接信息
	logger.Info("")
	logger.Success("📡 订阅连接信息")
	logger.Info("───────────────────────────────────────────────────────────")

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Warn("订阅数量        : 无法读取配置文件 ✗")
		logger.Error("配置文件错误: %v", err)
	} else {
		if len(cfg.Subs) == 0 {
			logger.Warn("订阅数量        : 0 (未配置订阅) ✗")
		} else {
			logger.Success("订阅数量        : %d ✓", len(cfg.Subs))

			for i, sub := range cfg.Subs {
				name := sub.Name
				if name == "" {
					name = fmt.Sprintf("订阅 %d", i+1)
				}

				// 脱敏处理URL
				maskedURL := fileutil.MaskSubscriptionURL(sub.URL)
				logger.Info("  └─ %-12s: %s", name, maskedURL)

				if sub.SkipTlsVerify {
					logger.Info("      └─ 跳过TLS验证: 是")
				}
				if sub.RemoveEmoji {
					logger.Info("      └─ 移除Emoji  : 是")
				}
			}
		}
	}

	// Footer
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════")

	return nil
}
