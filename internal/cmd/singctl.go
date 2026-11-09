package cmd

import (
	"fmt"
	"os"
	"runtime"
	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/serverweb"
	"singctl/internal/subhub"
	"singctl/internal/updater"
	"singctl/internal/util/file"

	"github.com/spf13/cobra"
)

// NewInfoCommand creates the info command
func NewInfoCommand(version string) *cobra.Command {
	return &cobra.Command{
		Use:   "info",
		Short: "配置  : 查看配置信息",
		Long:  "显示 sing-box 安装路径、配置文件路径、singctl 版本及订阅信息 / Display sing-box installation path, configuration file path, singctl version and subscription information",
		RunE: func(cmd *cobra.Command, args []string) error {
			configPath := cmd.Flag("config").Value.String()
			return showSystemInfo(configPath, version)
		},
	}
}

// NewDoctorCmd creates the doctor command
func NewDoctorCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"doc", "check"},
		Short:   "体检  : 全链路健康体检与故障自检",
		Long:    "自动化检测系统基础环境、TCP BBR 加速、端口监听、四核服务状态、TLS 证书有效性、Reality 伪装连通性及海外全球边缘多点出口画像与服务连通性",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, _ := loadCmdConfig(cmd, configPath)
			report := doctor.RunDoctor(cfg)
			doctor.PrintDoctorReport(report)
			return nil
		},
	}
}

func NewUpdateCmd(configPath string, version string) *cobra.Command {
	return &cobra.Command{
		Use:     "update <target> or u <target>",
		Short:   "更新  : 更新singctl到最新版",
		Aliases: []string{"u"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, configPath)
			if err != nil {
				return err
			}

			switch args[0] {
			case "s", "self":
				up := updater.New(cfg.GitHub.MirrorURL, "https://github.com/sixban6/singctl")
				if err := up.UpdateSelf(resolvedPath, version); err != nil {
					return err
				}
				if subhub.IsRunning() {
					_ = subhub.RestartService()
				}
				if serverweb.IsRunning(resolvedPath) {
					_ = serverweb.RestartService()
				}
				return nil
			default:
				return fmt.Errorf("unknown target: %s", args[0])
			}
		},
	}
}

func NewInternalMigrateCmd() *cobra.Command {
	var configPath string
	var templatePath string

	cmd := &cobra.Command{
		Use:    "internal-migrate",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" || templatePath == "" {
				return fmt.Errorf("both --config and --template are required")
			}
			tplData, err := os.ReadFile(templatePath)
			if err != nil {
				return fmt.Errorf("failed to read template file %s: %w", templatePath, err)
			}
			if err := config.MigrateConfig(configPath, tplData); err != nil {
				return fmt.Errorf("migration failed: %w", err)
			}
			logger.Success("Config migration completed successfully.")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "Path to user config file")
	cmd.Flags().StringVar(&templatePath, "template", "", "Path to template file")
	return cmd
}

func NewVersionCmd(Version string, BuildTime string, GitCommit string) *cobra.Command {
	return &cobra.Command{
		Use:     "version",
		Aliases: []string{"-v"},
		Short:   "查询  : 查询singctl版本",
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
	singboxPath := constant.SingBoxInstallDir
	if _, err := os.Stat(singboxPath); err == nil {
		logger.Success("安装路径        : %s ✓", singboxPath)
	} else {
		logger.Warn("安装路径        : %s (不存在) ✗", singboxPath)
	}

	// Sing-box 配置文件路径
	singboxConfigPath := constant.SingBoxConfigFile
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

	cfg, cfgErr := config.Load(configPath)

	if daemon.IsDaemonRunning() {
		logger.Success("守护进程状态    : 运行中 ✓")

		// 显示重启统计（从持久化状态恢复真实计数）
		maxRestarts := 3
		if cfg != nil && cfg.Watchdog.MaxRestarts > 0 {
			maxRestarts = cfg.Watchdog.MaxRestarts
		}
		limiter := daemon.NewRestartLimiterFromState(maxRestarts)
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

	// 3.5 客户端本地防劫持 DNS (AdGuard Home) 信息
	if runtime.GOOS == "linux" && cfg != nil && (adguard.IsInstalled() || cfg.DNS.Password != "") {
		logger.Info("")
		logger.Success("🛡️  AdGuard Home (本地防劫持 DNS)")
		logger.Info("───────────────────────────────────────────────────────────")
		st := adguard.NewManager(cfg, configPath).Status()
		if st.DNSHealthy {
			logger.Success("运行状态        : 运行中 (%s) ✓", st.DNSAddr)
		} else if st.Installed {
			logger.Warn("运行状态        : 未运行 (%s) ✗", st.DNSAddr)
		} else {
			logger.Warn("运行状态        : 未安装 ✗")
		}
		logger.Info("Web 管理面板    : %s", st.WebURL)
		logger.Info("管理员账号      : %s", st.Username)
		if st.Password != "" {
			logger.Info("管理员密码      : %s", st.Password)
		}
	}

	// 4. 订阅连接信息
	logger.Info("")
	logger.Success("📡 订阅连接信息")
	logger.Info("───────────────────────────────────────────────────────────")

	if cfgErr != nil {
		logger.Warn("订阅数量        : 无法读取配置文件 ✗")
		logger.Error("配置文件错误: %v", cfgErr)
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
				maskedURL := file.MaskSubscriptionURL(sub.URL)
				logger.Info("  └─ %-12s: %s", name, maskedURL)

				if sub.SkipTlsVerify {
					logger.Info("      └─ 跳过TLS验证: 是")
				}
				if sub.RemoveEmoji {
					logger.Info("      └─ 移除Emoji  : 是")
				}
				if sub.Include != "" {
					logger.Info("      └─ 保留规则   : %s", sub.Include)
				}
				if sub.Exclude != "" {
					logger.Info("      └─ 剔除规则   : %s", sub.Exclude)
				}
				if len(sub.Rename) > 0 {
					logger.Info("      └─ 重命名规则 : %d 条", len(sub.Rename))
				}
			}
		}
	}

	// Footer
	logger.Info("")
	logger.Info("═══════════════════════════════════════════════════════════")

	return nil
}
