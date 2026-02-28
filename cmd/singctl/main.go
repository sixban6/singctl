package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"singctl/internal/bandwidth"
	"singctl/internal/cmd"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/deploy"
	"singctl/internal/firewall"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/tailscale"
	"singctl/internal/updater"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

var configPath string

func init() {
	if runtime.GOOS == "windows" {
		configPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "singctl", "singctl.yaml")
	} else {
		configPath = "/etc/singctl/singctl.yaml"
	}
}

func ensureConfigDir() error {
	dir := filepath.Dir(configPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// 目录不存在，创建它（包括所有中间目录）
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

func initConfigFile(srcConfigPath string, dstConfigPath string) {
	file, err := os.ReadFile(srcConfigPath)
	if err != nil {
		log.Fatalf("Init failed to read config file: %v", err)
	}
	err = ensureConfigDir()
	if err != nil {
		log.Fatalf("Init failed to ensure config dir: %v", err)
	}

	err = os.WriteFile(dstConfigPath, file, 0644)
	if err != nil {
		log.Fatalf("Init failed to write config file: %v", err)
	}
}

func main() {
	// 只在配置文件不存在时才初始化
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 获取可执行文件所在目录
		exePath, err := os.Executable()
		if err != nil {
			log.Fatalf("Failed to get executable path: %v", err)
		}
		exeDir := filepath.Dir(exePath)
		srcConfigPath := filepath.Join(exeDir, "configs", "singctl.yaml")

		initConfigFile(srcConfigPath, configPath)
	}
	rootCmd := &cobra.Command{
		Use:   "singctl",
		Short: "Sing-box management tool",
		Long: `SingCtl is a powerful tool for managing sing-box configurations and lifecycle.
It supports automatic configuration generation from subscription URLs,
DNS optimization, and complete service lifecycle management.`,
	}

	var defaultConfigPath string
	if runtime.GOOS == "windows" {
		defaultConfigPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "singctl", "singctl.yaml")
	} else {
		defaultConfigPath = "/etc/singctl/singctl.yaml"
	}
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", defaultConfigPath, "config file")

	rootCmd.AddCommand(
		startCmd(),
		stopCmd(),
		genCmd(),
		installCmd(),
		updateCmd(),
		versionCmd(),
		testCmd(),
		firewallCmd(),
		serverCmd(),
		cmd.NewInfoCommand(Version),
		cmd.NewDaemonCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed: %v", err)
		os.Exit(1)
	}
}

func startCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Generate config and start sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			if err := cfg.ValidateSubs(); err != nil {
				return err
			}

			sb := singbox.New(cfg)

			// 先检查现有配置是否有效
			if err := sb.ValidateConfig(); err != nil {
				logger.Info("Current config is invalid or missing, generating new config...")
				// 配置无效或不存在，生成新配置
				if err := sb.GenerateConfig(); err != nil {
					return err
				}
			} else {
				logger.Info("Using existing valid config")
			}

			// 启动服务
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				// 对于GUI客户端，先确保配置已生成
				// GenerateConfig is called inside ValidateConfig if invalid, but if valid we might need to tell user where it is.
				// However, StartGUI handles app launch. Config inject?
				// Requirement 4: "Make user import generated config..."

				// Ensure config is generated/updated if using custom logic?
				// The existing code calls GenerateConfig if invalid.
				// Let's just call StartGUI.
				return sb.StartGUI()
			}
			return sb.Start()
		},
	}

	tsCmd := &cobra.Command{
		Use:   "tailscale",
		Short: "Start tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			exitNode, _ := cmd.Flags().GetBool("exit-node")
			cfg, _ := config.Load(configPath)
			ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
			return ts.Start(exitNode)
		},
	}
	tsCmd.Flags().Bool("exit-node", false, "Advertise this device as a Tailscale exit node")
	cmd.AddCommand(tsCmd)

	return cmd
}

func stopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop sing-box and daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				logger.Warn("Stop command is not supported/needed for GUI clients on this platform.")
				return nil
			}

			// 先停止守护进程
			if daemon.IsDaemonRunning() {
				logger.Info("Stopping daemon...")
				if err := daemon.StopDaemon(); err != nil {
					logger.Warn("Failed to stop daemon: %v", err)
				} else {
					logger.Success("Daemon stopped")
				}
			}

			// 再停止sing-box
			cfg, _ := config.Load(configPath)
			sb := singbox.New(cfg)
			return sb.Stop()
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "tailscale",
		Short: "Stop tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load(configPath)
			ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
			return ts.Stop()
		},
	})

	return cmd
}

func genCmd() *cobra.Command {
	var outputPath string
	var stdout bool
	cmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate sing-box configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			if err := cfg.ValidateSubs(); err != nil {
				return err
			}

			generator := singbox.NewConfigGenerator(cfg)
			configJSON, err := generator.Generate()
			if err != nil {
				return err
			}

			// 如果指定了--stdout，输出到标准输出
			if stdout {
				fmt.Print(configJSON)
				return nil
			}

			// 确定输出路径
			targetPath := "/etc/sing-box/config.json"
			if outputPath != "" {
				targetPath = outputPath
			}

			// 创建目录
			dir := filepath.Dir(targetPath)
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("创建目录失败: %w", err)
			}

			// 备份现有配置
			if _, err := os.Stat(targetPath); err == nil {
				backupPath := fmt.Sprintf("%s.backup.%d", targetPath, time.Now().Unix())
				if err := os.Rename(targetPath, backupPath); err != nil {
					return fmt.Errorf("备份现有配置失败: %w", err)
				}
				logger.Info("已备份现有配置到: %s", backupPath)
			}

			// 写入新配置
			if err := os.WriteFile(targetPath, []byte(configJSON), 0644); err != nil {
				return fmt.Errorf("写入配置文件失败: %w", err)
			}

			logger.Success("配置已生成: %s", targetPath)
			return nil
		},
	}
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "指定输出文件路径")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "输出到标准输出而不是文件")
	return cmd
}

func installCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install <target>",
		Short: "Install components",
		Long:  "Install sing-box: singctl install sb",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			switch args[0] {
			case "sb", "sing-box":
				sb := singbox.New(cfg)
				return sb.Install()
			case "tailscale":
				ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
				return ts.Install()
			default:
				return fmt.Errorf("unknown target: %s", args[0])
			}
		},
	}
}

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update <target>",
		Short: "Update components",
		Long: `Update components:
  sb        - update sing-box
  tailscale - update tailscale to the latest stable version
  self      - update singctl itself`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			switch args[0] {
			case "sb", "sing-box":
				if err := cfg.ValidateSubs(); err != nil {
					return err
				}
				sb := singbox.New(cfg)
				return sb.Update()
			case "tailscale":
				ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)

				// Run Tailscale Update
				if err := ts.Update(); err != nil {
					return err
				}

				// Synchronously update singctl self
				updater := updater.New(cfg.GitHub.MirrorURL, "https://github.com/sixban6/singctl")
				if err := updater.UpdateSelf(configPath); err != nil {
					return err
				}
				return nil
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

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			logger.Info("SingCtl %s", Version)
			logger.Info("Build Time: %s", BuildTime)
			logger.Info("Git Commit: %s", GitCommit)
		},
	}
}

func testCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test network features",
	}

	bdCmd := &cobra.Command{
		Use:   "bd",
		Short: "Test broadband bandwidth (upload/download speed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return bandwidth.RunSpeedTest()
		},
	}

	cmd.AddCommand(bdCmd)
	return cmd
}

func firewallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "firewall",
		Short: "Manage system firewall rules (nftables)",
	}

	enableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable security block rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return firewall.Enable()
		},
	}

	disableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable and remove security block rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return firewall.Disable()
		},
	}

	cmd.AddCommand(enableCmd)
	cmd.AddCommand(disableCmd)
	return cmd
}

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Server deployment commands",
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil
	}

	deployCmd := &cobra.Command{
		Use:   "install",
		Short: "install server components. Optionally specify: common|caddy|singbox|substore",
		RunE: func(cmd *cobra.Command, args []string) error {

			// Verify required config
			if cfg.Server.SBDomain == "" || cfg.Server.CFDNSKey == "" {
				return fmt.Errorf("server.sb_domain and server.cf_dns_key are required in singctl.yaml")
			}

			// If no target is specified, run them all in sequence
			if len(args) == 0 {
				if err := deploy.DeployCommon(); err != nil {
					return err
				}
				if err := deploy.DeployWarp(); err != nil {
					return err
				}
				if err := deploy.DeployCaddy(cfg); err != nil {
					return err
				}
				sbs := deploy.NewSingBoxServer(cfg)
				if err := sbs.DeploySingbox(); err != nil {
					return err
				}

				sbt := deploy.NewSubstore(cfg, "")
				if err := sbt.DeploySubstore(); err != nil {
					return err
				}

				err := sbt.UpdateSubstoreConfig(sbs)
				if err != nil {
					logger.Warn("Substore config update failed!")
					return err
				}

				sbs.ShowLoginInfo()
				sbt.ShowLoginInfo()
				return nil
			}

			sbs := deploy.NewSingBoxServer(cfg)
			sbt := deploy.Substore{Config: cfg, SSKey: ""}
			// Handle specified targets
			switch args[0] {
			case "common":
				return deploy.DeployCommon()
			case "caddy":
				return deploy.DeployCaddy(cfg)
			case "singbox":
				return sbs.DeploySingbox()
			case "substore":
				return sbt.DeploySubstore()
			case "warp":
				return deploy.DeployWarp()
			default:
				return fmt.Errorf("unknown target: %s (must be common, caddy, singbox, substore, or warp)", args[0])
			}
		},
	}

	uninstallCmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall server components. Optionally specify: caddy|singbox|substore|warp",
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) == 0 {
				logger.Info("Uninstalling all server components...")
				if err := deploy.UninstallCaddy(); err != nil {
					logger.Warn("Failed to uninstall Caddy: %v", err)
				}

				if err := deploy.UninstallSingbox(); err != nil {
					logger.Warn("Failed to uninstall sing-box: %v", err)
				}

				if err := deploy.UninstallSubstore(); err != nil {
					logger.Warn("Failed to uninstall Sub-Store: %v", err)
				}

				if err := deploy.UninstallWarp(); err != nil {
					logger.Warn("Failed to uninstall WARP: %v", err)
				}
				logger.Success("All specified server components have been uninstalled.")
				return nil
			}

			target := args[0]
			switch target {
			case "caddy":
				if err := deploy.UninstallCaddy(); err != nil {
					return err
				}
			case "singbox":
				if err := deploy.UninstallSingbox(); err != nil {
					return err
				}
			case "substore":
				if err := deploy.UninstallSubstore(); err != nil {
					return err
				}
			case "warp":
				if err := deploy.UninstallWarp(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unknown target: %s (must be caddy, singbox, substore, or warp)", target)
			}
			return nil
		},
	}

	cmd.AddCommand(deployCmd)
	cmd.AddCommand(uninstallCmd)
	return cmd
}
