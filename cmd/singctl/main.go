package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"singctl/internal/updater"
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
	)

	if err := rootCmd.Execute(); err != nil {
		logger.Error("Command execution failed: %v", err)
		os.Exit(1)
	}
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Generate config and start sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
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
			return sb.Start()
		},
	}
}

func stopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Stop sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _ := config.Load(configPath)
			sb := singbox.New(cfg)
			return sb.Stop()
		},
	}
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
  sb       - update sing-box
  self     - update singctl itself`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}

			switch args[0] {
			case "sb", "sing-box":
				sb := singbox.New(cfg)
				return sb.Update()
			case "self":
				updater := updater.New(cfg.GitHub.MirrorURL, "https://github.com/sixban6/singctl")
				return updater.UpdateSelf()
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
