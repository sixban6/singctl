package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"time"
)

func newStartCmd(cfg *config.Config) *cobra.Command {
	// 1. sb start
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Generate config and start sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {

			sb := singbox.New(cfg)
			if err := sb.ValidateConfig(); err != nil {
				logger.Info("Current config is invalid or missing, generating new config...")
				if err := sb.GenerateConfig(); err != nil {
					return err
				}
			} else {
				logger.Info("Using existing valid config")
			}
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				return sb.StartGUI()
			}
			return sb.Start()
		},
	}
	return cmd
}

func newStopCmd(cfg *config.Config) *cobra.Command {
	// 2. sb stop
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop sing-box and daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 原 stopCmd 的逻辑...
			if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
				logger.Warn("Stop command is not supported/needed for GUI clients on this platform.")
				return nil
			}
			if daemon.IsDaemonRunning() {
				logger.Info("Stopping daemon...")
				if err := daemon.StopDaemon(); err != nil {
					logger.Warn("Failed to stop daemon: %v", err)
				} else {
					logger.Success("Daemon stopped")
				}
			}
			sb := singbox.New(cfg)
			return sb.Stop()
		},
	}
	return cmd
}

func newGenCmd(cfg *config.Config) *cobra.Command {
	// 3. sb gen (将原 genCmd 逻辑移入，注意保留 Flag 处理)
	var outputPath string
	var stdout bool
	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "Generate sing-box configuration",
		RunE: func(cmd *cobra.Command, args []string) error {

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
	genCmd.Flags().StringVarP(&outputPath, "output", "o", "", "指定输出文件路径")
	genCmd.Flags().BoolVar(&stdout, "stdout", false, "输出到标准输出而不是文件")
	return genCmd
}

func newInstallCmd(cfg *config.Config) *cobra.Command {
	// 4. sb install
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			sb := singbox.New(cfg)
			return sb.Install()
		},
	}
	return installCmd
}

func newUpdateCmd(cfg *config.Config) *cobra.Command {
	// 5. sb update
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			sb := singbox.New(cfg)
			return sb.Update()
		},
	}
	return updateCmd
}

func NewSingboxCommand(configPath string) *cobra.Command {

	cmd := &cobra.Command{
		Use:     "singbox",
		Aliases: []string{"sb"}, // 添加快捷命令 singctl sb
		Short:   "客户端: singbox客户端的启动和配置(简写singctl sb)",
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("配置文件加载失败")
	}

	if err := cfg.ValidateSubs(); err != nil {
		logger.Error("配置校验失败", err)
	}

	cmd.AddCommand(
		newStartCmd(cfg),
		newStopCmd(cfg),
		newGenCmd(cfg),
		newInstallCmd(cfg),
		newUpdateCmd(cfg),
	)
	return cmd
}
