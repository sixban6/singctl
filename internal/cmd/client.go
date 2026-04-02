package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/daemon"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"time"

	"github.com/spf13/cobra"
)

var (
	commandRunner = exec.Command
	runtimeGOOS   = runtime.GOOS
)

func copyGeneratedConfigToClipboard(targetPath string) (bool, error) {
	if runtimeGOOS != "darwin" || targetPath != constant.SingBoxConfigFile {
		return false, nil
	}

	configFile, err := os.Open(targetPath)
	if err != nil {
		return false, fmt.Errorf("open generated config failed: %w", err)
	}
	defer configFile.Close()

	cmd := commandRunner("pbcopy")
	cmd.Stdin = configFile
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("run pbcopy failed: %w", err)
	}

	return true, nil
}

func runStartSingbox(cfg *config.Config) error {
	sb := singbox.New(cfg)
	if err := sb.ValidateConfig(); err != nil {
		// 现有配置无效或不存在，需要重新生成 → 此时才校验 subs
		logger.Info("Current config is invalid or missing, generating new config...")
		if err := cfg.ValidateSubs(); err != nil {
			return fmt.Errorf("subscription config invalid: %w", err)
		}
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
}

func runStopSingbox(cfg *config.Config) error {
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
}

func newStartCmd(cfg *config.Config) *cobra.Command {
	// 1. sb start
	cmd := &cobra.Command{
		Use:   "start",
		Short: "生成配置并启动 sing-box / Generate config and start sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStartSingbox(cfg)
		},
	}
	return cmd
}

func newStopCmd(cfg *config.Config) *cobra.Command {
	// 2. sb stop
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "停止 sing-box 和守护进程 / Stop sing-box and daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStopSingbox(cfg)
		},
	}
	return cmd
}

func newRestartCmd(cfg *config.Config) *cobra.Command {
	// 3. sb restart
	cmd := &cobra.Command{
		Use:   "restart",
		Short: "重启 sing-box / Restart sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger.Info("Restarting sing-box...")
			if err := runStopSingbox(cfg); err != nil {
				return err
			}
			return runStartSingbox(cfg)
		},
	}
	return cmd
}

func newGenCmd(cfg *config.Config) *cobra.Command {
	// 4. sb gen (将原 genCmd 逻辑移入，注意保留 Flag 处理)
	var outputPath string
	var stdout bool
	genCmd := &cobra.Command{
		Use:   "gen",
		Short: "生成 sing-box 配置文件 / Generate sing-box configuration",
		RunE: func(cmd *cobra.Command, args []string) error {

			// gen 命令必须依赖 subs，提前校验防止 index-out-of-range panic
			if err := cfg.ValidateSubs(); err != nil {
				return fmt.Errorf("subscription config invalid: %w", err)
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
			targetPath := constant.SingBoxConfigFile
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
			if copied, err := copyGeneratedConfigToClipboard(targetPath); err != nil {
				logger.Warn("配置已生成，但复制到粘贴板失败: %v", err)
			} else if copied {
				logger.Success("配置文件已经复制到粘贴板，可以直接粘贴")
			}
			return nil
		},
	}
	genCmd.Flags().StringVarP(&outputPath, "output", "o", "", "指定输出文件路径")
	genCmd.Flags().BoolVar(&stdout, "stdout", false, "输出到标准输出而不是文件")
	return genCmd
}

func newInstallCmd(cfg *config.Config) *cobra.Command {
	// 5. sb install
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "安装 sing-box / Install sing-box",
		RunE: func(cmd *cobra.Command, args []string) error {
			sb := singbox.New(cfg)
			return sb.Install()
		},
	}
	return installCmd
}

func newUpdateCmd(cfg *config.Config) *cobra.Command {
	// 6. sb update
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "更新 sing-box / Update sing-box",
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

	cmd.AddCommand(
		newStartCmd(cfg),
		newStopCmd(cfg),
		newRestartCmd(cfg),
		newGenCmd(cfg),
		newInstallCmd(cfg),
		newUpdateCmd(cfg),
	)
	return cmd
}
