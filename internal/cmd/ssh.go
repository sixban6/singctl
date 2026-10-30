package cmd

import (
	"singctl/internal/logger"
	"singctl/internal/ssh"

	"github.com/spf13/cobra"
)

// NewSSHCmd creates the top-level 'ssh' command for singctl
func NewSSHCmd() *cobra.Command {
	sshCmd := &cobra.Command{
		Use:   "ssh",
		Short: "SSH   : 批量免密、端口收敛与安全加固管理",
		Long: `singctl ssh 提供完整的服务器 SSH 安全基线加固与自动化免密管理能力。
支持基于约定自动加载当前目录下的 ./ssh-init.yaml，
通过双端口过渡保障绝不失联，并自动回写本地 ~/.ssh/config。`,
	}

	sshCmd.AddCommand(
		newSSHInitCmd(),
		newSSHTestCmd(),
		newSSHPushKeyCmd(),
		newSSHHardenCmd(),
		newSSHConfigCmd(),
		newSSHTplCmd(),
	)

	return sshCmd
}

func newSSHInitCmd() *cobra.Command {
	var (
		configFile  string
		concurrency int
		dryRun      bool
		skipConfig  bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "一键执行: 批量分发公钥、验证免密、切换端口与加固回写",
		Long: `一键执行完整的 SSH 安全加固流水线：
1. 建立初始连接并注入公钥到 ~/.ssh/authorized_keys
2. 本地外部验证 22 端口免密登录
3. 防火墙与 SELinux 放行目标端口并开启双端口过渡
4. 外部验证 2222 端口免密可用性 (失败自动熔断回滚)
5. 关闭 22 端口并禁用密码登录
6. 自动增量更新本地 ~/.ssh/config`,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, hosts, err := ssh.LoadConfig(configFile)
			if err != nil {
				return err
			}

			runner := ssh.NewRunner()
			results := runner.RunInit(hosts, concurrency, dryRun, skipConfig)
			ssh.PrintExecutionReport(results)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "file", "f", "ssh-init.yaml", "Path to configuration file")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 5, "Number of concurrent workers")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Simulate checks without making permanent changes")
	cmd.Flags().BoolVar(&skipConfig, "skip-config", false, "Do not write or update local ~/.ssh/config")

	return cmd
}

func newSSHTestCmd() *cobra.Command {
	var (
		configFile  string
		concurrency int
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "健康审计: 探测主机端口连通性、免密状态与密码开关",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, hosts, err := ssh.LoadConfig(configFile)
			if err != nil {
				return err
			}

			runner := ssh.NewRunner()
			results := runner.RunTest(hosts, concurrency)
			ssh.PrintTestReport(results)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "file", "f", "ssh-init.yaml", "Path to configuration file")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 5, "Number of concurrent workers")

	return cmd
}

func newSSHPushKeyCmd() *cobra.Command {
	var (
		configFile  string
		concurrency int
	)

	cmd := &cobra.Command{
		Use:   "push-key",
		Short: "免密分发: 批量将本地公钥分发并授权至目标机器",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, hosts, err := ssh.LoadConfig(configFile)
			if err != nil {
				return err
			}

			runner := ssh.NewRunner()
			results := runner.RunPushKey(hosts, concurrency)
			ssh.PrintExecutionReport(results)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "file", "f", "ssh-init.yaml", "Path to configuration file")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 5, "Number of concurrent workers")

	return cmd
}

func newSSHHardenCmd() *cobra.Command {
	var (
		configFile      string
		concurrency     int
		overridePort    int
		disablePassword bool
		skipConfig      bool
	)

	cmd := &cobra.Command{
		Use:   "harden",
		Short: "独立加固: 对已免密的主机执行端口收敛、关密码与防火墙配置",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, hosts, err := ssh.LoadConfig(configFile)
			if err != nil {
				return err
			}

			runner := ssh.NewRunner()
			results := runner.RunHarden(hosts, concurrency, overridePort, disablePassword, skipConfig)
			ssh.PrintExecutionReport(results)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "file", "f", "ssh-init.yaml", "Path to configuration file")
	cmd.Flags().IntVarP(&concurrency, "concurrency", "j", 5, "Number of concurrent workers")
	cmd.Flags().IntVarP(&overridePort, "target-port", "p", 0, "Override target SSH port")
	cmd.Flags().BoolVar(&disablePassword, "disable-password", true, "Disable password authentication")
	cmd.Flags().BoolVar(&skipConfig, "skip-config", false, "Do not write or update local ~/.ssh/config")

	return cmd
}

func newSSHConfigCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "配置管理: 管理本地 ~/.ssh/config 增量托管块",
	}

	var (
		configFile string
		targetPath string
	)

	syncCmd := &cobra.Command{
		Use:   "sync",
		Short: "同步配置: 将 ssh-init.yaml 主机信息幂等写入 ~/.ssh/config",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, hosts, err := ssh.LoadConfig(configFile)
			if err != nil {
				return err
			}

			cfgMgr := ssh.NewLocalConfigManager(targetPath)
			if err := cfgMgr.SyncHosts(hosts); err != nil {
				return err
			}

			logger.Success("成功同步 %d 台主机配置至 %s", len(hosts), cfgMgr.GetConfigPath())
			return nil
		},
	}
	syncCmd.Flags().StringVarP(&configFile, "file", "f", "ssh-init.yaml", "Path to configuration file")
	syncCmd.Flags().StringVarP(&targetPath, "output", "o", "", "Custom target ssh config path (defaults to ~/.ssh/config)")

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "查看托管: 列出 ~/.ssh/config 中由 singctl 托管的所有节点",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgMgr := ssh.NewLocalConfigManager(targetPath)
			hosts, err := cfgMgr.ListManagedHosts()
			if err != nil {
				return err
			}
			ssh.PrintManagedHosts(hosts, cfgMgr.GetConfigPath())
			return nil
		},
	}
	listCmd.Flags().StringVarP(&targetPath, "ssh-config", "s", "", "Custom ssh config path")

	var hostName string
	cleanCmd := &cobra.Command{
		Use:   "clean",
		Short: "清理托管: 从 ~/.ssh/config 中移除 singctl 托管标记块",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgMgr := ssh.NewLocalConfigManager(targetPath)
			count, err := cfgMgr.CleanManagedHosts(hostName)
			if err != nil {
				return err
			}
			if count == 0 {
				logger.Warn("未匹配到需要清理的托管标记块。")
			} else {
				logger.Success("已成功从 %s 清理 %d 个托管标记块。", cfgMgr.GetConfigPath(), count)
			}
			return nil
		},
	}
	cleanCmd.Flags().StringVarP(&hostName, "name", "n", "", "Host alias to clean (leave empty to clean all singctl hosts)")
	cleanCmd.Flags().StringVarP(&targetPath, "ssh-config", "s", "", "Custom ssh config path")

	configCmd.AddCommand(syncCmd, listCmd, cleanCmd)
	return configCmd
}

func newSSHTplCmd() *cobra.Command {
	var (
		outputPath string
		force      bool
	)

	cmd := &cobra.Command{
		Use:     "tpl",
		Aliases: []string{"template"},
		Short:   "生成模板: 在当前目录生成标准 ssh-init.yaml 配置文件模板",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := ssh.GenerateTemplate(outputPath, force); err != nil {
				return err
			}
			dest := outputPath
			if dest == "" {
				dest = "ssh-init.yaml"
			}
			logger.Success("已在当前目录生成配置文件模板: %s", dest)
			logger.Info("💡 提示: 请根据实际服务器 IP 与初始密码编辑该文件，然后运行 'singctl ssh init' 即可。")
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputPath, "output", "o", "ssh-init.yaml", "Destination file path")
	cmd.Flags().BoolVarP(&force, "force", "F", false, "Overwrite existing file if present")

	return cmd
}
