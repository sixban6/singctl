package cmd

import (
	"fmt"
	"singctl/internal/adguard"
	"singctl/internal/logger"
	"time"

	"github.com/spf13/cobra"
)

// NewDNSCmd 创建客户端本地防劫持 DNS (AdGuard Home) 管理命令组。
func NewDNSCmd(defaultConfigPath string) *cobra.Command {
	dnsCmd := &cobra.Command{
		Use:     "dns",
		Aliases: []string{"agh"},
		Short:   "DNS   : 管理客户端本地防劫持 AdGuard Home 服务 / Manage local AdGuard Home anti-hijack DNS",
		Long:    "一键安装、免向导初始化配置并托管本地 AdGuard Home (127.0.0.1:5353 + 局域网管理面板)，彻底解决客户端 dns_local 明文劫持问题。",
	}

	dnsCmd.AddCommand(
		newDNSInstallCmd(defaultConfigPath),
		newDNSStartCmd(defaultConfigPath),
		newDNSStopCmd(defaultConfigPath),
		newDNSRestartCmd(defaultConfigPath),
		newDNSStatusCmd(defaultConfigPath),
		newDNSResetPasswordCmd(defaultConfigPath),
		newDNSUninstallCmd(defaultConfigPath),
	)

	return dnsCmd
}

func newDNSInstallCmd(defaultConfigPath string) *cobra.Command {
	var username string
	var nonInteractive bool
	var forceDownload bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "安装并初始化配置 AdGuard Home / Install and initialize AdGuard Home",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			_, err = mgr.Install(adguard.InstallOptions{
				ConfigPath:     resolvedPath,
				Username:       username,
				NonInteractive: nonInteractive,
				ForceDownload:  forceDownload,
			})
			return err
		},
	}

	cmd.Flags().StringVarP(&username, "username", "u", "", "管理员账号 (留空交互式询问，直接回车默认 root)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "非交互模式，直接使用配置账号或默认 root")
	cmd.Flags().BoolVarP(&forceDownload, "force", "f", false, "强制重新下载最新 AdGuard Home 二进制")
	return cmd
}

func newDNSStartCmd(defaultConfigPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "启动本地 AdGuard Home 服务 / Start local AdGuard Home service",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			if err := mgr.Start(); err != nil {
				return err
			}
			mgr.PrintAccessSummary(mgr.Status())
			return nil
		},
	}
}

func newDNSStopCmd(defaultConfigPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "停止本地 AdGuard Home 服务 / Stop local AdGuard Home service",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			mgr := adguard.NewManager(cfg, resolveCmdConfigPath(cmd, defaultConfigPath))
			if err := mgr.Stop(); err != nil {
				return err
			}
			logger.Success("AdGuard Home 已停止")
			return nil
		},
	}
}

func newDNSRestartCmd(defaultConfigPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "restart",
		Aliases: []string{"r"},
		Short:   "重启本地 AdGuard Home 服务 / Restart local AdGuard Home service",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			if err := mgr.Restart(); err != nil {
				return err
			}
			mgr.PrintAccessSummary(mgr.Status())
			return nil
		},
	}
}

func newDNSStatusCmd(defaultConfigPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"s"},
		Short:   "查看本地 AdGuard Home 状态与面板凭据 / Show AdGuard Home status and credentials",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			mgr := adguard.NewManager(cfg, resolveCmdConfigPath(cmd, defaultConfigPath))
			st := mgr.Status()

			logger.Info("═══════════════════════════════════════════════════════════")
			logger.Success("           🛡️  AdGuard Home 状态面板")
			logger.Info("═══════════════════════════════════════════════════════════")
			if !st.Installed {
				logger.Warn("安装状态        : 未安装 (%s)", st.BinaryPath)
				logger.Info("安装命令        : singctl dns install")
				return nil
			}
			logger.Success("安装路径        : %s ✓", st.BinaryPath)
			if st.Version != "" {
				logger.Info("核心版本        : %s", st.Version)
			}
			logger.Info("配置文件        : %s", st.ConfigFile)

			if st.DNSHealthy {
				logger.Success("DNS 引擎状态    : 运行正常 (%s) ✓", st.DNSAddr)
				if ips, elapsed, err := adguard.ProbeUpstreamResolution(st.DNSAddr, "qq.com", 3*time.Second); err == nil && len(ips) > 0 {
					logger.Success("加密上游实测    : qq.com -> %s (耗时 %dms) ✓", ips[0], elapsed.Milliseconds())
				}
			} else if st.Running {
				logger.Warn("DNS 引擎状态    : 进程运行中但 %s 未响应 ✗", st.DNSAddr)
			} else {
				logger.Warn("DNS 引擎状态    : 未运行 ✗")
			}

			if st.WebHealthy {
				logger.Success("Web 管理面板    : %s (仅限局域网访问) ✓", st.WebURL)
			} else {
				logger.Warn("Web 管理面板    : %s (未监听) ✗", st.WebURL)
			}
			logger.Info("管理员账号      : %s", st.Username)
			if st.Password != "" {
				logger.Info("管理员密码      : %s", st.Password)
			} else {
				logger.Info("管理员密码      : (可通过 singctl dns reset-password 重置)")
			}
			logger.Info("═══════════════════════════════════════════════════════════")
			return nil
		},
	}
}

func newDNSResetPasswordCmd(defaultConfigPath string) *cobra.Command {
	var username string
	cmd := &cobra.Command{
		Use:   "reset-password",
		Short: "重置 AdGuard Home 管理员密码 / Reset AdGuard Home admin password",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			user, pass, err := mgr.ResetCredentials(username)
			if err != nil {
				return err
			}
			st := mgr.Status()
			logger.Success("已重置 AdGuard Home 登录凭据:")
			fmt.Printf("   • Web 面板 : %s\n", st.WebURL)
			fmt.Printf("   • 管理账号 : %s\n", user)
			fmt.Printf("   • 新 密 码 : %s\n", pass)
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "同时指定新的管理员账号 (留空保持现有账号)")
	return cmd
}

func newDNSUninstallCmd(defaultConfigPath string) *cobra.Command {
	var purge bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "停止并卸载本地 AdGuard Home / Stop and uninstall local AdGuard Home",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				cfg = loadCmdConfigOrDefault(cmd, defaultConfigPath)
				resolvedPath = resolveCmdConfigPath(cmd, defaultConfigPath)
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			if err := mgr.Uninstall(purge); err != nil {
				return err
			}
			logger.Success("已卸载 AdGuard Home；如需同步更新 sing-box 配置请执行: singctl sb gen && singctl sb restart")
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "同时清理 /etc/AdGuardHome 配置与数据目录")
	return cmd
}
