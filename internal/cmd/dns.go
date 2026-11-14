package cmd

import (
	"context"
	"fmt"
	"runtime"
	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/singbox"
	"time"

	"github.com/spf13/cobra"
)

// NewDNSCmd 创建客户端本地防劫持 DNS (AdGuard Home) 管理命令组。
func NewDNSCmd(defaultConfigPath string) *cobra.Command {
	dnsCmd := &cobra.Command{
		Use:     "dns",
		Aliases: []string{"agh"},
		Short:   "DNS   : 管理客户端本地防劫持 AdGuard Home 服务 / Manage local AdGuard Home anti-hijack DNS",
		Long:    "一键安装、免向导初始化配置并托管本地 AdGuard Home (127.0.0.1:5353 + 局域网管理面板)，自动原子切换 sing-box dns_local，彻底解决客户端明文 DNS 劫持问题。",
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

func syncSingBoxLocalDNSLink(ctx context.Context, cfg *config.Config, useAdGuard bool) {
	if runtime.GOOS != "linux" {
		return
	}
	dnsPort := 5353
	if cfg != nil {
		dnsPort = cfg.DNS.GetDNSPort()
	}
	if _, err := singbox.SyncLiveSingBoxDNSLocal(ctx, "", "", useAdGuard, dnsPort); err != nil {
		logger.Warn("同步更新 sing-box dns_local 失败: %v", err)
	}
}

func newDNSInstallCmd(defaultConfigPath string) *cobra.Command {
	var username string
	var nonInteractive bool
	var forceDownload bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "安装并无感启用 AdGuard Home 防劫持接管 / Install and enable AdGuard Home",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			st, err := mgr.Install(adguard.InstallOptions{
				ConfigPath:     resolvedPath,
				Username:       username,
				NonInteractive: nonInteractive,
				ForceDownload:  forceDownload,
			})
			if err != nil {
				return err
			}
			if st != nil && st.DNSHealthy {
				if ips, elapsed, pErr := adguard.ProbeUpstreamResolution(st.DNSAddr, "qq.com", 4*time.Second); pErr == nil && len(ips) > 0 {
					logger.Success("加密 DoH 上游实测通过: qq.com -> %s (%dms)", ips[0], elapsed.Milliseconds())
				}
				syncSingBoxLocalDNSLink(cmd.Context(), cfg, true)
			}
			return nil
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
		Short: "启动本地 AdGuard Home 并自动接管 sing-box dns_local / Start AdGuard Home",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			if !cfg.DNS.IsEnabled() {
				cfg.DNS.SetEnabled(true)
				if resolvedPath != "" {
					_ = config.Save(resolvedPath, cfg)
				}
			}
			mgr := adguard.NewManager(cfg, resolvedPath)
			if err := mgr.Start(); err != nil {
				return err
			}
			syncSingBoxLocalDNSLink(cmd.Context(), cfg, true)
			mgr.PrintAccessSummary(mgr.Status())
			return nil
		},
	}
}

func newDNSStopCmd(defaultConfigPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "零断网切回内置加密 DNS 并停止本地 AdGuard Home / Safely fallback DNS and stop AdGuard Home",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			cfg.DNS.SetEnabled(false)
			if resolvedPath != "" {
				_ = config.Save(resolvedPath, cfg)
			}
			// 零断网准则：必须先将 sing-box dns_local 切回内置纯 IP 加密 DoH，再停止 AdGuard Home 进程
			syncSingBoxLocalDNSLink(cmd.Context(), cfg, false)

			mgr := adguard.NewManager(cfg, resolvedPath)
			if err := mgr.Stop(); err != nil {
				return err
			}
			logger.Success("已安全回退 sing-box 至内置加密 DNS 并停止 AdGuard Home（全程零断网）")
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
			if cfg.DNS.IsEnabled() {
				syncSingBoxLocalDNSLink(cmd.Context(), cfg, true)
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
			linked, linkedPort := singbox.InspectSingBoxDNSLocal("")

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

			if linked {
				logger.Success("sing-box 联动   : 已接管 dns_local (127.0.0.1:%d) ✓", linkedPort)
			} else {
				logger.Info("sing-box 联动   : 未接管 (当前使用内置加密 DNS)")
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
		Short: "零断网切回内置加密 DNS 并卸载 AdGuard Home / Safely fallback DNS and uninstall AdGuard Home",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				cfg = loadCmdConfigOrDefault(cmd, defaultConfigPath)
				resolvedPath = resolveCmdConfigPath(cmd, defaultConfigPath)
			}
			// 卸载前先将运行中的 sing-box 平滑切回内置纯 IP 加密 DoH，防止卸载瞬间断网
			syncSingBoxLocalDNSLink(cmd.Context(), cfg, false)

			mgr := adguard.NewManager(cfg, resolvedPath)
			if err := mgr.Uninstall(purge); err != nil {
				return err
			}
			logger.Success("已安全回退 sing-box 解析并完成 AdGuard Home 卸载（全程零断网）")
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "同时清理 /etc/AdGuardHome 配置与数据目录")
	return cmd
}
