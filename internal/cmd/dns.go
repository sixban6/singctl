// 文件职责：提供客户端双引擎防劫持 DNS (`singctl dns` / `singctl agh`) 的安装、零断网切换、启停、状态与卸载子命令。
package cmd

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"singctl/internal/adguard"
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/localdns"
	"singctl/internal/logger"
	"singctl/internal/singbox"

	"github.com/spf13/cobra"
)

// NewDNSCmd 创建客户端本地防劫持 DNS 双引擎管理命令组（SmartDNS / AdGuard Home）。
func NewDNSCmd(defaultConfigPath string) *cobra.Command {
	dnsCmd := &cobra.Command{
		Use:     "dns",
		Aliases: []string{"agh"},
		Short:   "DNS   : 管理客户端双引擎防劫持 DNS (SmartDNS / AdGuard Home) / Manage local anti-hijack DNS",
		Long:    "统一管理客户端双引擎防劫持本地 DNS（SmartDNS 极速版 / AdGuard Home 可视版），支持按宿主机内存与闪存自动选型、两阶段零断网原子切换及 sing-box 纯 IP 加密 DoH 静默兜底。",
	}

	dnsCmd.AddCommand(
		newDNSInstallCmd(defaultConfigPath),
		newDNSSwitchCmd(defaultConfigPath),
		newDNSStartCmd(defaultConfigPath),
		newDNSStopCmd(defaultConfigPath),
		newDNSRestartCmd(defaultConfigPath),
		newDNSStatusCmd(defaultConfigPath),
		newDNSResetPasswordCmd(defaultConfigPath),
		newDNSUninstallCmd(defaultConfigPath),
	)

	return dnsCmd
}

func newLocalDNSRegistry(cfg *config.Config, cfgPath string) *localdns.Registry {
	return localdns.NewRegistry(cfg, localdns.EngineDeps{
		ConfigPath: cfgPath,
	})
}

func syncSingBoxLocalDNSLink(ctx context.Context, cfg *config.Config, useExternal bool) {
	if runtime.GOOS != "linux" {
		return
	}
	dnsPort := 5353
	fallbackGW := ""
	if cfg != nil {
		dnsPort = cfg.DNS.GetDNSPort()
		if !useExternal {
			if gw, ok := singbox.ExtractCascadedGatewayUpstream(cfg.DNS.Upstreams); ok {
				fallbackGW = gw
			}
		}
	}
	if !useExternal && fallbackGW == "" {
		fallbackGW = singbox.ProbeSafeWANFallbackDNS(nil, nil)
	}
	if _, err := singbox.SyncLiveSingBoxDNSLocalWithFallback(ctx, "", "", useExternal, dnsPort, fallbackGW); err != nil {
		logger.Warn("同步更新 sing-box dns_local 失败: %v", err)
	}
}

func resolveTargetDNSEngine(reg *localdns.Registry, flagEngine string, preferRecommended bool) (string, error) {
	norm := strings.ToLower(strings.TrimSpace(flagEngine))
	if norm == "" || norm == constant.DNSEngineAuto {
		sel := reg.ResolveSelection()
		if preferRecommended {
			return sel.RecommendedEngine, nil
		}
		return sel.ActiveEngine, nil
	}
	if !config.IsValidDNSEngine(norm) {
		return "", fmt.Errorf("不支持的 DNS 引擎 %q（可选: auto / smartdns / adguard）", flagEngine)
	}
	return norm, nil
}

func newDNSInstallCmd(defaultConfigPath string) *cobra.Command {
	var engineFlag string
	var username string
	var nonInteractive bool
	var forceDownload bool
	var forceLowMemory bool

	cmd := &cobra.Command{
		Use:   "install",
		Short: "按硬件自动选型或指定引擎安装并启用防劫持 DNS / Install and enable anti-hijack DNS",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			target, err := resolveTargetDNSEngine(reg, engineFlag, true)
			if err != nil {
				return err
			}

			// 交互指定 AdGuard 用户名或强制重装已安装二进制时先执行目标引擎 Install
			if target == constant.DNSEngineAdGuard && (forceDownload || username != "" || !nonInteractive) {
				if eng, ok := reg.Get(target); ok {
					if err := eng.Install(cmd.Context(), localdns.InstallOptions{
						Username:       username,
						NonInteractive: nonInteractive,
						ForceDownload:  forceDownload,
						ForceLowMemory: forceLowMemory,
					}); err != nil {
						return err
					}
				}
			} else if target == constant.DNSEngineSmartDNS && forceDownload {
				if eng, ok := reg.Get(target); ok {
					if err := eng.Install(cmd.Context(), localdns.InstallOptions{
						NonInteractive: true,
						ForceDownload:  true,
						ForceLowMemory: forceLowMemory,
						SkipWaitReady:  true,
					}); err != nil {
						return err
					}
				}
			}

			res, err := reg.SwitchEngine(cmd.Context(), localdns.SwitchRequest{
				TargetEngine:   target,
				ForceLowMemory: forceLowMemory,
				NonInteractive: nonInteractive,
			})
			if err != nil {
				return err
			}
			logger.Success("🛡️ 已完成防劫持 DNS 引擎安装与零断网接管: %s", res.ActiveEngine)
			if len(res.MigratedItems) > 0 {
				logger.Info("   • 已同步策略 : %s", strings.Join(res.MigratedItems, "、"))
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&engineFlag, "engine", constant.DNSEngineAuto, "目标 DNS 引擎: auto / smartdns / adguard")
	cmd.Flags().StringVarP(&username, "username", "u", "", "AdGuard Home 管理员账号 (留空交互式询问，直接回车默认 root)")
	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "非交互模式，直接使用配置账号或默认 root")
	cmd.Flags().BoolVarP(&forceDownload, "force", "f", false, "强制重新下载最新引擎二进制")
	cmd.Flags().BoolVar(&forceLowMemory, "force-low-memory", false, "忽略低内存防 OOM 保护护栏强制安装（不可绕过闪存不足护栏）")
	return cmd
}

func newDNSSwitchCmd(defaultConfigPath string) *cobra.Command {
	var engineFlag string
	var forceLowMemory bool

	cmd := &cobra.Command{
		Use:   "switch",
		Short: "零断网两阶段原子切换本地防劫持 DNS 引擎 / Zero-disconnect atomic DNS engine switch",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			res, err := reg.SwitchEngine(cmd.Context(), localdns.SwitchRequest{
				TargetEngine:   engineFlag,
				ForceLowMemory: forceLowMemory,
				NonInteractive: true,
			})
			if err != nil {
				return err
			}
			logger.Success("🛡️ 已零断网切换防劫持 DNS 引擎: configured=%s -> active=%s", res.ConfiguredEngine, res.ActiveEngine)
			if len(res.MigratedItems) > 0 {
				logger.Info("   • 已自动迁移 : %s", strings.Join(res.MigratedItems, "、"))
			}
			for _, w := range res.Warnings {
				logger.Warn("   • 提示 : %s", w)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&engineFlag, "engine", constant.DNSEngineAuto, "目标 DNS 引擎: auto / smartdns / adguard")
	cmd.Flags().BoolVar(&forceLowMemory, "force-low-memory", false, "忽略低内存防 OOM 护栏强制切换（不可绕过闪存不足护栏）")
	return cmd
}

func newDNSStartCmd(defaultConfigPath string) *cobra.Command {
	var engineFlag string
	cmd := &cobra.Command{
		Use:   "start",
		Short: "启动本地防劫持 DNS 引擎并接管 sing-box dns_local / Start local DNS engine",
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
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			target, err := resolveTargetDNSEngine(reg, engineFlag, false)
			if err != nil {
				return err
			}
			eng, ok := reg.Get(target)
			if !ok {
				return fmt.Errorf("未找到 DNS 引擎: %s", target)
			}
			if err := eng.Start(cmd.Context()); err != nil {
				return err
			}
			syncSingBoxLocalDNSLink(cmd.Context(), cfg, true)
			if target == constant.DNSEngineAdGuard {
				mgr := adguard.NewManager(cfg, resolvedPath)
				mgr.PrintAccessSummary(mgr.Status())
			} else {
				logger.Success("🛡️ %s 已启动并完成 sing-box 联动", eng.Meta().Name)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&engineFlag, "engine", "", "指定要启动的 DNS 引擎: auto / smartdns / adguard")
	return cmd
}

func newDNSStopCmd(defaultConfigPath string) *cobra.Command {
	var engineFlag string
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "零断网切回 sing-box 纯 IP 加密 DoH 并停止外部本地 DNS / Safely fallback and stop external DNS",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			target, err := resolveTargetDNSEngine(reg, engineFlag, false)
			if err != nil {
				return err
			}
			cfg.DNS.SetEnabled(false)
			if resolvedPath != "" {
				_ = config.Save(resolvedPath, cfg)
			}
			// 零断网准则：必须先将 sing-box dns_local 切回内置纯 IP 加密 DoH，再停止外部 DNS 进程
			syncSingBoxLocalDNSLink(cmd.Context(), cfg, false)

			if eng, ok := reg.Get(target); ok {
				if err := eng.Stop(cmd.Context()); err != nil {
					return err
				}
				logger.Success("已安全回退 sing-box dns_local 至原生 DNS 并停止 %s（全程零断网）", eng.Meta().Name)
				return nil
			}
			logger.Success("当前已使用 sing-box 内置纯 IP 加密 DoH 兜底")
			return nil
		},
	}
	cmd.Flags().StringVar(&engineFlag, "engine", "", "指定要停用的 DNS 引擎: auto / smartdns / adguard")
	return cmd
}

func newDNSRestartCmd(defaultConfigPath string) *cobra.Command {
	var engineFlag string
	cmd := &cobra.Command{
		Use:     "restart",
		Aliases: []string{"r"},
		Short:   "重启本地防劫持 DNS 服务 / Restart local DNS engine",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			target, err := resolveTargetDNSEngine(reg, engineFlag, false)
			if err != nil {
				return err
			}
			eng, ok := reg.Get(target)
			if !ok {
				return fmt.Errorf("未找到 DNS 引擎: %s", target)
			}
			if err := eng.Restart(cmd.Context()); err != nil {
				return err
			}
			if cfg.DNS.IsEnabled() {
				syncSingBoxLocalDNSLink(cmd.Context(), cfg, true)
			}
			logger.Success("已重启 %s", eng.Meta().Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&engineFlag, "engine", "", "指定要重启的 DNS 引擎: auto / smartdns / adguard")
	return cmd
}

func newDNSStatusCmd(defaultConfigPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "status",
		Aliases: []string{"s"},
		Short:   "查看双引擎防劫持 DNS 状态、硬件推荐与面板凭据 / Show local DNS status",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			resolvedPath := resolveCmdConfigPath(cmd, defaultConfigPath)
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			ov := reg.Overview(cmd.Context())
			linked, linkedPort := singbox.InspectSingBoxDNSLocal("")

			logger.Info("═══════════════════════════════════════════════════════════")
			logger.Success("           🛡️  双引擎防劫持 DNS 状态面板")
			logger.Info("═══════════════════════════════════════════════════════════")
			logger.Info("配置偏好        : %s", ov.ConfiguredEngine)
			logger.Success("当前活跃引擎    : %s (%s)", ov.ActiveEngineLabel, ov.ActiveEngine)
			logger.Info("硬件推荐引擎    : %s — %s", ov.RecommendedEngine, ov.RecommendedReason)
			if ov.Version != "" {
				logger.Info("核心版本        : %s", ov.Version)
			}
			if ov.DNSHealthy {
				logger.Success("DNS 引擎状态    : 运行正常 (%s) ✓", ov.DNSAddr)
			} else if ov.Running {
				logger.Warn("DNS 引擎状态    : 进程运行中但 %s 未响应 ✗", ov.DNSAddr)
			} else if !ov.Installed {
				logger.Warn("DNS 引擎状态    : 未安装 ✗")
			} else {
				logger.Warn("DNS 引擎状态    : 未运行 ✗")
			}

			if linked {
				logger.Success("sing-box 联动   : 已接管 dns_local (127.0.0.1:%d) ✓", linkedPort)
			} else {
				logger.Info("sing-box 联动   : sing-box 内置纯 IP 加密 DoH 兜底防劫持中 ✓")
			}

			logger.Info("───────────────────────────────────────────────────────────")
			for _, opt := range ov.Engines {
				mark := "  "
				if opt.Active {
					mark = "▶ "
				}
				state := "未安装"
				if opt.Installed {
					state = "已安装"
				}
				if opt.Recommended {
					state += " · 硬件推荐"
				}
				if !opt.Eligible && opt.BlockedReason != "" {
					state += " · 受限(" + opt.BlockedReason + ")"
				}
				logger.Info("%s%-14s [%s | %s / %s]", mark, opt.Name, state, opt.DiskHint, opt.RAMHint)
			}

			if ov.ActiveEngine == constant.DNSEngineAdGuard {
				logger.Info("───────────────────────────────────────────────────────────")
				if ov.WebHealthy {
					logger.Success("Web 管理面板    : %s (仅限局域网访问) ✓", ov.WebURL)
				} else {
					logger.Warn("Web 管理面板    : %s (未监听) ✗", ov.WebURL)
				}
				logger.Info("管理员账号      : %s", ov.Username)
				if cfg.DNS.GetPassword() != "" {
					logger.Info("管理员密码      : %s", cfg.DNS.GetPassword())
				}
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
	var engineFlag string
	var purge bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "零断网切回 sing-box 纯 IP 加密 DoH 并卸载外部本地 DNS / Safely fallback and uninstall external DNS",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, resolvedPath, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				cfg = loadCmdConfigOrDefault(cmd, defaultConfigPath)
				resolvedPath = resolveCmdConfigPath(cmd, defaultConfigPath)
			}
			reg := newLocalDNSRegistry(cfg, resolvedPath)
			target, err := resolveTargetDNSEngine(reg, engineFlag, false)
			if err != nil {
				return err
			}

			// 卸载前先将运行中的 sing-box 平滑切回纯 IP 加密 DoH，防止卸载瞬间断网
			syncSingBoxLocalDNSLink(cmd.Context(), cfg, false)

			eng, ok := reg.Get(target)
			if !ok {
				return fmt.Errorf("未找到 DNS 引擎: %s", target)
			}
			if err := eng.Uninstall(cmd.Context(), purge); err != nil {
				return err
			}
			if cfg.DNS.GetEngine() == target {
				cfg.DNS.SetEngine(constant.DNSEngineAuto)
				if resolvedPath != "" {
					_ = config.Save(resolvedPath, cfg)
				}
			}
			logger.Success("已安全回退 sing-box 纯 IP 加密 DoH 并完成 %s 卸载（全程零断网）", eng.Meta().Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&engineFlag, "engine", "", "指定要卸载的外部 DNS 引擎: smartdns / adguard")
	cmd.Flags().BoolVar(&purge, "purge", false, "同时清理配置与数据目录")
	return cmd
}
