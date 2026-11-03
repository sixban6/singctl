package cmd

import (
	"fmt"
	"os"
	"strings"

	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/deploy"
	"singctl/internal/deploy/masksite"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/serverweb"

	"github.com/spf13/cobra"
)

func newInstallServerCmd(configPath, version string) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "install",
		Short: "安装服务端组件 / Install server components (common|caddy|singbox|substore)",
		RunE: func(cmd *cobra.Command, args []string) error {

			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil || cfg == nil {
				return fmt.Errorf("加载配置文件失败: %w", err)
			}

			// Verify required config
			if cfg.Server.GetNodeDomain() == "" || cfg.Server.CFDNSKey == "" {
				return fmt.Errorf("server.node_domain (or sb_domain) and server.cf_dns_key are required in singctl.yaml")
			}

			// If no target is specified, run them all in sequence
			if len(args) == 0 {
				// 自动初始化服务端 WebUI 凭据与随机路径并保存，供 Caddyfile 渲染
				if cfg.Server.EnsureWebAdminCredentials() {
					_ = config.Save(resolvedPath, cfg)
				}

				if _, err := deploy.RunPreflight(cfg, true); err != nil {
					logger.Warn("预检发现警告: %v", err)
				}
				if err := deploy.DeployCommonWithConfig(cfg); err != nil {
					return err
				}
				if err := deploy.DeployWarp(); err != nil {
					return err
				}
				if err := deploy.DeployCaddy(cfg); err != nil {
					return err
				}
				sbs, err := deploy.NewSingBoxServer(cfg)
				if err != nil {
					return err
				}
				_ = sbs.LoadExistingCredentials()
				if err := sbs.DeploySingbox(); err != nil {
					return err
				}

				sbt := deploy.NewSubstore(cfg, "")
				sbt.ConfigPath = resolvedPath
				if err := sbt.DeploySubstore(); err != nil {
					return err
				}

				if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
					logger.Warn("Substore config update failed!")
					return err
				}

				// 后台启动服务端 WebUI (仅监听本地 127.0.0.1，通过 Caddy HTTPS 自动反向代理)
				if err := serverweb.InstallSystemdService(resolvedPath); err != nil {
					_ = serverweb.StartBackground(serverweb.Options{
						ConfigPath: resolvedPath,
						Listen:     fmt.Sprintf("127.0.0.1:%d", cfg.Server.GetWebAdminPort()),
						Username:   cfg.Server.GetWebAdminUsername(),
						Password:   cfg.Server.GetWebAdminPassword(),
						Version:    version,
					})
				}
				showUnifiedInstallSummary(cfg, sbs, sbt)
				return nil
			}

			// Handle specified targets
			switch args[0] {
			case "common":
				return deploy.DeployCommonWithConfig(cfg)
			case "caddy":
				return deploy.DeployCaddy(cfg)
			case "singbox":
				sbs, err := deploy.NewSingBoxServer(cfg)
				if err != nil {
					return err
				}
				_ = sbs.LoadExistingCredentials()
				if err := sbs.DeploySingbox(); err != nil {
					return err
				}
				// If Sub-Store is installed, keep its subscriptions in sync
				if _, err := os.Stat("/etc/sub-store"); err == nil {
					sbt := deploy.NewSubstore(cfg, "")
					if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
						logger.Warn("Sub-Store config sync failed (non-fatal): %v", err)
					}
				}
				return nil
			case "substore", "sub", "subhub":
				sbt := deploy.NewSubstore(cfg, "")
				sbt.ConfigPath = resolvedPath
				return sbt.DeploySubstore()
			case "warp":
				return deploy.DeployWarp()
			default:
				return fmt.Errorf("unknown target: %s (must be common, caddy, singbox, substore, or warp)", args[0])
			}
		},
	}

	return cmd
}

func newUninstallServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "卸载服务端组件 / Uninstall server components (caddy|singbox|substore|warp)",
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) == 0 {
				logger.Info("Uninstalling all server components...")
				_ = serverweb.UninstallSystemdService()
				_, _ = serverweb.StopServerWeb()

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
			case "substore", "sub", "subhub":
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
	return cmd
}

func NewServerCmd(configPath string, version ...string) *cobra.Command {
	ver := "dev"
	if len(version) > 0 && strings.TrimSpace(version[0]) != "" {
		ver = strings.TrimSpace(version[0])
	}
	cmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"sr"}, // 添加快捷命令 singctl sr
		Short:   "服务端: singbox服务端部署命令(简写singctl sr)",
	}

	cmd.AddCommand(newInitServerCmd(configPath))
	cmd.AddCommand(newPreflightServerCmd(configPath))
	cmd.AddCommand(newInstallServerCmd(configPath, ver))
	cmd.AddCommand(NewReinstallServerCmd(configPath))
	cmd.AddCommand(newUninstallServerCmd())
	cmd.AddCommand(newSniCmd(configPath))
	cmd.AddCommand(NewCfTokenCmd(configPath))
	cmd.AddCommand(newResetServerCmd(configPath))
	cmd.AddCommand(NewSyncServerCmd(configPath))
	cmd.AddCommand(NewInfoServerCmd(configPath))
	cmd.AddCommand(NewTerminalCmd(configPath))
	cmd.AddCommand(newServerWebCmd(configPath, ver))
	cmd.AddCommand(newServerSubCmd(configPath, ver))
	cmd.AddCommand(NewNetCmd(configPath))
	cmd.AddCommand(newServerDoctorCmd(configPath))
	cmd.AddCommand(newMaskSiteCmd(configPath))
	cmd.AddCommand(newServerUpdateCmd(configPath))
	cmd.AddCommand(newServerCheckCmd(configPath))
	return cmd
}

func newServerCheckCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "check-update [component]",
		Aliases: []string{"checkver", "cu"},
		Short:   "检查核心组件远端是否有新版本 / Check latest remote versions (singbox|caddy|substore|warp)",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "singbox"
			if len(args) > 0 {
				target = args[0]
			}
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("无法加载配置文件: %w", err)
			}

			res, err := deploy.CheckComponentUpdate(target, cfg)
			if err != nil {
				return err
			}
			if res.HasUpdate {
				logger.Warn("[%s] 发现新版本: v%s (当前本地: v%s)，可运行 'singctl sr update %s' 进行升级", res.DisplayName, res.LatestVersion, res.CurrentVersion, res.Component)
			} else {
				logger.Success("[%s] %s", res.DisplayName, res.Message)
			}
			return nil
		},
	}
}

func newServerUpdateCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "update [component]",
		Aliases: []string{"upgrade", "up"},
		Short:   "平滑升级服务端核心组件 / Smooth upgrade server components (singbox|caddy|substore|warp|all)",
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "all"
			if len(args) > 0 {
				target = args[0]
			}
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("无法加载配置文件: %w", err)
			}

			logger.Info("开始执行核心组件平滑升级: %s ...", target)
			results, err := deploy.UpgradeComponent(target, cfg)
			if err != nil {
				return err
			}

			for _, r := range results {
				if r.OldVersion != "" && r.OldVersion != r.NewVersion {
					logger.Success("[%s] 已成功从 %s 升级至 %s", r.DisplayName, r.OldVersion, r.NewVersion)
				} else {
					logger.Success("[%s] %s", r.DisplayName, r.Message)
				}
			}
			return nil
		},
	}
}

func newMaskSiteCmd(configPath string) *cobra.Command {
	var regen bool
	cmd := &cobra.Command{
		Use:     "mask-site",
		Aliases: []string{"mask", "camouflage"},
		Short:   "管理或重新生成 Caddy 伪装回落博客 / Manage or regenerate camouflage mask blog",
		RunE: func(cmd *cobra.Command, args []string) error {
			if regen || (len(args) > 0 && args[0] == "regen") {
				meta, err := deploy.RegenerateMaskSite()
				if err != nil {
					return err
				}
				logger.Success("Camouflage site regenerated successfully:")
				logger.Info("  Title:    %s", meta.BlogTitle)
				logger.Info("  Author:   %s (%s)", meta.AuthorName, meta.AuthorRole)
				logger.Info("  Category: %s", meta.Category)
				logger.Info("  Articles: %d posts generated", meta.ArticleCount)
				return nil
			}

			metaJson := masksite.ReadExistingMeta(constant.MaskSiteDir)
			if metaJson != "" {
				logger.Info("Current camouflage site metadata:\n%s", metaJson)
			} else {
				logger.Info("Camouflage site directory: %s", constant.MaskSiteDir)
			}
			logger.Info("To regenerate a brand new randomized persona and articles, run: singctl sr mask-site --regen")
			return nil
		},
	}
	cmd.Flags().BoolVarP(&regen, "regen", "r", false, "随机重新生成高熵伪装站点 (Randomly regenerate high-entropy camouflage blog)")
	return cmd
}

func newServerDoctorCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "doctor",
		Aliases: []string{"doc", "check"},
		Short:   "全链路健康体检与故障自检 / Full-stack health check and diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("无法加载配置文件: %w", err)
			}
			report := doctor.RunServerDoctor(cfg)
			doctor.PrintDoctorReport(report)
			return nil
		},
	}
}

// NewReinstallServerCmd creates the reinstall command (singctl sr ri)
func NewReinstallServerCmd(configPath string) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "reinstall [target]",
		Aliases: []string{"ri"},
		Short:   "重装服务端组件(简写singctl sr ri) / Reinstall server components (all|common|caddy|singbox|substore|warp)",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			target := "all"
			if len(args) > 0 {
				target = args[0]
			}

			switch target {
			case "all":
				return handleReinstallAll(cfg, force)
			case "common":
				return deploy.DeployCommonWithConfig(cfg)
			case "caddy":
				return handleReinstallCaddy(cfg, force)
			case "singbox":
				return handleReinstallSingbox(cfg, force)
			case "substore", "sub", "subhub":
				return handleReinstallSubstore(cfg, resolvedPath, force)
			case "warp":
				return handleReinstallWarp(cfg, force)
			default:
				return fmt.Errorf("unknown target: %s (must be all, common, caddy, singbox, substore, or warp)", target)
			}
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "强制重装，跳过版本检查 / Force reinstall without checking latest versions")
	return cmd
}

func handleReinstallAll(cfg *config.Config, force bool) error {
	// Verify required config
	if cfg.Server.GetNodeDomain() == "" || cfg.Server.CFDNSKey == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) and server.cf_dns_key are required in singctl.yaml")
	}

	if force {
		logger.Info("强制重装所有服务端组件 (-f)...")
		return reinstallAll(cfg)
	}

	logger.Info("正在检查服务端各组件最新版本...")
	results, err := deploy.CheckAllComponentVersions(cfg)
	if err != nil {
		logger.Warn("检查部分组件版本时发生错误: %v", err)
	}

	var hasAnyUpdate bool
	for _, info := range results {
		if info.HasUpdate {
			hasAnyUpdate = true
			logger.Info("📦 [%s]: 当前 %s -> 最新 %s (有新版本)", info.DisplayName, info.CurrentVersion, info.LatestVersion)
		} else {
			logger.Info("✅ [%s]: 当前 %s (已是最新)", info.DisplayName, info.CurrentVersion)
		}
	}

	if !hasAnyUpdate {
		logger.Success("所有服务端组件均已是最新版本，无需重装。使用 -f 参数可强制重装。")
		return nil
	}

	logger.Info("检测到有组件需要更新，开始重装对应组件...")

	var singboxReinstalled bool
	var lastSBS *deploy.SingBoxServer

	for _, info := range results {
		if !info.HasUpdate {
			continue
		}
		switch info.Name {
		case "warp":
			logger.Info("正在重装 WARP (wireproxy)...")
			if err := deploy.UninstallWarp(); err != nil {
				logger.Warn("Failed to uninstall WARP: %v", err)
			}
			if err := deploy.DeployWarp(); err != nil {
				return err
			}
		case "caddy":
			logger.Info("正在重装 Caddy...")
			if err := deploy.UninstallCaddy(); err != nil {
				logger.Warn("Failed to uninstall Caddy: %v", err)
			}
			if err := deploy.DeployCaddy(cfg); err != nil {
				return err
			}
		case "singbox":
			logger.Info("正在重装 sing-box...")
			if err := deploy.UninstallSingbox(); err != nil {
				logger.Warn("Failed to uninstall sing-box: %v", err)
			}
			sbs, err := deploy.NewSingBoxServer(cfg)
			if err != nil {
				return err
			}
			if err := sbs.DeploySingbox(); err != nil {
				return err
			}
			singboxReinstalled = true
			lastSBS = sbs
		case "substore":
			logger.Info("正在升级/重装原生 SubHub 订阅引擎 (保留现有订阅配置与密钥)...")
			sbt := deploy.NewSubstore(cfg, "")
			if err := sbt.DeploySubstore(); err != nil {
				return err
			}
			if lastSBS == nil {
				sbs, err := deploy.NewSingBoxServer(cfg)
				if err == nil {
					_ = sbs.LoadExistingCredentials()
					lastSBS = sbs
				}
			}
			if lastSBS != nil {
				if err := sbt.UpdateSubstoreConfig(lastSBS); err != nil {
					logger.Warn("SubHub config sync warning: %v", err)
				}
			}
		}
	}

	if singboxReinstalled && lastSBS != nil {
		sbt := deploy.NewSubstore(cfg, "")
		_ = sbt.UpdateSubstoreConfig(lastSBS)
		lastSBS.ShowLoginInfo()
	}

	logger.Success("组件更新/重装完成。")
	return nil
}

func handleReinstallCaddy(cfg *config.Config, force bool) error {
	if !force {
		logger.Info("正在检查 Caddy 最新版本...")
		info, err := deploy.CheckCaddyVersion(cfg)
		if err != nil {
			logger.Warn("无法获取 Caddy 远端最新版本 (%v)，如需强制重装请添加 -f 参数", err)
		} else if !info.HasUpdate {
			logger.Success("Caddy 已是最新版本 (%s)，无需重装。使用 -f 参数可强制重装。", info.CurrentVersion)
			return nil
		} else {
			logger.Info("Caddy 发现新版本: 当前 %s -> 最新 %s，开始重装...", info.CurrentVersion, info.LatestVersion)
		}
	}

	logger.Info("Reinstalling Caddy...")
	if err := deploy.UninstallCaddy(); err != nil {
		logger.Warn("Failed to uninstall Caddy: %v", err)
	}
	return deploy.DeployCaddy(cfg)
}

func handleReinstallSingbox(cfg *config.Config, force bool) error {
	if !force {
		logger.Info("正在检查 sing-box 最新版本...")
		info, err := deploy.CheckSingBoxVersion(cfg)
		if err != nil {
			logger.Warn("无法获取 sing-box 远端最新版本 (%v)，如需强制重装请添加 -f 参数", err)
		} else if !info.HasUpdate {
			logger.Success("sing-box 已是最新版本 (%s)，无需重装。使用 -f 参数可强制重装。", info.CurrentVersion)
			return nil
		} else {
			logger.Info("sing-box 发现新版本: 当前 %s -> 最新 %s，开始重装...", info.CurrentVersion, info.LatestVersion)
		}
	}

	logger.Info("Reinstalling sing-box...")
	if err := deploy.UninstallSingbox(); err != nil {
		logger.Warn("Failed to uninstall sing-box: %v", err)
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return err
	}
	_ = sbs.LoadExistingCredentials()
	if err := sbs.DeploySingbox(); err != nil {
		return err
	}
	if _, err := os.Stat("/etc/sub-store"); err == nil {
		sbt := deploy.NewSubstore(cfg, "")
		if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
			logger.Warn("Sub-Store config sync failed (non-fatal): %v", err)
		}
	}
	return nil
}

func handleReinstallSubstore(cfg *config.Config, configPath string, force bool) error {
	if !force {
		logger.Info("正在检查 SubHub 订阅引擎版本...")
		info, err := deploy.CheckSubstoreVersion(cfg)
		if err != nil {
			logger.Warn("无法获取远端版本 (%v)，如需强制重装请添加 -f 参数", err)
		} else if !info.HasUpdate {
			logger.Success("SubHub 已是最新版本 (%s)，无需重装。使用 -f 参数可强制重装。", info.CurrentVersion)
			return nil
		} else {
			logger.Info("SubHub 发现新版本或待迁移容器: 当前 %s -> 最新 %s，开始部署...", info.CurrentVersion, info.LatestVersion)
		}
	}

	logger.Info("Redeploying native SubHub subscription engine (preserving /etc/sub-store data)...")
	sbt := deploy.NewSubstore(cfg, "")
	sbt.ConfigPath = configPath
	return sbt.DeploySubstore()
}

func handleReinstallWarp(cfg *config.Config, force bool) error {
	if !force {
		logger.Info("正在检查 WARP (wireproxy) 最新版本...")
		info, err := deploy.CheckWarpVersion(cfg)
		if err != nil {
			logger.Warn("无法获取 WARP (wireproxy) 远端最新版本 (%v)，如需强制重装请添加 -f 参数", err)
		} else if !info.HasUpdate {
			logger.Success("WARP (wireproxy) 已是最新版本 (%s)，无需重装。使用 -f 参数可强制重装。", info.CurrentVersion)
			return nil
		} else {
			logger.Info("WARP (wireproxy) 发现新版本: 当前 %s -> 最新 %s，开始重装...", info.CurrentVersion, info.LatestVersion)
		}
	}

	logger.Info("Reinstalling WARP...")
	if err := deploy.UninstallWarp(); err != nil {
		logger.Warn("Failed to uninstall WARP: %v", err)
	}
	return deploy.DeployWarp()
}

func reinstallAll(cfg *config.Config) error {
	// Verify required config
	if cfg.Server.GetNodeDomain() == "" || cfg.Server.CFDNSKey == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) and server.cf_dns_key are required in singctl.yaml")
	}

	logger.Info("Reinstalling all server components...")

	// 1. Uninstall existing components
	logger.Info("Step 1/2: Uninstalling existing server components...")
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

	// 2. Install all components fresh
	logger.Info("Step 2/2: Installing all server components fresh...")
	if err := deploy.DeployCommonWithConfig(cfg); err != nil {
		return err
	}
	if err := deploy.DeployWarp(); err != nil {
		return err
	}
	if err := deploy.DeployCaddy(cfg); err != nil {
		return err
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return err
	}
	if err := sbs.DeploySingbox(); err != nil {
		return err
	}

	sbt := deploy.NewSubstore(cfg, "")
	if err := sbt.DeploySubstore(); err != nil {
		return err
	}

	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		logger.Warn("Substore config update failed!")
		return err
	}

	showUnifiedServerPanel(cfg, sbs, sbt, "🎉 SingCtl 服务端全组件重装部署成功！")
	return nil
}

// NewCfTokenCmd creates the cf-token command for rotating Cloudflare API token
func NewCfTokenCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "cf-token <token>",
		Aliases: []string{"cf", "token", "cftoken"},
		Short:   "轮换 Cloudflare API Token 并重启 Caddy / Rotate Cloudflare API token and restart Caddy",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newToken := strings.TrimSpace(args[0])
			if newToken == "" {
				return fmt.Errorf("cloudflare api token cannot be empty")
			}

			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			cfg.Server.CFDNSKey = newToken
			if err := config.Save(resolvedPath, cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			logger.Info("Cloudflare API token updated in config (%s)", resolvedPath)

			if err := deploy.RotateCloudflareToken(cfg); err != nil {
				return fmt.Errorf("failed to rotate cloudflare token: %w", err)
			}

			logger.Success("Cloudflare API token rotated successfully to: %s", newToken)
			return nil
		},
	}
}

func newResetServerCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "reset [target]",
		Short: "重置服务端凭证并更新订阅 / Reset server credentials and update Sub-Store (sb|singbox)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "sb"
			if len(args) > 0 {
				target = args[0]
			}

			switch target {
			case "sb", "singbox":
				resolvedPath := resolveConfigPath(cmd, configPath)
				return resetSingboxCredentials(resolvedPath)
			default:
				return fmt.Errorf("unknown target: %s (must be sb or singbox)", target)
			}
		},
	}
}

func resolveConfigPath(cmd *cobra.Command, fallback string) string {
	if f := cmd.Flag("config"); f != nil && f.Value.String() != "" {
		return f.Value.String()
	}
	if f := cmd.InheritedFlags().Lookup("config"); f != nil && f.Value.String() != "" {
		return f.Value.String()
	}
	return fallback
}

func resetSingboxCredentials(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Server.GetNodeDomain() == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) is required in config (%s)", configPath)
	}

	logger.Info("Resetting sing-box server credentials for domain: %s...", cfg.Server.GetNodeDomain())

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box server: %w", err)
	}

	if err := sbs.ResetCredentials(); err != nil {
		return fmt.Errorf("failed to reset sing-box credentials: %w", err)
	}

	sbt := deploy.NewSubstore(cfg, "")
	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		logger.Warn("Substore config update failed: %v", err)
		return fmt.Errorf("failed to update substore config: %w", err)
	}

	logger.Success("Sing-box credentials reset and Sub-Store subscriptions updated successfully.")
	return nil
}

func newSniCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "sni <domain>",
		Short: "更新 Reality SNI 域名 / Update Reality SNI domain and reload services",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newSni := args[0]

			resolvedPath := resolveConfigPath(cmd, configPath)
			cfg, err := config.Load(resolvedPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			cfg.Server.Sni = newSni
			if err := config.Save(resolvedPath, cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			logger.Info("SNI updated to %s in config", newSni)

			if err := deploy.DeployCaddy(cfg); err != nil {
				return fmt.Errorf("caddy update failed: %w", err)
			}

			sbs, err := deploy.NewSingBoxServer(cfg)
			if err != nil {
				return err
			}
			if err := sbs.LoadExistingCredentials(); err != nil {
				logger.Warn("Could not load existing credentials, new ones will be generated: %v", err)
			}
			if err := sbs.DeploySingbox(); err != nil {
				return fmt.Errorf("sing-box update failed: %w", err)
			}

			sbt := deploy.NewSubstore(cfg, "")
			if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
				logger.Warn("Substore config update failed (non-fatal): %v", err)
			}

			logger.Success("SNI updated successfully to: %s", newSni)
			return nil
		},
	}
}

// NewSyncServerCmd creates the command to sync latest node credentials from sing-box to Sub-Store.
func NewSyncServerCmd(configPath string) *cobra.Command {
	var restart bool
	var tag string

	cmd := &cobra.Command{
		Use:     "sync [target]",
		Aliases: []string{"ss", "sync-substore"},
		Short:   "同步最新节点信息到Sub-Store / Sync latest node info to Sub-Store (substore)",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "substore"
			if len(args) > 0 {
				target = args[0]
			}

			switch target {
			case "substore", "sub-store", "sb", "singbox":
				resolvedPath := resolveConfigPath(cmd, configPath)
				return syncNodeToSubstore(resolvedPath, restart, tag)
			default:
				return fmt.Errorf("unknown target: %s (must be substore, sub-store, sb, or singbox)", target)
			}
		},
	}

	cmd.Flags().BoolVarP(&restart, "restart", "r", true, "同步后自动重启 Sub-Store 容器保证数据最新 / Restart Sub-Store container after sync to ensure data is updated")
	cmd.Flags().StringVarP(&tag, "tag", "t", "", "节点名称/地区代号 (例如: los, sg)，若指定则同步更新并持久化到配置文件")
	return cmd
}

func syncNodeToSubstore(configPath string, restart bool, tag string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if tag != "" {
		cfg.Server.NodeTag = tag
		// If tag explicitly provided via CLI, update the config file atomically
		if curData, rErr := os.ReadFile(configPath); rErr == nil {
			_ = config.MigrateConfig(configPath, curData)
		}
	}

	if cfg.Server.GetNodeDomain() == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) is required in config (%s)", configPath)
	}

	logger.Info("正在从本地 sing-box 配置文件读取实际节点凭证与参数...")

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box server: %w", err)
	}

	if err := sbs.LoadExistingCredentials(); err != nil {
		return fmt.Errorf("failed to load existing sing-box credentials: %w", err)
	}

	sbt := deploy.NewSubstore(cfg, "")
	sbt.SkipRestart = !restart
	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		return fmt.Errorf("failed to update substore config: %w", err)
	}

	logger.Success("最新节点信息已成功同步至 Sub-Store！")
	fmt.Println("\n========================================================")
	fmt.Println("📡 已同步至 Sub-Store 的节点配置:")
	fmt.Printf("• Hysteria 2:    %s\n", sbs.ShareLinkHy2)
	fmt.Printf("• VLESS Reality: %s\n", sbs.ShareLinkVless)
	fmt.Println("========================================================")
	return nil
}

// NewInfoServerCmd creates the command to display server configuration, web admin panel, and node share links.
func NewInfoServerCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "info",
		Aliases: []string{"show", "status-info", "i"},
		Short:   "查看服务端核心配置、专属管理面板与节点订阅信息 / View server status, web admin panel and subscription info",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolvedPath := resolveConfigPath(cmd, configPath)
			return showServerInfo(resolvedPath)
		},
	}
}

func showServerInfo(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Server.GetNodeDomain() == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) is required in config (%s)", configPath)
	}

	// 确保后台管理凭证完备 (兼容升级场景)
	if cfg.Server.EnsureWebAdminCredentials() {
		_ = config.Save(configPath, cfg)
	}

	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize sing-box server: %w", err)
	}

	if err := sbs.LoadExistingCredentials(); err != nil {
		logger.Warn("未能从现有 sing-box 配置文件加载凭证: %v", err)
	}

	sbt := deploy.NewSubstore(cfg, "")
	showUnifiedServerPanel(cfg, sbs, sbt, "📌 SingCtl 服务端核心配置与连接信息")
	return nil
}

func showUnifiedInstallSummary(cfg *config.Config, sbs *deploy.SingBoxServer, sbt *deploy.Substore) {
	showUnifiedServerPanel(cfg, sbs, sbt, "🎉 SingCtl 服务端全组件部署成功！")
}

func showUnifiedServerPanel(cfg *config.Config, sbs *deploy.SingBoxServer, sbt *deploy.Substore, title string) {
	domain := cfg.Server.GetSubstoreDomain()
	if domain == "" {
		domain = cfg.Server.GetNodeDomain()
	}
	adminPath := cfg.Server.GetWebAdminPath()
	adminURL := ""
	if domain != "" && adminPath != "" {
		adminURL = fmt.Sprintf("https://%s%s/", domain, adminPath)
	}

	subURL := ""
	if sbt != nil {
		subURL = sbt.GetSubscriptionURL()
	} else if domain != "" {
		subURL = fmt.Sprintf("https://%s/api/substore/download/singctl", domain)
	}

	// 动态检测各核心服务版本
	versions := deploy.GetCoreServiceVersions()
	caddyVer := versions["caddy"]
	if caddyVer != "" {
		caddyVer = "v" + caddyVer
	} else {
		caddyVer = "已就绪"
	}

	sbVer := versions["singbox"]
	if sbVer != "" {
		sbVer = "v" + sbVer
	} else {
		sbVer = "已就绪"
	}

	ssVer := versions["substore"]
	if ssVer != "" {
		ssVer = "v" + ssVer
	} else {
		ssVer = "已就绪"
	}

	warpVer := versions["warp"]
	if warpVer != "" {
		warpVer = "v" + warpVer
	} else {
		warpVer = "已就绪"
	}

	fmt.Println("\n══════════════════════════════════════════════════════════════════════════")
	fmt.Printf("                     %s\n", title)
	fmt.Println("══════════════════════════════════════════════════════════════════════════")
	fmt.Printf(" [✓] Caddy %-11s : TLS 证书申请成功，443 端口反代已就绪\n", caddyVer)
	fmt.Printf(" [✓] sing-box %-9s: VLESS Reality & Hysteria 2 双协议已启动\n", sbVer)
	fmt.Printf(" [✓] SubHub %-10s : Go 原生多协议订阅聚合转换已就绪 (端口 3001)\n", ssVer)
	fmt.Printf(" [✓] WARP 出口 %-8s: 本地分流出口已就绪 (端口 40000)\n", warpVer)
	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 🌐 专属管理控制台 (核心 Web 后台入口):")
	if adminURL != "" {
		fmt.Printf("   • 访问链接 : %s\n", adminURL)
	} else {
		fmt.Println("   • 访问链接 : [未配置后台路径]")
	}
	fmt.Printf("   • 管理账号 : %s\n", cfg.Server.GetWebAdminUsername())
	if config.IsHashedPassword(cfg.Server.GetWebAdminPassword()) {
		fmt.Println("   • 登录密码 : [已加密保护] (已确认保存并完成 bcrypt 单向加密，可在后台修改)")
	} else {
		fmt.Printf("   • 登录密码 : %s (登录后台后可随时修改)\n", cfg.Server.GetWebAdminPassword())
		fmt.Println("   • 请立即把密码写入密码管理器。终端滚动记录和截图都会留下这行。")
	}
	fmt.Println("   • 安全机制 : 纯会话 Cookie 认证，公网端口严密关闭，防爆破 3次错封IP 保护")
	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 📦 客户端全平台聚合订阅:")
	if subURL != "" {
		fmt.Printf("   • 订阅地址 : %s\n", subURL)
	} else {
		fmt.Printf("   • 订阅地址 : https://%s/api/substore/download/singctl\n", domain)
	}
	fmt.Println("   • 快速导入 : 登录上述管理控制台，可一键唤醒导入 Shadowrocket、")
	fmt.Println("                Clash Verge、Sing-box，或在网页端直接扫码导入。")

	if sbs != nil && (sbs.ShareLinkHy2 != "" || sbs.ShareLinkVless != "") {
		fmt.Println("──────────────────────────────────────────────────────────────────────────")
		fmt.Println(" 📡 服务端节点直连分享链接 (Node Share Links):")
		if sbs.ShareLinkHy2 != "" {
			fmt.Printf("   • Hysteria 2    : %s\n", sbs.ShareLinkHy2)
		}
		if sbs.ShareLinkVless != "" {
			fmt.Printf("   • VLESS Reality : %s\n", sbs.ShareLinkVless)
		}
	}

	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 🛡️ 伪装回落与辅助入口 (Mask Site & Fallback):")
	if serverIP := cfg.Server.GetServerIP(); serverIP != "" {
		fmt.Printf("   • 公网 IP 直连  : https://%s (Let's Encrypt 原生免费公网 IP 证书)\n", deploy.FormatIPForCaddy(serverIP))
	}
	if nodeDomain := cfg.Server.GetNodeDomain(); nodeDomain != "" {
		fmt.Printf("   • 节点域名伪装  : https://%s\n", nodeDomain)
	}
	if cfg.Server.WebTerminal.Enabled && cfg.Server.WebTerminal.Path != "" {
		terminalDomain := cfg.Server.GetNodeDomain()
		if terminalDomain == "" {
			terminalDomain = cfg.Server.GetSubstoreDomain()
		}
		if terminalDomain != "" {
			fmt.Printf("   • Web 运维终端   : https://%s%s/ (mTLS 双向认证保护)\n", terminalDomain, cfg.Server.WebTerminal.Path)
		}
	}

	fmt.Println("──────────────────────────────────────────────────────────────────────────")
	fmt.Println(" 💡 核心运维常用命令:")
	fmt.Println("   • 全链路健康体检   : singctl doctor")
	fmt.Println("   • 查看控制台访问信息: singctl sr info")
	fmt.Println("   • 检查组件远端升级 : singctl sr check-update [singbox|caddy|substore|warp]")
	fmt.Println("   • 一键平滑升级组件 : singctl sr update [component|all]")
	fmt.Println("   • 一键解封受限 IP  : singctl sr web unban [IP|all]")
	fmt.Println("   • 动态修改伪装域名 : singctl sr sni <新域名>")
	fmt.Println("══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
}
