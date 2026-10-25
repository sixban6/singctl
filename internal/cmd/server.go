package cmd

import (
	"fmt"
	"strings"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

func newInstallServerCmd(cfg *config.Config) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "install",
		Short: "安装服务端组件 / Install server components (common|caddy|singbox|substore)",
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

				sbs.ShowLoginInfo()
				sbt.ShowLoginInfo()
				return nil
			}

			sbs, err := deploy.NewSingBoxServer(cfg)
			if err != nil {
				return err
			}
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

	return cmd
}

func newUninstallServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "卸载服务端组件 / Uninstall server components (caddy|singbox|substore|warp)",
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
	return cmd
}

func NewServerCmd(configPath string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "server",
		Aliases: []string{"sr"}, // 添加快捷命令 singctl sr
		Short:   "服务端: singbox服务端部署命令(简写singctl sr)",
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Warn("Failed to load config: %v", err)
	}

	cmd.AddCommand(newInstallServerCmd(cfg))
	cmd.AddCommand(NewReinstallServerCmd(configPath))
	cmd.AddCommand(newUninstallServerCmd())
	cmd.AddCommand(newSniCmd(configPath))
	cmd.AddCommand(NewCfTokenCmd(configPath))
	cmd.AddCommand(newResetServerCmd(configPath))
	cmd.AddCommand(NewSyncServerCmd(configPath))
	return cmd
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
				return deploy.DeployCommon()
			case "caddy":
				return handleReinstallCaddy(cfg, force)
			case "singbox":
				return handleReinstallSingbox(cfg, force)
			case "substore":
				return handleReinstallSubstore(cfg, force)
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
	if cfg.Server.SBDomain == "" || cfg.Server.CFDNSKey == "" {
		return fmt.Errorf("server.sb_domain and server.cf_dns_key are required in singctl.yaml")
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
			logger.Info("正在重装 Sub-Store...")
			if err := deploy.UninstallSubstore(); err != nil {
				logger.Warn("Failed to uninstall Sub-Store: %v", err)
			}
			sbt := deploy.NewSubstore(cfg, "")
			if err := sbt.DeploySubstore(); err != nil {
				return err
			}
			if lastSBS == nil {
				sbs, err := deploy.NewSingBoxServer(cfg)
				if err == nil {
					lastSBS = sbs
				}
			}
			if lastSBS != nil {
				if err := sbt.UpdateSubstoreConfig(lastSBS); err != nil {
					logger.Warn("Substore config update failed: %v", err)
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
	return sbs.DeploySingbox()
}

func handleReinstallSubstore(cfg *config.Config, force bool) error {
	if !force {
		logger.Info("正在检查 Sub-Store 镜像版本...")
		info, err := deploy.CheckSubstoreVersion(cfg)
		if err != nil {
			logger.Warn("无法获取 Sub-Store 镜像版本 (%v)，如需强制重装请添加 -f 参数", err)
		} else if !info.HasUpdate {
			logger.Success("Sub-Store 已是最新版本，无需重装。使用 -f 参数可强制重装。")
			return nil
		} else {
			logger.Info("Sub-Store 发现新版本镜像: 当前 %s -> 最新 %s，开始重装...", info.CurrentVersion, info.LatestVersion)
		}
	}

	logger.Info("Reinstalling Sub-Store...")
	if err := deploy.UninstallSubstore(); err != nil {
		logger.Warn("Failed to uninstall Sub-Store: %v", err)
	}
	sbt := deploy.NewSubstore(cfg, "")
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
	if cfg.Server.SBDomain == "" || cfg.Server.CFDNSKey == "" {
		return fmt.Errorf("server.sb_domain and server.cf_dns_key are required in singctl.yaml")
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
	if err := deploy.DeployCommon(); err != nil {
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

	sbs.ShowLoginInfo()
	sbt.ShowLoginInfo()
	logger.Success("All server components reinstalled successfully.")
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

	if cfg.Server.SBDomain == "" {
		return fmt.Errorf("server.sb_domain is required in config (%s)", configPath)
	}

	logger.Info("Resetting sing-box server credentials for domain: %s...", cfg.Server.SBDomain)

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
				return syncNodeToSubstore(resolvedPath, restart)
			default:
				return fmt.Errorf("unknown target: %s (must be substore, sub-store, sb, or singbox)", target)
			}
		},
	}

	cmd.Flags().BoolVarP(&restart, "restart", "r", true, "同步后自动重启 Sub-Store 容器保证数据最新 / Restart Sub-Store container after sync to ensure data is updated")
	return cmd
}

func syncNodeToSubstore(configPath string, restart bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if cfg.Server.SBDomain == "" {
		return fmt.Errorf("server.sb_domain is required in config (%s)", configPath)
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
	fmt.Printf("• TUIC:          %s\n", sbs.ShareLinkTuic)
	fmt.Println("========================================================")
	return nil
}
