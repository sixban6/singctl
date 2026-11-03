package cmd

import (
	"fmt"
	"os"

	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

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
	if cfg.Server.GetNodeDomain() == "" || cfg.Server.CFDNSKey == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) and server.cf_dns_key are required in singctl.yaml")
	}

	logger.Info("Reinstalling all server components...")

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
