//go:build !lite

package cmd

import (
	"fmt"

	"singctl/internal/component"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"
	"singctl/internal/terminal"

	"github.com/spf13/cobra"
)

// NewReinstallServerCmd creates the reinstall command (singctl sr ri)
func NewReinstallServerCmd(configPath string) *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:     "reinstall [target]",
		Aliases: []string{"ri"},
		Short:   "重装服务端组件(简写singctl sr ri) / Reinstall server components (all|common|caddy|singbox|warp)",
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
				return reinstallAll(cfg, resolvedPath)
			case "common":
				return deploy.DeployCommonWithConfig(cfg)
			default:
				comp, resErr := deploy.ServerRegistry().Resolve(target)
				if resErr != nil {
					return fmt.Errorf("unknown target: %s (must be all, common, caddy, singbox, or warp)", target)
				}
				life, ok := comp.(component.ServerLifecycle)
				if !ok {
					return fmt.Errorf("unknown target: %s (must be all, common, caddy, singbox, or warp)", target)
				}
				return life.ReinstallServer(cfg)
			}
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "强制重装 / Force reinstall")
	return cmd
}

func reinstallAll(cfg *config.Config, resolvedPath string) error {
	if cfg.Server.GetNodeDomain() == "" || cfg.Server.CFDNSKey == "" {
		return fmt.Errorf("server.node_domain (or sb_domain) and server.cf_dns_key are required in singctl.yaml")
	}

	logger.Info("Reinstalling all server components...")

	// Step 0: Snapshot mTLS vault & existing sing-box credentials before tearing down directories.
	if err := deploy.MigrateLegacyCaddyMtlsToVault(); err != nil {
		logger.Warn("Migrate mTLS vault warning: %v", err)
	}
	sbs, err := deploy.NewSingBoxServer(cfg)
	if err != nil {
		return err
	}
	_ = sbs.LoadExistingCredentials()

	logger.Info("Step 1/2: Uninstalling existing server components...")
	if err := deploy.UninstallCaddy(); err != nil {
		logger.Warn("Failed to uninstall Caddy: %v", err)
	}
	if err := deploy.UninstallSingbox(); err != nil {
		logger.Warn("Failed to uninstall sing-box: %v", err)
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
	if cfg.Server.WebTerminal.Enabled {
		logger.Info("检测到配置已启用 Web 终端，正在前置恢复 mTLS 证书与终端服务...")
		if _, tErr := terminal.Install(cfg, resolvedPath, terminal.InstallOptions{SkipCaddyDeploy: true}); tErr != nil {
			logger.Warn("前置恢复 Web 终端警告 (Caddy 将自动安全降级保护网关): %v", tErr)
		} else if refreshed, lErr := config.Load(resolvedPath); lErr == nil && refreshed != nil {
			cfg = refreshed
			sbs.SetConfig(cfg)
		}
	}
	if err := deploy.DeployCaddy(cfg); err != nil {
		return err
	}
	sbs.RefreshCaddyCertPath()
	if err := sbs.DeploySingbox(); err != nil {
		return err
	}

	sbt := deploy.NewSubstore(cfg, "")
	sbt.ConfigPath = resolvedPath
	if err := sbt.DeploySubstore(); err != nil {
		return err
	}
	if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
		logger.Warn("SubHub config update failed!")
		return err
	}

	if err := installServerUIService(resolvedPath); err != nil {
		logger.Warn("重装服务端管理面板服务警告: %v", err)
	}

	sbs.ShowLoginInfo()
	return nil
}
