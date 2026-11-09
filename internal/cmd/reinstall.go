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
				return reinstallAll(cfg)
			case "common":
				return deploy.DeployCommonWithConfig(cfg)
			case "caddy":
				return reinstallCaddy(cfg)
			case "singbox":
				return reinstallSingbox(cfg)
			case "warp":
				return reinstallWarp()
			default:
				return fmt.Errorf("unknown target: %s (must be all, common, caddy, singbox, or warp)", target)
			}
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "强制重装 / Force reinstall")
	return cmd
}

func reinstallCaddy(cfg *config.Config) error {
	logger.Info("Reinstalling Caddy...")
	if err := deploy.UninstallCaddy(); err != nil {
		logger.Warn("Failed to uninstall Caddy: %v", err)
	}
	return deploy.DeployCaddy(cfg)
}

func reinstallSingbox(cfg *config.Config) error {
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
			logger.Warn("SubHub config sync failed (non-fatal): %v", err)
		}
	}
	return nil
}

func reinstallWarp() error {
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
		logger.Warn("SubHub config update failed!")
		return err
	}

	sbs.ShowLoginInfo()
	return nil
}
