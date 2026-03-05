package cmd

import (
	"fmt"
	"singctl/internal/config"
	"singctl/internal/deploy"
	"singctl/internal/logger"

	"github.com/spf13/cobra"
)

func newInstallServerCmd(cfg *config.Config) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "install",
		Short: "install server components. Optionally specify: common|caddy|singbox|substore",
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
				sbs := deploy.NewSingBoxServer(cfg)
				if err := sbs.DeploySingbox(); err != nil {
					return err
				}

				sbt := deploy.NewSubstore(cfg, "")
				if err := sbt.DeploySubstore(); err != nil {
					return err
				}

				err := sbt.UpdateSubstoreConfig(sbs)
				if err != nil {
					logger.Warn("Substore config update failed!")
					return err
				}

				sbs.ShowLoginInfo()
				sbt.ShowLoginInfo()
				return nil
			}

			sbs := deploy.NewSingBoxServer(cfg)
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
		Short: "Uninstall server components. Optionally specify: caddy|singbox|substore|warp",
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
		return nil
	}

	cmd.AddCommand(newInstallServerCmd(cfg))
	cmd.AddCommand(newUninstallServerCmd())
	cmd.AddCommand(newSniCmd(configPath))
	return cmd
}

func newSniCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:   "sni <domain>",
		Short: "Update Reality SNI domain and reload services without regenerating credentials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			newSni := args[0]

			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			cfg.Server.Sni = newSni
			if err := config.Save(configPath, cfg); err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}
			logger.Info("SNI updated to %s in config", newSni)

			if err := deploy.DeployCaddy(cfg); err != nil {
				return fmt.Errorf("caddy update failed: %w", err)
			}

			sbs := deploy.NewSingBoxServer(cfg)
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
