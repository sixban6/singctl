package cmd

import (
	"fmt"
	"os"
	"strings"

	"singctl/internal/config"
	"singctl/internal/deploy"
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

			if cfg.Server.GetNodeDomain() == "" || cfg.Server.CFDNSKey == "" {
				return fmt.Errorf("server.node_domain (or sb_domain) and server.cf_dns_key are required in singctl.yaml")
			}

			if len(args) == 0 {
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
					logger.Warn("SubHub config update failed!")
					return err
				}

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
				if _, err := os.Stat("/etc/sub-store"); err == nil {
					sbt := deploy.NewSubstore(cfg, "")
					if err := sbt.UpdateSubstoreConfig(sbs); err != nil {
						logger.Warn("SubHub config sync failed (non-fatal): %v", err)
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
					logger.Warn("Failed to uninstall SubHub: %v", err)
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
				return deploy.UninstallCaddy()
			case "singbox":
				return deploy.UninstallSingbox()
			case "substore", "sub", "subhub":
				return deploy.UninstallSubstore()
			case "warp":
				return deploy.UninstallWarp()
			default:
				return fmt.Errorf("unknown target: %s (must be caddy, singbox, substore, or warp)", target)
			}
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
		Aliases: []string{"sr"},
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
	cmd.AddCommand(newServerTopCmd())
	cmd.AddCommand(NewFleetCmd(configPath))
	cmd.AddCommand(NewNetCmd(configPath))
	cmd.AddCommand(newServerDoctorCmd(configPath))
	cmd.AddCommand(newServerHealCmd(configPath, ver))
	cmd.AddCommand(newMaskSiteCmd(configPath))
	cmd.AddCommand(newServerUpdateCmd(configPath))
	cmd.AddCommand(newServerCheckCmd(configPath))
	return cmd
}

func newServerCheckCmd(configPath string) *cobra.Command {
	return &cobra.Command{
		Use:     "check-update [component]",
		Aliases: []string{"checkver", "cu"},
		Short:   "检查核心组件远端是否有新版本 / Check latest remote versions (singbox|caddy|subhub|warp)",
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
		Short:   "平滑升级服务端核心组件 / Smooth upgrade server components (singbox|caddy|subhub|warp|all)",
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

func resolveConfigPath(cmd *cobra.Command, fallback string) string {
	if f := cmd.Flag("config"); f != nil && f.Value.String() != "" {
		return f.Value.String()
	}
	if f := cmd.InheritedFlags().Lookup("config"); f != nil && f.Value.String() != "" {
		return f.Value.String()
	}
	return fallback
}
