package cmd

import (
	"fmt"
	"singctl/internal/constant"
	"singctl/internal/tailscale"
	"strings"

	"github.com/spf13/cobra"
)

func newStartTailScaleCmd(defaultConfigPath string) *cobra.Command {
	// 1. tailscale start
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "启动 Tailscale / Start tailscale",
		Example: `  singctl ts start
	  singctl ts start --router
	  singctl ts start --exit-node
	  singctl ts start --router --exit-node
	  singctl ts start --router --exit-node --accept-routes
	  singctl ts start --mode gateway
	  singctl ts start -m gateway --accept-routes`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := loadCmdConfig(cmd, defaultConfigPath)
			if err != nil {
				return err
			}
			exitNode, _ := cmd.Flags().GetBool(constant.ExitNode)
			mainRouter, _ := cmd.Flags().GetBool(constant.MainRouter)
			// acceptRoutes, _ := cmd.Flags().GetBool(constant.AcceptRoutes)
			acceptRoutes := false
			mode, _ := cmd.Flags().GetString(constant.TailscaleMode)

			routerFlagChanged := cmd.Flags().Changed(constant.MainRouter)
			exitFlagChanged := cmd.Flags().Changed(constant.ExitNode)
			// acceptRoutesChanged := cmd.Flags().Changed(constant.AcceptRoutes)

			mode = strings.ToLower(strings.TrimSpace(mode))
			if mode != "" {
				if routerFlagChanged || exitFlagChanged {
					return fmt.Errorf("--%s cannot be used with --%s/--%s", constant.TailscaleMode, constant.MainRouter, constant.ExitNode)
				}

				switch mode {
				case "client":
					mainRouter = false
					exitNode = false
				case "router":
					mainRouter = true
					exitNode = false
				case "exit":
					mainRouter = false
					exitNode = true
				case "gateway":
					// gateway: main router + exit node.
					// Do NOT auto-enable accept-routes here:
					// importing remote routes on a TProxy router can hijack
					// the default path and make the box appear fully offline.
					mainRouter = true
					exitNode = true
					acceptRoutes = true
				default:
					return fmt.Errorf("invalid --%s: %q (supported: client, router, exit, gateway)", constant.TailscaleMode, mode)
				}
			}

			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Start(exitNode, mainRouter, &acceptRoutes)
		},
	}
	startCmd.Flags().BoolP(constant.ExitNode, "e", false,
		"将本机设为出口节点 / Advertise this device as a Tailscale exit node")
	startCmd.Flags().BoolP(constant.MainRouter, "r", false,
		"广播本机 LAN 子网路由（适合部署在路由器上） / Advertise LAN subnet routes (for router devices)")
	startCmd.Flags().BoolP(constant.AcceptRoutes, "a", false,
		"接收其他节点广播路由 / Accept routes advertised by other nodes")
	startCmd.Flags().StringP(constant.TailscaleMode, "m", "",
		"快速模式: client|router|exit|gateway (gateway = router+exit-node; add --accept-routes only if you really need remote routes)")
	return startCmd
}

func newStopTailScaleCmd(defaultConfigPath string) *cobra.Command {
	// 2. tailscale stop
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "停止 Tailscale / Stop tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Stop()
		},
	}

	return stopCmd
}

func newInstallTailScaleCmd(defaultConfigPath string) *cobra.Command {
	// 3. tailscale install
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "安装 Tailscale / Install tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Install()
		},
	}
	return installCmd
}
func newUpdateTailScaleCmd(defaultConfigPath string) *cobra.Command {
	// 4. tailscale update
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "更新 Tailscale / Update tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := loadCmdConfigOrDefault(cmd, defaultConfigPath)
			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Update()
		},
	}
	return updateCmd
}

func NewTailscaleCmd(configPath string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tailscale",
		Aliases: []string{"ts"}, // 添加快捷命令 singctl ts
		Short:   "组网  : 管理tailscale的命令(简写singctl ts)",
	}

	cmd.AddCommand(newStartTailScaleCmd(configPath))
	cmd.AddCommand(newStopTailScaleCmd(configPath))
	cmd.AddCommand(newInstallTailScaleCmd(configPath))
	cmd.AddCommand(newUpdateTailScaleCmd(configPath))
	return cmd
}
