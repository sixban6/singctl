package cmd

import (
	"singctl/internal/config"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"singctl/internal/tailscale"

	"github.com/spf13/cobra"
)

func newStartTailScaleCmd(cfg *config.Config) *cobra.Command {
	// 1. tailscale start
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "启动 Tailscale / Start tailscale",
		Example: `  singctl ts start
  singctl ts start --router
  singctl ts start --exit-node
  singctl ts start --router --exit-node`,
		RunE: func(cmd *cobra.Command, args []string) error {
			exitNode, _ := cmd.Flags().GetBool(constant.ExitNode)
			mainRouter, _ := cmd.Flags().GetBool(constant.MainRouter)
			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Start(exitNode, mainRouter)
		},
	}
	startCmd.Flags().Bool(constant.ExitNode, false,
		"将本机设为出口节点 / Advertise this device as a Tailscale exit node")
	startCmd.Flags().Bool(constant.MainRouter, false,
		"广播本机 LAN 子网路由（适合部署在路由器上） / Advertise LAN subnet routes (for router devices)")
	return startCmd
}

func newStopTailScaleCmd(cfg *config.Config) *cobra.Command {

	// 2. tailscale stop
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "停止 Tailscale / Stop tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Stop()
		},
	}

	return stopCmd
}

func newInstallTailScaleCmd(cfg *config.Config) *cobra.Command {
	// 3. tailscale install
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "安装 Tailscale / Install tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			ts := tailscale.New(cfg.GitHub.MirrorURL, &cfg.Tailscale)
			return ts.Install()
		},
	}
	return installCmd
}
func newUpdateTailScaleCmd(cfg *config.Config) *cobra.Command {
	// 4. tailscale update
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "更新 Tailscale / Update tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
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

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("配置文件加载失败")
	}

	cmd.AddCommand(newStartTailScaleCmd(cfg))
	cmd.AddCommand(newStopTailScaleCmd(cfg))
	cmd.AddCommand(newInstallTailScaleCmd(cfg))
	cmd.AddCommand(newUpdateTailScaleCmd(cfg))
	return cmd
}
