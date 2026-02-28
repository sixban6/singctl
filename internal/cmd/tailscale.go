package cmd

import (
	"github.com/spf13/cobra"
	"singctl/internal/config"
	"singctl/internal/logger"
	"singctl/internal/tailscale"
)

func newStartTailScaleCmd(cfg *config.Config) *cobra.Command {
	// 1. tailscale start
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			exitNode, _ := cmd.Flags().GetBool("exit-node")
			ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
			return ts.Start(exitNode)
		},
	}
	startCmd.Flags().Bool("exit-node", false, "Advertise this device as a Tailscale exit node")
	return startCmd
}

func newStopTailScaleCmd(cfg *config.Config) *cobra.Command {

	// 2. tailscale stop
	stopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
			return ts.Stop()
		},
	}

	return stopCmd
}

func newInstallTailScaleCmd(cfg *config.Config) *cobra.Command {
	// 3. tailscale install
	installCmd := &cobra.Command{
		Use:   "install",
		Short: "Install tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
			return ts.Install()
		},
	}
	return installCmd
}
func newUpdateTailScaleCmd(cfg *config.Config) *cobra.Command {
	// 4. tailscale update
	updateCmd := &cobra.Command{
		Use:   "update",
		Short: "Update tailscale",
		RunE: func(cmd *cobra.Command, args []string) error {
			ts := tailscale.New(cfg.GitHub.MirrorURL, cfg.Tailscale.AuthKey)
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
