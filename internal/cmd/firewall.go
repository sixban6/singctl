package cmd

import (
	"github.com/spf13/cobra"
	"singctl/internal/firewall"
)

func newEnableCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable security block rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return firewall.Enable()
		},
	}

	return cmd
}

func newDisableCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable and remove security block rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return firewall.Disable()
		},
	}

	return cmd
}

func NewFirewallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "firewall",
		Aliases: []string{"fw"}, // 添加快捷命令 singctl fw
		Short:   "防火墙: 服务器防火墙加固命令(简写singctl fw)",
	}

	cmd.AddCommand(newEnableCmd())
	cmd.AddCommand(newDisableCmd())
	return cmd
}
