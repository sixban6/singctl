package cmd

import (
	"singctl/internal/firewall"

	"github.com/spf13/cobra"
)

func newEnableCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "enable",
		Short: "启用安全封锁规则 / Enable security block rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			return firewall.Enable()
		},
	}

	return cmd
}

func newDisableCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "disable",
		Short: "禁用并移除安全封锁规则 / Disable and remove security block rules",
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
