package cmd

import (
	"singctl/internal/util/netinfo"

	"github.com/spf13/cobra"
)

func NewUtilCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "util",
		Aliases: []string{"ut"}, // 添加快捷命令 singctl ut
		Short:   "工具  : 其他命令工具集合(简写:singctl ut)",
	}

	cmd.AddCommand(newBDCmd())
	return cmd
}

func newBDCmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "testbd",
		Short: "测试网络上下行带宽(upload/download speed)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return netinfo.RunSpeedTest()
		},
	}

	return cmd
}
