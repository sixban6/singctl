//go:build lite

// 文件职责：在 -tags lite 纯客户端精简版中零服务端重包依赖地注册极薄命令桩与自更新空钩子。
package cmd

import (
	"errors"

	"github.com/spf13/cobra"
)

// LiteUnsupportedServerMsg 为 -tags lite 纯客户端精简版触发服务端/机群/SSH/测速命令时的统一友好提示。
const LiteUnsupportedServerMsg = "当前为 SingCtl -lite 路由器客户端精简版，不含服务端/机群/SSH 运维命令；请使用标准完整版执行该操作"

func isLiteEdition() bool {
	return true
}

func registerEditionGroups(_ *cobra.Command) {}

func mountEditionCommands(rootCmd *cobra.Command, cfgPath string, info BuildInfo, _ func(groupID string, cmds ...*cobra.Command)) {
	rootCmd.AddCommand(
		NewServerCmd(cfgPath, info.Version),
		NewFleetCmd(cfgPath),
		NewReinstallServerCmd(cfgPath),
		NewCfTokenCmd(cfgPath),
		NewTerminalCmd(cfgPath),
		NewSSHCmd(),
		NewUtilCmd(),
	)
}

func restartServerServicesAfterSelfUpdate(_ string) {}

func newLiteStubCmd(use string, aliases []string, short string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Aliases:            aliases,
		Short:              short,
		Hidden:             true,
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New(LiteUnsupportedServerMsg)
		},
	}
}

// NewServerCmd 返回 lite 精简版服务端命令占位桩。
func NewServerCmd(_ string, _ ...string) *cobra.Command {
	return newLiteStubCmd("server", []string{"sr"}, "服务端部署命令 (标准完整版专属)")
}

// NewFleetCmd 返回 lite 精简版机群命令占位桩。
func NewFleetCmd(_ string) *cobra.Command {
	return newLiteStubCmd("fleet", []string{"fl", "cluster"}, "多节点舰队管理 (标准完整版专属)")
}

// NewReinstallServerCmd 返回 lite 精简版服务端重装命令占位桩。
func NewReinstallServerCmd(_ string) *cobra.Command {
	return newLiteStubCmd("reinstall", []string{"ri"}, "重装服务端组件 (标准完整版专属)")
}

// NewCfTokenCmd 返回 lite 精简版 Cloudflare Token 命令占位桩。
func NewCfTokenCmd(_ string) *cobra.Command {
	return newLiteStubCmd("cf-token", []string{"cf", "token", "cftoken"}, "更新 Cloudflare Token (标准完整版专属)")
}

// NewTerminalCmd 返回 lite 精简版 Web 终端命令占位桩。
func NewTerminalCmd(_ string) *cobra.Command {
	return newLiteStubCmd("term", []string{"terminal", "gotty"}, "Web 终端管理 (标准完整版专属)")
}

// NewSSHCmd 返回 lite 精简版 SSH 运维命令占位桩。
func NewSSHCmd() *cobra.Command {
	return newLiteStubCmd("ssh", nil, "SSH 密钥与连接管理 (标准完整版专属)")
}

// NewUtilCmd 返回 lite 精简版带宽测速工具占位桩。
func NewUtilCmd() *cobra.Command {
	return newLiteStubCmd("util", []string{"ut"}, "带宽测速工具集 (标准完整版专属)")
}
