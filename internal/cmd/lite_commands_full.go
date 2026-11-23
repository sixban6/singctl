//go:build !lite

// 文件职责：在标准完整版中向根命令挂载服务端运维组、机群/SSH/终端/测速子命令及自更新后服务端守护进程联动重启。
package cmd

import (
	"singctl/internal/subhub"

	"github.com/spf13/cobra"
)

func isLiteEdition() bool {
	return false
}

func registerEditionGroups(rootCmd *cobra.Command) {
	rootCmd.AddGroup(
		&cobra.Group{ID: "server", Title: "【服务端核心运维 (Server Fleet)】"},
	)
}

func mountEditionCommands(rootCmd *cobra.Command, cfgPath string, info BuildInfo, addGrouped func(groupID string, cmds ...*cobra.Command)) {
	addGrouped("server",
		NewServerCmd(cfgPath, info.Version),
		NewFleetCmd(cfgPath),
		NewReinstallServerCmd(cfgPath),
		NewCfTokenCmd(cfgPath),
	)
	addGrouped("system",
		NewTerminalCmd(cfgPath),
		NewSSHCmd(),
		NewUtilCmd(),
	)
}

func restartServerServicesAfterSelfUpdate(resolvedPath string) {
	if subhub.IsRunning() {
		_ = subhub.RestartService()
	}
	if isServerUIServiceRunning(resolvedPath) {
		_ = restartServerUIService()
	}
}
