//go:build windows
// +build windows

package webui

import (
	"os/exec"
	"syscall"
)

// setWebSpawnAttrs Windows 后台进程属性:脱离控制台 + 独立进程组
func setWebSpawnAttrs(cmd *exec.Cmd) {
	const detachedProcess = 0x00000008 // DETACHED_PROCESS
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}
