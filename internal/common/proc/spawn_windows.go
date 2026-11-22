//go:build windows

// 文件职责：提供 Windows 平台脱离控制台的独立进程组属性（CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS）。
package proc

import (
	"os/exec"
	"syscall"
)

// SetDetachedAttr 为 Windows 后台子进程设置脱离控制台与新进程组标志。
func SetDetachedAttr(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	const detachedProcess = 0x00000008 // DETACHED_PROCESS
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}

// NotifyReadyPipe 在 Windows 平台上为空操作（Windows 无 ExtraFiles fd3 管道传递）。
func NotifyReadyPipe(int) {}

// NotifyReadyPipeResult 在 Windows 平台上为空操作。
func NotifyReadyPipeResult(int, bool) {}
