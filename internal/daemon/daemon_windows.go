//go:build windows
// +build windows

package daemon

import (
	"os/exec"
	"syscall"
)

// setProcAttrs 设置Windows系统的进程属性：
// DETACHED_PROCESS 使子进程脱离当前控制台（Ctrl+C 不再波及守护进程），
// CREATE_NEW_PROCESS_GROUP 让其拥有独立进程组。
func (d *Daemon) setProcAttrs(cmd *exec.Cmd) {
	const detachedProcess = 0x00000008 // DETACHED_PROCESS
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}
