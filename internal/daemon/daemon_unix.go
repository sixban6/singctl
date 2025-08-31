//go:build !windows
// +build !windows

package daemon

import (
	"os/exec"
	"syscall"
)

// setProcAttrs 设置Unix系统的进程属性
func (d *Daemon) setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // 创建新会话
	}
}