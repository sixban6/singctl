//go:build !windows
// +build !windows

package webui

import (
	"os/exec"
	"syscall"
)

// setWebSpawnAttrs Unix 后台进程属性:新会话,脱离控制终端
func setWebSpawnAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
