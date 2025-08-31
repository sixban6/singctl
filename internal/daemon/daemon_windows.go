//go:build windows
// +build windows

package daemon

import (
	"os/exec"
)

// setProcAttrs 设置Windows系统的进程属性
func (d *Daemon) setProcAttrs(cmd *exec.Cmd) {
	// Windows下不需要设置Setsid
	// Windows有不同的进程创建机制
}