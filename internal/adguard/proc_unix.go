//go:build !windows

package adguard

import (
	"os/exec"
	"syscall"
)

func setDetachedSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
