//go:build unix

// 文件职责：提供 Unix 平台安全回滚看门狗子进程的 Setsid 进程组脱离配置。
package safecommit

import (
	"os/exec"
	"syscall"
)

func setWatcherDetached(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
