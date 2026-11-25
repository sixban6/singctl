//go:build !windows

// 文件职责：提供 Unix/Linux 平台向精确 PID 发送 SIGHUP 热重载信号的底层封装。
package singbox

import "syscall"

func sendSIGHUPToPID(pid int) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(pid, syscall.SIGHUP)
}
