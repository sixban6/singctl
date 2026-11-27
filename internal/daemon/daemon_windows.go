//go:build windows

// 文件职责：提供 Windows 平台看门狗热重载信号占位函数。
package daemon

import "os/exec"

func detachExecCmd(*exec.Cmd) {}

func installReloadSignal(func()) {}

func notifyPidReload(int) bool {
	return false
}
