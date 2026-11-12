//go:build !windows
// +build !windows

package daemon

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// setProcAttrs 设置Unix系统的进程属性
func (d *Daemon) setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // 创建新会话
	}
}

func installReloadSignal(onReload func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			if onReload != nil {
				onReload()
			}
		}
	}()
}

func notifyPidReload(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.SIGHUP) == nil
}
