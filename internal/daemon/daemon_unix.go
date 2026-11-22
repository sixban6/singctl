//go:build !windows

// 文件职责：提供 Unix 平台看门狗进程 SIGHUP 热重载信号监听与发送辅助。
package daemon

import (
	"os"
	"os/signal"
	"syscall"
)

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
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.SIGHUP) == nil
}
