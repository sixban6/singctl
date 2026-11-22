//go:build !windows

// 文件职责：提供 Unix 平台后台进程组分离属性（Setsid）与基于 syscall.Fstat S_IFIFO 校验的安全就绪管道通知。
package proc

import (
	"os/exec"
	"syscall"
)

// SetDetachedAttr 为子进程配置新会话属性，使其脱离父进程控制终端。
func SetDetachedAttr(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// NotifyReadyPipe 安全向父进程就绪管道写入 1 字节成功信号并关闭该描述符。
func NotifyReadyPipe(fd int) {
	NotifyReadyPipeResult(fd, true)
}

// NotifyReadyPipeResult 在通过底层 syscall.Fstat 严格确认 fd 为 FIFO 管道后写入 1 字节状态信号（ok=1 / fail=0）。
// 严禁调用 os.NewFile：若 fd 并非真实就绪管道（例如误继承环境变量指向普通文件、监听 Socket 或 macOS kqueue），
// os.NewFile 注册的 GC finalizer 会异步 close(fd)，炸毁 Go runtime netpoller。
func NotifyReadyPipeResult(fd int, ok bool) {
	if fd < 0 {
		return
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFIFO {
		return
	}
	sig := byte(0)
	if ok {
		sig = 1
	}
	// macOS XNU kqueue_stat() 也会对 kqueue fd 返回 S_IFIFO，但其 write 必然失败；
	// 仅在真实成功写入 1 字节后才关闭 fd，100% 保护 runtime netpoller。
	if n, err := syscall.Write(fd, []byte{sig}); err != nil || n != 1 {
		return
	}
	_ = syscall.Close(fd)
}
