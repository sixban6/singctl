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

// notifyReadyPipe 安全向父进程就绪管道写入 1 字节并关闭描述符。
// 必须先用底层 syscall.Fstat 确认 fd 确为 FIFO/Pipe，严禁直接调用 os.NewFile，
// 否则在 fd 并非管道时（如误继承环境变量），Go GC finalizer 仍会异步 close(fd)，
// 进而炸毁 Go runtime 的 epoll/kqueue 或 HTTP 监听 Socket。
func notifyReadyPipe(fd int) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return
	}
	if (st.Mode & syscall.S_IFMT) != syscall.S_IFIFO {
		return
	}
	// macOS XNU kqueue_stat() 也会对 kqueue FD 返回 S_IFIFO；仅在成功写入 1 字节就绪信号后才关闭 fd，
	// 避免误关 Go runtime netpoller 的 kqueue 描述符。
	if n, err := syscall.Write(fd, []byte{1}); err != nil || n != 1 {
		return
	}
	_ = syscall.Close(fd)
}
