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
	_, _ = syscall.Write(fd, []byte{1})
	_ = syscall.Close(fd)
}
