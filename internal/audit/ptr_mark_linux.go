//go:build linux

// 文件职责：在 Linux 旁路由上为内网反向 PTR DNS 查询套接字注入 SO_MARK 0x80000 绕行标记，使请求直达主路由而非回环进本机 sing-box。
package audit

import "syscall"

const ptrBypassSocketMark = 0x80000

func ptrBypassDialControl(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, ptrBypassSocketMark)
	})
	return nil
}
