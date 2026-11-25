//go:build !linux

// 文件职责：非 Linux 平台内网反向 PTR 查询套接字控制空实现（保证多平台跨编译通过）。
package audit

import "syscall"

func ptrBypassDialControl(_, _ string, _ syscall.RawConn) error {
	return nil
}
