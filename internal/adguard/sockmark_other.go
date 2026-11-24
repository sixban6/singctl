//go:build !linux

// 文件职责：非 Linux 平台的直连探测套接字标记占位实现（无副作用）。
package adguard

import "syscall"

func controlSocketWithBypassMark(_, _ string, _ syscall.RawConn) error {
	return nil
}
