//go:build linux

// 文件职责：在 Linux 宿主上为直连上游网关 DNS 探测套接字附加 SO_MARK=0x1，避免命中 TProxy OUTPUT 劫持环路。
package adguard

import (
	"syscall"
)

func controlSocketWithBypassMark(_, _ string, c syscall.RawConn) error {
	_ = c.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 1)
	})
	return nil
}
