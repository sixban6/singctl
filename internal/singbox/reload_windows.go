//go:build windows

// 文件职责：提供 Windows 平台 SIGHUP 信号的空实现占位，保持跨平台编译兼容。
package singbox

func sendSIGHUPToPID(int) error {
	return nil
}
