//go:build windows

// 文件职责：提供 Windows 平台磁盘容量探测占位返回（返回 errors.ErrUnsupported）。
package sysinfo

import "errors"

// Statfs 在 Windows 平台上返回 errors.ErrUnsupported，由上层按需优雅降级。
func Statfs(string) (DiskSpace, error) {
	return DiskSpace{}, errors.ErrUnsupported
}
