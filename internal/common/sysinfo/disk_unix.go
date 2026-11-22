//go:build !windows

// 文件职责：提供 Unix 平台基于 syscall.Statfs 的挂载点磁盘容量探测（支持沿尚未创建的父目录向上回退）。
package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Statfs 查询 targetPath 所在挂载点的磁盘空间（若目标目录尚未创建则自动向上回退至最近已存在父目录）。
func Statfs(targetPath string) (DiskSpace, error) {
	checkPath := targetPath
	for checkPath != "/" && checkPath != "." && checkPath != "" {
		if _, err := os.Stat(checkPath); err == nil {
			break
		}
		checkPath = filepath.Dir(checkPath)
	}
	if checkPath == "" {
		checkPath = "/"
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(checkPath, &stat); err != nil {
		return DiskSpace{}, fmt.Errorf("statfs %s: %w", checkPath, err)
	}
	if stat.Bsize <= 0 {
		return DiskSpace{}, nil
	}
	bsize := uint64(stat.Bsize)
	total := uint64(stat.Blocks) * bsize
	free := uint64(stat.Bfree) * bsize
	avail := uint64(stat.Bavail) * bsize
	if total == 0 || total < free {
		return DiskSpace{TotalBytes: total, FreeBytes: free, AvailBytes: avail}, nil
	}
	used := total - free
	denom := used + avail
	pct := 0
	if denom > 0 {
		pct = int(float64(used)*100.0/float64(denom) + 0.5)
	}
	return DiskSpace{
		TotalBytes:  total,
		FreeBytes:   free,
		AvailBytes:  avail,
		UsedBytes:   used,
		UsedPercent: pct,
	}, nil
}
