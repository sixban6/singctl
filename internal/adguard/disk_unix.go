//go:build !windows

package adguard

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// availableDiskMB 返回指定路径所在挂载点的可用空间（MB）。
func availableDiskMB(targetPath string) (uint64, error) {
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
		return 0, fmt.Errorf("statfs %s: %w", checkPath, err)
	}
	availBytes := uint64(stat.Bavail) * uint64(stat.Bsize)
	return availBytes / (1024 * 1024), nil
}
