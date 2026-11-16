//go:build !windows

package serverweb

import (
	"fmt"
	"syscall"
)

func getRootDiskUsage() (usedStr, totalStr, pctStr string, ok bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return "", "", "", false
	}
	bsize := uint64(stat.Bsize)
	total := uint64(stat.Blocks) * bsize
	free := uint64(stat.Bfree) * bsize
	avail := uint64(stat.Bavail) * bsize
	if total == 0 || total < free {
		return "", "", "", false
	}
	used := total - free
	denom := used + avail
	pct := 0
	if denom > 0 {
		pct = int(float64(used)*100.0/float64(denom) + 0.5)
	}
	return formatDiskBytes(used), formatDiskBytes(total), fmt.Sprintf("%d%%", pct), true
}

func formatDiskBytes(b uint64) string {
	const (
		KB = 1024.0
		MB = 1024.0 * KB
		GB = 1024.0 * MB
		TB = 1024.0 * GB
	)
	fb := float64(b)
	switch {
	case fb >= TB:
		return fmt.Sprintf("%.1fT", fb/TB)
	case fb >= GB:
		if fb/GB >= 10 {
			return fmt.Sprintf("%.0fG", fb/GB)
		}
		return fmt.Sprintf("%.1fG", fb/GB)
	case fb >= MB:
		return fmt.Sprintf("%.0fM", fb/MB)
	default:
		return fmt.Sprintf("%.0fK", fb/KB)
	}
}
