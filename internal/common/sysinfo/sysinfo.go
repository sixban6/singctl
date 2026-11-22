// 文件职责：提供宿主机发行版识别（OpenWrt/Debian）、/proc/meminfo 内存解析以及字节与速率人性化格式化函数。
package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// DiskSpace 汇总挂载点的总容量、空闲、非特权可用容量与使用率。
type DiskSpace struct {
	TotalBytes  uint64
	FreeBytes   uint64
	AvailBytes  uint64
	UsedBytes   uint64
	UsedPercent int
}

// MemInfo 汇总 /proc/meminfo 解析出的物理内存与交换分区字节数。
type MemInfo struct {
	TotalBytes     uint64
	FreeBytes      uint64
	AvailableBytes uint64
	BuffersBytes   uint64
	CachedBytes    uint64
	SwapTotalBytes uint64
	SwapFreeBytes  uint64
}

// IsOpenWrt 判断当前 Linux 宿主机是否运行 OpenWrt / ImmortalWrt 固件。
func IsOpenWrt() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return IsOpenWrtAt("/")
}

// IsOpenWrtAt 在给定根目录前缀下检测 OpenWrt 标识文件（便于离线单元测试）。
func IsOpenWrtAt(root string) bool {
	if root == "" {
		root = "/"
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "openwrt_release")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "openwrt_version")); err == nil {
		return true
	}
	if raw, err := os.ReadFile(filepath.Join(root, "etc", "os-release")); err == nil {
		return strings.Contains(strings.ToLower(string(raw)), "openwrt")
	}
	return false
}

// IsDebian 判断当前 Linux 宿主机是否为 Debian / Ubuntu 系列发行版。
func IsDebian() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return IsDebianAt("/")
}

// IsDebianAt 在给定根目录前缀下检测 Debian / Ubuntu 发行版特征。
func IsDebianAt(root string) bool {
	if root == "" {
		root = "/"
	}
	if _, err := os.Stat(filepath.Join(root, "etc", "debian_version")); err == nil {
		return true
	}
	if raw, err := os.ReadFile(filepath.Join(root, "etc", "os-release")); err == nil {
		lower := strings.ToLower(string(raw))
		return strings.Contains(lower, "debian") || strings.Contains(lower, "ubuntu")
	}
	return false
}

// ReadMemInfo 读取并解析 Linux /proc/meminfo。
func ReadMemInfo() (MemInfo, error) {
	if runtime.GOOS != "linux" {
		return MemInfo{}, os.ErrNotExist
	}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return MemInfo{}, err
	}
	return ParseMemInfo(string(raw)), nil
}

// ParseMemInfo 解析 /proc/meminfo 文本；若旧内核缺少 MemAvailable 则回退为 MemFree+Buffers+Cached。
func ParseMemInfo(raw string) MemInfo {
	var m MemInfo
	var hasAvail bool
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		bytesVal := kb * 1024
		switch fields[0] {
		case "MemTotal:":
			m.TotalBytes = bytesVal
		case "MemFree:":
			m.FreeBytes = bytesVal
		case "MemAvailable:":
			m.AvailableBytes = bytesVal
			hasAvail = true
		case "Buffers:":
			m.BuffersBytes = bytesVal
		case "Cached:":
			m.CachedBytes = bytesVal
		case "SwapTotal:":
			m.SwapTotalBytes = bytesVal
		case "SwapFree:":
			m.SwapFreeBytes = bytesVal
		}
	}
	if !hasAvail {
		m.AvailableBytes = m.FreeBytes + m.BuffersBytes + m.CachedBytes
	}
	return m
}

// FormatBytes 将累计字节数格式化为易读单位（B / KB / MB / GB / TB）。
func FormatBytes(b int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// FormatDiskBytes 将磁盘容量字节格式化为紧凑短字符串（如 512M / 1.5G / 25G / 1.2T）。
func FormatDiskBytes(b uint64) string {
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

// FormatRate 将每秒字节速率（B/s）折算为比特率文本（bps / Kbps / Mbps / Gbps）。
func FormatRate(bps int64) string {
	bits := float64(bps) * 8
	switch {
	case bits >= 1_000_000_000:
		return fmt.Sprintf("%.2f Gbps", bits/1_000_000_000)
	case bits >= 1_000_000:
		return fmt.Sprintf("%.2f Mbps", bits/1_000_000)
	case bits >= 1_000:
		return fmt.Sprintf("%.1f Kbps", bits/1_000)
	default:
		return fmt.Sprintf("%d bps", int64(bits))
	}
}
