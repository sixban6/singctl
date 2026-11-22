// 文件职责：提供宿主机发行版识别（OpenWrt/Debian）、/proc/meminfo 内存解析、低内存判定及字节速率格式化函数。
package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	// LowMemoryThresholdBytes 定义低内存设备总物理内存自动激活阈值（512 MiB，覆盖 256MB/512MB 软硬路由）。
	LowMemoryThresholdBytes = 512 * 1024 * 1024
	// UltraLowMemoryThresholdBytes 定义超小内存设备总物理内存阈值（288 MiB，覆盖 224MB/256MB 极限内存路由）。
	UltraLowMemoryThresholdBytes = 288 * 1024 * 1024
	// LowMemoryAvailableThresholdBytes 定义无线驱动等内核预留后的低可用物理内存阈值（256 MiB，如 MT7986 512M 路由实剩 ~205MiB）。
	LowMemoryAvailableThresholdBytes = 256 * 1024 * 1024
	// LowFlashTotalThresholdBytes 定义小闪存路由器总容量阈值（160 MiB，覆盖 128 MB NAND 实际 ~83-100 MB /overlay 设备）。
	LowFlashTotalThresholdBytes uint64 = 160 * 1024 * 1024
	// LowFlashAvailThresholdBytes 定义小闪存路由器可用空间阈值（64 MiB）。
	LowFlashAvailThresholdBytes uint64 = 64 * 1024 * 1024
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

// IsLowMemoryRAM 判断给定总物理内存字节数是否属于低内存设备（0 表示未知，返回 false）。
func IsLowMemoryRAM(totalBytes uint64) bool {
	return totalBytes > 0 && totalBytes <= LowMemoryThresholdBytes
}

// IsUltraLowMemoryRAM 判断给定总物理内存字节数是否属于 <= 288 MiB 超小内存设备（0 表示未知，返回 false）。
func IsUltraLowMemoryRAM(totalBytes uint64) bool {
	return totalBytes > 0 && totalBytes <= UltraLowMemoryThresholdBytes
}

// IsLowMemoryMemInfo 综合总内存（<= 512 MiB）与可用内存（<= 256 MiB）判定是否为低内存运行环境。
func IsLowMemoryMemInfo(mi MemInfo) bool {
	if IsLowMemoryRAM(mi.TotalBytes) {
		return true
	}
	return mi.AvailableBytes > 0 && mi.AvailableBytes <= LowMemoryAvailableThresholdBytes
}

// IsLowMemoryHost 读取当前宿主机 /proc/meminfo 判断是否处于低内存设备环境。
func IsLowMemoryHost() bool {
	mi, err := ReadMemInfo()
	if err != nil {
		return false
	}
	return IsLowMemoryMemInfo(mi)
}

// IsLowFlashSpace 判断给定磁盘空间快照是否满足小闪存设备阈值（总容量 <= 160 MiB 或可用空间 <= 64 MiB；0 表示未知）。
func IsLowFlashSpace(ds DiskSpace) bool {
	if ds.TotalBytes > 0 && ds.TotalBytes <= LowFlashTotalThresholdBytes {
		return true
	}
	return ds.AvailBytes > 0 && ds.AvailBytes <= LowFlashAvailThresholdBytes
}

// IsLowFlashHostWithDeps 使用可注入的发行版与磁盘探测依赖判断是否为小闪存宿主机：
//   - OpenWrt 宿主机：优先检测 /overlay（不可读或零值时回退 /），按 IsLowFlashSpace 综合总容量与可用空间判定；
//   - 非 OpenWrt Linux 宿主机：仅当 / 根分区总容量 <= 160 MiB 时判定为嵌入式小闪存，避免普通 20GB VPS 剩余空间紧张时误判。
func IsLowFlashHostWithDeps(isOpenWrt func() bool, statfs func(string) (DiskSpace, error)) bool {
	if isOpenWrt == nil {
		isOpenWrt = IsOpenWrt
	}
	if statfs == nil {
		statfs = Statfs
	}
	if isOpenWrt() {
		ds, err := statfs("/overlay")
		if err != nil || (ds.TotalBytes == 0 && ds.AvailBytes == 0) {
			ds, err = statfs("/")
			if err != nil {
				return false
			}
		}
		return IsLowFlashSpace(ds)
	}
	ds, err := statfs("/")
	if err != nil {
		return false
	}
	return ds.TotalBytes > 0 && ds.TotalBytes <= LowFlashTotalThresholdBytes
}

// IsLowFlashHost 判断当前 Linux 宿主机是否属于小闪存嵌入式/软路由设备（非 Linux 平台恒返回 false）。
func IsLowFlashHost() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return IsLowFlashHostWithDeps(IsOpenWrt, Statfs)
}

// TotalRAMBytes 返回当前 Linux 宿主机的总物理内存字节数（非 Linux 或不可读时返回 0）。
func TotalRAMBytes() uint64 {
	mi, err := ReadMemInfo()
	if err != nil {
		return 0
	}
	return mi.TotalBytes
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
