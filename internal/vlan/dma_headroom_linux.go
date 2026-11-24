//go:build linux

// 文件职责：在低内存或联发科 mt_wifi/mtk_warp 硬件转发路由器上，于 wifi reload 前整理连续页帧以预防 512KB DMA 分配失败引发 Kernel Panic。
package vlan

import (
	"os"
	"syscall"
	"time"

	"singctl/internal/common/sysinfo"
)

func shouldPrepareWirelessDMAHeadroom() bool {
	if sysinfo.IsLowMemoryHost() {
		return true
	}
	for _, modPath := range []string{"/sys/module/mtk_warp", "/sys/module/mt_wifi"} {
		if _, err := os.Stat(modPath); err == nil {
			return true
		}
	}
	return false
}

func prepareWirelessDMAHeadroomOS() {
	if !shouldPrepareWirelessDMAHeadroom() {
		return
	}
	syscall.Sync()
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0644)
	_ = os.WriteFile("/proc/sys/vm/compact_memory", []byte("1\n"), 0644)
	time.Sleep(150 * time.Millisecond)
}
