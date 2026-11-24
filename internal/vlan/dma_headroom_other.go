//go:build !linux

// 文件职责：非 Linux 平台的无线 DMA 内存页整理空实现。
package vlan

func prepareWirelessDMAHeadroomOS() {}
