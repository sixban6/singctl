package tailscale

import "os"

func isOpenWrt() bool {
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/openwrt_version"); err == nil {
		return true
	}
	return false
}
