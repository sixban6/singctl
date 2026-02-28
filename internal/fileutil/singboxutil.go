package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// GetSingBoxInstallDir 返回适合当前系统的 sing-box 安装路径
func GetSingBoxInstallDir() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "sing-box", "sing-box.exe")
	case "linux":
		// 检查是否为 OpenWrt 系统
		if _, err := os.Stat("/etc/openwrt_release"); err == nil {
			return "/usr/bin/sing-box"
		}
		if _, err := os.Stat("/etc/openwrt_version"); err == nil {
			return "/usr/bin/sing-box"
		}
		return "/usr/local/bin/sing-box"
	default:
		// macOS等其他系统
		return "/usr/local/bin/sing-box"
	}
}

func GetSingboxConfigPath() string {
	var configPath string
	if runtime.GOOS == "windows" {
		configPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "sing-box", "config.json")
	} else if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		configPath = filepath.Join(home, "Documents", "sing-box-config.json")
	} else {
		configPath = "/etc/sing-box/config.json"
	}
	return configPath
}
