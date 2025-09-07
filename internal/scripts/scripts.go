package scripts

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Linux/OpenWrt scripts
//go:embed start_singbox.sh
var startScriptLinux string

//go:embed stop_singbox.sh
var stopScriptLinux string

// Debian scripts
//go:embed start_singbox_debian.sh
var startScriptDebian string

//go:embed stop_singbox_debian.sh
var stopScriptDebian string

// macOS scripts
//go:embed start_singbox_darwin.sh
var startScriptDarwin string

//go:embed stop_singbox_darwin.sh
var stopScriptDarwin string

// Windows scripts
//go:embed start_singbox_windows.bat
var startScriptWindows string

//go:embed stop_singbox_windows.bat
var stopScriptWindows string

// WriteStartScript writes the embedded start script to the specified path
func WriteStartScript(path string) error {
	return writeScriptFile(path, GetStartScript())
}

// WriteStopScript writes the embedded stop script to the specified path
func WriteStopScript(path string) error {
	return writeScriptFile(path, GetStopScript())
}

// isDebian checks if the current system is Debian/Ubuntu
func isDebian() bool {
	// Check for Debian/Ubuntu specific files
	debianFiles := []string{
		"/etc/debian_version",
		"/etc/apt/sources.list",
	}
	
	for _, file := range debianFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	
	// Check /etc/os-release for Debian/Ubuntu
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		osRelease := strings.ToLower(string(content))
		if strings.Contains(osRelease, "debian") || strings.Contains(osRelease, "ubuntu") {
			return true
		}
	}
	
	return false
}

// isOpenWrt checks if the current system is OpenWrt
func isOpenWrt() bool {
	// Check for OpenWrt specific files
	openwrtFiles := []string{
		"/etc/openwrt_release",
		"/etc/openwrt_version",
	}
	
	for _, file := range openwrtFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	
	return false
}

// GetStartScript returns the content of the start script for current OS
func GetStartScript() string {
	switch runtime.GOOS {
	case "darwin":
		return startScriptDarwin
	case "windows":
		return startScriptWindows
	case "linux":
		// Linux 系统需要进一步判断发行版
		if isDebian() {
			return startScriptDebian
		} else if isOpenWrt() {
			return startScriptLinux  // OpenWrt 使用原来的脚本
		} else {
			return startScriptLinux  // 其他 Linux 发行版使用默认脚本
		}
	default:
		return startScriptLinux
	}
}

// GetStopScript returns the content of the stop script for current OS
func GetStopScript() string {
	switch runtime.GOOS {
	case "darwin":
		return stopScriptDarwin
	case "windows":
		return stopScriptWindows
	case "linux":
		// Linux 系统需要进一步判断发行版
		if isDebian() {
			return stopScriptDebian
		} else if isOpenWrt() {
			return stopScriptLinux  // OpenWrt 使用原来的脚本
		} else {
			return stopScriptLinux  // 其他 Linux 发行版使用默认脚本
		}
	default:
		return stopScriptLinux
	}
}

// writeScriptFile writes script content to file with executable permissions
func writeScriptFile(path, content string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	// Write script content to file
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		return err
	}
	
	return nil
}