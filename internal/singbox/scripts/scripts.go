// 文件职责：嵌入并按目标操作系统与 Linux 发行版分发 sing-box 客户端启停脚本。
package scripts

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed start_singbox.sh
var startScriptLinux string

//go:embed stop_singbox.sh
var stopScriptLinux string

//go:embed start_singbox_debian.sh
var startScriptDebian string

//go:embed stop_singbox_debian.sh
var stopScriptDebian string

//go:embed start_singbox_darwin.sh
var startScriptDarwin string

//go:embed stop_singbox_darwin.sh
var stopScriptDarwin string

//go:embed start_singbox_windows.bat
var startScriptWindows string

//go:embed stop_singbox_windows.bat
var stopScriptWindows string

// WriteStartScript 将当前系统匹配的启动脚本以可执行权限写入指定路径。
func WriteStartScript(path string) error {
	return writeScriptFile(path, GetStartScript())
}

// WriteStopScript 将当前系统匹配的停止脚本以可执行权限写入指定路径。
func WriteStopScript(path string) error {
	return writeScriptFile(path, GetStopScript())
}

// GetStartScript 返回当前操作系统对应的启动脚本内容。
func GetStartScript() string {
	switch runtime.GOOS {
	case "darwin":
		return startScriptDarwin
	case "windows":
		return startScriptWindows
	case "linux":
		if isDebian() {
			return startScriptDebian
		}
		return startScriptLinux
	default:
		return startScriptLinux
	}
}

// GetStopScript 返回当前操作系统对应的停止脚本内容。
func GetStopScript() string {
	switch runtime.GOOS {
	case "darwin":
		return stopScriptDarwin
	case "windows":
		return stopScriptWindows
	case "linux":
		if isDebian() {
			return stopScriptDebian
		}
		return startOrStopFallback(stopScriptLinux)
	default:
		return stopScriptLinux
	}
}

func startOrStopFallback(s string) string { return s }

func isDebian() bool {
	for _, file := range []string{"/etc/debian_version", "/etc/apt/sources.list"} {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		osRelease := strings.ToLower(string(content))
		if strings.Contains(osRelease, "debian") || strings.Contains(osRelease, "ubuntu") {
			return true
		}
	}
	return false
}

func writeScriptFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0755)
}
