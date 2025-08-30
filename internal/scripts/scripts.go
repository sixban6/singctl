package scripts

import (
	_ "embed"
	"os"
	"path/filepath"
	"runtime"
)

// Linux/OpenWrt scripts
//go:embed start_singbox.sh
var startScriptLinux string

//go:embed stop_singbox.sh
var stopScriptLinux string

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

// GetStartScript returns the content of the start script for current OS
func GetStartScript() string {
	switch runtime.GOOS {
	case "darwin":
		return startScriptDarwin
	case "windows":
		return startScriptWindows
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