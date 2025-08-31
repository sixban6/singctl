package daemon

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

const (
	// PID文件路径（跨平台）
	pidFileName = "singctl-daemon.pid"
	// 日志文件名
	logFileName = "singctl-daemon.log"
)

// getPidFilePath 获取PID文件路径
func getPidFilePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), pidFileName)
	}
	return filepath.Join("/tmp", pidFileName)
}

// GetDaemonLogPath 获取守护进程日志文件路径
func GetDaemonLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), logFileName)
	}
	return filepath.Join("/tmp", logFileName)
}

// WritePidFile 写入PID文件
func WritePidFile() error {
	pidFile := getPidFilePath()
	pid := strconv.Itoa(os.Getpid())
	return ioutil.WriteFile(pidFile, []byte(pid), 0644)
}

// RemovePidFile 删除PID文件
func RemovePidFile() error {
	pidFile := getPidFilePath()
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		return nil // 文件不存在，无需删除
	}
	return os.Remove(pidFile)
}

// ReadDaemonPid 读取守护进程PID
func ReadDaemonPid() (int, error) {
	pidFile := getPidFilePath()
	data, err := ioutil.ReadFile(pidFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read pid file: %w", err)
	}
	
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, fmt.Errorf("invalid pid in file: %w", err)
	}
	
	return pid, nil
}

// IsDaemonRunning 检查守护进程是否运行
func IsDaemonRunning() bool {
	pid, err := ReadDaemonPid()
	if err != nil {
		return false
	}
	return ProcessExists(pid)
}

// ProcessExists 检查进程是否存在（跨平台）
func ProcessExists(pid int) bool {
	if pid <= 0 {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// 发送信号0检查进程是否存在
	if runtime.GOOS == "windows" {
		// Windows下，FindProcess总是成功，需要用Signal检查
		err = process.Signal(os.Signal(syscall.Signal(0)))
		return err == nil
	} else {
		// Unix系统
		err = process.Signal(syscall.Signal(0))
		return err == nil
	}
}

// StopDaemon 停止守护进程
func StopDaemon() error {
	pid, err := ReadDaemonPid()
	if err != nil {
		return nil // 守护进程不存在
	}

	// 发送终止信号
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find daemon process: %w", err)
	}

	if runtime.GOOS == "windows" {
		err = process.Kill()
	} else {
		err = process.Signal(syscall.SIGTERM)
	}

	if err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	// 删除PID文件
	RemovePidFile()
	return nil
}

// IsSingBoxRunning 检查sing-box进程是否运行
func IsSingBoxRunning() bool {
	return isSingBoxProcessRunning()
}

// isSingBoxProcessRunning 检查sing-box进程（跨平台实现）
func isSingBoxProcessRunning() bool {
	var cmd string
	var args []string

	if runtime.GOOS == "windows" {
		cmd = "tasklist"
		args = []string{"/FI", "IMAGENAME eq sing-box.exe", "/NH"}
	} else {
		cmd = "pgrep"
		args = []string{"-x", "sing-box"}
	}

	// 这里简化实现，实际中应该更精确地检查进程
	// 可以通过解析ps输出或使用系统特定的API
	return checkProcessByCommand(cmd, args)
}

// checkProcessByCommand 通过命令检查进程
func checkProcessByCommand(cmd string, args []string) bool {
	// 简化实现：通过文件系统检查
	// 实际实现中应该使用更可靠的方法
	
	// 检查常见的sing-box安装路径
	singboxPaths := []string{
		"/usr/local/bin/sing-box",
		"/usr/bin/sing-box",
	}
	
	if runtime.GOOS == "windows" {
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			singboxPaths = append(singboxPaths, filepath.Join(localAppData, "Programs", "sing-box", "sing-box.exe"))
		}
	}
	
	// 这是一个简化的实现，实际中需要更准确的进程检查
	// 可以使用 github.com/shirou/gopsutil 库来精确检查进程
	for _, path := range singboxPaths {
		if _, err := os.Stat(path); err == nil {
			// 如果可执行文件存在，假设进程正在运行
			// 这里需要更精确的实现
			return true
		}
	}
	
	return false
}