package daemon

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
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
func checkProcessByCommand(cmdName string, args []string) bool {
	// 1. 使用 os/exec 包来创建一个代表外部命令的对象
	cmd := exec.Command(cmdName, args...)

	// 2. 根据不同的命令，使用不同的策略来判断结果
	switch cmdName {
	case "pgrep":
		// 对于 pgrep，我们只关心它的退出状态码。
		// 如果 pgrep 找到了进程，它会以状态码 0 正常退出，此时 .Run() 方法返回的 err 是 nil。
		// 如果没找到，它会以状态码 1 退出，.Run() 会返回一个 *exec.ExitError。
		// 所以，只需要判断 err 是否为 nil 即可。
		err := cmd.Run()
		return err == nil

	case "tasklist":
		// 对于 tasklist，即使没有找到进程，只要命令语法正确，它通常也会以状态码 0 退出。
		// 因此，我们必须检查它的输出内容。
		output, err := cmd.Output()
		if err != nil {
			// 如果命令执行本身就出错了（比如 tasklist 不在 PATH 中），
			// 我们可以安全地认为进程没有在运行。
			return false
		}

		// 如果输出中包含了 "sing-box.exe" 字符串，说明进程存在。
		return bytes.Contains(output, []byte("sing-box.exe"))

	default:
		// 如果传入了未知的命令，返回 false。
		return false
	}
}
