package daemon

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// PID文件路径（跨平台）
	pidFileName = "singctl-daemon.pid"
	// 日志文件名
	logFileName = "singctl-daemon.log"
	// 重启计数状态文件名（/tmp 在 OpenWrt 上是 tmpfs，重启自动清零）
	stateFileName = "singctl-daemon.state"
)

// errDaemonAlreadyRunning 已有守护进程运行
var errDaemonAlreadyRunning = errors.New("daemon already running")

// 路径覆盖钩子（仅测试使用）
var (
	pidFilePathOverride   string
	stateFilePathOverride string
	// expectedProcNameFn 返回守护进程期望的进程名（默认取当前可执行文件名）
	expectedProcNameFn = defaultProcName
)

func defaultProcName() string {
	if p, err := os.Executable(); err == nil {
		name := filepath.Base(p)
		return strings.TrimSuffix(name, ".exe")
	}
	return "singctl"
}

// getPidFilePath 获取PID文件路径
func getPidFilePath() string {
	if pidFilePathOverride != "" {
		return pidFilePathOverride
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), pidFileName)
	}
	return filepath.Join("/tmp", pidFileName)
}

// getStateFilePath 获取重启计数状态文件路径
func getStateFilePath() string {
	if stateFilePathOverride != "" {
		return stateFilePathOverride
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), stateFileName)
	}
	return filepath.Join("/tmp", stateFileName)
}

// GetDaemonLogPath 获取守护进程日志文件路径
func GetDaemonLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), logFileName)
	}
	return filepath.Join("/tmp", logFileName)
}

// acquirePidLock 以 O_EXCL 原子创建 PID 文件作为互斥锁，写入当前进程 PID。
//
// 用途：防止并发 `dm start` 分裂出多个守护进程。
// 若文件已存在：
//   - PID 存活且进程名匹配 → 返回 errDaemonAlreadyRunning
//   - PID 已死或进程名不符（PID 回绕复用）→ 视为残留锁，清除后重试一次
func acquirePidLock() error {
	pid := os.Getpid()
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(getPidFilePath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err == nil {
			_, werr := f.WriteString(strconv.Itoa(pid))
			f.Close()
			if werr != nil {
				return fmt.Errorf("failed to write pid file: %w", werr)
			}
			return nil
		}
		if !os.IsExist(err) {
			return fmt.Errorf("failed to create pid file: %w", err)
		}

		// 文件已存在：判断是否为活锁
		oldPid, rerr := ReadDaemonPid()
		if rerr == nil && daemonProcessMatches(oldPid) {
			return errDaemonAlreadyRunning
		}
		// 残留锁（进程已死或 PID 被无关进程复用），清除后重试
		_ = os.Remove(getPidFilePath())
	}
	return errDaemonAlreadyRunning
}

// WritePidFile 以原子方式写入PID文件（先写临时文件再 rename，避免读到半截内容）
func WritePidFile() error {
	pidFile := getPidFilePath()
	pid := strconv.Itoa(os.Getpid())
	tmp := pidFile + ".tmp"
	if err := ioutil.WriteFile(tmp, []byte(pid), 0644); err != nil {
		return err
	}
	return os.Rename(tmp, pidFile)
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

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid in file: %w", err)
	}

	return pid, nil
}

// IsDaemonRunning 检查守护进程是否运行（PID 存活 + 进程名匹配，防 PID 回绕误判）
func IsDaemonRunning() bool {
	pid, err := ReadDaemonPid()
	if err != nil {
		return false
	}
	return daemonProcessMatches(pid)
}

// daemonProcessMatches 判断 PID 对应的进程是否为存活的 singctl 守护进程
func daemonProcessMatches(pid int) bool {
	if !ProcessExists(pid) {
		return false
	}

	expected := expectedProcNameFn()

	// Linux: /proc/<pid>/comm（最快且无副作用）
	if runtime.GOOS != "windows" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			return strings.TrimSpace(string(b)) == expected
		}
	}

	// macOS / 其他 Unix: ps 查询
	if runtime.GOOS != "windows" {
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
		if err != nil {
			// ps 不可用时保守地认为匹配，避免完全失去检测能力
			return true
		}
		name := filepath.Base(strings.TrimSpace(string(out)))
		return name == expected || strings.HasPrefix(name, expected)
	}

	// Windows: 无法低成本校验进程名，仅依赖 Signal(0)
	return true
}

// ProcessExists 检查进程是否存在（跨平台）。
// 儵尸进程视为不存在：进程已死只是尚未被父进程收尸，对存活判定而言就是已退出。
func ProcessExists(pid int) bool {
	if pid <= 0 {
		return false
	}

	if isZombie(pid) {
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

// isZombie 检测进程是否为僵尸（仅 Linux；僵尸=已退出但未被父进程收尸）
func isZombie(pid int) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// 格式: pid (comm) state ...；comm 可能含空格/括号，取最后一个 ')' 之后的状态字符
	if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) {
		return b[i+2] == 'Z'
	}
	return false
}

// StopDaemon 停止守护进程。
//
// 发送 SIGTERM 后轮询等待进程真正退出（上限 5s），超时则 SIGKILL 兜底。
// 等待退出是必要的：若只发信号就返回，而看门狗恰好在 doRestart 的
// stop→start 间隙，sing-box 会被重新拉起，出现"停不掉"的假象。
func StopDaemon() error {
	pid, err := ReadDaemonPid()
	if err != nil {
		return nil // 守护进程不存在
	}

	if !daemonProcessMatches(pid) {
		// PID 已死或被无关进程复用 → 残留文件，清理即可
		RemovePidFile()
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find daemon process: %w", err)
	}

	send := func(sig os.Signal) {
		if runtime.GOOS == "windows" {
			_ = process.Kill()
		} else {
			_ = process.Signal(sig)
		}
	}
	send(syscall.SIGTERM)

	// 等待优雅退出（看门狗 ctx 取消 → 日志收尾 → 退出）
	if waitProcessExit(pid, 5*time.Second) {
		RemovePidFile()
		return nil
	}

	// 超时强杀
	send(syscall.SIGKILL)
	waitProcessExit(pid, 3*time.Second)
	RemovePidFile()
	return nil
}

// waitProcessExit 轮询等待进程退出
func waitProcessExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !ProcessExists(pid) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return !ProcessExists(pid)
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

	return checkProcessByCommand(cmd, args)
}

// checkProcessByCommand 通过命令检查进程
func checkProcessByCommand(cmdName string, args []string) bool {
	cmd := exec.Command(cmdName, args...)

	switch cmdName {
	case "pgrep":
		err := cmd.Run()
		return err == nil

	case "tasklist":
		output, err := cmd.Output()
		if err != nil {
			return false
		}
		return bytes.Contains(output, []byte("sing-box.exe"))

	default:
		return false
	}
}
