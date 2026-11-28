// 文件职责：管理守护进程文件路径配置、PID 原子文件锁、进程身份校验与跨平台启停控制。
package daemon

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"singctl/internal/common/execx"
	"singctl/internal/common/fsx"
	"singctl/internal/common/proc"
	"singctl/internal/updater"
)

const (
	PidFileName   = "singctl-daemon.pid"
	logFileName   = "singctl-daemon.log"
	StateFileName = "singctl-daemon.state"
)

// ErrDaemonAlreadyRunning 表示已有守护进程实例在运行。
var ErrDaemonAlreadyRunning = errors.New("daemon already running")

// Paths 显式注入守护进程的 PID、状态、日志与内嵌 WebUI 标记文件路径。
type Paths struct {
	PidFile         string
	StateFile       string
	LogFile         string
	WebEmbeddedFile string
	WebLogFile      string
}

// 兼容顶层集成测试 test/daemon_test.go 的回退钩子；包内生产与测试优先通过 Paths 显式注入。
var (
	PidFilePathOverride     string
	StateFilePathOverride   string
	DaemonLogPathOverride   string
	WebEmbeddedPathOverride string
	ExpectedProcNameFn      = defaultProcName
)

// DefaultPaths 返回当前平台默认的守护进程运行路径配置。
func DefaultPaths() Paths {
	return Paths{
		PidFile:         GetPidFilePath(),
		StateFile:       GetStateFilePath(),
		LogFile:         GetDaemonLogPath(),
		WebEmbeddedFile: GetWebEmbeddedPath(),
		WebLogFile:      filepath.Join(defaultTempDir(), "singctl-web.log"),
	}
}

func defaultProcName() string {
	if p, err := os.Executable(); err == nil {
		return SanitizeProcName(p)
	}
	return "singctl"
}

// SanitizeProcName 剥离自更新残留后缀（如 " (deleted)" / ".backup" / ".exe"）提取纯净进程名。
func SanitizeProcName(exePath string) string {
	p := strings.TrimSpace(exePath)
	for {
		trimmed := strings.TrimSuffix(p, " (deleted)")
		trimmed = strings.TrimSuffix(trimmed, ".backup")
		trimmed = strings.TrimSuffix(trimmed, ".exe")
		if trimmed == p {
			break
		}
		p = trimmed
	}
	if p == "" {
		return "singctl"
	}
	name := filepath.Base(p)
	for {
		trimmed := strings.TrimSuffix(name, " (deleted)")
		trimmed = strings.TrimSuffix(trimmed, ".backup")
		trimmed = strings.TrimSuffix(trimmed, ".exe")
		if trimmed == name {
			break
		}
		name = trimmed
	}
	if name == "" || name == "." || name == "/" {
		return "singctl"
	}
	return name
}

func extractPositionalSubcommands(args []string) []string {
	if len(args) <= 1 {
		return nil
	}
	var out []string
	for i := 1; i < len(args); i++ {
		a := strings.TrimSpace(args[i])
		if a == "" {
			continue
		}
		if a == "-c" || a == "--config" || a == "-l" || a == "--listen" {
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// IsDaemonStartCmdline 判断命令行参数是否为 `singctl dm/daemon start`。
func IsDaemonStartCmdline(args []string) bool {
	subs := extractPositionalSubcommands(args)
	return len(subs) >= 2 && (subs[0] == "dm" || subs[0] == "daemon") && subs[1] == "start"
}

// IsConflictingSingctlSubcommand 判断命令行是否为同二进制的非守护子命令（如 web / sr / fleet）。
func IsConflictingSingctlSubcommand(args []string) bool {
	subs := extractPositionalSubcommands(args)
	if len(subs) == 0 {
		return false
	}
	switch subs[0] {
	case "web", "w", "sr", "server", "sub", "subhub", "update", "u", "fleet", "fl":
		return true
	default:
		return false
	}
}

func defaultTempDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("TEMP")
	}
	return "/tmp"
}

// GetPidFilePath 获取 PID 文件路径。
func GetPidFilePath() string {
	return cmp.Or(PidFilePathOverride, filepath.Join(defaultTempDir(), PidFileName))
}

// GetStateFilePath 获取重启与运行态快照文件路径。
func GetStateFilePath() string {
	return cmp.Or(StateFilePathOverride, filepath.Join(defaultTempDir(), StateFileName))
}

// GetDaemonLogPath 获取守护进程日志文件路径。
func GetDaemonLogPath() string {
	return cmp.Or(DaemonLogPathOverride, filepath.Join(defaultTempDir(), logFileName))
}

// AcquirePidLock 以硬链接原子创建 PID 文件作为互斥锁，写入当前进程 PID。
func AcquirePidLock() error {
	pid := strconv.Itoa(os.Getpid())
	err := proc.AcquireLinkLock(GetPidFilePath(), []byte(pid), func() bool {
		oldPid, rerr := ReadDaemonPid()
		return rerr == nil && DaemonProcessMatches(oldPid)
	})
	if errors.Is(err, proc.ErrLockHeld) {
		return ErrDaemonAlreadyRunning
	}
	return err
}

// WritePidFile 以原子方式写入默认 PID 文件（强制 0600 权限）。
func WritePidFile() error {
	return WritePidFileAt(GetPidFilePath())
}

// WritePidFileAt 以原子方式将当前进程 PID 写入指定路径（强制 0600 权限）。
func WritePidFileAt(pidFile string) error {
	pid := strconv.Itoa(os.Getpid())
	return fsx.WriteAtomic0600(pidFile, []byte(pid))
}

// RemovePidFile 删除默认 PID 文件。
func RemovePidFile() error {
	return RemovePidFileAt(GetPidFilePath())
}

// RemovePidFileAt 删除指定路径的 PID 文件。
func RemovePidFileAt(pidFile string) error {
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(pidFile)
}

// ReadDaemonPid 读取默认守护进程 PID；Linux 生产环境下缺失时兜底扫描 /proc。
func ReadDaemonPid() (int, error) {
	return readDaemonPidInternal(GetPidFilePath(), PidFilePathOverride == "")
}

// ReadDaemonPidAt 从指定 PID 文件路径读取进程号（不触发宿主 /proc 扫描）。
func ReadDaemonPidAt(pidFile string) (int, error) {
	return readDaemonPidInternal(pidFile, false)
}

func readDaemonPidInternal(pidFile string, allowProcFallback bool) (int, error) {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		if allowProcFallback && runtime.GOOS == "linux" {
			if orphanPid := findOrphanDaemonPid(); orphanPid > 0 {
				return orphanPid, nil
			}
		}
		return 0, fmt.Errorf("failed to read pid file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid in file: %w", err)
	}
	return pid, nil
}

func findOrphanDaemonPid() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	selfPid := os.Getpid()
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == selfPid {
			continue
		}
		rawCmd, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(rawCmd) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(rawCmd), "\x00"), "\x00")
		if IsDaemonStartCmdline(args) && DaemonProcessMatches(pid) {
			return pid
		}
	}
	return 0
}

// IsDaemonRunning 检查守护进程是否运行（PID 存活 + 进程名匹配）。
func IsDaemonRunning() bool {
	pid, err := ReadDaemonPid()
	if err != nil {
		return false
	}
	return DaemonProcessMatches(pid)
}

// DaemonProcessMatches 判断 PID 对应的进程是否为存活的 singctl 守护进程。
func DaemonProcessMatches(pid int) bool {
	if !ProcessExists(pid) {
		return false
	}
	expected := ExpectedProcNameFn()

	if runtime.GOOS != "windows" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
			comm := strings.TrimSpace(string(b))
			matched := comm == expected || (len(expected) > 15 && comm == expected[:15])
			if !matched {
				return false
			}
			if rawCmd, cErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); cErr == nil && len(rawCmd) > 0 {
				args := strings.Split(strings.TrimRight(string(rawCmd), "\x00"), "\x00")
				if IsConflictingSingctlSubcommand(args) {
					return false
				}
			}
			return true
		}
	}

	if runtime.GOOS != "windows" {
		out, err := OutputCmdTimeout(context.Background(), defaultDaemonCmdTimeout, "ps", "-p", strconv.Itoa(pid), "-o", "comm=")
		if err != nil {
			return true
		}
		name := filepath.Base(strings.TrimSpace(string(out)))
		if !(name == expected || strings.HasPrefix(name, expected)) {
			return false
		}
		if cmdOut, cErr := OutputCmdTimeout(context.Background(), defaultDaemonCmdTimeout, "ps", "-p", strconv.Itoa(pid), "-o", "command="); cErr == nil {
			if IsConflictingSingctlSubcommand(strings.Fields(string(cmdOut))) {
				return false
			}
		}
		return true
	}

	return true
}

// ProcessExists 检查进程是否存在（跨平台，自动过滤僵尸态进程）。
func ProcessExists(pid int) bool {
	return proc.IsAlive(pid)
}

// StopDaemon 优雅停止守护进程并清理 PID 与内嵌状态文件。
func StopDaemon() error {
	pid, err := ReadDaemonPid()
	if err != nil {
		_ = RemoveWebEmbeddedFileAt(GetWebEmbeddedPath())
		return nil
	}
	if !DaemonProcessMatches(pid) {
		_ = RemovePidFile()
		_ = RemoveWebEmbeddedFileAt(GetWebEmbeddedPath())
		return nil
	}
	_ = proc.TerminateGracefully(pid, 5*time.Second, 3*time.Second)
	_ = RemovePidFile()
	_ = RemoveWebEmbeddedFileAt(GetWebEmbeddedPath())
	return nil
}

// IsDaemonBinaryStale 检测运行中的看门狗进程是否指向已被覆盖删除的旧版二进制。
func IsDaemonBinaryStale() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	pid, err := ReadDaemonPid()
	if err != nil || !DaemonProcessMatches(pid) {
		return false
	}
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	return strings.HasSuffix(link, " (deleted)") || strings.HasSuffix(link, ".backup")
}

// NotifyReload 向运行中的看门狗进程发送 SIGHUP，通知其立即热重载磁盘最新配置。
func NotifyReload() bool {
	pid, err := ReadDaemonPid()
	if err != nil || !DaemonProcessMatches(pid) {
		return false
	}
	return notifyPidReload(pid)
}

// RestartDaemon 平滑重启看门狗守护进程（不影响运行中的 sing-box 透明代理）。
func RestartDaemon(configPath string) error {
	if IsDaemonRunning() {
		if err := StopDaemon(); err != nil {
			return err
		}
	}
	exe, err := updater.ResolveExecutablePath()
	if err != nil {
		return err
	}
	var args []string
	if strings.TrimSpace(configPath) != "" {
		args = append(args, "--config", configPath)
	}
	args = append(args, "dm", "start")
	var devNull *os.File
	if nFile, nErr := os.OpenFile(os.DevNull, os.O_RDWR, 0); nErr == nil {
		devNull = nFile
		defer nFile.Close()
	}
	cleanEnv := BuildCleanSubprocessEnv(os.Environ(), "LC_ALL=C")
	return execx.RunIO(context.Background(), defaultDaemonRunTimeout, cleanEnv, devNull, os.Stdout, os.Stderr, exe, args...)
}

// IsSingBoxRunning 检查 sing-box 进程是否运行。
func IsSingBoxRunning() bool {
	if runtime.GOOS == "windows" {
		output, err := OutputCmdTimeout(context.Background(), defaultDaemonCmdTimeout, "tasklist", "/FI", "IMAGENAME eq sing-box.exe", "/NH")
		if err != nil {
			return false
		}
		return bytes.Contains(output, []byte("sing-box.exe"))
	}
	return proc.PgrepMatch("sing-box")
}
