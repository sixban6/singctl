package serverweb

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"singctl/internal/logger"
	"singctl/internal/updater"
)

const (
	envServerWebBackground = "SINGCTL_SERVER_WEB_BACKGROUND"
	serverWebReadyFd       = 3
	serverWebStateName     = "singctl-serverweb.pid"
	serverWebLogName       = "singctl-serverweb.log"
)

type serverWebState struct {
	Pid    int    `json:"pid"`
	Listen string `json:"listen"`
}

var errServerWebAlreadyRunning = errors.New("server web already running")

// ServerWebStatePath 状态文件路径
func ServerWebStatePath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), serverWebStateName)
	}
	return filepath.Join("/tmp", serverWebStateName)
}

// ServerWebLogPath 后台运行日志路径
func ServerWebLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), serverWebLogName)
	}
	return filepath.Join("/tmp", serverWebLogName)
}

// IsBackgroundChild 当前进程是否为后台子进程
func IsBackgroundChild() bool {
	return os.Getenv(envServerWebBackground) == "1"
}

func readState() (serverWebState, error) {
	data, err := os.ReadFile(ServerWebStatePath())
	if err != nil {
		return serverWebState{}, err
	}
	var st serverWebState
	if err := json.Unmarshal(data, &st); err != nil {
		return serverWebState{}, err
	}
	return st, nil
}

func writeStateAtomic(st serverWebState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	path := ServerWebStatePath()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// StartBackground 在后台拉起服务
func StartBackground(opts Options) error {
	st, running := ServerWebStatus()
	if running {
		logger.Warn("服务端 WebUI 已在运行中 (pid=%d, listen=%s)", st.Pid, st.Listen)
		return nil
	}

	execPath, err := updater.ResolveExecutablePath()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	logFile, err := os.OpenFile(ServerWebLogPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer logFile.Close()

	rPipe, wPipe, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("failed to create handshake pipe: %w", err)
	}
	defer rPipe.Close()

	args := make([]string, 0, len(os.Args))
	for _, arg := range os.Args[1:] {
		if arg == "restart" || arg == "r" {
			args = append(args, "start")
		} else {
			args = append(args, arg)
		}
	}
	cmd := exec.Command(execPath, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.ExtraFiles = []*os.File{wPipe}
	cmd.Env = append(os.Environ(), envServerWebBackground+"=1")

	if err := cmd.Start(); err != nil {
		_ = wPipe.Close()
		return fmt.Errorf("failed to spawn child process: %w", err)
	}
	_ = wPipe.Close()

	buf := make([]byte, 256)
	_ = rPipe.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := rPipe.Read(buf)
	if err != nil {
		return fmt.Errorf("child failed to report readiness (check log: %s): %w", ServerWebLogPath(), err)
	}

	listenAddr := strings.TrimSpace(string(buf[:n]))
	_ = writeStateAtomic(serverWebState{Pid: cmd.Process.Pid, Listen: listenAddr})

	logger.Success("服务端 WebUI 已在后台启动 (pid=%d)", cmd.Process.Pid)
	logger.Info("  ➜  http://%s", listenAddr)
	return nil
}

// ChildReady 子进程 Listen 成功后的回调
func ChildReady(listenAddr string) {
	// 立即清除后台子进程标记环境变量，防止后续 Web 触发自愈执行 singctl sr web restart 时继承该变量而跳过重启
	_ = os.Unsetenv(envServerWebBackground)
	pipe := os.NewFile(uintptr(serverWebReadyFd), "serverWebReadyPipe")
	if pipe != nil {
		_, _ = pipe.WriteString(listenAddr)
		_ = pipe.Close()
	}
}

// StopServerWeb 停止后台服务
func StopServerWeb() (bool, error) {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		_ = exec.Command("systemctl", "stop", "singctl-serverweb.service").Run()
	}

	st, running := ServerWebStatus()
	if !running {
		_ = os.Remove(ServerWebStatePath())
		return false, nil
	}

	proc, err := os.FindProcess(st.Pid)
	if err != nil {
		_ = os.Remove(ServerWebStatePath())
		return false, nil
	}

	_ = proc.Signal(syscall.SIGTERM)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := proc.Signal(syscall.Signal(0)); err != nil {
			_ = os.Remove(ServerWebStatePath())
			return true, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	_ = proc.Kill()
	_ = os.Remove(ServerWebStatePath())
	return true, nil
}

// ServerWebStatus 检查后台运行状态
func ServerWebStatus() (serverWebState, bool) {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		out, err := exec.Command("systemctl", "is-active", "singctl-serverweb.service").Output()
		if err == nil && strings.TrimSpace(string(out)) == "active" {
			return serverWebState{Pid: 1, Listen: "127.0.0.1:8092"}, true
		}
	}

	st, err := readState()
	if err != nil || st.Pid <= 0 {
		return serverWebState{}, false
	}

	proc, err := os.FindProcess(st.Pid)
	if err != nil {
		return serverWebState{}, false
	}
	if err := proc.Signal(syscall.Signal(0)); err != nil {
		return serverWebState{}, false
	}
	return st, true
}

// InstallSystemdService 安装并启动系统级 systemd 守护进程
func InstallSystemdService(cfgPath string) error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	execPath, err := updater.ResolveExecutablePath()
	if err != nil || strings.TrimSpace(execPath) == "" {
		execPath = "/usr/local/bin/singctl"
	}
	content := fmt.Sprintf(`[Unit]
Description=SingCtl Server Admin WebUI
After=network.target caddy.service

[Service]
Type=simple
ExecStart=%s -c %s sr web
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`, execPath, cfgPath)

	servicePath := "/etc/systemd/system/singctl-serverweb.service"
	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	_ = exec.Command("systemctl", "enable", "--now", "singctl-serverweb.service").Run()
	return nil
}

// UninstallSystemdService 卸载 systemd 服务
func UninstallSystemdService() error {
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	_ = exec.Command("systemctl", "stop", "singctl-serverweb.service").Run()
	_ = exec.Command("systemctl", "disable", "singctl-serverweb.service").Run()
	_ = os.Remove("/etc/systemd/system/singctl-serverweb.service")
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}
