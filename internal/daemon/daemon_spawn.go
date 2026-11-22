// 文件职责：负责守护进程后台分离派生（fork/ready-pipe 握手）及 0600 守护日志打开、轮转与清理。
package daemon

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"singctl/internal/common/proc"
	"singctl/internal/constant"
	"singctl/internal/logger"
	"strings"
	"time"
)

// BuildDaemonSpawnEnv 构造守护后台子进程的环境变量：
// 1. 去重设置 SINGCTL_DAEMONIZED=1；
// 2. 若父进程由 WebUI 触发（SINGCTL_FROM_WEBUI=1）或已携带 SINGCTL_DEFER_WEB_HANDOFF=1，
//    则显式透传 SINGCTL_DEFER_WEB_HANDOFF=1，让合体守护进程礼貌等待独立 WebUI 完成 HTTP 推流后让渡端口。
func BuildDaemonSpawnEnv(parentEnv []string) []string {
	out := make([]string, 0, len(parentEnv)+2)
	deferHandoff := false
	for _, kv := range parentEnv {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			out = append(out, kv)
			continue
		}
		if k == EnvFromWebUI && v == "1" {
			deferHandoff = true
		}
		if k == EnvDeferWebHandoff {
			if v == "1" {
				deferHandoff = true
			}
			continue
		}
		if k == envDaemonized {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, envDaemonized+"=1")
	if deferHandoff {
		out = append(out, EnvDeferWebHandoff+"=1")
	}
	return out
}

func (d *Daemon) closeLogFile() {
	d.logMu.Lock()
	if d.logFile != nil {
		_ = d.logFile.Close()
		d.logFile = nil
	}
	d.logMu.Unlock()
}

// spawn fork 后台子进程并等待就绪信号
func (d *Daemon) spawn() error {
	// Intentional bare exec.Command: detached background daemon child must outlive spawn().
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = BuildDaemonSpawnEnv(os.Environ())

	proc.SetDetachedAttr(cmd)

	devNull := "/dev/null"
	if runtime.GOOS == "windows" {
		devNull = "NUL"
	}
	nullFile, err := os.OpenFile(devNull, os.O_RDWR, 0)
	if err != nil {
		_ = RemovePidFile()
		return err
	}
	defer nullFile.Close()

	cmd.Stdin = nullFile
	cmd.Stdout = nullFile
	cmd.Stderr = nullFile

	var readyR *os.File
	if runtime.GOOS != "windows" {
		var readyW *os.File
		readyR, readyW, err = os.Pipe()
		if err == nil {
			cmd.ExtraFiles = []*os.File{readyW}
		}
	}

	if err := cmd.Start(); err != nil {
		logger.Error("failed to daemonize: %v", err)
		_ = RemovePidFile()
		return fmt.Errorf("failed to daemonize: %w", err)
	}

	if readyR == nil {
		logger.Success("Daemon started in background (pid=%d)", cmd.Process.Pid)
		return nil
	}

	if extra := cmd.ExtraFiles; len(extra) > 0 {
		_ = extra[0].Close()
	}

	err = waitReady(readyR, 10*time.Second)
	_ = readyR.Close()
	switch {
	case err == nil:
		logger.Success("Daemon started in background (pid=%d)", cmd.Process.Pid)
		return nil
	case errors.Is(err, errChildDied):
		_ = RemovePidFile()
		logger.Error("daemon child exited during startup")
		return err
	default:
		logger.Warn("daemon startup not confirmed within timeout; check %s", GetDaemonLogPath())
		return nil
	}
}

var errChildDied = proc.ErrChildExited

func waitReady(r *os.File, timeout time.Duration) error {
	return proc.WaitReadyPipe(r, timeout)
}

func notifyParentReady(ok bool) {
	proc.NotifyReadyPipeResult(readyFd, ok)
}
func (d *Daemon) effectiveMaxDaemonLogBytes() int64 {
	if d != nil && d.lowMemory {
		return MaxLowMemDaemonLogBytes
	}
	return MaxDaemonLogBytes
}

func (d *Daemon) effectiveWebLogPath() string {
	if d != nil && d.webLogOverride != "" {
		return d.webLogOverride
	}
	if d != nil && d.logPathOverride != "" {
		// 测试隔离了守护日志目录但未显式提供 WebLogFile 时，不触碰宿主机 /tmp/singctl-web.log
		return ""
	}
	return filepath.Join(defaultTempDir(), "singctl-web.log")
}

func (d *Daemon) setupLogFile() error {
	logPath := cmp.Or(d.logPathOverride, GetDaemonLogPath())
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	maxLogBytes := d.effectiveMaxDaemonLogBytes()
	_, _ = CleanAndTrimDaemonLog(logPath, maxLogBytes)
	if d.lowMemory {
		if webLog := d.effectiveWebLogPath(); webLog != "" {
			_, _ = TrimLogInPlace(webLog, MaxLowMemDaemonLogBytes)
		}
	}

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	_ = logFile.Chmod(0600)

	d.logMu.Lock()
	d.logFile = logFile
	if d.logPathOverride == "" {
		logger.SetOutput(logFile)
		logger.SetColor(false)
	}
	d.logMu.Unlock()

	return nil
}

func (d *Daemon) maybeRotateLogFile() {
	for _, sbLog := range []string{constant.SingBoxBasicLogFile, constant.SingBoxSimpleLogFile} {
		if sbLog != "" {
			_, _ = TrimLogInPlace(sbLog, MaxSingBoxLogBytes)
		}
	}
	if d.lowMemory {
		if webLog := d.effectiveWebLogPath(); webLog != "" {
			_, _ = TrimLogInPlace(webLog, MaxLowMemDaemonLogBytes)
		}
	}
	logPath := cmp.Or(d.logPathOverride, GetDaemonLogPath())
	trimmed, err := CleanAndTrimDaemonLog(logPath, d.effectiveMaxDaemonLogBytes())
	if err != nil || !trimmed {
		return
	}
	d.logMu.Lock()
	defer d.logMu.Unlock()
	newFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	_ = newFile.Chmod(0600)
	if d.logPathOverride == "" {
		logger.SetOutput(newFile)
	}
	if d.logFile != nil {
		_ = d.logFile.Close()
	}
	d.logFile = newFile
}
