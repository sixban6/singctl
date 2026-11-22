// 文件职责：实现 Safe Commit 脱离进程组看门狗子进程拉起（stdin/stdout/stderr 重定向至 watch.log）、令牌安全校验与防 PID 复用回收。
package safecommit

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"singctl/internal/common/proc"
)

func (m *Manager) spawnDefaultWatcher(token string) (int, error) {
	if err := validateTokenFormat(token); err != nil {
		return 0, err
	}
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("resolve executable: %w", err)
	}
	if err := m.ensureStateDir(); err != nil {
		return 0, err
	}

	logPath := filepath.Join(m.stateDir, watchLogFileName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return 0, fmt.Errorf("open watcher log: %w", err)
	}
	_ = os.Chmod(logPath, 0600)

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		_ = logFile.Close()
		return 0, fmt.Errorf("open devnull: %w", err)
	}

	cmd := exec.Command(exe, "safe-commit", "_watch", "--token", token)
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	setWatcherDetached(cmd)

	startErr := cmd.Start()
	_ = devNull.Close()
	_ = logFile.Close()
	if startErr != nil {
		return 0, fmt.Errorf("start watcher process: %w", startErr)
	}
	pid := cmd.Process.Pid
	// 后台回收子进程防止长驻 WebUI 累积僵尸进程；若父进程先行退出则由 init/procd 接管。
	go func() {
		_ = cmd.Wait()
	}()
	return pid, nil
}

func defaultKillWatcher(pid int) error {
	if pid <= 0 || pid == os.Getpid() || !proc.IsAlive(pid) {
		return nil
	}
	cmdline := proc.ReadCmdline(pid)
	if !slices.Contains(cmdline, "safe-commit") || !slices.Contains(cmdline, "_watch") {
		return nil
	}
	return proc.TerminateGracefully(pid, 2*time.Second, time.Second)
}

func validateTokenFormat(token string) error {
	if token == "" || len(token) > 128 {
		return errors.New("invalid watcher token length")
	}
	for i := range len(token) {
		c := token[i]
		isValid := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_'
		if !isValid {
			return fmt.Errorf("invalid character in watcher token")
		}
	}
	return nil
}
