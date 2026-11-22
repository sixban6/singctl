// 文件职责：提供跨平台硬链接 PID 锁、就绪管道等待、防僵尸态进程存活判定、优雅终止与 BusyBox 兼容 pgrep。
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"singctl/internal/common/execx"
)

var (
	// ErrChildExited 表示后台子进程在写入就绪握手信号前已异常退出或汇报失败。
	ErrChildExited = errors.New("child process exited before ready signal")
	// ErrLockHeld 表示目标状态/PID 锁已被另一个存活进程持有。
	ErrLockHeld = errors.New("process lock already held")
)

// WaitReadyPipe 在指定超时内等待后台子进程从管道写回 1 字节成功信号。
func WaitReadyPipe(r *os.File, timeout time.Duration) error {
	if r == nil {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ch := make(chan error, 1)
	go func() {
		var buf [1]byte
		n, err := r.Read(buf[:])
		switch {
		case n > 0 && buf[0] == 1:
			ch <- nil
		case n > 0:
			ch <- fmt.Errorf("%w: status byte %d", ErrChildExited, buf[0])
		case err != nil:
			ch <- ErrChildExited
		default:
			ch <- ErrChildExited
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-ch:
		return err
	case <-timer.C:
		return fmt.Errorf("timeout waiting for child ready signal after %s", timeout)
	}
}

// AcquireLinkLock 通过同目录 0600 随机临时文件 + os.Link 原子抢占互斥状态锁。
// 若目标锁文件已存在，调用 isHolderAlive 判定持有者是否仍存活；已死残留锁会自动清理并重试一次。
func AcquireLinkLock(targetPath string, payload []byte, isHolderAlive func() bool) error {
	cleanTarget := strings.TrimSpace(targetPath)
	if cleanTarget == "" {
		return errors.New("empty lock file path")
	}
	dir := filepath.Dir(cleanTarget)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("mkdir lock dir: %w", err)
		}
	}

	tmpFile, err := os.CreateTemp(dir, "."+filepath.Base(cleanTarget)+".lock-*")
	if err != nil {
		return fmt.Errorf("create lock temp file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if _, err := tmpFile.Write(payload); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write lock temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	for range 2 {
		err := os.Link(tmpName, cleanTarget)
		if err == nil {
			_ = os.Chmod(cleanTarget, 0600)
			return nil
		}
		if !os.IsExist(err) {
			return fmt.Errorf("claim link lock %s: %w", cleanTarget, err)
		}
		if isHolderAlive != nil && isHolderAlive() {
			return ErrLockHeld
		}
		_ = os.Remove(cleanTarget)
	}
	return ErrLockHeld
}

// IsAlive 检查指定 PID 是否真实存活（显式过滤 Linux /proc/<pid>/stat 与 macOS ps 中的 Z 僵尸态进程）。
func IsAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
			if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) {
				if b[i+2] == 'Z' {
					return false
				}
			}
		}
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if p.Signal(syscall.Signal(0)) != nil {
		return false
	}
	if runtime.GOOS == "darwin" {
		if out, err := execx.Output(context.Background(), execx.DefaultProbeTimeout, "ps", "-p", strconv.Itoa(pid), "-o", "stat="); err == nil {
			return !strings.Contains(strings.TrimSpace(string(out)), "Z")
		}
	}
	return true
}

// ReadCmdline 读取指定 PID 的命令行参数列表（Linux 走 /proc/<pid>/cmdline，macOS 走有界 ps）。
func ReadCmdline(pid int) []string {
	if pid <= 0 {
		return nil
	}
	if runtime.GOOS == "linux" {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil || len(raw) == 0 {
			return nil
		}
		trimmed := strings.TrimRight(string(raw), "\x00")
		if trimmed == "" {
			return nil
		}
		return strings.Split(trimmed, "\x00")
	}
	if runtime.GOOS == "darwin" {
		out, err := execx.Output(context.Background(), execx.DefaultProbeTimeout, "ps", "-p", strconv.Itoa(pid), "-o", "command=")
		if err != nil {
			return nil
		}
		return strings.Fields(string(out))
	}
	return nil
}

// TerminateGracefully 先发送 SIGTERM 等待进程在 graceTimeout 内退出，超时后升级为 SIGKILL 兜底回收。
func TerminateGracefully(pid int, graceTimeout, killTimeout time.Duration) error {
	if pid <= 0 || !IsAlive(pid) {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	sendSig := func(sig syscall.Signal) {
		if runtime.GOOS == "windows" {
			_ = p.Kill()
			return
		}
		_ = p.Signal(sig)
	}
	if graceTimeout <= 0 {
		graceTimeout = 5 * time.Second
	}
	if killTimeout <= 0 {
		killTimeout = 3 * time.Second
	}

	sendSig(syscall.SIGTERM)
	if WaitExit(pid, graceTimeout) {
		return nil
	}
	sendSig(syscall.SIGKILL)
	WaitExit(pid, killTimeout)
	return nil
}

// WaitExit 轮询等待目标 PID 退出，直至超时。
func WaitExit(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsAlive(pid) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return !IsAlive(pid)
}

// PgrepMatch 采用两级策略检查是否存在指定名称的进程（兼容 OpenWrt BusyBox `pgrep -x` 漏匹配怪癖）。
func PgrepMatch(name string) bool {
	if runtime.GOOS == "windows" || strings.TrimSpace(name) == "" {
		return false
	}
	if execx.Run(context.Background(), execx.DefaultProbeTimeout, "pgrep", "-x", name) == nil {
		return true
	}
	return execx.Run(context.Background(), execx.DefaultProbeTimeout, "pgrep", name) == nil
}
