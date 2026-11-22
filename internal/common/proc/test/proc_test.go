// 文件职责：验证 proc 包的硬链接 PID 锁、跨平台存活/僵尸检测与分离进程属性。
package proc_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"singctl/internal/common/proc"
)

func TestAcquireLinkLock_ConcurrencyAndStaleRecovery(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "daemon.pid")

	// Pre-populate stale lock file -> holder not alive -> must auto-recover
	if err := os.WriteFile(lockPath, []byte("999999"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := proc.AcquireLinkLock(lockPath, []byte("1001"), func() bool { return false }); err != nil {
		t.Fatalf("expected stale lock recovery, got %v", err)
	}
	st, err := os.Stat(lockPath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 lock file, got %v (%v)", st, err)
	}

	// Active holder -> must return ErrLockHeld
	if err := proc.AcquireLinkLock(lockPath, []byte("1002"), func() bool { return true }); !errors.Is(err, proc.ErrLockHeld) {
		t.Fatalf("expected ErrLockHeld when holder is alive, got %v", err)
	}

	// High-concurrency race to claim a fresh lock: exactly 1 winner
	freshLock := filepath.Join(t.TempDir(), "race.pid")
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			err := proc.AcquireLinkLock(freshLock, []byte("winner"), func() bool { return true })
			if err == nil {
				winners.Add(1)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("expected exactly 1 lock winner under contention, got %d", winners.Load())
	}
}

func TestIsAlive_SetDetachedAttr_TerminateGracefully_Pgrep(t *testing.T) {
	if proc.IsAlive(0) || proc.IsAlive(-5) {
		t.Fatal("non-positive PID must not be alive")
	}
	if !proc.IsAlive(os.Getpid()) {
		t.Fatal("current process must be alive")
	}
	_ = proc.ReadCmdline(os.Getpid())
	_ = proc.PgrepMatch("definitely-nonexistent-proc-xyz-999")

	if runtime.GOOS == "windows" {
		return
	}

	cmd := exec.Command("/bin/sleep", "30")
	proc.SetDetachedAttr(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SetDetachedAttr did not populate SysProcAttr")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	// Reap child in background so it doesn't stay zombie when killed
	go func() { _ = cmd.Wait() }()

	if !proc.IsAlive(pid) {
		t.Fatalf("spawned sleep child pid=%d should be alive", pid)
	}
	if err := proc.TerminateGracefully(pid, 2*time.Second, time.Second); err != nil {
		t.Fatalf("TerminateGracefully failed: %v", err)
	}
	if !proc.WaitExit(pid, time.Second) {
		t.Fatalf("expected pid=%d to exit after TerminateGracefully", pid)
	}
}
