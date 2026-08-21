package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// killPid 尽力杀死指定进程（测试清理用）
func killPid(pid int) {
	if proc, err := os.FindProcess(pid); err == nil {
		_ = proc.Signal(syscall.SIGKILL)
	}
}

// withTestPaths 将 PID/状态文件重定向到临时目录
func withTestPaths(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	pidFilePathOverride = filepath.Join(dir, pidFileName)
	stateFilePathOverride = filepath.Join(dir, stateFileName)
	t.Cleanup(func() {
		pidFilePathOverride = ""
		stateFilePathOverride = ""
	})
}

func TestAcquirePidLock_ExcludesConcurrentStarts(t *testing.T) {
	withTestPaths(t)

	if err := acquirePidLock(); err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// 第二个启动者必须被拒绝
	if err := acquirePidLock(); err == nil {
		t.Fatal("expected second acquire to fail with errDaemonAlreadyRunning")
	} else if err != errDaemonAlreadyRunning {
		t.Fatalf("expected errDaemonAlreadyRunning, got %v", err)
	}

	// IsDaemonRunning 应为 true（当前测试进程就是持锁的 singctl 进程）
	if !IsDaemonRunning() {
		t.Error("expected IsDaemonRunning true while holding lock")
	}

	_ = RemovePidFile()
	if IsDaemonRunning() {
		t.Error("expected IsDaemonRunning false after lock removed")
	}
}

func TestAcquirePidLock_CleansStaleLock(t *testing.T) {
	withTestPaths(t)

	// 写入一个已死亡进程的 PID（1 号进程可能存活，用一个大号 PID 更可靠）
	if err := os.WriteFile(getPidFilePath(), []byte("99999999"), 0644); err != nil {
		t.Fatal(err)
	}

	// 残留锁应被清除并成功获取
	if err := acquirePidLock(); err != nil {
		t.Fatalf("expected stale lock to be cleaned, got %v", err)
	}
	_ = RemovePidFile()
}

func TestAcquirePidLock_Concurrent(t *testing.T) {
	withTestPaths(t)

	const n = 8
	var mu sync.Mutex
	var acquired int
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := acquirePidLock(); err == nil {
				mu.Lock()
				acquired++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if acquired != 1 {
		t.Fatalf("expected exactly 1 winner under concurrency, got %d", acquired)
	}
}

func TestDaemonProcessMatches_PIDReuse(t *testing.T) {
	withTestPaths(t)

	// 找一个肯定不是 singctl 的进程：sleep
	sleep := exec.Command("sleep", "30")
	if err := sleep.Start(); err != nil {
		t.Skip("sleep not available")
	}
	defer sleep.Process.Kill()
	defer sleep.Wait()

	// PID 被无关进程复用 → 不应被认作守护进程
	if daemonProcessMatches(sleep.Process.Pid) {
		t.Errorf("pid %d (sleep) should not match daemon process name", sleep.Process.Pid)
	}
	// 但进程本身是存在的
	if !ProcessExists(sleep.Process.Pid) {
		t.Error("process should exist")
	}
}

func TestWritePidFile_Atomic(t *testing.T) {
	withTestPaths(t)

	if err := WritePidFile(); err != nil {
		t.Fatal(err)
	}
	pid, err := ReadDaemonPid()
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Errorf("expected pid %d, got %d", os.Getpid(), pid)
	}
}

func TestStopDaemon_WaitsForExit(t *testing.T) {
	withTestPaths(t)

	// 通过孤儿化的后台进程伪装守护进程：避免测试进程成为其父进程
	// （未收尸的僵尸会让 Signal(0) 误报存活；生产中守护进程由 init 收尸）
	out, err := exec.Command("sh", "-c", "sleep 30 >/dev/null 2>&1 & echo $!").Output()
	if err != nil {
		t.Skip("sh not available")
	}
	sleepPid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("failed to parse fake daemon pid: %v", err)
	}
	t.Cleanup(func() { killPid(sleepPid) })

	// 进程名校验会拒绝非 singctl 进程，这里通过钩子放宽
	oldName := expectedProcNameFn
	expectedProcNameFn = func() string { return "sleep" }
	t.Cleanup(func() { expectedProcNameFn = oldName })

	if err := os.WriteFile(getPidFilePath(), []byte(strconv.Itoa(sleepPid)), 0644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := StopDaemon(); err != nil {
		t.Fatalf("StopDaemon failed: %v", err)
	}
	elapsed := time.Since(start)

	// 进程应已退出，且是“等待退出”而不是等满超时
	if ProcessExists(sleepPid) {
		t.Error("process should have exited after StopDaemon")
	}
	if elapsed > 3*time.Second {
		t.Errorf("StopDaemon took %v; expected fast graceful exit", elapsed)
	}
	// PID 文件应被清理
	if _, err := os.Stat(getPidFilePath()); !os.IsNotExist(err) {
		t.Error("pid file should be removed after stop")
	}
}

func TestRestartLimiter_PersistsAcrossInstances(t *testing.T) {
	withTestPaths(t)

	// 守护进程侧：记录两次重启
	rl := NewRestartLimiter()
	rl.RecordRestart()
	rl.RecordRestart()
	if rl.GetRestartCount() != 2 {
		t.Fatalf("expected 2 restarts, got %d", rl.GetRestartCount())
	}

	// 外部观察者侧（dm status）：从状态文件恢复计数
	loaded := NewRestartLimiterFromState(0)
	if loaded.GetRestartCount() != 2 {
		t.Errorf("expected 2 restarts restored from state file, got %d", loaded.GetRestartCount())
	}
	if loaded.GetMaxRestarts() != DefaultMaxRestarts {
		t.Errorf("expected default max %d when max=0, got %d", DefaultMaxRestarts, loaded.GetMaxRestarts())
	}

	// 配置自定义上限
	custom := NewRestartLimiterFromState(7)
	if custom.GetMaxRestarts() != 7 {
		t.Errorf("expected max 7, got %d", custom.GetMaxRestarts())
	}
}

func TestRestartLimiter_ZeroTimestampsIgnored(t *testing.T) {
	withTestPaths(t)

	// 写入一个窗口外的旧时间戳
	old := time.Now().Add(-2 * time.Hour).Unix()
	if err := os.WriteFile(getStateFilePath(), []byte("["+strconv.FormatInt(old, 10)+"]"), 0644); err != nil {
		t.Fatal(err)
	}

	loaded := NewRestartLimiterFromState(0)
	if loaded.GetRestartCount() != 0 {
		t.Errorf("expected expired entries pruned, got %d", loaded.GetRestartCount())
	}
	if !loaded.CanRestart() {
		t.Error("expected CanRestart true with only expired entries")
	}
}
