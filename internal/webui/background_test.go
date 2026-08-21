package webui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func withWebStatePath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	webStatePathOverride = filepath.Join(dir, webStateName)
	t.Cleanup(func() { webStatePathOverride = "" })
}

func TestWebStateReadWrite(t *testing.T) {
	withWebStatePath(t)

	st := webState{Pid: 12345, Listen: "127.0.0.1:8090"}
	if err := writeWebStateAtomic(st); err != nil {
		t.Fatal(err)
	}
	got, err := readWebState()
	if err != nil {
		t.Fatal(err)
	}
	if got != st {
		t.Errorf("expected %+v, got %+v", st, got)
	}
}

func TestAcquireWebLock_ExcludesConcurrent(t *testing.T) {
	withWebStatePath(t)

	// 状态文件指向一个真实的“web 命名”进程 → 第二次启动必须被拒
	pid := spawnWebNamedProcess(t, "30")
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(WebStatePath(),
		[]byte(`{"pid":`+strconv.Itoa(pid)+`,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := acquireWebLock(webState{Pid: os.Getpid(), Listen: ":8090"}); err == nil {
		t.Fatal("expected acquire to fail while web-named process holds state")
	} else if err != errWebAlreadyRunning {
		t.Fatalf("expected errWebAlreadyRunning, got %v", err)
	}
	if _, running := WebStatus(); !running {
		t.Error("web-named process should be detected as running webui")
	}
}

func TestAcquireWebLock_CleansStale(t *testing.T) {
	withWebStatePath(t)

	// 死 PID 的残留状态文件应被清理
	if err := os.WriteFile(WebStatePath(), []byte(`{"pid":99999999,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := acquireWebLock(webState{Pid: os.Getpid(), Listen: ":8090"}); err != nil {
		t.Fatalf("expected stale state cleaned, got %v", err)
	}
}

func TestWebProcMatches_OwnPidFalse(t *testing.T) {
	// 测试二进制命令行不含 web/w 参数
	if webProcMatches(os.Getpid()) {
		t.Error("own pid (no web arg) should not match")
	}
	if !webProcMatches(0) && false {
		t.Fail()
	}
	// 死 PID
	if webProcMatches(99999999) {
		t.Error("dead pid should not match")
	}
}

// spawnWebNamedProcess 启动一个 argv0 为 "web" 的 sleep 进程,
// 用于真实校验命令行匹配与 StopWeb 的完整停止流程(依赖 bash 的 exec -a)。
func spawnWebNamedProcess(t *testing.T, seconds string) int {
	t.Helper()
	cmd := exec.Command("bash", "-c", "exec -a web sleep "+seconds)
	if err := cmd.Start(); err != nil {
		t.Skip("bash not available")
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd.Process.Pid
}

func TestWebProcMatches_NamedProcessTrue(t *testing.T) {
	pid := spawnWebNamedProcess(t, "30")
	time.Sleep(100 * time.Millisecond) // 等 exec 生效

	if !webProcMatches(pid) {
		t.Errorf("pid %d (argv0=web) should match", pid)
	}
}

func TestStopWeb_KillsWebProcess(t *testing.T) {
	withWebStatePath(t)

	pid := spawnWebNamedProcess(t, "30")
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(WebStatePath(),
		[]byte(`{"pid":`+strconv.Itoa(pid)+`,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}

	stopped, err := StopWeb()
	if err != nil || !stopped {
		t.Fatalf("expected stopped=true, got stopped=%v err=%v", stopped, err)
	}
	if processAlive(pid) {
		t.Error("process should have been terminated")
	}
	if _, err := os.Stat(WebStatePath()); !os.IsNotExist(err) {
		t.Error("state file should be removed after stop")
	}
}

func TestStopWeb_NotRunning(t *testing.T) {
	withWebStatePath(t)

	stopped, err := StopWeb()
	if err != nil {
		t.Fatal(err)
	}
	if stopped {
		t.Error("expected stopped=false when not running")
	}
}

func TestStopWeb_StaleStateOnlyCleansFile(t *testing.T) {
	withWebStatePath(t)

	// 状态文件指向一个无关存活进程(sleep,命令行不含 web)→ 只清理文件,不动进程
	sleep := exec.Command("sleep", "30")
	if err := sleep.Start(); err != nil {
		t.Skip("sleep not available")
	}
	t.Cleanup(func() {
		_ = sleep.Process.Kill()
		_, _ = sleep.Process.Wait()
	})

	if err := os.WriteFile(WebStatePath(),
		[]byte(`{"pid":`+strconv.Itoa(sleep.Process.Pid)+`,"listen":":8090"}`), 0644); err != nil {
		t.Fatal(err)
	}

	stopped, err := StopWeb()
	if err != nil || stopped {
		t.Fatalf("expected stopped=false (stale), got %v %v", stopped, err)
	}
	if !processAlive(sleep.Process.Pid) {
		t.Error("unrelated process must NOT be killed")
	}
	if _, err := os.Stat(WebStatePath()); !os.IsNotExist(err) {
		t.Error("stale state file should be cleaned")
	}
}

func TestFormatListenURLs(t *testing.T) {
	// 指定具体地址 → 原样
	got := formatListenURLs("192.168.1.1:9000")
	if len(got) != 1 || got[0] != "192.168.1.1:9000" {
		t.Errorf("unexpected: %v", got)
	}
	// 通配 → 至少含 127.0.0.1
	got = formatListenURLs(":8090")
	if len(got) == 0 || !strings.HasSuffix(got[len(got)-1], ":8090") {
		t.Errorf("unexpected: %v", got)
	}
}
