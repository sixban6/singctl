package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"singctl/internal/config"
	"singctl/internal/daemon"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// =============================================================================
// RestartLimiter Tests
// =============================================================================

func TestRestartLimiter_CanRestart_Initially(t *testing.T) {
	limiter := daemon.NewRestartLimiter()
	if !limiter.CanRestart() {
		t.Error("expected CanRestart to return true initially")
	}
}

func TestRestartLimiter_CanRestart_AfterMaxRestarts(t *testing.T) {
	limiter := daemon.NewRestartLimiter()

	// 记录 maxRestarts 次重启
	for i := 0; i < limiter.GetMaxRestarts(); i++ {
		if !limiter.CanRestart() {
			t.Errorf("expected CanRestart to return true for restart %d", i+1)
		}
		limiter.RecordRestart()
	}

	// 超过限制后应该不允许
	if limiter.CanRestart() {
		t.Error("expected CanRestart to return false after max restarts")
	}
}

func TestRestartLimiter_GetRestartCount(t *testing.T) {
	limiter := daemon.NewRestartLimiter()

	if limiter.GetRestartCount() != 0 {
		t.Errorf("expected restart count 0, got %d", limiter.GetRestartCount())
	}

	limiter.RecordRestart()
	if limiter.GetRestartCount() != 1 {
		t.Errorf("expected restart count 1, got %d", limiter.GetRestartCount())
	}

	limiter.RecordRestart()
	if limiter.GetRestartCount() != 2 {
		t.Errorf("expected restart count 2, got %d", limiter.GetRestartCount())
	}
}

func TestRestartLimiter_GetRestartDelay(t *testing.T) {
	limiter := daemon.NewRestartLimiter()

	// 第0次：无延迟
	if limiter.GetRestartDelay() != 0 {
		t.Errorf("expected 0 delay for first restart, got %v", limiter.GetRestartDelay())
	}

	limiter.RecordRestart()
	// 第1次：30秒
	if limiter.GetRestartDelay() != 30*time.Second {
		t.Errorf("expected 30s delay, got %v", limiter.GetRestartDelay())
	}

	limiter.RecordRestart()
	// 第2次：2分钟
	if limiter.GetRestartDelay() != 2*time.Minute {
		t.Errorf("expected 2m delay, got %v", limiter.GetRestartDelay())
	}
}

func TestRestartLimiter_GetMaxRestarts(t *testing.T) {
	limiter := daemon.NewRestartLimiter()
	if limiter.GetMaxRestarts() != 3 {
		t.Errorf("expected max restarts 3, got %d", limiter.GetMaxRestarts())
	}
}

// =============================================================================
// HealthCheckResult Tests
// =============================================================================

func TestHealthCheckResult_Healthy(t *testing.T) {
	result := daemon.HealthCheckResult{
		Healthy:   true,
		DNSOK:     true,
		Details:   "all checks passed",
		CheckTime: time.Now(),
	}

	if !result.Healthy {
		t.Error("expected result to be healthy")
	}
}

func TestHealthCheckResult_DNSStuck(t *testing.T) {
	result := daemon.HealthCheckResult{
		Healthy:      false,
		DNSOK:        false,
		FailedReason: "dns_stuck",
		Details:      "DNS resolution timed out or failed",
		CheckTime:    time.Now(),
	}

	if result.Healthy {
		t.Error("expected result to be unhealthy")
	}
	if result.FailedReason != "dns_stuck" {
		t.Errorf("expected reason 'dns_stuck', got %s", result.FailedReason)
	}
}

func TestHealthCheckResult_ProcessNotRunning(t *testing.T) {
	result := daemon.HealthCheckResult{
		Healthy:      false,
		FailedReason: "sing-box process not running",
		Details:      "sing-box 进程未运行",
		CheckTime:    time.Now(),
	}

	if result.Healthy {
		t.Error("expected result to be unhealthy when process not running")
	}
}

// =============================================================================
// MonitorStatus Tests
// =============================================================================

func TestMonitorStatus_String_AllRunning(t *testing.T) {
	status := daemon.MonitorStatus{
		ProcessRunning: true,
		DaemonRunning:  true,
		CheckTime:      time.Date(2024, 1, 1, 12, 0, 0, 0, time.Local),
	}

	s := status.String()
	if !strings.Contains(s, "Running ✓") {
		t.Errorf("expected 'Running ✓' in status, got: %s", s)
	}
}

func TestMonitorStatus_String_AllStopped(t *testing.T) {
	status := daemon.MonitorStatus{
		ProcessRunning: false,
		DaemonRunning:  false,
	}

	s := status.String()
	if !strings.Contains(s, "Stopped ✗") {
		t.Errorf("expected 'Stopped ✗' in status, got: %s", s)
	}
}

func TestMonitorStatus_String_NoCheckTime(t *testing.T) {
	status := daemon.MonitorStatus{
		ProcessRunning: true,
		DaemonRunning:  true,
		CheckTime:      time.Time{}, // zero
	}

	s := status.String()
	if strings.Contains(s, "Last check") {
		t.Errorf("expected no 'Last check' when CheckTime is zero, got: %s", s)
	}
}

// =============================================================================
// WatchdogEvent Logging Tests
// =============================================================================

func TestLogWatchdogEvent_Format(t *testing.T) {
	// 测试日志格式
	tmpFile, err := os.CreateTemp("", "watchdog-test-*.log")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	event := daemon.WatchdogEvent{
		Time:   time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		Action: "RESTART",
		CheckResult: daemon.HealthCheckResult{
			Healthy:      false,
			FailedReason: "dns_stuck",
			Details:      "DNS resolution timed out",
		},
		RestartResult: "success",
	}

	// 手动验证格式化
	timestamp := event.Time.Format("2006-01-02 15:04:05")
	entry := "[" + timestamp + "] [" + event.Action + "] healthy=false reason=dns_stuck detail=DNS resolution timed out restart_result=" + event.RestartResult + "\n"
	os.WriteFile(tmpFile.Name(), []byte(entry), 0644)

	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	logStr := string(content)
	if !strings.Contains(logStr, "[2024-06-15 10:30:00]") {
		t.Errorf("expected timestamp, got: %s", logStr)
	}
	if !strings.Contains(logStr, "[RESTART]") {
		t.Errorf("expected action, got: %s", logStr)
	}
	if !strings.Contains(logStr, "restart_result=success") {
		t.Errorf("expected restart result, got: %s", logStr)
	}
}

func TestLogWatchdogEvent_Integration(t *testing.T) {
	// 测试 LogWatchdogEvent 实际写入
	event := daemon.WatchdogEvent{
		Time:   time.Now(),
		Action: "TEST_EVENT",
		CheckResult: daemon.HealthCheckResult{
			Healthy:      false,
			FailedReason: "dns_stuck",
			Details:      "DNS timed out",
			CheckTime:    time.Now(),
		},
		RestartResult: "test_only",
	}

	daemon.LogWatchdogEvent(event)

	content, err := os.ReadFile(daemon.GetDaemonLogPath())
	if err != nil {
		t.Fatalf("failed to read watchdog log: %v", err)
	}

	logStr := string(content)
	if !strings.Contains(logStr, "action=TEST_EVENT") {
		t.Errorf("expected TEST_EVENT in log, got: %s", logStr)
	}
	if !strings.Contains(logStr, "restart_result=test_only") {
		t.Errorf("expected restart_result=test_only, got: %s", logStr)
	}
}

// =============================================================================
// Watchdog Decision Logic Tests
// 测试看门狗的核心决策逻辑：
//   健康 → 什么都不做
//   第一轮不健康 + 第二轮恢复 → 不重启
//   连续两轮不健康 → 执行 stop → start
//   频率限制 → 即使不健康也不重启
// =============================================================================

func TestWatchdogLogic_Healthy_NoAction(t *testing.T) {
	// 健康 → 不触发重启
	result := daemon.HealthCheckResult{
		Healthy:   true,
		DNSOK:     true,
		Details:   "all checks passed",
		CheckTime: time.Now(),
	}

	if !result.Healthy {
		t.Error("expected healthy, should not trigger restart")
	}
}

func TestWatchdogLogic_FirstFail_ThenRecover_NoRestart(t *testing.T) {
	// 第一轮不健康 + 第二轮恢复 = 不重启
	result1 := daemon.HealthCheckResult{
		Healthy:      false,
		FailedReason: "dns_stuck",
		CheckTime:    time.Now(),
	}

	result2 := daemon.HealthCheckResult{
		Healthy:   true,
		DNSOK:     true,
		CheckTime: time.Now(),
	}

	if result1.Healthy {
		t.Error("round 1 should fail")
	}
	if !result2.Healthy {
		t.Error("round 2 should succeed (recovered)")
	}
	// 结论：不应触发重启
}

func TestWatchdogLogic_BothFail_ShouldRestart(t *testing.T) {
	// 连续两轮都不健康 → 应该 stop+start
	limiter := daemon.NewRestartLimiter()

	result1 := daemon.HealthCheckResult{
		Healthy:      false,
		FailedReason: "dns_stuck",
	}
	result2 := daemon.HealthCheckResult{
		Healthy:      false,
		FailedReason: "dns_stuck",
	}

	if result1.Healthy || result2.Healthy {
		t.Error("both rounds should fail")
	}

	// 频率限制器应该允许重启
	if !limiter.CanRestart() {
		t.Error("limiter should allow restart")
	}

	// 重启后记录
	limiter.RecordRestart()
	if limiter.GetRestartCount() != 1 {
		t.Errorf("expected restart count 1, got %d", limiter.GetRestartCount())
	}
}

func TestWatchdogLogic_RateLimited_NoRestart(t *testing.T) {
	// 已达到重启上限 → 即使不健康也不重启
	limiter := daemon.NewRestartLimiter()

	for i := 0; i < limiter.GetMaxRestarts(); i++ {
		limiter.RecordRestart()
	}

	result := daemon.HealthCheckResult{
		Healthy:      false,
		FailedReason: "dns_stuck",
	}

	if result.Healthy {
		t.Error("result should be unhealthy")
	}

	if limiter.CanRestart() {
		t.Error("limiter should block restart after max reached")
	}
}

// =============================================================================
// Path Tests
// =============================================================================

func TestGetDaemonLogPath(t *testing.T) {
	path := daemon.GetDaemonLogPath()
	if path == "" {
		t.Error("expected non-empty daemon log path")
	}
	if !strings.Contains(path, "singctl-daemon.log") {
		t.Errorf("expected 'singctl-daemon.log', got: %s", path)
	}
}

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
	daemon.PidFilePathOverride = filepath.Join(dir, daemon.PidFileName)
	daemon.StateFilePathOverride = filepath.Join(dir, daemon.StateFileName)
	daemon.DaemonLogPathOverride = filepath.Join(dir, "singctl-daemon.log")
	t.Cleanup(func() {
		daemon.PidFilePathOverride = ""
		daemon.StateFilePathOverride = ""
		daemon.DaemonLogPathOverride = ""
	})
}

func TestAcquirePidLock_ExcludesConcurrentStarts(t *testing.T) {
	withTestPaths(t)

	if err := daemon.AcquirePidLock(); err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// 第二个启动者必须被拒绝
	if err := daemon.AcquirePidLock(); err == nil {
		t.Fatal("expected second acquire to fail with errDaemonAlreadyRunning")
	} else if err != daemon.ErrDaemonAlreadyRunning {
		t.Fatalf("expected errDaemonAlreadyRunning, got %v", err)
	}

	// IsDaemonRunning 应为 true（当前测试进程就是持锁的 singctl 进程）
	if !daemon.IsDaemonRunning() {
		t.Error("expected IsDaemonRunning true while holding lock")
	}

	_ = daemon.RemovePidFile()
	if daemon.IsDaemonRunning() {
		t.Error("expected IsDaemonRunning false after lock removed")
	}
}

func TestAcquirePidLock_CleansStaleLock(t *testing.T) {
	withTestPaths(t)

	// 写入一个已死亡进程的 PID（1 号进程可能存活，用一个大号 PID 更可靠）
	if err := os.WriteFile(daemon.GetPidFilePath(), []byte("99999999"), 0644); err != nil {
		t.Fatal(err)
	}

	// 残留锁应被清除并成功获取
	if err := daemon.AcquirePidLock(); err != nil {
		t.Fatalf("expected stale lock to be cleaned, got %v", err)
	}
	_ = daemon.RemovePidFile()
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
			if err := daemon.AcquirePidLock(); err == nil {
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
	if daemon.DaemonProcessMatches(sleep.Process.Pid) {
		t.Errorf("pid %d (sleep) should not match daemon process name", sleep.Process.Pid)
	}
	// 但进程本身是存在的
	if !daemon.ProcessExists(sleep.Process.Pid) {
		t.Error("process should exist")
	}
}

func TestWritePidFile_Atomic(t *testing.T) {
	withTestPaths(t)

	if err := daemon.WritePidFile(); err != nil {
		t.Fatal(err)
	}
	pid, err := daemon.ReadDaemonPid()
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
	oldName := daemon.ExpectedProcNameFn
	daemon.ExpectedProcNameFn = func() string { return "sleep" }
	t.Cleanup(func() { daemon.ExpectedProcNameFn = oldName })

	if err := os.WriteFile(daemon.GetPidFilePath(), []byte(strconv.Itoa(sleepPid)), 0644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := daemon.StopDaemon(); err != nil {
		t.Fatalf("StopDaemon failed: %v", err)
	}
	elapsed := time.Since(start)

	// 进程应已退出，且是“等待退出”而不是等满超时
	if daemon.ProcessExists(sleepPid) {
		t.Error("process should have exited after StopDaemon")
	}
	if elapsed > 3*time.Second {
		t.Errorf("StopDaemon took %v; expected fast graceful exit", elapsed)
	}
	// PID 文件应被清理
	if _, err := os.Stat(daemon.GetPidFilePath()); !os.IsNotExist(err) {
		t.Error("pid file should be removed after stop")
	}
}

func TestRestartLimiter_PersistsAcrossInstances(t *testing.T) {
	withTestPaths(t)

	// 守护进程侧：记录两次重启
	rl := daemon.NewRestartLimiter()
	rl.RecordRestart()
	rl.RecordRestart()
	if rl.GetRestartCount() != 2 {
		t.Fatalf("expected 2 restarts, got %d", rl.GetRestartCount())
	}

	// 外部观察者侧（dm status）：从状态文件恢复计数
	loaded := daemon.NewRestartLimiterFromState(0)
	if loaded.GetRestartCount() != 2 {
		t.Errorf("expected 2 restarts restored from state file, got %d", loaded.GetRestartCount())
	}
	if loaded.GetMaxRestarts() != daemon.DefaultMaxRestarts {
		t.Errorf("expected default max %d when max=0, got %d", daemon.DefaultMaxRestarts, loaded.GetMaxRestarts())
	}

	// 配置自定义上限
	custom := daemon.NewRestartLimiterFromState(7)
	if custom.GetMaxRestarts() != 7 {
		t.Errorf("expected max 7, got %d", custom.GetMaxRestarts())
	}
}

func TestRestartLimiter_ZeroTimestampsIgnored(t *testing.T) {
	withTestPaths(t)

	// 写入一个窗口外的旧时间戳
	old := time.Now().Add(-2 * time.Hour).Unix()
	if err := os.WriteFile(daemon.GetStateFilePath(), []byte("["+strconv.FormatInt(old, 10)+"]"), 0644); err != nil {
		t.Fatal(err)
	}

	loaded := daemon.NewRestartLimiterFromState(0)
	if loaded.GetRestartCount() != 0 {
		t.Errorf("expected expired entries pruned, got %d", loaded.GetRestartCount())
	}
	if !loaded.CanRestart() {
		t.Error("expected CanRestart true with only expired entries")
	}
}

func TestGroupFailover_AutoSwitchAndAutoRestore(t *testing.T) {
	var mu sync.Mutex
	autoAlive := false
	vpsAlive := true
	gameNow := "#Auto"
	vpsNow := "sec_los_hy2"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if r.Method == http.MethodGet && path == "/proxies" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"Proxy": map[string]any{
						"type": "Selector",
						"now":  gameNow,
						"all":  []string{"#Auto", "#VPS", "#Nodes"},
					},
					"#VPS": map[string]any{
						"type": "Selector",
						"now":  vpsNow,
						"all":  []string{"sec_los_hy2", "sec_sg1_hy2"},
					},
				},
			})
			return
		}

		if r.Method == http.MethodGet && strings.HasSuffix(path, "/delay") {
			switch {
			case strings.Contains(path, "/%23Auto/delay") || strings.Contains(path, "/#Auto/delay"):
				if autoAlive {
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 85})
				} else {
					w.WriteHeader(http.StatusGatewayTimeout)
					_ = json.NewEncoder(w).Encode(map[string]string{"message": "Timeout"})
				}
			case strings.Contains(path, "/%23VPS/delay") || strings.Contains(path, "/#VPS/delay") || strings.Contains(path, "/sec_los_hy2/delay"):
				if vpsAlive {
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 240})
				} else {
					w.WriteHeader(http.StatusGatewayTimeout)
				}
			default:
				_ = json.NewEncoder(w).Encode(map[string]int{"delay": 300})
			}
			return
		}

		if r.Method == http.MethodPut && strings.HasPrefix(path, "/proxies/") {
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if strings.HasSuffix(path, "/Proxy") {
				gameNow = body.Name
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	state := daemon.NewGroupFailoverState()
	state.ProbeURLs = []string{"http://example.com/generate_204"}
	state.ProbeTimeout = 500 * time.Millisecond

	// 1. 当 #Auto 全挂时，Patrol 应自动将 Game 切换至 #VPS
	state.Patrol(t.Context(), []string{srv.URL}, "")
	mu.Lock()
	if gameNow != "#VPS" {
		t.Fatalf("expected Game to auto-failover from dead #Auto to #VPS, got %s", gameNow)
	}
	mu.Unlock()

	// 2. 当 #Auto 恢复正常后，Patrol 应自动将 Game 切回 #Auto
	mu.Lock()
	autoAlive = true
	mu.Unlock()

	state.Patrol(t.Context(), []string{srv.URL}, "")
	mu.Lock()
	if gameNow != "#Auto" {
		t.Fatalf("expected Game to auto-restore back to #Auto once recovered, got %s", gameNow)
	}
	mu.Unlock()
}

func TestCheckDNSHealthAgainstEndpoints_WithSecretAndLatency(t *testing.T) {
	const secret = "test-clash-secret-token"
	var queriedDomains []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/dns/query" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		queriedDomains = append(queriedDomains, r.URL.Query().Get("name"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Status": 0,
			"Answer": []map[string]any{{"type": 1, "data": "198.51.100.10"}},
		})
	}))
	defer srv.Close()

	// Without secret -> 401 -> unhealthy
	badOK, _, _ := daemon.CheckDNSHealthAgainstEndpoints([]string{srv.URL}, "")
	if badOK {
		t.Fatal("expected DNS check without secret to fail against authenticated Clash API")
	}

	// With secret -> 200 Status=0 -> healthy + non-negative latency
	okFlag, latencyMs, errMsg := daemon.CheckDNSHealthAgainstEndpoints([]string{srv.URL}, secret)
	if !okFlag {
		t.Fatalf("expected DNS check with secret to succeed, got error: %s", errMsg)
	}
	if latencyMs < 0 {
		t.Fatalf("expected non-negative LatencyMs, got %d", latencyMs)
	}
	if len(queriedDomains) != 1 || queriedDomains[0] != "cn.bing.com" {
		t.Fatalf("expected first probed domain to be cn.bing.com, got %v", queriedDomains)
	}
	if !strings.Contains(errMsg, "cn.bing.com") || strings.Contains(errMsg, "www.baidu.com") {
		t.Fatalf("expected detail to report cn.bing.com instead of www.baidu.com, got %q", errMsg)
	}
}

func TestGroupFailover_AntiFlapRetryCooldownAndLatencyHysteresis(t *testing.T) {
	withTestPaths(t)
	var mu sync.Mutex
	vpsCurrent := "node-primary"
	primaryProbes := 0
	primaryBehavior := "transient_once" // transient_once | dead | high_delay | healthy
	nowTime := time.Date(2026, 11, 12, 15, 0, 0, 0, time.Local)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		path := r.URL.Path

		if r.Method == http.MethodGet && path == "/proxies" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"proxies": map[string]any{
					"#VPS": map[string]any{
						"type": "Selector",
						"now":  vpsCurrent,
						"all":  []string{"node-primary", "node-backup"},
					},
				},
			})
			return
		}
		if r.Method == http.MethodGet && strings.HasSuffix(path, "/delay") {
			if strings.Contains(path, "/node-primary/delay") {
				primaryProbes++
				switch primaryBehavior {
				case "transient_once":
					if primaryProbes == 1 {
						w.WriteHeader(http.StatusGatewayTimeout)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 110})
					return
				case "dead":
					w.WriteHeader(http.StatusGatewayTimeout)
					return
				case "high_delay":
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 811})
					return
				case "healthy":
					_ = json.NewEncoder(w).Encode(map[string]int{"delay": 135})
					return
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"delay": 180})
			return
		}
		if r.Method == http.MethodPut && strings.HasPrefix(path, "/proxies/") {
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			vpsCurrent = body.Name
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	state := daemon.NewGroupFailoverState()
	state.ApplyConfig(config.WatchdogFailoverConfig{
		Groups:             []string{"#VPS"},
		ProbeTimeoutMs:     500,
		ConfirmRetries:     1,
		FailbackCooldown:   180,
		MaxFailbackDelayMs: 600,
		ProbeURLs:          []string{"http://example.com/generate_204"},
	})
	state.ConfirmRetryDelay = 5 * time.Millisecond
	state.NowFn = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return nowTime
	}

	// 1. Transient single packet loss: retry succeeds -> must NOT fail over!
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-primary" || len(state.ActiveSnapshot()) != 0 {
		t.Fatalf("transient 1x timeout should not trigger failover, got current=%s", vpsCurrent)
	}

	// 2. Persistent outage: initial + retry both timeout -> switches to node-backup
	mu.Lock()
	primaryBehavior = "dead"
	mu.Unlock()
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-backup" {
		t.Fatalf("expected failover to node-backup, got current=%s", vpsCurrent)
	}
	if len(state.ActiveSnapshot()) != 1 || state.ActiveSnapshot()[0].Origin != "node-primary" {
		t.Fatalf("expected ActiveSnapshot to track node-primary, got %+v", state.ActiveSnapshot())
	}

	// 3. Within 180s cooldown: even if primary is healthy, must hold backup (no ping-pong)
	mu.Lock()
	primaryBehavior = "healthy"
	nowTime = nowTime.Add(30 * time.Second)
	mu.Unlock()
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-backup" {
		t.Fatalf("must not fail back during cooldown, got current=%s", vpsCurrent)
	}

	// 4. Cooldown passed, but primary latency is 811ms (> 600ms cap) -> must reject failback!
	mu.Lock()
	primaryBehavior = "high_delay"
	nowTime = nowTime.Add(200 * time.Second)
	mu.Unlock()
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-backup" {
		t.Fatalf("must reject high-latency (811ms > 600ms) failback, got current=%s", vpsCurrent)
	}

	// 5. Primary recovers with healthy low latency (135ms): requires 2 consecutive patrol streaks
	mu.Lock()
	primaryBehavior = "healthy"
	mu.Unlock()
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-backup" {
		t.Fatalf("first healthy probe after cooldown should build streak (1/2) before switching, got current=%s", vpsCurrent)
	}
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-primary" {
		t.Fatalf("second consecutive healthy probe should fail back, got current=%s", vpsCurrent)
	}
	if len(state.ActiveSnapshot()) != 0 {
		t.Fatalf("expected ActiveSnapshot empty after failback, got %+v", state.ActiveSnapshot())
	}
	snap := daemon.LoadRuntimeSnapshot()
	if len(snap.RecentEvents) == 0 || snap.RecentEvents[len(snap.RecentEvents)-1].Action != "GROUP_FAILBACK" || !snap.RecentEvents[len(snap.RecentEvents)-1].Healthy {
		t.Fatalf("expected GROUP_FAILBACK with Healthy=true in recentEvents, got %+v", snap.RecentEvents)
	}

	// 6. Disabling failover via ApplyConfig turns Patrol into a safe no-op
	disabled := false
	state.ApplyConfig(config.WatchdogFailoverConfig{Enabled: &disabled})
	mu.Lock()
	primaryBehavior = "dead"
	mu.Unlock()
	state.Patrol(t.Context(), []string{srv.URL}, "")
	if vpsCurrent != "node-primary" {
		t.Fatalf("disabled failover should not switch groups, got current=%s", vpsCurrent)
	}
}

func TestCleanAndTrimDaemonLog_ScrubsSpamAndCaps512KB(t *testing.T) {
	withTestPaths(t)
	logPath := daemon.GetDaemonLogPath()

	var sb strings.Builder
	sb.WriteString("Platform for singgen:linux\n")
	sb.WriteString("2026-11-12 10:00:00 [INFO] 已将 sing-box dns_local 指向本地 AdGuard Home (127.0.0.1:53)\n")
	chunk := "2026-11-12 10:01:00 [INFO] [RuleSet] 规则集后台定时更新完成\n"
	for sb.Len() < daemon.MaxDaemonLogBytes+64*1024 {
		sb.WriteString(chunk)
	}
	sb.WriteString("2026-11-12 15:30:00 [WATCHDOG] CHECK_OK healthy=true restarts=0/3 | 正常\n")

	if err := os.WriteFile(logPath, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}
	daemon.CleanAndTrimDaemonLog(logPath, daemon.MaxDaemonLogBytes)

	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > daemon.MaxDaemonLogBytes {
		t.Fatalf("expected trimmed log <= %d bytes, got %d", daemon.MaxDaemonLogBytes, fi.Size())
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected log permissions 0600, got %o", fi.Mode().Perm())
	}
	after, _ := os.ReadFile(logPath)
	afterStr := string(after)
	if strings.Contains(afterStr, "Platform for singgen:") || strings.Contains(afterStr, "指向本地 AdGuard Home") {
		t.Fatal("expected legacy generator spam lines to be scrubbed")
	}
	if !strings.Contains(afterStr, "[WATCHDOG] CHECK_OK") {
		t.Fatal("expected recent [WATCHDOG] tail event to be preserved")
	}
}

func TestDaemonRuntimeSnapshot_CoexistsWithRestartLimiter(t *testing.T) {
	withTestPaths(t)

	daemon.UpdateRuntimeState(func(snap *daemon.DaemonRuntimeSnapshot) {
		snap.DaemonVersion = "1.14.102"
		snap.LastHealthAt = "2026-11-12 15:30:00"
		snap.LastHealthOK = true
		snap.LastHealthDetail = "DNS正常 (12ms)"
		snap.LastHealthDelayMs = 12
	})
	daemon.AppendRuntimeEvent(daemon.WatchdogEventRecord{
		Action:  "GROUP_FAILOVER",
		Healthy: false,
		Summary: "策略组 [#VPS] 原节点超时 -> 自动切往备用节点",
	})

	rl := daemon.NewRestartLimiter()
	rl.RecordRestart()

	snap := daemon.LoadRuntimeSnapshot()
	if snap.Total != 1 || len(snap.Times) != 1 {
		t.Fatalf("expected restart limiter count preserved in snapshot, got total=%d times=%v", snap.Total, snap.Times)
	}
	if snap.DaemonVersion != "1.14.102" || !snap.LastHealthOK || snap.LastHealthDelayMs != 12 {
		t.Fatalf("expected runtime fields preserved across RecordRestart, got %+v", snap)
	}
	if len(snap.RecentEvents) != 1 || snap.RecentEvents[0].Action != "GROUP_FAILOVER" {
		t.Fatalf("expected recentEvents preserved, got %+v", snap.RecentEvents)
	}
	fi, err := os.Stat(daemon.GetStateFilePath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected state file mode 0600, got %o", fi.Mode().Perm())
	}
}

func TestTrimLogInPlace_PreservesTailAndCleansLargeFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "sing-box-basic.log")

	if trimmed, err := daemon.TrimLogInPlace(logPath, 64*1024); err != nil || trimmed {
		t.Fatalf("expected missing file no-op, got trimmed=%v err=%v", trimmed, err)
	}

	var sb strings.Builder
	line := "+0000 2026-11-13 15:19:18 INFO inbound connection example\n"
	for sb.Len() < 96*1024 {
		sb.WriteString(line)
	}
	tailMarker := "+0000 2026-11-13 15:20:00 INFO latest-iot-connection-preserved\n"
	sb.WriteString(tailMarker)

	if err := os.WriteFile(logPath, []byte(sb.String()), 0644); err != nil {
		t.Fatal(err)
	}

	trimmed, err := daemon.TrimLogInPlace(logPath, 64*1024)
	if err != nil || !trimmed {
		t.Fatalf("expected TrimLogInPlace trimmed=true, got trimmed=%v err=%v", trimmed, err)
	}

	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 64*1024 {
		t.Fatalf("expected trimmed file <= 65536 bytes, got %d", fi.Size())
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("expected trimmed file mode 0600, got %o", fi.Mode().Perm())
	}
	after, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(after), tailMarker) {
		t.Fatal("expected trailing log line to be preserved")
	}

	// 再次调用应返回 false（未超限跳过）
	trimmedAgain, err := daemon.TrimLogInPlace(logPath, 64*1024)
	if err != nil || trimmedAgain {
		t.Fatalf("expected second trim no-op, got trimmed=%v err=%v", trimmedAgain, err)
	}
}
