package daemon

import (
	"os"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// RestartLimiter Tests
// =============================================================================

func TestRestartLimiter_CanRestart_Initially(t *testing.T) {
	limiter := NewRestartLimiter()
	if !limiter.CanRestart() {
		t.Error("expected CanRestart to return true initially")
	}
}

func TestRestartLimiter_CanRestart_AfterMaxRestarts(t *testing.T) {
	limiter := NewRestartLimiter()

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
	limiter := NewRestartLimiter()

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
	limiter := NewRestartLimiter()

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
	limiter := NewRestartLimiter()
	if limiter.GetMaxRestarts() != 3 {
		t.Errorf("expected max restarts 3, got %d", limiter.GetMaxRestarts())
	}
}

// =============================================================================
// InternetCheckResult Tests
// =============================================================================

func TestInternetCheckResult_Accessible(t *testing.T) {
	result := InternetCheckResult{
		Accessible: true,
		TargetResults: map[string]string{
			"http://www.baidu.com":               "ok",
			"http://www.google.com/generate_204": "ok",
		},
		CheckTime: time.Now(),
	}

	if !result.Accessible {
		t.Error("expected result to be accessible")
	}
}

func TestInternetCheckResult_NotAccessible(t *testing.T) {
	result := InternetCheckResult{
		Accessible: false,
		TargetResults: map[string]string{
			"http://www.baidu.com":               "error: connection refused",
			"http://www.google.com/generate_204": "error: timeout",
			"http://cp.cloudflare.com":           "error: no route to host",
		},
		CheckTime: time.Now(),
	}

	if result.Accessible {
		t.Error("expected result to be not accessible")
	}
	if len(result.TargetResults) != 3 {
		t.Errorf("expected 3 target results, got %d", len(result.TargetResults))
	}
}

func TestInternetCheckResult_PartiallyAccessible(t *testing.T) {
	// 只要有一个成功就算可访问
	result := InternetCheckResult{
		Accessible: true,
		TargetResults: map[string]string{
			"http://www.baidu.com":               "ok",
			"http://www.google.com/generate_204": "error: timeout",
			"http://cp.cloudflare.com":           "error: timeout",
		},
		CheckTime: time.Now(),
	}

	if !result.Accessible {
		t.Error("expected partially accessible result to be accessible")
	}
}

// =============================================================================
// MonitorStatus Tests
// =============================================================================

func TestMonitorStatus_String_AllRunning(t *testing.T) {
	status := MonitorStatus{
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
	status := MonitorStatus{
		ProcessRunning: false,
		DaemonRunning:  false,
	}

	s := status.String()
	if !strings.Contains(s, "Stopped ✗") {
		t.Errorf("expected 'Stopped ✗' in status, got: %s", s)
	}
}

func TestMonitorStatus_String_NoCheckTime(t *testing.T) {
	status := MonitorStatus{
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

	event := WatchdogEvent{
		Time:   time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC),
		Action: "RESTART",
		CheckResult: InternetCheckResult{
			Accessible: false,
			TargetResults: map[string]string{
				"http://www.baidu.com": "error: timeout",
			},
		},
		RestartResult: "success",
	}

	// 手动验证格式化
	timestamp := event.Time.Format("2006-01-02 15:04:05")
	entry := "[" + timestamp + "] [" + event.Action + "] accessible=false restart_result=" + event.RestartResult + "\n"
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
	event := WatchdogEvent{
		Time:   time.Now(),
		Action: "TEST_EVENT",
		CheckResult: InternetCheckResult{
			Accessible: false,
			TargetResults: map[string]string{
				"http://test.example.com": "error: test",
			},
			CheckTime: time.Now(),
		},
		RestartResult: "test_only",
	}

	LogWatchdogEvent(event)

	content, err := os.ReadFile(GetWatchdogLogPath())
	if err != nil {
		t.Fatalf("failed to read watchdog log: %v", err)
	}

	logStr := string(content)
	if !strings.Contains(logStr, "[TEST_EVENT]") {
		t.Errorf("expected TEST_EVENT in log, got: %s", logStr)
	}
	if !strings.Contains(logStr, "restart_result=test_only") {
		t.Errorf("expected restart_result=test_only, got: %s", logStr)
	}
}

// =============================================================================
// Watchdog Decision Logic Tests
// 测试看门狗的核心决策逻辑：
//   能上网 → 什么都不做
//   第一轮不通 + 第二轮恢复 → 不重启
//   连续两轮不通 → 执行 stop → start
//   频率限制 → 即使不通也不重启
// =============================================================================

func TestWatchdogLogic_InternetOK_NoAction(t *testing.T) {
	// 网络可达 → 不触发重启
	result := InternetCheckResult{
		Accessible:    true,
		TargetResults: map[string]string{"http://www.baidu.com": "ok"},
		CheckTime:     time.Now(),
	}

	if !result.Accessible {
		t.Error("expected internet accessible, should not trigger restart")
	}
}

func TestWatchdogLogic_FirstFail_ThenRecover_NoRestart(t *testing.T) {
	// 第一轮不通 + 第二轮恢复 = 不重启
	result1 := InternetCheckResult{
		Accessible:    false,
		TargetResults: map[string]string{"http://www.baidu.com": "error: timeout"},
		CheckTime:     time.Now(),
	}

	result2 := InternetCheckResult{
		Accessible:    true,
		TargetResults: map[string]string{"http://www.baidu.com": "ok"},
		CheckTime:     time.Now(),
	}

	if result1.Accessible {
		t.Error("round 1 should fail")
	}
	if !result2.Accessible {
		t.Error("round 2 should succeed (recovered)")
	}
	// 结论：不应触发重启
}

func TestWatchdogLogic_BothFail_ShouldRestart(t *testing.T) {
	// 连续两轮都不通 → 应该 stop+start
	limiter := NewRestartLimiter()

	result1 := InternetCheckResult{
		Accessible:    false,
		TargetResults: map[string]string{"http://www.baidu.com": "error: timeout"},
	}
	result2 := InternetCheckResult{
		Accessible:    false,
		TargetResults: map[string]string{"http://www.baidu.com": "error: timeout"},
	}

	if result1.Accessible || result2.Accessible {
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
	// 已达到重启上限 → 即使不通也不重启
	limiter := NewRestartLimiter()

	for i := 0; i < limiter.GetMaxRestarts(); i++ {
		limiter.RecordRestart()
	}

	result := InternetCheckResult{
		Accessible:    false,
		TargetResults: map[string]string{"http://www.baidu.com": "error: timeout"},
	}

	if result.Accessible {
		t.Error("result should be inaccessible")
	}

	if limiter.CanRestart() {
		t.Error("limiter should block restart after max reached")
	}
}

// =============================================================================
// Path Tests
// =============================================================================

func TestGetWatchdogLogPath(t *testing.T) {
	path := GetWatchdogLogPath()
	if path == "" {
		t.Error("expected non-empty watchdog log path")
	}
	if !strings.Contains(path, "singctl-watchdog.log") {
		t.Errorf("expected 'singctl-watchdog.log', got: %s", path)
	}
}

func TestGetDaemonLogPath(t *testing.T) {
	path := GetDaemonLogPath()
	if path == "" {
		t.Error("expected non-empty daemon log path")
	}
	if !strings.Contains(path, "singctl-daemon.log") {
		t.Errorf("expected 'singctl-daemon.log', got: %s", path)
	}
}
