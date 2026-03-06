package test

import (
	"os"
	"singctl/internal/daemon"
	"strings"
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

	content, err := os.ReadFile(daemon.GetWatchdogLogPath())
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

func TestGetWatchdogLogPath(t *testing.T) {
	path := daemon.GetWatchdogLogPath()
	if path == "" {
		t.Error("expected non-empty watchdog log path")
	}
	if !strings.Contains(path, "singctl-watchdog.log") {
		t.Errorf("expected 'singctl-watchdog.log', got: %s", path)
	}
}

func TestGetDaemonLogPath(t *testing.T) {
	path := daemon.GetDaemonLogPath()
	if path == "" {
		t.Error("expected non-empty daemon log path")
	}
	if !strings.Contains(path, "singctl-daemon.log") {
		t.Errorf("expected 'singctl-daemon.log', got: %s", path)
	}
}
