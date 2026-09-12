package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WatchdogEvent 看门狗事件
type WatchdogEvent struct {
	Time          time.Time
	Action        string // "DETECT" / "CONFIRM" / "RESTART" / "RESTART_BLOCKED"
	CheckResult   HealthCheckResult
	RestartResult string // 重启结果 ("success" / 错误信息)
}

// LogWatchdogEvent 记录看门狗事件。
// 事件统一追加写入守护进程日志(daemon.log) —— 运行日志与事件审计是同一批
// 内容, 不再单独维护 watchdog.log。行格式固定 [WATCHDOG] 前缀, 便于 grep。
// 直接以 O_APPEND 写入(与 zap 输出同文件), 单行写入在普通文件上具备原子性。
func LogWatchdogEvent(event WatchdogEvent) {
	logPath := GetDaemonLogPath()

	// 确保日志目录存在
	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return // 日志写入失败不影响主流程
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return // 日志写入失败不影响主流程
	}
	defer f.Close()

	fmt.Fprintf(f, "[%s] [WATCHDOG] action=%s healthy=%v reason=%s detail=%s restart_result=%s\n",
		event.Time.Format("2006-01-02 15:04:05"),
		event.Action,
		event.CheckResult.Healthy,
		event.CheckResult.FailedReason,
		event.CheckResult.Details,
		event.RestartResult,
	)
}
