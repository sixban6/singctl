package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	watchdogLogFileName = "singctl-watchdog.log"
)

// GetWatchdogLogPath 获取看门狗日志文件路径
func GetWatchdogLogPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("TEMP"), watchdogLogFileName)
	}
	return filepath.Join("/tmp", watchdogLogFileName)
}

// WatchdogEvent 看门狗事件
type WatchdogEvent struct {
	Time          time.Time
	Action        string // "DETECT" / "CONFIRM" / "RESTART" / "RESTART_BLOCKED"
	CheckResult   HealthCheckResult
	RestartResult string // 重启结果 ("success" / 错误信息)
}

// LogWatchdogEvent 记录看门狗事件到专用日志文件
func LogWatchdogEvent(event WatchdogEvent) {
	logPath := GetWatchdogLogPath()

	// 确保日志目录存在
	logDir := filepath.Dir(logPath)
	os.MkdirAll(logDir, 0755)

	// 追加写入日志
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return // 日志写入失败不影响主流程
	}
	defer f.Close()

	timestamp := event.Time.Format("2006-01-02 15:04:05")

	entry := fmt.Sprintf("[%s] [%s] healthy=%v reason=%s detail=%s restart_result=%s\n",
		timestamp,
		event.Action,
		event.CheckResult.Healthy,
		event.CheckResult.FailedReason,
		event.CheckResult.Details,
		event.RestartResult,
	)

	f.WriteString(entry)
}
