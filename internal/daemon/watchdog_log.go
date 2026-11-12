package daemon

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxDaemonLogBytes 守护日志文件大小上限（512 KB），防止 OpenWrt /tmp (tmpfs) 长期运行膨胀占满内存。
const MaxDaemonLogBytes = 512 * 1024

// WatchdogEvent 看门狗事件
type WatchdogEvent struct {
	Time          time.Time
	Action        string // "DETECT" / "CONFIRM" / "RESTART" / "RESTART_BLOCKED" / "GROUP_FAILOVER" / "GROUP_FAILBACK" / "SUB_SYNC"
	CheckResult   HealthCheckResult
	RestartResult string // 重启或切换结果 ("success" / 错误信息 / 切换摘要)
}

// LogWatchdogEvent 记录看门狗事件到守护日志并同步写入结构化状态快照。
func LogWatchdogEvent(event WatchdogEvent) {
	logPath := GetDaemonLogPath()
	ts := event.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err == nil {
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			_ = f.Chmod(0600)
			fmt.Fprintf(f, "[%s] [WATCHDOG] action=%s healthy=%v reason=%s detail=%s restart_result=%s\n",
				ts.Format("2006-01-02 15:04:05"),
				event.Action,
				event.CheckResult.Healthy,
				event.CheckResult.FailedReason,
				event.CheckResult.Details,
				event.RestartResult,
			)
			_ = f.Close()
		}
	}

	summary := strings.TrimSpace(event.RestartResult)
	if summary == "" || summary == "-" {
		if d := strings.TrimSpace(event.CheckResult.Details); d != "" {
			summary = d
		} else {
			summary = strings.TrimSpace(event.CheckResult.FailedReason)
		}
	}
	AppendRuntimeEvent(WatchdogEventRecord{
		Time:    ts.Format("2006-01-02 15:04:05"),
		Action:  event.Action,
		Healthy: event.CheckResult.Healthy,
		Summary: summary,
	})
}

func isLegacyDaemonSpamLine(line string) bool {
	return strings.Contains(line, "[INFO] Platform for singgen:") ||
		strings.Contains(line, "已将 sing-box dns_local 指向本地 AdGuard Home")
}

// CleanAndTrimDaemonLog 清理历史重复噪音行，并在日志文件超过 maxBytes 时截断保留最新后半部分。
// 返回 true 表示文件内容已被重写（调用方若持有打开的追加句柄应重新打开）。
func CleanAndTrimDaemonLog(logPath string, maxBytes int64) (bool, error) {
	if maxBytes <= 0 {
		maxBytes = MaxDaemonLogBytes
	}
	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		return false, err
	}

	hasSpam := bytes.Contains(data, []byte("Platform for singgen:")) ||
		bytes.Contains(data, []byte("已将 sing-box dns_local 指向本地 AdGuard Home"))

	if !hasSpam && info.Size() <= maxBytes {
		_ = os.Chmod(logPath, 0600)
		return false, nil
	}

	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		if isLegacyDaemonSpamLine(line) {
			continue
		}
		kept = append(kept, line)
	}
	cleaned := strings.Join(kept, "\n")
	if cleaned != "" {
		cleaned += "\n"
	}

	keepTarget := max(int(maxBytes/2), 4096)
	if int64(len(cleaned)) > maxBytes && len(cleaned) > keepTarget {
		tail := cleaned[len(cleaned)-keepTarget:]
		if nl := strings.IndexByte(tail, '\n'); nl >= 0 && nl+1 < len(tail) {
			tail = tail[nl+1:]
		}
		cleaned = tail
	}

	tmp := logPath + ".trim.tmp"
	if err := os.WriteFile(tmp, []byte(cleaned), 0600); err != nil {
		return false, err
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, logPath); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	return true, nil
}
