package daemon

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxDaemonLogBytes 守护日志文件大小上限（512 KB），防止 OpenWrt /tmp (tmpfs) 长期运行膨胀占满内存。
const MaxDaemonLogBytes = 512 * 1024

// MaxSingBoxLogBytes sing-box 运行标准输出日志上限（16 MB），防止 info 日志长期写入将 OpenWrt /tmp (tmpfs) 撑爆导致 DNS/DHCP 异常。
const MaxSingBoxLogBytes = 16 * 1024 * 1024

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

// TrimLogInPlace 原地截断超大外部进程日志文件（保留尾部最新记录），保持原 inode 不变并释放 tmpfs 空间。
func TrimLogInPlace(logPath string, maxBytes int64) (bool, error) {
	if strings.TrimSpace(logPath) == "" {
		return false, nil
	}
	if maxBytes <= 0 {
		maxBytes = MaxSingBoxLogBytes
	}
	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if info.Size() <= maxBytes {
		return false, nil
	}

	f, err := os.OpenFile(logPath, os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer f.Close()

	keepTarget := max(maxBytes/4, 4096)
	offset := max(info.Size()-keepTarget, 0)
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return false, err
	}
	tail, err := io.ReadAll(io.LimitReader(f, keepTarget))
	if err != nil {
		return false, err
	}
	if offset > 0 {
		if nl := bytes.IndexByte(tail, '\n'); nl >= 0 && nl+1 < len(tail) {
			tail = tail[nl+1:]
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return false, err
	}
	if _, err := f.Write(tail); err != nil {
		return false, err
	}
	if err := f.Truncate(int64(len(tail))); err != nil {
		return false, err
	}
	_ = f.Chmod(0600)
	return true, nil
}
