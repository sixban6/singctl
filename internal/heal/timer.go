package heal

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"singctl/internal/platform/servicemgr"
	"singctl/internal/updater"
)

const (
	healServicePath = "/etc/systemd/system/singctl-heal.service"
	healTimerPath   = "/etc/systemd/system/singctl-heal.timer"
)

var validCalendarRe = regexp.MustCompile(`^[A-Za-z0-9*:,\- /._~]+$`)

var knownCalendarKeywords = map[string]bool{
	"minutely": true, "hourly": true, "daily": true, "monthly": true,
	"weekly": true, "yearly": true, "annually": true, "quarterly": true, "semiannually": true,
}

// ValidateSchedule guards against systemd unit injection and malformed OnCalendar strings.
func ValidateSchedule(schedule string) error {
	s := strings.TrimSpace(schedule)
	if s == "" {
		return errors.New("定时调度表达式不能为空")
	}
	if len(s) > 64 || strings.ContainsAny(s, "\r\n\t") || !validCalendarRe.MatchString(s) {
		return errors.New("无效的 systemd OnCalendar 表达式 (示例: *-*-* 04:00:00)")
	}
	if !knownCalendarKeywords[strings.ToLower(s)] && !strings.ContainsAny(s, "0123456789") {
		return errors.New("无效的 systemd OnCalendar 表达式 (示例: *-*-* 04:00:00)")
	}
	return nil
}

// GetTimerStatus inspects systemd for singctl-heal.timer status without resident memory overhead.
func GetTimerStatus(fallbackSchedule string) TimerStatus {
	sched := cmp.Or(strings.TrimSpace(fallbackSchedule), DefaultPolicy().Schedule)
	st := TimerStatus{
		Supported: runtime.GOOS == "linux" && hasBinary("systemctl") && !isOpenWrtSystem(),
		Schedule:  sched,
	}
	if !st.Supported {
		return st
	}

	if raw, err := os.ReadFile(healTimerPath); err == nil {
		for line := range strings.SplitSeq(string(raw), "\n") {
			if after, ok := strings.CutPrefix(strings.TrimSpace(line), "OnCalendar="); ok {
				st.Schedule = strings.TrimSpace(after)
				break
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mgr := servicemgr.NewSystemd(nil)
	st.Enabled = mgr.IsEnabled(ctx, "singctl-heal.timer")
	st.Active = mgr.IsActive(ctx, "singctl-heal.timer")

	if props, err := mgr.ShowProperties(ctx, 2*time.Second, "singctl-heal.timer", "NextElapseUSecRealtime", "LastTriggerUSec"); err == nil {
		st.NextRun = props["NextElapseUSecRealtime"]
		st.LastRun = props["LastTriggerUSec"]
	}
	return st
}

// ApplyPolicy updates security_heal.json and installs/enables or disables singctl-heal.timer accordingly.
func ApplyPolicy(configPath string, policy HealPolicy) (TimerStatus, error) {
	if strings.TrimSpace(policy.Schedule) == "" {
		policy.Schedule = DefaultPolicy().Schedule
	}
	if err := ValidateSchedule(policy.Schedule); err != nil {
		return TimerStatus{}, err
	}
	if err := SavePolicy(configPath, policy); err != nil {
		return TimerStatus{}, fmt.Errorf("保存安全自愈策略失败: %w", err)
	}

	if runtime.GOOS != "linux" || !hasBinary("systemctl") || isOpenWrtSystem() {
		return GetTimerStatus(policy.Schedule), nil
	}

	if policy.AutoHealEnabled {
		if err := installAndEnableTimer(configPath, policy); err != nil {
			return GetTimerStatus(policy.Schedule), err
		}
	} else {
		_ = disableAndRemoveTimer()
	}
	return GetTimerStatus(policy.Schedule), nil
}

func installAndEnableTimer(configPath string, policy HealPolicy) error {
	exePath := "/usr/local/bin/singctl"
	if cur, err := updater.ResolveExecutablePath(); err == nil && strings.TrimSpace(cur) != "" {
		if _, sErr := os.Stat(cur); sErr == nil {
			exePath = cur
		}
	}
	cfgArg := cmp.Or(strings.TrimSpace(configPath), "/etc/singctl/singctl.yaml")
	rebootFlag := ""
	if policy.AutoReboot {
		rebootFlag = " --reboot-if-needed"
	}

	svcUnit := fmt.Sprintf(`[Unit]
Description=SingCtl 3-Layer Automated Security Self-Healing Task
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
KillMode=process
ExecStart=%s sr heal --trigger timer%s -c %s
Nice=10
IOSchedulingClass=best-effort
`, exePath, rebootFlag, cfgArg)

	timerUnit := fmt.Sprintf(`[Unit]
Description=Daily Maintenance Schedule for SingCtl Security Self-Healing

[Timer]
OnCalendar=%s
RandomizedDelaySec=15m
Persistent=true
Unit=singctl-heal.service

[Install]
WantedBy=timers.target
`, strings.TrimSpace(policy.Schedule))

	if err := os.WriteFile(healServicePath, []byte(svcUnit), 0644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", healServicePath, err)
	}
	if err := os.WriteFile(healTimerPath, []byte(timerUnit), 0644); err != nil {
		return fmt.Errorf("写入 %s 失败: %w", healTimerPath, err)
	}

	mgr := servicemgr.NewSystemd(nil)
	ctx := context.Background()
	if err := mgr.DaemonReload(ctx); err != nil {
		return fmt.Errorf("systemctl daemon-reload 失败: %w", err)
	}
	if err := mgr.EnableNow(ctx, "singctl-heal.timer"); err != nil {
		return fmt.Errorf("启用 singctl-heal.timer 失败: %w", err)
	}
	return nil
}

func disableAndRemoveTimer() error {
	mgr := servicemgr.NewSystemd(nil)
	ctx := context.Background()
	_ = mgr.DisableNow(ctx, "singctl-heal.timer")
	_ = os.Remove(healTimerPath)
	_ = os.Remove(healServicePath)
	_ = mgr.DaemonReload(ctx)
	return nil
}
