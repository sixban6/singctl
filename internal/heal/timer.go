package heal

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"singctl/internal/updater"
)

const (
	healServicePath = "/etc/systemd/system/singctl-heal.service"
	healTimerPath   = "/etc/systemd/system/singctl-heal.timer"
)

var validCalendarRe = regexp.MustCompile(`^[A-Za-z0-9*:,\-\s/._~]+$`)

// ValidateSchedule guards against systemd unit injection in OnCalendar strings.
func ValidateSchedule(schedule string) error {
	s := strings.TrimSpace(schedule)
	if s == "" {
		return errors.New("定时调度表达式不能为空")
	}
	if len(s) > 64 || strings.ContainsAny(s, "\r\n") || !validCalendarRe.MatchString(s) {
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

	if out, err := exec.Command("systemctl", "is-enabled", "singctl-heal.timer").Output(); err == nil {
		s := strings.TrimSpace(string(out))
		st.Enabled = s == "enabled" || s == "static"
	}
	if out, err := exec.Command("systemctl", "is-active", "singctl-heal.timer").Output(); err == nil {
		st.Active = strings.TrimSpace(string(out)) == "active"
	}

	if out, err := exec.Command("systemctl", "show", "singctl-heal.timer",
		"--property=NextElapseUSecRealtime,LastTriggerUSec").Output(); err == nil {
		for line := range strings.SplitSeq(string(out), "\n") {
			line = strings.TrimSpace(line)
			if after, ok := strings.CutPrefix(line, "NextElapseUSecRealtime="); ok && after != "" && after != "n/a" {
				st.NextRun = after
			}
			if after, ok := strings.CutPrefix(line, "LastTriggerUSec="); ok && after != "" && after != "n/a" {
				st.LastRun = after
			}
		}
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

	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload 失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("systemctl", "enable", "--now", "singctl-heal.timer").CombinedOutput(); err != nil {
		return fmt.Errorf("启用 singctl-heal.timer 失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func disableAndRemoveTimer() error {
	_ = exec.Command("systemctl", "disable", "--now", "singctl-heal.timer").Run()
	_ = os.Remove(healTimerPath)
	_ = os.Remove(healServicePath)
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}
