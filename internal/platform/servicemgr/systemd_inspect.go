// 文件职责：提供 systemd 批量状态探测（show）、属性查询及立即启停（enable/disable --now）受控扩展能力。
package servicemgr

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// UnitStatus 描述 systemd 单元的实时运行状态摘要。
type UnitStatus struct {
	ID                   string
	Running              bool
	PID                  string
	ActiveEnterTimestamp string
}

var systemdPropNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)

// ParseSystemdShowBatch 解析 `systemctl show --property=Id,ActiveState,MainPID,ActiveEnterTimestamp ...` 的多段落输出。
func ParseSystemdShowBatch(raw string) map[string]UnitStatus {
	out := make(map[string]UnitStatus)
	var curUnit string
	var curSnap UnitStatus

	flush := func() {
		if curUnit != "" {
			curSnap.ID = curUnit
			out[curUnit] = curSnap
		}
		curUnit = ""
		curSnap = UnitStatus{}
	}

	for line := range strings.SplitSeq(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "Id":
			curUnit = strings.TrimSuffix(v, ".service")
		case "ActiveState":
			curSnap.Running = v == "active"
		case "MainPID":
			if v != "" && v != "0" {
				curSnap.PID = v
			}
		case "ActiveEnterTimestamp":
			if v != "" && v != "n/a" {
				curSnap.ActiveEnterTimestamp = v
			}
		}
	}
	flush()
	return out
}

// ShowUnitsBatch 一次性批量读取多个 systemd 服务单元的运行态、PID 与启动时间戳；任一单元名非法时安全拒绝执行。
func (m *SystemdManager) ShowUnitsBatch(ctx context.Context, timeout time.Duration, units ...string) map[string]UnitStatus {
	if len(units) == 0 {
		return map[string]UnitStatus{}
	}
	for _, u := range units {
		if ValidateUnitName(u) != nil {
			return map[string]UnitStatus{}
		}
	}
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	args := make([]string, 0, 2+len(units))
	args = append(args, "show", "--property=Id,ActiveState,MainPID,ActiveEnterTimestamp")
	args = append(args, units...)
	out, err := m.runner.CombinedOutput(ctx, timeout, "systemctl", args...)
	if err != nil && len(out) == 0 {
		return map[string]UnitStatus{}
	}
	return ParseSystemdShowBatch(string(out))
}

// IsEnabled 查询指定 systemd 单元是否处于 enabled 或 static 自启状态。
func (m *SystemdManager) IsEnabled(ctx context.Context, name string) bool {
	if ValidateUnitName(name) != nil {
		return false
	}
	out, err := m.runner.CombinedOutput(ctx, defaultProbeTimeout, "systemctl", "is-enabled", name)
	if err != nil {
		return false
	}
	state := strings.TrimSpace(string(out))
	return state == "enabled" || state == "static"
}

// EnableNow 执行 `systemctl enable --now <name>`，用于 Timer 或常驻单元的立即激活与开机自启。
func (m *SystemdManager) EnableNow(ctx context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	out, err := m.runner.CombinedOutput(ctx, defaultActionTimeout, "systemctl", "enable", "--now", name)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("systemctl enable --now %s: %w (%s)", name, err, msg)
		}
		return fmt.Errorf("systemctl enable --now %s: %w", name, err)
	}
	return nil
}

// DisableNow 执行 `systemctl disable --now <name>`，用于停用并取消开机自启。
func (m *SystemdManager) DisableNow(ctx context.Context, name string) error {
	if err := ValidateUnitName(name); err != nil {
		return err
	}
	if m.hasLocalUnitOverride(name) {
		return nil
	}
	out, err := m.runner.CombinedOutput(ctx, defaultActionTimeout, "systemctl", "disable", "--now", name)
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("systemctl disable --now %s: %w (%s)", name, err, msg)
		}
		return fmt.Errorf("systemctl disable --now %s: %w", name, err)
	}
	return nil
}

// ShowProperties 查询单个 systemd 单元的一组白名单属性键值（自动将 "n/a" 规范化为空字符串）。
func (m *SystemdManager) ShowProperties(ctx context.Context, timeout time.Duration, name string, props ...string) (map[string]string, error) {
	if err := ValidateUnitName(name); err != nil {
		return nil, err
	}
	if len(props) == 0 {
		return nil, errors.New("empty systemd property list")
	}
	cleanProps := make([]string, 0, len(props))
	for _, p := range props {
		trimmed := strings.TrimSpace(p)
		if !systemdPropNameRe.MatchString(trimmed) {
			return nil, fmt.Errorf("invalid systemd property name: %q", p)
		}
		cleanProps = append(cleanProps, trimmed)
	}
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	out, err := m.runner.CombinedOutput(ctx, timeout, "systemctl", "show", name, "--property="+strings.Join(cleanProps, ","))
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("systemctl show %s: %w", name, err)
	}
	res := make(map[string]string, len(cleanProps))
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if v == "n/a" {
			v = ""
		}
		res[k] = v
	}
	return res, nil
}
