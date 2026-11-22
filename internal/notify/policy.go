// 文件职责：实现静默时间窗口解析/判定、防刷屏冷却配对及每日限额策略。
package notify

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"
)

const maxCooldownEntries = 256

// QuietWindow 表示解析后的每日静默时间窗口（支持同日与跨午夜区间）。
type QuietWindow struct {
	Enabled     bool
	StartMinute int
	EndMinute   int
}

// ParseQuietHours 解析 "HH:MM-HH:MM" 格式的静默时间窗口，空串返回未启用窗口。
func ParseQuietHours(spec string) (QuietWindow, error) {
	if hasControlChars(spec) {
		return QuietWindow{}, errors.New("quiet hours contains control characters")
	}
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return QuietWindow{}, nil
	}
	startRaw, endRaw, ok := strings.Cut(trimmed, "-")
	if !ok || strings.Contains(endRaw, "-") {
		return QuietWindow{}, fmt.Errorf("invalid quiet hours format %q (expected HH:MM-HH:MM)", spec)
	}
	startMin, err := parseClockMinute(strings.TrimSpace(startRaw))
	if err != nil {
		return QuietWindow{}, fmt.Errorf("invalid quiet hours start %q: %w", startRaw, err)
	}
	endMin, err := parseClockMinute(strings.TrimSpace(endRaw))
	if err != nil {
		return QuietWindow{}, fmt.Errorf("invalid quiet hours end %q: %w", endRaw, err)
	}
	if startMin == endMin {
		return QuietWindow{}, errors.New("quiet hours start and end cannot be equal")
	}
	return QuietWindow{
		Enabled:     true,
		StartMinute: startMin,
		EndMinute:   endMin,
	}, nil
}

func parseClockMinute(raw string) (int, error) {
	hStr, mStr, ok := strings.Cut(raw, ":")
	if !ok || strings.Contains(mStr, ":") || len(hStr) < 1 || len(hStr) > 2 || len(mStr) != 2 {
		return 0, errors.New("expected HH:MM")
	}
	if !isAllASCIIDigits(hStr) || !isAllASCIIDigits(mStr) {
		return 0, errors.New("non-digit time component")
	}
	h, err := strconv.Atoi(hStr)
	if err != nil || h < 0 || h > 23 {
		return 0, errors.New("hour out of range 00..23")
	}
	m, err := strconv.Atoi(mStr)
	if err != nil || m < 0 || m > 59 {
		return 0, errors.New("minute out of range 00..59")
	}
	return h*60 + m, nil
}

func isAllASCIIDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// IsInQuietHours 判断给定时刻是否处于静默窗口内（左闭右开 [start, end)）。
func (w QuietWindow) IsInQuietHours(now time.Time) bool {
	if !w.Enabled {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	if w.StartMinute < w.EndMinute {
		return cur >= w.StartMinute && cur < w.EndMinute
	}
	return cur >= w.StartMinute || cur < w.EndMinute
}

type cooldownKey struct {
	eventType EventType
	dedupKey  string
}

type cooldownEntry struct {
	lastAlertAt    time.Time
	lastResolvedAt time.Time
	alertActive    bool
}

type policyState struct {
	cooldowns  map[cooldownKey]cooldownEntry
	dailyDate  string
	dailyCount int
}

func newPolicyState() policyState {
	return policyState{
		cooldowns: make(map[cooldownKey]cooldownEntry),
	}
}

func effectiveCooldown(minutes int) time.Duration {
	if minutes <= 0 {
		minutes = DefaultCooldownMinutes
	}
	return time.Duration(minutes) * time.Minute
}

func effectiveDailyLimit(limit int) int {
	if limit <= 0 {
		return DefaultDailyLimit
	}
	return limit
}

// evaluateAndRecord 执行防刷屏规则校验，全部通过时原子记录冷却与每日计数。
func (p *policyState) evaluateAndRecord(opts Options, quiet QuietWindow, hasChannels bool, ev Event, now time.Time) (bool, string) {
	if !opts.Enabled {
		return false, "disabled"
	}
	if opts.EnabledEvents != nil && !opts.EnabledEvents[ev.Type] {
		return false, "event_disabled"
	}
	if !hasChannels {
		return false, "no_channels"
	}
	if quiet.IsInQuietHours(now) && ev.Severity != SeverityCritical {
		return false, "quiet_hours"
	}

	cooldown := effectiveCooldown(opts.CooldownMinutes)
	today := now.Format("2006-01-02")
	if p.dailyDate != today {
		p.dailyDate = today
		p.dailyCount = 0
		p.pruneExpired(now, cooldown)
	}
	if p.dailyCount >= effectiveDailyLimit(opts.DailyLimit) {
		return false, "daily_limit"
	}

	key := cooldownKey{
		eventType: ev.Type,
		dedupKey:  strings.TrimSpace(ev.DedupKey),
	}
	entry := p.cooldowns[key]
	if ev.Resolved {
		// 恢复通知可与在途活跃故障配对放行一次；无配对活跃故障时仍受冷却约束防重复恢复刷屏。
		if !entry.alertActive && !entry.lastResolvedAt.IsZero() && now.Sub(entry.lastResolvedAt) < cooldown {
			return false, "cooldown"
		}
		entry.alertActive = false
		entry.lastResolvedAt = now
	} else {
		if !entry.lastAlertAt.IsZero() && now.Sub(entry.lastAlertAt) < cooldown {
			return false, "cooldown"
		}
		entry.alertActive = true
		entry.lastAlertAt = now
	}

	p.cooldowns[key] = entry
	p.dailyCount++
	if len(p.cooldowns) > maxCooldownEntries {
		p.pruneExpired(now, cooldown)
	}
	return true, ""
}

func (p *policyState) pruneExpired(now time.Time, cooldown time.Duration) {
	maps.DeleteFunc(p.cooldowns, func(_ cooldownKey, entry cooldownEntry) bool {
		alertExpired := entry.lastAlertAt.IsZero() || now.Sub(entry.lastAlertAt) >= cooldown
		resolvedExpired := entry.lastResolvedAt.IsZero() || now.Sub(entry.lastResolvedAt) >= cooldown
		return alertExpired && resolvedExpired && !entry.alertActive
	})
}
