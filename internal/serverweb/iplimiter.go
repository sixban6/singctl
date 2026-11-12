package serverweb

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	BanSourceLoginFail   = "login_fail"
	BanSourceManualSniff = "manual_sniff"
)

type ipAttempt struct {
	FailCount   int       `json:"fail_count"`
	LastFail    time.Time `json:"last_fail"`
	BannedUntil time.Time `json:"banned_until"`
	Source      string    `json:"source,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// BanDetail 结构化封禁详情（区分密码爆破拦截与嗅探手动封禁）
type BanDetail struct {
	IP          string
	Remaining   time.Duration
	BannedUntil time.Time
	FailCount   int
	Source      string
	SourceLabel string
	Reason      string
}

// IPLimiter IP 登录限流与防暴力破解器 (支持 0600 文件持久化)
type IPLimiter struct {
	mu          sync.RWMutex
	attempts    map[string]*ipAttempt
	maxAttempts int
	window      time.Duration
	banDuration time.Duration
	stopCleaner chan struct{}
	filePath    string
}

// NewIPLimiter 创建 IPLimiter 实例 (默认 3 次失败、10 分钟窗口、15 分钟封禁，支持传入 0600 小文件持久化路径)
func NewIPLimiter(maxAttempts int, window, banDuration time.Duration, filePath ...string) *IPLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	if banDuration <= 0 {
		banDuration = 15 * time.Minute
	}

	fp := ""
	if len(filePath) > 0 {
		fp = strings.TrimSpace(filePath[0])
	}

	l := &IPLimiter{
		attempts:    make(map[string]*ipAttempt),
		maxAttempts: maxAttempts,
		window:      window,
		banDuration: banDuration,
		stopCleaner: make(chan struct{}),
		filePath:    fp,
	}
	l.loadLocked()
	go l.startCleaner()
	return l
}

func (l *IPLimiter) loadLocked() {
	if l.filePath == "" {
		return
	}
	data, err := os.ReadFile(l.filePath)
	if err != nil {
		return
	}
	var loaded map[string]*ipAttempt
	if err := json.Unmarshal(data, &loaded); err != nil {
		return
	}
	now := time.Now()
	for ip, att := range loaded {
		if att == nil {
			continue
		}
		// 兼容旧版未带 source 字段的持久化记录：封禁跨度超过 1 小时自动归类为嗅探手动拉黑
		if att.Source == "" {
			if !att.BannedUntil.IsZero() && att.BannedUntil.Sub(att.LastFail) > time.Hour {
				att.Source = BanSourceManualSniff
				att.Reason = cmp.Or(att.Reason, "嗅探雷达手动拉黑")
			} else {
				att.Source = BanSourceLoginFail
				att.Reason = cmp.Or(att.Reason, "后台登录密码连续输错")
			}
		}
		// 恢复封禁中或仍在失败统计窗口内的 IP
		if now.Before(att.BannedUntil) || now.Sub(att.LastFail) <= l.window {
			l.attempts[ip] = att
		}
	}
}

func (l *IPLimiter) SaveLocked() {
	if l.filePath == "" {
		return
	}
	data, err := json.MarshalIndent(l.attempts, "", "  ")
	if err != nil {
		return
	}
	dir := filepath.Dir(l.filePath)
	_ = os.MkdirAll(dir, 0700)

	tmp := fmt.Sprintf("%s.%d.tmp", l.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, l.filePath); err != nil {
		_ = os.Remove(tmp)
		_ = os.WriteFile(l.filePath, data, 0600)
		_ = os.Chmod(l.filePath, 0600)
	}
}

// GetClientIP 只在本机反代连接上信任 Caddy 覆写的 X-Real-IP。
// 调用方自带的 CF-Connecting-IP 和 X-Forwarded-For 一律忽略。
func GetClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		host = r.RemoteAddr
	}
	if isWhitelisted(host) {
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			if ip := net.ParseIP(real); ip != nil {
				return ip.String()
			}
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// isWhitelisted 本地回环免锁保护
func isWhitelisted(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

// CheckBan 检查指定 IP 是否正处于封禁期，返回 (剩余封禁时间, 是否被封)
func (l *IPLimiter) CheckBan(ip string) (time.Duration, bool) {
	if isWhitelisted(ip) {
		return 0, false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()

	att, exists := l.attempts[ip]
	if !exists {
		return 0, false
	}
	now := time.Now()
	if now.Before(att.BannedUntil) {
		return att.BannedUntil.Sub(now), true
	}
	return 0, false
}

// RecordFailure 记录一次密码错误尝试，返回 (是否触发封禁, 剩余封锁时间, 累计失败次数)
func (l *IPLimiter) RecordFailure(ip string) (banned bool, remainingTime time.Duration, fails int) {
	if isWhitelisted(ip) {
		return false, 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	att, exists := l.attempts[ip]
	if !exists || now.Sub(att.LastFail) > l.window {
		att = &ipAttempt{
			FailCount: 1,
			LastFail:  now,
			Source:    BanSourceLoginFail,
			Reason:    "后台登录密码连续输错",
		}
		l.attempts[ip] = att
		l.SaveLocked()
		return false, 0, 1
	}

	att.FailCount++
	att.LastFail = now
	if att.Source == "" {
		att.Source = BanSourceLoginFail
	}
	if att.Reason == "" {
		att.Reason = "后台登录密码连续输错"
	}

	if att.FailCount >= l.maxAttempts {
		if now.After(att.BannedUntil) || att.BannedUntil.Sub(now) < l.banDuration {
			att.BannedUntil = now.Add(l.banDuration)
		}
		l.SaveLocked()
		return true, time.Until(att.BannedUntil), att.FailCount
	}

	l.SaveLocked()
	return false, 0, att.FailCount
}

// RecordSuccess 登录成功时清空该 IP 的失败记录
func (l *IPLimiter) RecordSuccess(ip string) {
	if isWhitelisted(ip) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.attempts[ip]; exists {
		delete(l.attempts, ip)
		l.SaveLocked()
	}
}

// Unban 解除指定 IP 或全部 IP 的封禁
func (l *IPLimiter) Unban(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ip == "all" || ip == "*" || ip == "" {
		if len(l.attempts) > 0 {
			l.attempts = make(map[string]*ipAttempt)
			l.SaveLocked()
		}
		return true
	}
	if _, exists := l.attempts[ip]; exists {
		delete(l.attempts, ip)
		l.SaveLocked()
		return true
	}
	return false
}

// ListBans 获取当前所有活跃封禁中的 IP 及其剩余时间
func (l *IPLimiter) ListBans() map[string]time.Duration {
	l.mu.RLock()
	defer l.mu.RUnlock()
	result := make(map[string]time.Duration)
	now := time.Now()
	for ip, att := range l.attempts {
		if now.Before(att.BannedUntil) {
			result[ip] = att.BannedUntil.Sub(now)
		}
	}
	return result
}

// BanSourceLabel 返回封禁来源的可读中文标签
func BanSourceLabel(source string) string {
	if source == BanSourceManualSniff {
		return "嗅探手动封禁"
	}
	return "密码试错拦截"
}

// FormatDurationCN 将时长格式化为友好的中文剩余时间（如 "6天14小时"、"12分钟"）
func FormatDurationCN(d time.Duration) string {
	if d <= 0 {
		return "即将解封"
	}
	totalMins := int((d + 30*time.Second) / time.Minute)
	if totalMins < 1 {
		return "< 1 分钟"
	}
	days := totalMins / (24 * 60)
	hours := (totalMins % (24 * 60)) / 60
	mins := totalMins % 60
	if days > 0 {
		if hours > 0 {
			return fmt.Sprintf("%d 天 %d 小时", days, hours)
		}
		return fmt.Sprintf("%d 天", days)
	}
	if hours > 0 {
		if mins > 0 {
			return fmt.Sprintf("%d 小时 %d 分钟", hours, mins)
		}
		return fmt.Sprintf("%d 小时", hours)
	}
	return fmt.Sprintf("%d 分钟", mins)
}

// ListBanDetails 获取当前所有活跃封禁记录的结构化详情（优先展示密码爆破拦截）
func (l *IPLimiter) ListBanDetails() []BanDetail {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	out := make([]BanDetail, 0, len(l.attempts))
	for ip, att := range l.attempts {
		if att == nil || !now.Before(att.BannedUntil) {
			continue
		}
		src := att.Source
		if src == "" {
			if att.BannedUntil.Sub(att.LastFail) > time.Hour {
				src = BanSourceManualSniff
			} else {
				src = BanSourceLoginFail
			}
		}
		reason := att.Reason
		if reason == "" {
			if src == BanSourceManualSniff {
				reason = "嗅探雷达手动拉黑"
			} else {
				reason = "后台登录密码连续输错"
			}
		}
		out = append(out, BanDetail{
			IP:          ip,
			Remaining:   att.BannedUntil.Sub(now),
			BannedUntil: att.BannedUntil,
			FailCount:   max(att.FailCount, 1),
			Source:      src,
			SourceLabel: BanSourceLabel(src),
			Reason:      reason,
		})
	}
	slices.SortFunc(out, func(a, b BanDetail) int {
		if a.Source != b.Source {
			if a.Source == BanSourceLoginFail {
				return -1
			}
			return 1
		}
		if !a.BannedUntil.Equal(b.BannedUntil) {
			if a.BannedUntil.After(b.BannedUntil) {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.IP, b.IP)
	})
	return out
}

// AttemptSnapshot 暴露给嗅探追踪器的只读失败记录快照
type AttemptSnapshot struct {
	IP        string
	FailCount int
	LastFail  time.Time
	Banned    bool
	Source    string
}

// ListAllAttempts 返回窗口内所有试探或已封禁的 IP 快照
func (l *IPLimiter) ListAllAttempts() []AttemptSnapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()
	now := time.Now()
	out := make([]AttemptSnapshot, 0, len(l.attempts))
	for ip, att := range l.attempts {
		if att == nil || isWhitelisted(ip) {
			continue
		}
		banned := now.Before(att.BannedUntil)
		if banned || now.Sub(att.LastFail) <= l.window {
			out = append(out, AttemptSnapshot{
				IP:        ip,
				FailCount: max(att.FailCount, 1),
				LastFail:  att.LastFail,
				Banned:    banned,
				Source:    cmp.Or(att.Source, BanSourceLoginFail),
			})
		}
	}
	return out
}

// BanManual 手动封禁指定 IP 指定时长并持久化
func (l *IPLimiter) BanManual(ip string, duration time.Duration, reason ...string) {
	ip = strings.TrimSpace(ip)
	if ip == "" || isWhitelisted(ip) {
		return
	}
	if duration <= 0 {
		duration = 7 * 24 * time.Hour
	}
	note := "嗅探雷达手动拉黑"
	if len(reason) > 0 && strings.TrimSpace(reason[0]) != "" {
		note = strings.TrimSpace(reason[0])
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	att, exists := l.attempts[ip]
	if !exists || att == nil {
		att = &ipAttempt{
			FailCount: l.maxAttempts,
			LastFail:  now,
		}
		l.attempts[ip] = att
	}
	if att.FailCount < l.maxAttempts {
		att.FailCount = l.maxAttempts
	}
	att.LastFail = now
	att.BannedUntil = now.Add(duration)
	att.Source = BanSourceManualSniff
	att.Reason = note
	l.SaveLocked()
}

// startCleaner 定时清理过期记录，杜绝内存泄漏
func (l *IPLimiter) startCleaner() {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.mu.Lock()
			now := time.Now()
			changed := false
			for ip, att := range l.attempts {
				if now.After(att.BannedUntil) && now.Sub(att.LastFail) > l.window {
					delete(l.attempts, ip)
					changed = true
				}
			}
			if changed {
				l.SaveLocked()
			}
			l.mu.Unlock()
		case <-l.stopCleaner:
			return
		}
	}
}

// Close 停止后台清理协程
func (l *IPLimiter) Close() {
	select {
	case <-l.stopCleaner:
	default:
		close(l.stopCleaner)
	}
}

// UnbanPersistedIP 直接修改磁盘上的持久化封禁记录文件（供本地 CLI 兜底解封使用）
func UnbanPersistedIP(banFilePath, targetIP string) error {
	if strings.TrimSpace(banFilePath) == "" {
		return nil
	}
	if _, err := os.Stat(banFilePath); os.IsNotExist(err) {
		return nil
	}
	l := NewIPLimiter(3, 10*time.Minute, 15*time.Minute, banFilePath)
	defer l.Close()
	l.Unban(strings.TrimSpace(targetIP))
	return nil
}
