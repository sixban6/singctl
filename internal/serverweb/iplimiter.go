package serverweb

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ipAttempt struct {
	failCount   int
	lastFail    time.Time
	bannedUntil time.Time
}

// IPLimiter IP 登录限流与防暴力破解器
type IPLimiter struct {
	mu          sync.RWMutex
	attempts    map[string]*ipAttempt
	maxAttempts int
	window      time.Duration
	banDuration time.Duration
	stopCleaner chan struct{}
}

// NewIPLimiter 创建 IPLimiter 实例 (默认 3 次失败、10 分钟窗口、15 分钟封禁)
func NewIPLimiter(maxAttempts int, window, banDuration time.Duration) *IPLimiter {
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	if window <= 0 {
		window = 10 * time.Minute
	}
	if banDuration <= 0 {
		banDuration = 15 * time.Minute
	}

	l := &IPLimiter{
		attempts:    make(map[string]*ipAttempt),
		maxAttempts: maxAttempts,
		window:      window,
		banDuration: banDuration,
		stopCleaner: make(chan struct{}),
	}
	go l.startCleaner()
	return l
}

// GetClientIP 提取真实终端源 IP (支持 Cloudflare、Caddy 反代头与 RemoteAddr)
func GetClientIP(r *http.Request) string {
	// 1. Cloudflare CDN Header
	if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
		return cf
	}
	// 2. X-Real-IP
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	// 3. X-Forwarded-For (提取首个真实客户端 IP)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	// 4. RemoteAddr 回退 (去除端口)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
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
	if now.Before(att.bannedUntil) {
		return att.bannedUntil.Sub(now), true
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
	if !exists || now.Sub(att.lastFail) > l.window {
		att = &ipAttempt{
			failCount: 1,
			lastFail:  now,
		}
		l.attempts[ip] = att
		return false, 0, 1
	}

	att.failCount++
	att.lastFail = now

	if att.failCount >= l.maxAttempts {
		att.bannedUntil = now.Add(l.banDuration)
		return true, l.banDuration, att.failCount
	}

	return false, 0, att.failCount
}

// RecordSuccess 登录成功时清空该 IP 的失败记录
func (l *IPLimiter) RecordSuccess(ip string) {
	if isWhitelisted(ip) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// Unban 解除指定 IP 或全部 IP 的封禁
func (l *IPLimiter) Unban(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ip == "all" || ip == "*" || ip == "" {
		l.attempts = make(map[string]*ipAttempt)
		return true
	}
	if _, exists := l.attempts[ip]; exists {
		delete(l.attempts, ip)
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
		if now.Before(att.bannedUntil) {
			result[ip] = att.bannedUntil.Sub(now)
		}
	}
	return result
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
			for ip, att := range l.attempts {
				if now.After(att.bannedUntil) && now.Sub(att.lastFail) > l.window {
					delete(l.attempts, ip)
				}
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
