package daemon

import (
	"sync"
	"time"
)

// RestartLimiter 重启频率限制器
type RestartLimiter struct {
	maxRestarts  int           // 最大重启次数
	timeWindow   time.Duration // 时间窗口
	restartTimes []time.Time   // 重启时间记录
	mu           sync.Mutex    // 并发保护
}

// NewRestartLimiter 创建重启限制器
func NewRestartLimiter() *RestartLimiter {
	return &RestartLimiter{
		maxRestarts:  3,                    // 1小时最多3次
		timeWindow:   time.Hour,            // 1小时窗口
		restartTimes: make([]time.Time, 0),
	}
}

// CanRestart 检查是否可以重启
func (rl *RestartLimiter) CanRestart() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.timeWindow) // 1小时前的时间

	// 清理过期的重启记录
	validRestarts := make([]time.Time, 0)
	for _, t := range rl.restartTimes {
		if t.After(cutoff) {
			validRestarts = append(validRestarts, t)
		}
	}
	rl.restartTimes = validRestarts

	// 检查是否超出限制
	return len(rl.restartTimes) < rl.maxRestarts
}

// RecordRestart 记录重启时间
func (rl *RestartLimiter) RecordRestart() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.restartTimes = append(rl.restartTimes, time.Now())
}

// GetRestartCount 获取当前时间窗口内的重启次数
func (rl *RestartLimiter) GetRestartCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.timeWindow)

	count := 0
	for _, t := range rl.restartTimes {
		if t.After(cutoff) {
			count++
		}
	}

	return count
}

// GetMaxRestarts 获取最大重启次数
func (rl *RestartLimiter) GetMaxRestarts() int {
	return rl.maxRestarts
}

// GetRestartDelay 获取重启延迟（渐进式退避）
func (rl *RestartLimiter) GetRestartDelay() time.Duration {
	restartCount := rl.GetRestartCount()
	
	switch restartCount {
	case 0:
		return 0 // 第1次立即重启
	case 1:
		return 30 * time.Second // 第2次等待30秒
	case 2:
		return 2 * time.Minute // 第3次等待2分钟
	default:
		return 5 * time.Minute // 其他情况等待5分钟
	}
}