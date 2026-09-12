package daemon

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const (
	// DefaultMaxRestarts 默认每小时最大自动重启次数
	DefaultMaxRestarts = 3
	defaultTimeWindow  = time.Hour
)

// RestartLimiter 重启频率限制器
type RestartLimiter struct {
	maxRestarts    int           // 最大重启次数
	timeWindow     time.Duration // 时间窗口
	restartTimes   []time.Time   // 重启时间记录
	totalRestarts  int64         // 累计重启总数(跨窗口, 随状态文件持久化)
	mu             sync.Mutex    // 并发保护
}

// NewRestartLimiter 创建重启限制器（内存态，不读取持久化状态）。
// 守护进程自身使用；需要展示历史计数时用 NewRestartLimiterFromState。
func NewRestartLimiter() *RestartLimiter {
	return &RestartLimiter{
		maxRestarts:  DefaultMaxRestarts,
		timeWindow:   defaultTimeWindow,
		restartTimes: make([]time.Time, 0),
	}
}

// NewRestartLimiterWithMax 创建指定上限的重启限制器
func NewRestartLimiterWithMax(max int) *RestartLimiter {
	rl := NewRestartLimiter()
	if max > 0 {
		rl.maxRestarts = max
	}
	return rl
}

// NewRestartLimiterFromState 读取持久化的重启记录构建限制器。
// 用于 dm status / WebUI 等外部观察者：真实计数只存在于看门狗进程内存中，
// 这里从状态文件恢复（看门狗每次 RecordRestart 都会落盘）。
// 兼容旧格式(纯时间戳数组, 无累计总数——总数从 0 重新累计)。
func NewRestartLimiterFromState(max int) *RestartLimiter {
	rl := NewRestartLimiterWithMax(max)
	if data, err := os.ReadFile(getStateFilePath()); err == nil {
		var legacy []int64
		if json.Unmarshal(data, &legacy) == nil {
			// 旧格式: 纯时间戳数组
			rl.loadTimes(legacy)
			return rl
		}
		var st struct {
			Total int64   `json:"total"`
			Times []int64 `json:"times"`
		}
		if json.Unmarshal(data, &st) == nil {
			rl.totalRestarts = st.Total
			rl.loadTimes(st.Times)
		}
	}
	return rl
}

// loadTimes 载入窗口内的时间戳(丢弃过期记录)
func (rl *RestartLimiter) loadTimes(ts []int64) {
	cutoff := time.Now().Add(-rl.timeWindow)
	for _, v := range ts {
		if t := time.Unix(v, 0); t.After(cutoff) {
			rl.restartTimes = append(rl.restartTimes, t)
		}
	}
}

// persist 将重启记录写入状态文件（调用方需持有锁）
// 格式: {"total":累计总数,"times":窗口内时间戳}; 兼容读取旧格式(纯数组)
func (rl *RestartLimiter) persist() {
	ts := make([]int64, 0, len(rl.restartTimes))
	for _, t := range rl.restartTimes {
		ts = append(ts, t.Unix())
	}
	b, err := json.Marshal(struct {
		Total int64   `json:"total"`
		Times []int64 `json:"times"`
	}{Total: rl.totalRestarts, Times: ts})
	if err != nil {
		return
	}
	tmp := getStateFilePath() + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, getStateFilePath())
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

// RecordRestart 记录重启时间（累计总数+1 并持久化）
func (rl *RestartLimiter) RecordRestart() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.restartTimes = append(rl.restartTimes, time.Now())
	rl.totalRestarts++
	rl.persist()
}

// GetTotalRestarts 获取累计重启总数(跨时间窗口, 从状态文件恢复)
func (rl *RestartLimiter) GetTotalRestarts() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.totalRestarts
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
