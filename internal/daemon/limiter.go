// 文件职责：实现每小时重启次数滑动窗口限流器与指数退避策略，并与 StateStore 无缝同步持久化。
package daemon

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const (
	DefaultMaxRestarts = 3
	defaultTimeWindow  = time.Hour
)

// RestartLimiter 重启频率限制器。
type RestartLimiter struct {
	maxRestarts   int
	timeWindow    time.Duration
	restartTimes  []time.Time
	totalRestarts int64
	store         *StateStore
	mu            sync.Mutex
}

// NewRestartLimiter 创建默认重启限制器（内存态，落盘时合并至默认 StateStore）。
func NewRestartLimiter() *RestartLimiter {
	return &RestartLimiter{
		maxRestarts:  DefaultMaxRestarts,
		timeWindow:   defaultTimeWindow,
		restartTimes: make([]time.Time, 0),
		store:        defaultStateStore,
	}
}

// NewRestartLimiterWithMax 创建指定上限的重启限制器。
func NewRestartLimiterWithMax(max int) *RestartLimiter {
	rl := NewRestartLimiter()
	if max > 0 {
		rl.maxRestarts = max
	}
	return rl
}

// NewRestartLimiterFromState 读取默认状态文件中的持久化重启记录构建限制器。
func NewRestartLimiterFromState(max int) *RestartLimiter {
	return NewRestartLimiterFromStore(max, defaultStateStore)
}

// NewRestartLimiterFromStore 从指定 StateStore 恢复持久化的重启记录构建限制器。
func NewRestartLimiterFromStore(max int, store *StateStore) *RestartLimiter {
	if store == nil {
		store = defaultStateStore
	}
	rl := NewRestartLimiterWithMax(max)
	rl.store = store
	p := store.effectivePaths()
	if data, err := os.ReadFile(p.StateFile); err == nil {
		var legacy []int64
		if json.Unmarshal(data, &legacy) == nil {
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

func (rl *RestartLimiter) loadTimes(ts []int64) {
	cutoff := time.Now().Add(-rl.timeWindow)
	for _, v := range ts {
		if t := time.Unix(v, 0); t.After(cutoff) {
			rl.restartTimes = append(rl.restartTimes, t)
		}
	}
}

func (rl *RestartLimiter) persist() {
	ts := make([]int64, 0, len(rl.restartTimes))
	for _, t := range rl.restartTimes {
		ts = append(ts, t.Unix())
	}
	total := rl.totalRestarts
	store := rl.store
	if store == nil {
		store = defaultStateStore
	}
	store.Update(func(snap *DaemonRuntimeSnapshot) {
		snap.Total = total
		snap.Times = ts
	})
}

// SetMaxRestarts 动态更新每小时最大重启次数上限。
func (rl *RestartLimiter) SetMaxRestarts(max int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if max > 0 {
		rl.maxRestarts = max
	} else {
		rl.maxRestarts = DefaultMaxRestarts
	}
}

// CanRestart 检查当前滑动窗口内是否允许继续自动重启。
func (rl *RestartLimiter) CanRestart() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.timeWindow)
	validRestarts := make([]time.Time, 0, len(rl.restartTimes))
	for _, t := range rl.restartTimes {
		if t.After(cutoff) {
			validRestarts = append(validRestarts, t)
		}
	}
	rl.restartTimes = validRestarts
	return len(rl.restartTimes) < rl.maxRestarts
}

// RecordRestart 记录一次重启并持久化到关联的 StateStore。
func (rl *RestartLimiter) RecordRestart() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.restartTimes = append(rl.restartTimes, time.Now())
	rl.totalRestarts++
	rl.persist()
}

// GetTotalRestarts 获取累计重启总数。
func (rl *RestartLimiter) GetTotalRestarts() int64 {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.totalRestarts
}

// GetRestartCount 获取当前时间窗口内的重启次数。
func (rl *RestartLimiter) GetRestartCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.timeWindow)
	count := 0
	for _, t := range rl.restartTimes {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// GetMaxRestarts 获取每小时最大重启次数。
func (rl *RestartLimiter) GetMaxRestarts() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.maxRestarts
}

// GetRestartDelay 获取重启渐进式退避延迟。
func (rl *RestartLimiter) GetRestartDelay() time.Duration {
	switch rl.GetRestartCount() {
	case 0:
		return 0
	case 1:
		return 30 * time.Second
	case 2:
		return 2 * time.Minute
	default:
		return 5 * time.Minute
	}
}
