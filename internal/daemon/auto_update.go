// 文件职责：实现客户端核心组件（sing-box / AdGuard Home / Tailscale / SingCtl）的声明式后台定时自动更新编排与冷却状态机。
package daemon

import (
	"cmp"
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
)

const (
	AutoUpdateComponentSingCtl   = "singctl"
	AutoUpdateComponentSingBox   = "singbox"
	AutoUpdateComponentAdGuard   = "adguard_home"
	AutoUpdateComponentTailscale = "tailscale"

	defaultAutoUpdateFailureCooldown = 2 * time.Hour
	autoUpdateTickerInterval         = 30 * time.Minute
)

// AutoUpdateCheckResult 描述单个组件一次自动更新检查或升级的结果。
type AutoUpdateCheckResult struct {
	Component      string `json:"component"`
	Installed      bool   `json:"installed"`
	Updated        bool   `json:"updated"`
	Skipped        bool   `json:"skipped,omitempty"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	LatestVersion  string `json:"latestVersion,omitempty"`
	Message        string `json:"message,omitempty"`
}

// AutoUpdateComponentState 持久化在守护进程运行态快照中的单组件自动更新摘要。
type AutoUpdateComponentState struct {
	LastCheckedAt  string `json:"lastCheckedAt,omitempty"`
	LastUpdatedAt  string `json:"lastUpdatedAt,omitempty"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	LatestVersion  string `json:"latestVersion,omitempty"`
	Status         string `json:"status,omitempty"`
	Message        string `json:"message,omitempty"`
	LastError      string `json:"lastError,omitempty"`
}

// AutoUpdateTarget 声明式组件自动更新策略接口（符合开闭原则）。
type AutoUpdateTarget interface {
	ID() string
	DisplayName() string
	Enabled(cfg *config.Config) bool
	Run(ctx context.Context, cfg *config.Config) (AutoUpdateCheckResult, error)
}

// AutoUpdaterOptions 显式注入组件自动更新编排器的协作者（测试可注入假目标与可控时钟）。
type AutoUpdaterOptions struct {
	Targets         []AutoUpdateTarget
	Now             func() time.Time
	StateStore      *StateStore
	FailureCooldown time.Duration
	OnEvent         func(WatchdogEventRecord)
}

type autoUpdateTrack struct {
	lastChecked time.Time
	lastFailed  time.Time
	failed      bool
}

// ComponentAutoUpdater 编排多组件串行检查、周期限频、失败退避与快照持久化。
type ComponentAutoUpdater struct {
	targets         []AutoUpdateTarget
	nowFn           func() time.Time
	stateStore      *StateStore
	failureCooldown time.Duration
	onEvent         func(WatchdogEventRecord)

	running atomic.Bool
	mu      sync.Mutex
	tracks  map[string]autoUpdateTrack
}

// NewComponentAutoUpdater 创建核心组件定时自动更新编排器。
func NewComponentAutoUpdater(opts AutoUpdaterOptions) *ComponentAutoUpdater {
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	cooldown := opts.FailureCooldown
	if cooldown <= 0 {
		cooldown = defaultAutoUpdateFailureCooldown
	}
	return &ComponentAutoUpdater{
		targets:         opts.Targets,
		nowFn:           nowFn,
		stateStore:      opts.StateStore,
		failureCooldown: cooldown,
		onEvent:         opts.OnEvent,
		tracks:          make(map[string]autoUpdateTrack, len(opts.Targets)),
	}
}

func (u *ComponentAutoUpdater) shouldRunTarget(id string, now time.Time, interval time.Duration, force bool) bool {
	if force {
		return true
	}
	u.mu.Lock()
	tr, ok := u.tracks[id]
	u.mu.Unlock()
	if !ok {
		return true
	}
	if tr.failed {
		return now.Sub(tr.lastFailed) >= u.failureCooldown
	}
	return now.Sub(tr.lastChecked) >= interval
}

func (u *ComponentAutoUpdater) markTarget(id string, now time.Time, failed bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	tr := u.tracks[id]
	tr.lastChecked = now
	tr.failed = failed
	if failed {
		tr.lastFailed = now
	} else {
		tr.lastFailed = time.Time{}
	}
	u.tracks[id] = tr
}

func (u *ComponentAutoUpdater) persistTargetState(id string, st AutoUpdateComponentState) {
	if u.stateStore == nil {
		return
	}
	u.stateStore.Update(func(snap *DaemonRuntimeSnapshot) {
		if snap.AutoUpdate == nil {
			snap.AutoUpdate = make(map[string]AutoUpdateComponentState)
		}
		prev := snap.AutoUpdate[id]
		if st.LastUpdatedAt == "" {
			st.LastUpdatedAt = prev.LastUpdatedAt
		}
		snap.AutoUpdate[id] = st
	})
}

func (u *ComponentAutoUpdater) emitEvent(ev WatchdogEventRecord) {
	if u.onEvent != nil {
		u.onEvent(ev)
		return
	}
	if u.stateStore != nil {
		u.stateStore.AppendEvent(ev)
	}
}

// RunOnce 执行一轮组件自动更新检查（单并发互斥，全关零执行，严格按声明顺序串行执行）。
func (u *ComponentAutoUpdater) RunOnce(ctx context.Context, cfg *config.Config, force bool) []AutoUpdateCheckResult {
	if u == nil || cfg == nil || !cfg.Watchdog.AutoUpdate.AnyEnabled() {
		return nil
	}
	if !u.running.CompareAndSwap(false, true) {
		return nil
	}
	defer u.running.Store(false)

	interval := cfg.Watchdog.AutoUpdate.EffectiveInterval()
	var results []AutoUpdateCheckResult

	for _, target := range u.targets {
		if target == nil || !target.Enabled(cfg) {
			continue
		}
		if ctx != nil && ctx.Err() != nil {
			break
		}
		now := u.nowFn()
		id := target.ID()
		if !u.shouldRunTarget(id, now, interval, force) {
			continue
		}

		res, err := target.Run(ctx, cfg)
		if res.Component == "" {
			res.Component = id
		}
		checkedAt := u.nowFn()
		checkedStr := checkedAt.Format(time.DateTime)

		if err != nil {
			u.markTarget(id, checkedAt, true)
			msg := cmp.Or(res.Message, err.Error())
			u.persistTargetState(id, AutoUpdateComponentState{
				LastCheckedAt:  checkedStr,
				CurrentVersion: res.CurrentVersion,
				LatestVersion:  res.LatestVersion,
				Status:         "failed",
				Message:        msg,
				LastError:      err.Error(),
			})
			logger.Warn("[AutoUpdate] %s 自动更新失败: %v", target.DisplayName(), err)
			u.emitEvent(WatchdogEventRecord{
				Time:    checkedStr,
				Action:  "AUTO_UPDATE",
				Healthy: false,
				Summary: fmt.Sprintf("%s 自动更新失败: %s", target.DisplayName(), err.Error()),
			})
			results = append(results, res)
			continue
		}

		u.markTarget(id, checkedAt, false)
		status := "up_to_date"
		updatedAt := ""
		if res.Updated {
			status = "updated"
			updatedAt = checkedStr
			summary := cmp.Or(res.Message, fmt.Sprintf("%s 已自动更新至 %s", target.DisplayName(), res.LatestVersion))
			logger.Success("[AutoUpdate] %s", summary)
			u.emitEvent(WatchdogEventRecord{
				Time:    checkedStr,
				Action:  "AUTO_UPDATE",
				Healthy: true,
				Summary: summary,
			})
		} else if res.Skipped {
			status = "skipped"
		}

		u.persistTargetState(id, AutoUpdateComponentState{
			LastCheckedAt:  checkedStr,
			LastUpdatedAt:  updatedAt,
			CurrentVersion: res.CurrentVersion,
			LatestVersion:  res.LatestVersion,
			Status:         status,
			Message:        res.Message,
			LastError:      "",
		})
		results = append(results, res)
	}

	return results
}

func (d *Daemon) maybeRunAutoUpdateAsync(force bool) {
	if d == nil || d.autoUpdater == nil {
		return
	}
	cfg := d.currentConfig()
	if cfg == nil || !cfg.Watchdog.AutoUpdate.AnyEnabled() {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(d.ctx, 10*time.Minute)
		defer cancel()
		d.autoUpdater.RunOnce(ctx, cfg, force)
	}()
}
