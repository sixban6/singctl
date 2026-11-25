// 文件职责：管理守护进程运行态全景快照持久化（StateStore）、0600 原子落盘与历史看门狗事件回填。
package daemon

import (
	"cmp"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/homedomain"
	"singctl/internal/tailscale"
)

const maxRecentWatchdogEvents = 25

// FailoverActiveItem 记录当前正处于故障切备接管状态的策略组详情。
type FailoverActiveItem struct {
	Group     string `json:"group"`
	Origin    string `json:"origin"`
	Current   string `json:"current"`
	Since     string `json:"since"`
	LastDelay int    `json:"lastDelayMs,omitempty"`
}

// WatchdogEventRecord 结构化守护事件记录（供 WebUI 时间线与 dm status 展示）。
type WatchdogEventRecord struct {
	Time    string `json:"time"`
	Action  string `json:"action"`
	Healthy bool   `json:"healthy"`
	Summary string `json:"summary"`
}

// DaemonRuntimeSnapshot 持久化在 /tmp/singctl-daemon.state 中的运行态全景快照。
// 同时兼容旧版 RestartLimiter 的 total / times 字段，保证平滑升级零断层。
type DaemonRuntimeSnapshot struct {
	Total             int64                         `json:"total"`
	Times             []int64                       `json:"times"`
	DaemonVersion     string                        `json:"daemonVersion,omitempty"`
	StartedAt         string                        `json:"startedAt,omitempty"`
	LastHealthAt      string                        `json:"lastHealthAt,omitempty"`
	LastHealthOK      bool                          `json:"lastHealthOK"`
	LastHealthDetail  string                        `json:"lastHealthDetail,omitempty"`
	LastHealthDelayMs int                           `json:"lastHealthDelayMs,omitempty"`
	LastSubSyncAt     string                        `json:"lastSubSyncAt,omitempty"`
	LastSubSyncNodeCt int                           `json:"lastSubSyncNodeCount,omitempty"`
	LastSubSyncResult string                        `json:"lastSubSyncResult,omitempty"`
	LastRuleSetAt     string                        `json:"lastRuleSetAt,omitempty"`
	LastRuleSetResult string                        `json:"lastRuleSetResult,omitempty"`
	LastFailoverAt    string                        `json:"lastFailoverAt,omitempty"`
	ActiveFailovers   []FailoverActiveItem          `json:"activeFailovers,omitempty"`
	TailscaleP2P      *tailscale.P2PRuntimeSnapshot `json:"tailscaleP2P,omitempty"`
	HomeDomainDNS     *homedomain.ResponderStatus   `json:"homeDomainDns,omitempty"`
	WebEmbedded       bool                          `json:"webEmbedded,omitempty"`
	WebEmbeddedListen string                        `json:"webEmbeddedListen,omitempty"`
	RecentEvents      []WatchdogEventRecord         `json:"recentEvents,omitempty"`
}

// StateStore 以显式注入的 Paths 并发安全地读写守护进程运行态快照。
type StateStore struct {
	paths Paths
	mu    sync.Mutex
}

// NewStateStore 创建隔离文件路径的守护进程状态存储器。
func NewStateStore(paths Paths) *StateStore {
	return &StateStore{paths: paths}
}

func (s *StateStore) effectivePaths() Paths {
	def := DefaultPaths()
	if s == nil {
		return def
	}
	return Paths{
		PidFile:   cmp.Or(strings.TrimSpace(s.paths.PidFile), def.PidFile),
		StateFile: cmp.Or(strings.TrimSpace(s.paths.StateFile), def.StateFile),
		LogFile:   cmp.Or(strings.TrimSpace(s.paths.LogFile), def.LogFile),
	}
}

// Load 读取当前运行态快照（兼容旧版纯时间戳数组格式）。
func (s *StateStore) Load() DaemonRuntimeSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadUnlocked()
}

func (s *StateStore) loadUnlocked() DaemonRuntimeSnapshot {
	p := s.effectivePaths()
	var snap DaemonRuntimeSnapshot
	data, err := os.ReadFile(p.StateFile)
	if err == nil && len(data) > 0 {
		var legacy []int64
		if json.Unmarshal(data, &legacy) == nil {
			snap.Times = legacy
		} else {
			_ = json.Unmarshal(data, &snap)
		}
	}
	if len(snap.RecentEvents) == 0 {
		snap.RecentEvents = backfillRecentEventsFromDaemonLog(p.LogFile, maxRecentWatchdogEvents)
	}
	return snap
}

// Update 以并发安全、0600 原子替换方式读取-修改-保存运行态快照。
func (s *StateStore) Update(mutator func(*DaemonRuntimeSnapshot)) {
	if mutator == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.effectivePaths()
	snap := s.loadUnlocked()
	mutator(&snap)
	if len(snap.RecentEvents) > maxRecentWatchdogEvents {
		snap.RecentEvents = snap.RecentEvents[len(snap.RecentEvents)-maxRecentWatchdogEvents:]
	}

	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	_ = fsx.WriteAtomic0600(p.StateFile, b)
}

// AppendEvent 向状态快照追加一条结构化事件。
func (s *StateStore) AppendEvent(ev WatchdogEventRecord) {
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.DateTime)
	}
	s.Update(func(snap *DaemonRuntimeSnapshot) {
		snap.RecentEvents = append(snap.RecentEvents, ev)
	})
}

var defaultStateStore = &StateStore{}

// LoadRuntimeSnapshot 读取当前守护进程运行态快照（兼容旧版纯时间戳数组格式）。
func LoadRuntimeSnapshot() DaemonRuntimeSnapshot {
	return defaultStateStore.Load()
}

// UpdateRuntimeState 以并发安全、0600 原子替换方式读取-修改-保存守护进程状态文件。
func UpdateRuntimeState(mutator func(*DaemonRuntimeSnapshot)) {
	defaultStateStore.Update(mutator)
}

// AppendRuntimeEvent 向状态快照追加一条结构化事件。
func AppendRuntimeEvent(ev WatchdogEventRecord) {
	defaultStateStore.AppendEvent(ev)
}

var (
	watchdogLogLineRe = regexp.MustCompile(`^\[([0-9-]+ [0-9:]+)\] \[WATCHDOG\] action=([^\s]+) healthy=(true|false) reason=(.*?) detail=(.*?) restart_result=(.*)$`)
	ruleSetLogLineRe  = regexp.MustCompile(`^([0-9/]+ [0-9:]+) \[INFO\] \[RuleSet\] Background silent refresh completed: (.*)$`)
)

func backfillRecentEventsFromDaemonLog(logPath string, limit int) []WatchdogEventRecord {
	data, err := os.ReadFile(logPath)
	if err != nil || len(data) == 0 {
		return nil
	}
	if len(data) > 128*1024 {
		data = data[len(data)-128*1024:]
	}
	var out []WatchdogEventRecord
	for raw := range strings.SplitSeq(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if m := watchdogLogLineRe.FindStringSubmatch(line); len(m) == 7 {
			ts, action, healthyStr, reason, detail, res := m[1], m[2], m[3], strings.TrimSpace(m[4]), strings.TrimSpace(m[5]), strings.TrimSpace(m[6])
			healthy := healthyStr == "true" || action == "GROUP_FAILBACK" || (action == "SUB_SYNC" && !strings.Contains(res, "rolled back"))
			summary := res
			if summary == "" || summary == "-" {
				summary = cmp.Or(detail, reason)
			}
			out = append(out, WatchdogEventRecord{
				Time:    ts,
				Action:  action,
				Healthy: healthy,
				Summary: summary,
			})
			continue
		}
		if m := ruleSetLogLineRe.FindStringSubmatch(line); len(m) == 3 {
			ts := strings.ReplaceAll(m[1], "/", "-")
			out = append(out, WatchdogEventRecord{
				Time:    ts,
				Action:  "RULESET_REFRESH",
				Healthy: true,
				Summary: strings.TrimSpace(m[2]),
			})
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}
