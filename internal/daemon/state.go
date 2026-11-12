package daemon

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
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
	Total             int64                 `json:"total"`
	Times             []int64               `json:"times"`
	DaemonVersion     string                `json:"daemonVersion,omitempty"`
	StartedAt         string                `json:"startedAt,omitempty"`
	LastHealthAt      string                `json:"lastHealthAt,omitempty"`
	LastHealthOK      bool                  `json:"lastHealthOK"`
	LastHealthDetail  string                `json:"lastHealthDetail,omitempty"`
	LastHealthDelayMs int                   `json:"lastHealthDelayMs,omitempty"`
	LastSubSyncAt     string                `json:"lastSubSyncAt,omitempty"`
	LastSubSyncNodeCt int                   `json:"lastSubSyncNodeCount,omitempty"`
	LastSubSyncResult string                `json:"lastSubSyncResult,omitempty"`
	LastRuleSetAt     string                `json:"lastRuleSetAt,omitempty"`
	LastRuleSetResult string                `json:"lastRuleSetResult,omitempty"`
	LastFailoverAt    string                `json:"lastFailoverAt,omitempty"`
	ActiveFailovers   []FailoverActiveItem  `json:"activeFailovers,omitempty"`
	RecentEvents      []WatchdogEventRecord `json:"recentEvents,omitempty"`
}

var stateFileMu sync.Mutex

// LoadRuntimeSnapshot 读取当前守护进程运行态快照（兼容旧版纯时间戳数组格式）。
func LoadRuntimeSnapshot() DaemonRuntimeSnapshot {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()
	return loadRuntimeSnapshotUnlocked()
}

func loadRuntimeSnapshotUnlocked() DaemonRuntimeSnapshot {
	var snap DaemonRuntimeSnapshot
	data, err := os.ReadFile(GetStateFilePath())
	if err == nil && len(data) > 0 {
		var legacy []int64
		if json.Unmarshal(data, &legacy) == nil {
			snap.Times = legacy
		} else {
			_ = json.Unmarshal(data, &snap)
		}
	}
	if len(snap.RecentEvents) == 0 {
		snap.RecentEvents = backfillRecentEventsFromDaemonLog(GetDaemonLogPath(), maxRecentWatchdogEvents)
	}
	return snap
}

// UpdateRuntimeState 以并发安全、0600 原子替换方式读取-修改-保存守护进程状态文件。
func UpdateRuntimeState(mutator func(*DaemonRuntimeSnapshot)) {
	stateFileMu.Lock()
	defer stateFileMu.Unlock()

	snap := loadRuntimeSnapshotUnlocked()
	mutator(&snap)
	if len(snap.RecentEvents) > maxRecentWatchdogEvents {
		snap.RecentEvents = snap.RecentEvents[len(snap.RecentEvents)-maxRecentWatchdogEvents:]
	}

	b, err := json.Marshal(snap)
	if err != nil {
		return
	}
	target := GetStateFilePath()
	tmp := target + ".tmp"
	if os.WriteFile(tmp, b, 0600) == nil {
		_ = os.Chmod(tmp, 0600)
		_ = os.Rename(tmp, target)
	}
}

// AppendRuntimeEvent 向状态快照追加一条结构化事件。
func AppendRuntimeEvent(ev WatchdogEventRecord) {
	if ev.Time == "" {
		ev.Time = time.Now().Format(time.DateTime)
	}
	UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
		snap.RecentEvents = append(snap.RecentEvents, ev)
	})
}

var (
	watchdogLogLineRe = regexp.MustCompile(`^\[([0-9-]+ [0-9:]+)\] \[WATCHDOG\] action=([^\s]+) healthy=(true|false) reason=(.*?) detail=(.*?) restart_result=(.*)$`)
	ruleSetLogLineRe  = regexp.MustCompile(`^([0-9/]+ [0-9:]+) \[INFO\] \[RuleSet\] Background silent refresh completed: (.*)$`)
)

// backfillRecentEventsFromDaemonLog 在状态快照尚无事件时，从已有 daemon.log 尾部提取历史看门狗事件。
func backfillRecentEventsFromDaemonLog(logPath string, limit int) []WatchdogEventRecord {
	data, err := os.ReadFile(logPath)
	if err != nil || len(data) == 0 {
		return nil
	}
	// 仅扫描文件末尾最多 128KB，避免大文件开销
	if len(data) > 128*1024 {
		data = data[len(data)-128*1024:]
	}
	lines := strings.Split(string(data), "\n")
	var out []WatchdogEventRecord
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if m := watchdogLogLineRe.FindStringSubmatch(line); len(m) == 7 {
			ts, action, healthyStr, reason, detail, res := m[1], m[2], m[3], strings.TrimSpace(m[4]), strings.TrimSpace(m[5]), strings.TrimSpace(m[6])
			healthy := healthyStr == "true" || action == "GROUP_FAILBACK" || (action == "SUB_SYNC" && !strings.Contains(res, "rolled back"))
			summary := res
			if summary == "" || summary == "-" {
				if detail != "" {
					summary = detail
				} else {
					summary = reason
				}
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
