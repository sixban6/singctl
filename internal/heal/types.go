package heal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PostureLevel summarizes the overall 3-layer security state of a node.
const (
	PostureHealthy        = "healthy"         // 已全面免疫
	PostureUpdatesPending = "updates_pending" // 存在待修复的核心组件或系统安全补丁
	PostureRebootRequired = "reboot_required" // 补丁已就绪，待滚动重启生效新内核
)

// ComponentCheck describes version & update status of a single Layer-1 core binary.
type ComponentCheck struct {
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	Installed      bool   `json:"installed"`
	HasUpdate      bool   `json:"hasUpdate"`
}

// CoreLayerStatus captures Layer-1 (SingCtl + 4-core proxy stack) security posture.
type CoreLayerStatus struct {
	Components   []ComponentCheck `json:"components"`
	PendingCount int              `json:"pendingCount"`
	Healthy      bool             `json:"healthy"`
}

// OSLayerStatus captures Layer-2 (OS security repository updates + stale deleted .so in RAM).
type OSLayerStatus struct {
	Distro             string   `json:"distro"`
	PackageManager     string   `json:"packageManager"` // apt | dnf | opkg | unknown
	OpenWrtProtected   bool     `json:"openwrtProtected,omitempty"`
	SecurityUpdates    []string `json:"securityUpdates"`
	SecurityCount      int      `json:"securityCount"`
	StaleServices      []string `json:"staleServices"` // services holding (deleted) .so in memory
	LastAptCacheUpdate string   `json:"lastAptCacheUpdate,omitempty"`
	Healthy            bool     `json:"healthy"`
}

// KernelLayerStatus captures Layer-3 (running kernel vs installed kernel & reboot-required flag).
type KernelLayerStatus struct {
	RunningKernel   string   `json:"runningKernel"`
	InstalledKernel string   `json:"installedKernel,omitempty"`
	RebootRequired  bool     `json:"rebootRequired"`
	RebootReason    string   `json:"rebootReason,omitempty"`
	AffectedPkgs    []string `json:"affectedPkgs,omitempty"`
	Healthy         bool     `json:"healthy"`
}

// TimerStatus describes the native systemd timer schedule for zero-RAM automated self-healing.
type TimerStatus struct {
	Supported bool   `json:"supported"`
	Enabled   bool   `json:"enabled"`
	Active    bool   `json:"active"`
	Schedule  string `json:"schedule"`
	NextRun   string `json:"nextRun,omitempty"`
	LastRun   string `json:"lastRun,omitempty"`
}

// HealPolicy configures automated self-healing behavior persisted in security_heal.json.
type HealPolicy struct {
	AutoHealEnabled bool   `json:"autoHealEnabled"`
	Schedule        string `json:"schedule"`   // systemd OnCalendar, default "*-*-* 04:00:00"
	AutoReboot      bool   `json:"autoReboot"` // allow scheduled 04:00 maintenance reboot when kernel requires it
}

// DefaultPolicy returns safe production defaults for automated security self-healing.
func DefaultPolicy() HealPolicy {
	return HealPolicy{
		AutoHealEnabled: false,
		Schedule:        "*-*-* 04:00:00",
		AutoReboot:      false,
	}
}

// LayerActionDetail records concrete remediation steps or rollbacks during a heal run.
type LayerActionDetail struct {
	Layer      string `json:"layer"`   // core | os | kernel
	Target     string `json:"target"`  // singbox | caddy | apt-security | stale-libs | kernel
	Success    bool   `json:"success"` // true if applied or already clean
	Updated    bool   `json:"updated"` // true if a change/reload occurred
	RolledBack bool   `json:"rolledBack,omitempty"`
	Message    string `json:"message"`
}

// HealHistoryItem stores an immutable audit entry for a completed self-healing run.
type HealHistoryItem struct {
	Timestamp      string              `json:"timestamp"`
	Trigger        string              `json:"trigger"` // manual | timer | fleet
	Success        bool                `json:"success"`
	DurationMs     int64               `json:"durationMs"`
	Summary        string              `json:"summary"`
	Actions        []LayerActionDetail `json:"actions"`
	RebootRequired bool                `json:"rebootRequired"`
}

// StatusReport is the complete 3-layer security posture + timer + history view returned to CLI & WebUI.
type StatusReport struct {
	CheckedAt    string            `json:"checkedAt"`
	Posture      string            `json:"posture"`
	PostureLabel string            `json:"postureLabel"`
	Core         CoreLayerStatus   `json:"core"`
	OS           OSLayerStatus     `json:"os"`
	Kernel       KernelLayerStatus `json:"kernel"`
	Timer        TimerStatus       `json:"timer"`
	Policy       HealPolicy        `json:"policy"`
	History      []HealHistoryItem `json:"history"`
}

// RunOptions controls execution of a self-healing pass.
type RunOptions struct {
	ConfigPath        string
	CurrentSingctlVer string
	CheckOnly         bool
	AllowReboot       bool
	Trigger           string // "manual" | "timer" | "fleet"
	// AsyncWebRestart defers restarting singctl-web by 2s so an in-flight HTTP response finishes cleanly.
	AsyncWebRestart bool
}

// RunResult returns both the execution audit item and the refreshed post-heal posture.
type RunResult struct {
	Execution HealHistoryItem `json:"execution"`
	Status    StatusReport    `json:"status"`
}

type PersistedHealState struct {
	Policy     HealPolicy        `json:"policy"`
	LastStatus *StatusReport     `json:"lastStatus,omitempty"`
	History    []HealHistoryItem `json:"history"`
}

var stateMu sync.Mutex

// ResolveStateFilePath locates security_heal.json alongside singctl.yaml.
func ResolveStateFilePath(configPath string) string {
	if strings.TrimSpace(configPath) != "" {
		return filepath.Join(filepath.Dir(configPath), "security_heal.json")
	}
	if st, err := os.Stat("/etc/singctl"); err == nil && st.IsDir() {
		return "/etc/singctl/security_heal.json"
	}
	return filepath.Join(os.TempDir(), "singctl-heal", "security_heal.json")
}

func LoadPersistedState(statePath string) PersistedHealState {
	stateMu.Lock()
	defer stateMu.Unlock()
	return readStateUnlocked(statePath)
}

func readStateUnlocked(statePath string) PersistedHealState {
	def := PersistedHealState{
		Policy:  DefaultPolicy(),
		History: []HealHistoryItem{},
	}
	raw, err := os.ReadFile(statePath)
	if err != nil || len(raw) == 0 {
		return def
	}
	var st PersistedHealState
	if err := json.Unmarshal(raw, &st); err != nil {
		return def
	}
	if strings.TrimSpace(st.Policy.Schedule) == "" {
		st.Policy.Schedule = DefaultPolicy().Schedule
	}
	if st.History == nil {
		st.History = []HealHistoryItem{}
	}
	return st
}

func writeStateUnlocked(statePath string, st PersistedHealState) error {
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, statePath)
}

// SavePolicy updates the persisted HealPolicy with 0600 permissions.
func SavePolicy(configPath string, policy HealPolicy) error {
	statePath := ResolveStateFilePath(configPath)
	stateMu.Lock()
	defer stateMu.Unlock()
	st := readStateUnlocked(statePath)
	if strings.TrimSpace(policy.Schedule) == "" {
		policy.Schedule = DefaultPolicy().Schedule
	}
	st.Policy = policy
	return writeStateUnlocked(statePath, st)
}

// RecordExecution appends a HealHistoryItem (retaining the latest 30 entries) and snapshots StatusReport.
func RecordExecution(configPath string, item HealHistoryItem, report *StatusReport) error {
	statePath := ResolveStateFilePath(configPath)
	stateMu.Lock()
	defer stateMu.Unlock()
	st := readStateUnlocked(statePath)
	if item.Timestamp == "" {
		item.Timestamp = time.Now().Format(time.RFC3339)
	}
	st.History = append([]HealHistoryItem{item}, st.History...)
	if len(st.History) > 30 {
		st.History = st.History[:30]
	}
	if report != nil {
		cp := *report
		cp.History = st.History
		cp.Policy = st.Policy
		st.LastStatus = &cp
	}
	return writeStateUnlocked(statePath, st)
}
