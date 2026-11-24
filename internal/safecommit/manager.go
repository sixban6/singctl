// 文件职责：提供远端安全回滚保险丝（Safe Commit）的状态机、0600 内存盘快照、脱离进程组看门狗调度与幂等原子回滚。
package safecommit

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
)

const (
	// DefaultStateDir 为默认安全回滚状态与快照根目录（落盘内存盘 /tmp，零闪存磨损）。
	DefaultStateDir = "/tmp/singctl-safecommit"
	// DefaultTTLSec 为未指定 TTL 时的默认倒计时秒数（3 分钟）。
	DefaultTTLSec = 180
	// MinTTLSec 为允许的最小回滚倒计时秒数（1 分钟）。
	MinTTLSec = 60
	// MaxTTLSec 为允许的最大回滚倒计时秒数（10 分钟）。
	MaxTTLSec = 600

	stateFileName        = "state.json"
	lastRollbackFileName = "last_rollback.json"
	watchLogFileName     = "watch.log"
	snapshotsDirName     = "snapshots"
)

var (
	// ErrInvalidTTL 表示 ArmRequest.TTLSec 超出 [MinTTLSec, MaxTTLSec] 范围。
	ErrInvalidTTL = errors.New("safecommit TTL must be between 60 and 600 seconds")
	// ErrTokenMismatch 表示 Confirm 提供的令牌与当前激活保险丝令牌不匹配。
	ErrTokenMismatch = errors.New("safecommit token mismatch")
)

// State 记录当前激活态安全回滚保险丝的元数据与快照映射。
type State struct {
	Token             string            `json:"token"`
	Reason            string            `json:"reason,omitzero"`
	ArmedAt           int64             `json:"armedAt"`
	DeadlineUnix      int64             `json:"deadlineUnix"`
	TTLSec            int               `json:"ttlSec"`
	WatcherPID        int               `json:"watcherPid,omitzero"`
	SingBoxWasRunning bool              `json:"singBoxWasRunning"`
	FirewallWasActive bool              `json:"firewallWasActive"`
	DNSEngine         string            `json:"dnsEngine,omitzero"`
	Snapshots         map[string]string `json:"snapshots,omitzero"`
}

// RollbackRecord 记录一次安全回滚的执行结果与动作清单。
type RollbackRecord struct {
	Token        string   `json:"token,omitzero"`
	Reason       string   `json:"reason,omitzero"`
	RolledBackAt int64    `json:"rolledBackAt"`
	Trigger      string   `json:"trigger"`
	Success      bool     `json:"success"`
	Actions      []string `json:"actions,omitzero"`
	Error        string   `json:"error,omitzero"`
}

// StatusReport 汇总安全回滚保险丝实时只读状态与 tailscaled OOM 免疫状态。
type StatusReport struct {
	Active       bool            `json:"active"`
	State        *State          `json:"state,omitzero"`
	RemainingSec int64           `json:"remainingSec"`
	LastRollback *RollbackRecord `json:"lastRollback,omitzero"`
	TailscaleOOM OOMShieldStatus `json:"tailscaleOom"`
}

// ArmRequest 定义启动或续期安全回滚保险丝所需的快照与服务基线状态。
type ArmRequest struct {
	TTLSec            int               `json:"ttlSec"`
	Reason            string            `json:"reason"`
	SingBoxWasRunning bool              `json:"singBoxWasRunning"`
	FirewallWasActive bool              `json:"firewallWasActive"`
	DNSEngine         string            `json:"dnsEngine"`
	SnapshotFiles     map[string]string `json:"snapshotFiles"`
}

// RollbackOps 封装回滚阶段需要调用的外部服务恢复回调，严禁直接硬编码宿主服务管理器命令。
type RollbackOps struct {
	StopSingBox          func(ctx context.Context) error
	StartOrReloadSingBox func(ctx context.Context) error
	DisableFirewall      func(ctx context.Context) error
	ReloadFirewall       func(ctx context.Context) error
	ReloadDNS            func(ctx context.Context, engine string) error
	ReloadOpenWrtNetwork func(ctx context.Context) error
	OnRolledBack         func(rec RollbackRecord)
}

// ManagerOptions 封装 Safe Commit 管理器全部可注入依赖（零值回退生产默认实现）。
type ManagerOptions struct {
	StateDir      string
	ProcRoot      string
	NowFunc       func() time.Time
	SpawnWatcher  func(token string) (int, error)
	KillWatcher   func(pid int) error
	WatchInterval time.Duration
	RollbackOps   RollbackOps
}

// Manager 管理安全回滚保险丝的启动、确认解除、看门狗巡检与幂等回滚。
type Manager struct {
	mu            sync.Mutex
	stateDir      string
	procRoot      string
	now           func() time.Time
	spawnWatcher  func(token string) (int, error)
	killWatcher   func(pid int) error
	watchInterval time.Duration
	ops           RollbackOps
}

// NewManager 创建带显式依赖注入的 Safe Commit 管理器实例。
func NewManager(opts ManagerOptions) *Manager {
	m := &Manager{
		stateDir:      cmp.Or(strings.TrimSpace(opts.StateDir), DefaultStateDir),
		procRoot:      strings.TrimSpace(opts.ProcRoot),
		now:           opts.NowFunc,
		spawnWatcher:  opts.SpawnWatcher,
		killWatcher:   opts.KillWatcher,
		watchInterval: opts.WatchInterval,
		ops:           opts.RollbackOps,
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.watchInterval <= 0 {
		m.watchInterval = time.Second
	}
	if m.spawnWatcher == nil {
		m.spawnWatcher = m.spawnDefaultWatcher
	}
	if m.killWatcher == nil {
		m.killWatcher = defaultKillWatcher
	}
	return m
}

// Arm 启动（或安全续期覆盖）安全回滚保险丝并备份已有配置文件。
func (m *Manager) Arm(ctx context.Context, req ArmRequest) (*State, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}

	ttl := req.TTLSec
	if ttl == 0 {
		ttl = DefaultTTLSec
	}
	if ttl < MinTTLSec || ttl > MaxTTLSec {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidTTL, req.TTLSec)
	}

	sortedNames := slices.Sorted(maps.Keys(req.SnapshotFiles))
	for _, name := range sortedNames {
		if err := validateSnapshotName(name); err != nil {
			return nil, err
		}
		if err := validateSnapshotPath(req.SnapshotFiles[name]); err != nil {
			return nil, fmt.Errorf("snapshot %q: %w", name, err)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.ensureStateDir(); err != nil {
		return nil, err
	}

	prevState, _ := m.readStateFile()
	nowUnix := m.now().Unix()
	inheritPrevBaseline := prevState != nil && prevState.Token != "" && nowUnix < prevState.DeadlineUnix

	token, err := generateRandomToken()
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	snapDir := filepath.Join(m.stateDir, snapshotsDirName, token)
	snapshots := make(map[string]string, len(sortedNames))
	for _, name := range sortedNames {
		srcPath := filepath.Clean(strings.TrimSpace(req.SnapshotFiles[name]))
		var raw []byte
		inherited := false
		if inheritPrevBaseline && prevState.Snapshots[name] == srcPath {
			prevSnapFile := filepath.Join(m.stateDir, snapshotsDirName, prevState.Token, name)
			if prevRaw, rErr := os.ReadFile(prevSnapFile); rErr == nil {
				raw = prevRaw
				inherited = true
			}
		}
		if !inherited {
			info, statErr := os.Stat(srcPath)
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			if statErr != nil {
				_ = os.RemoveAll(snapDir)
				return nil, fmt.Errorf("stat snapshot source %s: %w", srcPath, statErr)
			}
			if info.IsDir() {
				_ = os.RemoveAll(snapDir)
				return nil, fmt.Errorf("snapshot source %s is a directory", srcPath)
			}

			var readErr error
			raw, readErr = os.ReadFile(srcPath)
			if readErr != nil {
				_ = os.RemoveAll(snapDir)
				return nil, fmt.Errorf("read snapshot source %s: %w", srcPath, readErr)
			}
		}
		if mkErr := os.MkdirAll(snapDir, 0700); mkErr != nil {
			_ = os.RemoveAll(snapDir)
			return nil, fmt.Errorf("mkdir snapshot dir: %w", mkErr)
		}
		_ = os.Chmod(snapDir, 0700)
		dstPath := filepath.Join(snapDir, name)
		if wErr := fsx.WriteAtomic0600(dstPath, raw); wErr != nil {
			_ = os.RemoveAll(snapDir)
			return nil, fmt.Errorf("write snapshot %s: %w", name, wErr)
		}
		snapshots[name] = srcPath
	}

	st := State{
		Token:             token,
		Reason:            strings.TrimSpace(req.Reason),
		ArmedAt:           nowUnix,
		DeadlineUnix:      nowUnix + int64(ttl),
		TTLSec:            ttl,
		SingBoxWasRunning: req.SingBoxWasRunning,
		FirewallWasActive: req.FirewallWasActive,
		DNSEngine:         strings.TrimSpace(req.DNSEngine),
		Snapshots:         snapshots,
	}

	// 先落盘 state.json 再拉起 watcher，彻底消除 watcher 先醒来读不到 token 的竞态。
	if err := m.writeStateFile(st); err != nil {
		_ = os.RemoveAll(snapDir)
		return nil, fmt.Errorf("write state: %w", err)
	}

	watcherPID, err := m.spawnWatcher(token)
	if err != nil {
		// 若拉起看门狗失败，撤销本次半激活态以免遗留无看护保险丝。
		if cur, rErr := m.readStateFile(); rErr == nil && cur.Token == token {
			_ = os.Remove(m.statePath())
		}
		_ = os.RemoveAll(snapDir)
		return nil, fmt.Errorf("spawn watcher: %w", err)
	}

	st.WatcherPID = watcherPID
	if cur, rErr := m.readStateFile(); rErr == nil && cur.Token == token {
		if err := m.writeStateFile(st); err != nil {
			_ = m.killWatcher(watcherPID)
			_ = os.Remove(m.statePath())
			_ = os.RemoveAll(snapDir)
			return nil, fmt.Errorf("persist watcher pid: %w", err)
		}
	} else {
		_ = m.killWatcher(watcherPID)
	}

	// 优雅回收上一轮未过期保险丝的旧 watcher 与快照目录。
	if prevState != nil {
		if prevState.WatcherPID > 0 && prevState.WatcherPID != watcherPID {
			_ = m.killWatcher(prevState.WatcherPID)
		}
		if prevState.Token != "" && prevState.Token != token {
			_ = os.RemoveAll(filepath.Join(m.stateDir, snapshotsDirName, prevState.Token))
		}
	}

	out := cloneState(st)
	return &out, nil
}

// Confirm 确认变更有效并原子解除安全回滚保险丝。
func (m *Manager) Confirm(token string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, err := m.readStateFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	want := strings.TrimSpace(token)
	if want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(st.Token)) != 1 {
		return false, ErrTokenMismatch
	}

	claimed, claimedPath, err := m.claimStateFile("confirm")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	_ = os.Remove(claimedPath)

	m.cleanupSnapshots(claimed.Token)
	if claimed.WatcherPID > 0 && claimed.WatcherPID != os.Getpid() {
		_ = m.killWatcher(claimed.WatcherPID)
	}
	return true, nil
}

// Rollback 幂等执行配置原子还原与服务恢复，落盘 last_rollback.json 并触发回调。
func (m *Manager) Rollback(ctx context.Context, trigger string) (*RollbackRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	trigger = cmp.Or(strings.TrimSpace(trigger), "manual")

	m.mu.Lock()
	st, claimedPath, claimErr := m.claimStateFile("rollback")
	if claimErr != nil {
		m.mu.Unlock()
		if errors.Is(claimErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, claimErr
	}
	_ = os.Remove(claimedPath)

	var actions []string
	var errs []error
	allRestored := true
	restoredUCI := false

	for _, name := range slices.Sorted(maps.Keys(st.Snapshots)) {
		origPath := st.Snapshots[name]
		if vErr := validateSnapshotName(name); vErr != nil {
			allRestored = false
			errs = append(errs, vErr)
			continue
		}
		if vErr := validateSnapshotPath(origPath); vErr != nil {
			allRestored = false
			errs = append(errs, fmt.Errorf("restore %q: %w", name, vErr))
			continue
		}

		snapPath := m.resolveSnapshotFile(st.Token, name)
		data, readErr := os.ReadFile(snapPath)
		if readErr != nil {
			allRestored = false
			errs = append(errs, fmt.Errorf("read snapshot %s: %w", name, readErr))
			continue
		}
		if wErr := fsx.WriteAtomic0600(origPath, data); wErr != nil {
			allRestored = false
			errs = append(errs, fmt.Errorf("restore %s -> %s: %w", name, origPath, wErr))
			continue
		}
		if strings.HasPrefix(name, "uci_") || strings.HasPrefix(origPath, "/etc/config/") {
			restoredUCI = true
		}
		actions = append(actions, fmt.Sprintf("restore:%s->%s", name, origPath))
	}

	if allRestored {
		m.cleanupSnapshots(st.Token)
	}
	if st.WatcherPID > 0 && st.WatcherPID != os.Getpid() {
		_ = m.killWatcher(st.WatcherPID)
	}

	if restoredUCI && m.ops.ReloadOpenWrtNetwork != nil {
		if err := m.ops.ReloadOpenWrtNetwork(ctx); err != nil {
			errs = append(errs, fmt.Errorf("reload openwrt network: %w", err))
		}
		actions = append(actions, "openwrt_network:reload")
	}

	// 严格按回滚恢复序执行全部回调；单项出错绝不阻断其余关键服务恢复。
	if st.SingBoxWasRunning {
		if m.ops.StartOrReloadSingBox != nil {
			if err := m.ops.StartOrReloadSingBox(ctx); err != nil {
				errs = append(errs, fmt.Errorf("start/reload sing-box: %w", err))
			}
			actions = append(actions, "sing-box:start_or_reload")
		}
	} else {
		if m.ops.StopSingBox != nil {
			if err := m.ops.StopSingBox(ctx); err != nil {
				errs = append(errs, fmt.Errorf("stop sing-box: %w", err))
			}
			actions = append(actions, "sing-box:stop")
		}
	}

	if st.FirewallWasActive {
		if m.ops.ReloadFirewall != nil {
			if err := m.ops.ReloadFirewall(ctx); err != nil {
				errs = append(errs, fmt.Errorf("reload firewall: %w", err))
			}
			actions = append(actions, "firewall:reload")
		}
	} else {
		if m.ops.DisableFirewall != nil {
			if err := m.ops.DisableFirewall(ctx); err != nil {
				errs = append(errs, fmt.Errorf("disable firewall: %w", err))
			}
			actions = append(actions, "firewall:disable")
		}
	}

	if engine := strings.TrimSpace(st.DNSEngine); engine != "" && m.ops.ReloadDNS != nil {
		if err := m.ops.ReloadDNS(ctx, engine); err != nil {
			errs = append(errs, fmt.Errorf("reload dns (%s): %w", engine, err))
		}
		actions = append(actions, "dns:reload:"+engine)
	}

	joinedErr := errors.Join(errs...)
	rec := RollbackRecord{
		Token:        st.Token,
		Reason:       st.Reason,
		RolledBackAt: m.now().Unix(),
		Trigger:      trigger,
		Success:      joinedErr == nil,
		Actions:      actions,
	}
	if joinedErr != nil {
		rec.Error = joinedErr.Error()
	}

	if wErr := m.writeLastRollback(rec); wErr != nil {
		joinedErr = errors.Join(joinedErr, fmt.Errorf("persist last_rollback: %w", wErr))
	}
	onRolledBack := m.ops.OnRolledBack
	m.mu.Unlock()

	if onRolledBack != nil {
		onRolledBack(rec)
	}
	return &rec, joinedErr
}

// Watch 持续轮询 state.json，在被解除或令牌变更时退出，超时即触发安全回滚。
func (m *Manager) Watch(ctx context.Context, token string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return errors.New("watch token must not be empty")
	}

	checkOnce := func() (done bool, err error) {
		st, readErr := m.readStateFile()
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				return true, nil
			}
			return true, readErr
		}
		if st.Token != trimmed {
			return true, nil
		}
		if m.now().Unix() >= st.DeadlineUnix {
			_, rbErr := m.Rollback(ctx, "timeout")
			return true, rbErr
		}
		return false, nil
	}

	if done, err := checkOnce(); done {
		return err
	}

	ticker := time.NewTicker(m.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if done, err := checkOnce(); done {
				return err
			}
		}
	}
}

// Status 毫秒级只读返回保险丝激活态、剩余秒数、最近回滚记录与 Tailscale OOM 免疫状态。
func (m *Manager) Status() StatusReport {
	rep := StatusReport{
		TailscaleOOM: InspectTailscaledOOM(m.procRoot),
	}
	if st, err := m.readStateFile(); err == nil && st != nil {
		cp := cloneState(*st)
		rep.Active = true
		rep.State = &cp
		rep.RemainingSec = max(0, st.DeadlineUnix-m.now().Unix())
	}
	if rec, err := m.readLastRollback(); err == nil && rec != nil {
		rep.LastRollback = rec
	}
	return rep
}

func (m *Manager) statePath() string {
	return filepath.Join(m.stateDir, stateFileName)
}

func (m *Manager) lastRollbackPath() string {
	return filepath.Join(m.stateDir, lastRollbackFileName)
}

func (m *Manager) ensureStateDir() error {
	if err := os.MkdirAll(m.stateDir, 0700); err != nil {
		return fmt.Errorf("mkdir state dir %s: %w", m.stateDir, err)
	}
	return os.Chmod(m.stateDir, 0700)
}

func (m *Manager) readStateFile() (*State, error) {
	raw, err := os.ReadFile(m.statePath())
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("parse state.json: %w", err)
	}
	return &st, nil
}

func (m *Manager) writeStateFile(st State) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic0600(m.statePath(), append(raw, '\n'))
}

// claimStateFile 通过同目录原子 rename 独占认领 state.json，彻底防止跨进程/跨协程 Confirm 与 Rollback 双重触发。
func (m *Manager) claimStateFile(op string) (*State, string, error) {
	suffix, err := generateRandomToken()
	if err != nil {
		return nil, "", err
	}
	claimPath := filepath.Join(m.stateDir, fmt.Sprintf(".%s.%s-%s", stateFileName, op, suffix[:12]))
	if err := os.Rename(m.statePath(), claimPath); err != nil {
		return nil, "", err
	}
	raw, err := os.ReadFile(claimPath)
	if err != nil {
		_ = os.Remove(claimPath)
		return nil, "", err
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		_ = os.Remove(claimPath)
		return nil, "", fmt.Errorf("parse claimed state.json: %w", err)
	}
	return &st, claimPath, nil
}

func (m *Manager) writeLastRollback(rec RollbackRecord) error {
	if err := m.ensureStateDir(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return fsx.WriteAtomic0600(m.lastRollbackPath(), append(raw, '\n'))
}

func (m *Manager) readLastRollback() (*RollbackRecord, error) {
	raw, err := os.ReadFile(m.lastRollbackPath())
	if err != nil {
		return nil, err
	}
	var rec RollbackRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (m *Manager) resolveSnapshotFile(token, name string) string {
	tokenScoped := filepath.Join(m.stateDir, snapshotsDirName, token, name)
	if _, err := os.Stat(tokenScoped); err == nil {
		return tokenScoped
	}
	return filepath.Join(m.stateDir, snapshotsDirName, name)
}

func (m *Manager) cleanupSnapshots(token string) {
	if token != "" {
		_ = os.RemoveAll(filepath.Join(m.stateDir, snapshotsDirName, token))
	}
	snapsRoot := filepath.Join(m.stateDir, snapshotsDirName)
	if entries, err := os.ReadDir(snapsRoot); err == nil && len(entries) == 0 {
		_ = os.Remove(snapsRoot)
	}
}

func generateRandomToken() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func validateSnapshotName(name string) error {
	if name == "" || name == "." || name == ".." {
		return fmt.Errorf("invalid snapshot logical name %q", name)
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("snapshot logical name %q contains illegal path separator", name)
	}
	for i := range len(name) {
		c := name[i]
		if c < 0x20 || c == 0x7f {
			return fmt.Errorf("snapshot logical name %q contains control characters", name)
		}
	}
	return nil
}

func validateSnapshotPath(p string) error {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" || strings.ContainsRune(trimmed, 0) {
		return errors.New("empty or invalid snapshot file path")
	}
	if !filepath.IsAbs(trimmed) {
		return fmt.Errorf("snapshot file path %q must be absolute", p)
	}
	return nil
}

func cloneState(st State) State {
	if st.Snapshots != nil {
		st.Snapshots = maps.Clone(st.Snapshots)
	}
	return st
}
