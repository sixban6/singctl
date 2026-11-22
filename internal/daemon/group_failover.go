// 文件职责：维护策略组容灾状态机（GroupFailoverState），执行自底向上依赖拓扑巡检与切备/回切状态迁移。
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/notify"
	"singctl/internal/singbox"
	"singctl/internal/singbox/clashapi"
)

const (
	defaultGroupFailoverInterval = 300 * time.Second
	defaultGroupProbeTimeout     = 5000 * time.Millisecond
	defaultConfirmRetryDelay     = 5 * time.Millisecond * 1000 // 5s
	maxCandidateProbeBatch       = 16
	candidateProbeConcurrency    = 6
)

var domesticWANProbeURLs = []string{
	"http://connect.rom.miui.com/generate_204",
	"http://connectivitycheck.platform.hicloud.com/generate_204",
	"https://223.5.5.5/dns-query",
}

var infoPlaceholderKeywords = []string{
	"剩余流量", "套餐到期", "距离下次", "流量重置", "重置日",
	"到期时间", "已过期", "过期时间", "官网", "网址",
	"群组", "频道", "公告", "http://", "https://",
	"traffic:", "expire:", "remaining:",
}

// IsInfoPlaceholderNode 判断节点名是否为机场订阅中常见的不可连通信息提示伪节点。
func IsInfoPlaceholderNode(name string) bool {
	s := strings.ToLower(strings.TrimSpace(name))
	if s == "" {
		return true
	}
	for _, kw := range infoPlaceholderKeywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// SelectorGroupSummary 供 WebUI 展示的 Clash Selector 策略组实时状态与容灾守护状态。
type SelectorGroupSummary struct {
	Name       string   `json:"name"`
	Now        string   `json:"now"`
	Candidates int      `json:"candidates"`
	Watched    bool     `json:"watched"`
	FailedOver bool     `json:"failedOver"`
	Origin     string   `json:"origin,omitempty"`
	Since      string   `json:"since,omitempty"`
	All        []string `json:"all,omitempty"`
}

// GroupFailoverState tracks automatic selector failover with anti-flap stepped confirmation,
// local WAN outage gating, concurrent best-latency backup selection, cooldown, and latency hysteresis.
type GroupFailoverState struct {
	mu              sync.Mutex
	failoverOrigin  map[string]string
	failoverCurrent map[string]string
	failoverSince   map[string]time.Time
	failoverDelay   map[string]int
	recoverStreak   map[string]int

	clash *clashapi.Client

	Enabled               bool
	WatchedGroups         []string
	ProbeURLs             []string
	ProbeTimeout          time.Duration
	ConfirmRetries        int
	ConfirmRetryDelay     time.Duration
	AutoFailback          bool
	FailbackCooldown      time.Duration
	FailbackHealthyStreak int
	MaxFailbackDelayMs    int
	SingBoxConfigPath     string
	EnableWANGate         bool
	CheckWANFn            func(ctx context.Context) bool
	NowFn                 func() time.Time
	OnNotify              func(ev notify.Event)
}

// NewGroupFailoverState creates a new failover state tracker.
func NewGroupFailoverState() *GroupFailoverState {
	return &GroupFailoverState{
		failoverOrigin:        make(map[string]string),
		failoverCurrent:       make(map[string]string),
		failoverSince:         make(map[string]time.Time),
		failoverDelay:         make(map[string]int),
		recoverStreak:         make(map[string]int),
		clash:                 clashapi.NewClient(clashapi.Options{RequestTimeout: 2500 * time.Millisecond}),
		Enabled:               true,
		WatchedGroups:         slices.Clone(config.DefaultWatchdogFailoverGroups),
		ProbeURLs:             slices.Clone(config.DefaultWatchdogProbeURLs),
		ProbeTimeout:          defaultGroupProbeTimeout,
		AutoFailback:          true,
		FailbackHealthyStreak: 1,
		NowFn:                 time.Now,
	}
}

func (s *GroupFailoverState) clashClient() *clashapi.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clash == nil {
		s.clash = clashapi.NewClient(clashapi.Options{RequestTimeout: 2500 * time.Millisecond})
	}
	return s.clash
}

// ApplyConfig 将 singctl.yaml 中的 watchdog.failover 配置热更新至内存状态机。
func (s *GroupFailoverState) ApplyConfig(fc config.WatchdogFailoverConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Enabled = fc.IsEnabled()
	s.WatchedGroups = fc.EffectiveGroups()
	s.ProbeURLs = fc.EffectiveProbeURLs()
	s.ProbeTimeout = fc.EffectiveProbeTimeout()
	s.ConfirmRetries = fc.EffectiveConfirmRetries()
	if s.ConfirmRetries > 0 && s.ConfirmRetryDelay == 0 {
		s.ConfirmRetryDelay = defaultConfirmRetryDelay
	}
	s.AutoFailback = fc.AutoFailbackEnabled()
	if s.AutoFailback {
		s.FailbackCooldown = fc.EffectiveFailbackCooldown()
		if s.FailbackCooldown > 0 {
			s.FailbackHealthyStreak = 2
		} else {
			s.FailbackHealthyStreak = 1
		}
	} else {
		s.FailbackCooldown = -1
		s.FailbackHealthyStreak = 1
	}
	s.MaxFailbackDelayMs = fc.EffectiveMaxFailbackDelayMs()

	for grp := range s.failoverOrigin {
		if !s.Enabled || !slices.Contains(s.WatchedGroups, grp) {
			s.clearGroupLocked(grp)
		}
	}
}

// RestoreSnapshot 在守护进程启动时从持久化运行快照恢复未完结的切备记忆。
func (s *GroupFailoverState) RestoreSnapshot(items []FailoverActiveItem) {
	if len(items) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.Enabled {
		return
	}
	for _, it := range items {
		grp := strings.TrimSpace(it.Group)
		orig := strings.TrimSpace(it.Origin)
		cur := strings.TrimSpace(it.Current)
		if grp == "" || orig == "" || cur == "" || orig == cur {
			continue
		}
		if len(s.WatchedGroups) > 0 && !slices.Contains(s.WatchedGroups, grp) {
			continue
		}
		s.failoverOrigin[grp] = orig
		s.failoverCurrent[grp] = cur
		s.failoverDelay[grp] = it.LastDelay
		if it.Since != "" {
			if t, err := time.ParseInLocation(time.DateTime, it.Since, time.Local); err == nil {
				s.failoverSince[grp] = t
			}
		}
	}
}

// ActiveSnapshot 返回当前处于故障切备接管状态的策略组快照。
func (s *GroupFailoverState) ActiveSnapshot() []FailoverActiveItem {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.failoverOrigin) == 0 {
		return nil
	}
	out := make([]FailoverActiveItem, 0, len(s.failoverOrigin))
	for grp, orig := range s.failoverOrigin {
		cur := s.failoverCurrent[grp]
		if orig == "" || cur == "" {
			continue
		}
		sinceStr := ""
		if t := s.failoverSince[grp]; !t.IsZero() {
			sinceStr = t.Format(time.DateTime)
		}
		out = append(out, FailoverActiveItem{
			Group:     grp,
			Origin:    orig,
			Current:   cur,
			Since:     sinceStr,
			LastDelay: s.failoverDelay[grp],
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Group < out[j].Group })
	return out
}

func (s *GroupFailoverState) now() time.Time {
	if s.NowFn != nil {
		return s.NowFn()
	}
	return time.Now()
}

func (d *Daemon) maybePatrolGroupFailoverAsync() {
	cfg := d.currentConfig()
	if cfg != nil {
		if doctor.IsServerEnvironment(cfg) && len(cfg.Subs) == 0 {
			return
		}
		if !cfg.Watchdog.Failover.IsEnabled() {
			UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
				snap.ActiveFailovers = nil
			})
			return
		}
	}
	if d.reloading.Load() || !IsSingBoxRunning() {
		return
	}
	if !d.failoverRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.failoverRunning.Store(false)
		if d.failover == nil {
			return
		}
		d.failover.Patrol(d.ctx, singbox.ClashAPIEndpoints(), singbox.ClashAPISecret())
		nowStr := time.Now().Format(time.DateTime)
		active := d.failover.ActiveSnapshot()
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastFailoverAt = nowStr
			snap.ActiveFailovers = active
		})
	}()
}

// Patrol inspects watched Selector groups via the Clash API, automatically fails over
// dead targets, and restores the original target once it stably recovers.
func (s *GroupFailoverState) Patrol(ctx context.Context, endpoints []string, secret string) {
	s.mu.Lock()
	enabled := s.Enabled
	groups := slices.Clone(s.WatchedGroups)
	sbCfgPath := s.SingBoxConfigPath
	trackedCopy := maps.Clone(s.failoverOrigin)
	s.mu.Unlock()

	if !enabled {
		return
	}
	if len(groups) == 0 {
		groups = slices.Clone(config.DefaultWatchdogFailoverGroups)
	}

	base, proxies, err := s.clashClient().ResolveProxiesAcross(ctx, endpoints, secret)
	if err != nil || len(proxies) == 0 {
		return
	}

	activeGroups := ActiveRouteGroupsFromConfig(sbCfgPath, proxies, trackedCopy)

	var wanChecked, wanAlive bool
	checkWANOnce := func(gCtx context.Context) bool {
		if wanChecked {
			return wanAlive
		}
		wanChecked = true
		s.mu.Lock()
		fn := s.CheckWANFn
		gateOn := s.EnableWANGate
		s.mu.Unlock()

		if fn != nil {
			wanAlive = fn(gCtx)
			return wanAlive
		}
		if !gateOn {
			wanAlive = true
			return true
		}
		wanAlive = CheckLocalWANConnectivity(gCtx, base, secret, proxies)
		return wanAlive
	}

	for _, groupName := range orderGroupsBottomUp(groups, proxies) {
		if ctx.Err() != nil {
			return
		}
		if activeGroups != nil && !activeGroups[groupName] {
			continue
		}
		grpCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		s.checkAndHealGroup(grpCtx, base, secret, proxies, groupName, checkWANOnce)
		cancel()
	}
}

func orderGroupsBottomUp(groups []string, proxies map[string]clashapi.ProxyItem) []string {
	inSet := make(map[string]bool, len(groups))
	for _, g := range groups {
		inSet[g] = true
	}
	visited := make(map[string]int, len(groups))
	out := make([]string, 0, len(groups))

	var dfs func(name string)
	dfs = func(name string) {
		if visited[name] != 0 {
			return
		}
		visited[name] = 1
		if item, ok := proxies[name]; ok && strings.EqualFold(item.Type, "Selector") {
			child := strings.TrimSpace(item.Now)
			if child != "" && child != name && inSet[child] {
				dfs(child)
			}
		}
		visited[name] = 2
		out = append(out, name)
	}
	for _, g := range groups {
		dfs(g)
	}
	return out
}

// ActiveRouteGroupsFromConfig 解析 sing-box 配置文件中的路由规则与 Clash API Selector 指向，计算当前承载流量的活跃策略组集合。
func ActiveRouteGroupsFromConfig(
	sbConfigPath string,
	proxies map[string]clashapi.ProxyItem,
	trackedOrigins map[string]string,
) map[string]bool {
	if strings.TrimSpace(sbConfigPath) == "" {
		return nil
	}
	raw, err := os.ReadFile(sbConfigPath)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var parsed struct {
		Route struct {
			Final string `json:"final"`
			Rules []struct {
				Outbound string `json:"outbound"`
			} `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}

	var queue []string
	seen := make(map[string]bool)
	enqueue := func(tag string) {
		tag = strings.TrimSpace(tag)
		if tag == "" || seen[tag] || isDirectOutboundTag(tag) {
			return
		}
		if _, ok := proxies[tag]; ok {
			seen[tag] = true
			queue = append(queue, tag)
		}
	}

	enqueue(parsed.Route.Final)
	for _, r := range parsed.Route.Rules {
		enqueue(r.Outbound)
	}
	for grp, orig := range trackedOrigins {
		if orig != "" {
			enqueue(grp)
		}
	}
	if len(queue) == 0 {
		return nil
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if item, ok := proxies[cur]; ok && strings.EqualFold(item.Type, "Selector") && item.Now != "" {
			enqueue(item.Now)
		}
	}
	return seen
}

func isDirectOutboundTag(tag string) bool {
	return strings.EqualFold(tag, "#DC") || strings.EqualFold(tag, "DirectConn") || strings.EqualFold(tag, "direct")
}

func isAggregateGroupTag(tag string, proxies map[string]clashapi.ProxyItem) bool {
	if strings.EqualFold(tag, "#Nodes") {
		return false
	}
	item, ok := proxies[tag]
	if !ok {
		return false
	}
	return strings.EqualFold(item.Type, "URLTest") ||
		strings.EqualFold(item.Type, "Selector") ||
		strings.EqualFold(item.Type, "Fallback")
}

func steppedRetryDelay(base time.Duration, retryIdx int) time.Duration {
	if base <= 0 {
		return 0
	}
	switch retryIdx {
	case 0:
		return base
	case 1:
		return (base * 8) / 5
	default:
		return base * 2
	}
}

func (s *GroupFailoverState) clearGroupLocked(groupName string) {
	delete(s.failoverOrigin, groupName)
	delete(s.failoverCurrent, groupName)
	delete(s.failoverSince, groupName)
	delete(s.failoverDelay, groupName)
	delete(s.recoverStreak, groupName)
}

type groupCheckParams struct {
	origin         string
	since          time.Time
	autoFailback   bool
	cooldown       time.Duration
	needStreak     int
	maxDelayMs     int
	confirmRetries int
	confirmDelay   time.Duration
}

func (s *GroupFailoverState) loadGroupCheckParams(groupName, cur string) groupCheckParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	origin := s.failoverOrigin[groupName]
	expectedCur := s.failoverCurrent[groupName]
	if origin != "" && expectedCur != "" && cur != expectedCur {
		s.clearGroupLocked(groupName)
		origin = ""
	}
	return groupCheckParams{
		origin:         origin,
		since:          s.failoverSince[groupName],
		autoFailback:   s.AutoFailback,
		cooldown:       s.FailbackCooldown,
		needStreak:     max(1, s.FailbackHealthyStreak),
		maxDelayMs:     s.MaxFailbackDelayMs,
		confirmRetries: max(0, s.ConfirmRetries),
		confirmDelay:   s.ConfirmRetryDelay,
	}
}

func (s *GroupFailoverState) checkAndHealGroup(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashapi.ProxyItem,
	groupName string,
	wanGate func(context.Context) bool,
) {
	grp, exists := proxies[groupName]
	if !exists || !strings.EqualFold(grp.Type, "Selector") {
		return
	}
	cur := strings.TrimSpace(grp.Now)
	if cur == "" || isDirectOutboundTag(cur) {
		return
	}

	now := s.now()
	params := s.loadGroupCheckParams(groupName, cur)

	if s.tryFailbackToOrigin(ctx, base, secret, proxies, groupName, grp, cur, now, params) {
		return
	}
	if s.confirmCurrentAliveWithBackoff(ctx, base, secret, proxies, cur, params) {
		return
	}
	if ctx.Err() != nil {
		return
	}
	if wanGate != nil && !wanGate(ctx) {
		logger.Warn("[GroupFailover] 检测到本机宽带直连异常，暂停策略组 [%s] 自动切换以避免误切", groupName)
		return
	}
	if ctx.Err() != nil {
		return
	}

	s.failoverToBestBackup(ctx, base, secret, proxies, groupName, grp, cur, wanGate)
}

func (s *GroupFailoverState) tryFailbackToOrigin(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashapi.ProxyItem,
	groupName string,
	grp clashapi.ProxyItem,
	cur string,
	now time.Time,
	p groupCheckParams,
) bool {
	if !p.autoFailback || p.origin == "" || p.origin == cur || !slices.Contains(grp.All, p.origin) || IsInfoPlaceholderNode(p.origin) {
		return false
	}
	if p.cooldown > 0 && !p.since.IsZero() && now.Sub(p.since) < p.cooldown {
		return false
	}
	delay, ok := s.probeOutboundAlive(ctx, base, secret, p.origin)
	if !ok || (p.maxDelayMs > 0 && delay > p.maxDelayMs) {
		if ctx.Err() == nil {
			s.mu.Lock()
			s.recoverStreak[groupName] = 0
			s.mu.Unlock()
		}
		return false
	}

	s.mu.Lock()
	s.recoverStreak[groupName]++
	streak := s.recoverStreak[groupName]
	s.mu.Unlock()
	if streak < p.needStreak {
		return false
	}
	if err := s.clashClient().SwitchSelectorAt(ctx, base, secret, groupName, p.origin); err != nil {
		return false
	}

	proxies[groupName] = clashapi.ProxyItem{Type: grp.Type, Now: p.origin, All: grp.All}
	s.mu.Lock()
	s.clearGroupLocked(groupName)
	s.mu.Unlock()
	logger.Success("[GroupFailover] 分流组 [%s] 原主选线路 [%s] 已稳定恢复 (delay=%dms)，自动切回: %s -> %s",
		groupName, p.origin, delay, cur, p.origin)
	if s.OnNotify != nil {
		s.OnNotify(notify.Event{
			Type:     notify.EventSubOrNodeFail,
			Severity: notify.SeverityInfo,
			DedupKey: "failover:" + groupName,
			Title:    fmt.Sprintf("策略组 [%s] 原主选线路已恢复", groupName),
			Body:     fmt.Sprintf("已从备选 [%s] 自动切回原线路 [%s] (延迟 %dms)", cur, p.origin, delay),
			Resolved: true,
		})
	}
	LogWatchdogEvent(WatchdogEvent{
		Time:   now,
		Action: "GROUP_FAILBACK",
		CheckResult: HealthCheckResult{
			Healthy:   true,
			CheckTime: now,
			Details:   fmt.Sprintf("%s 原线路 %s 恢复健康", groupName, p.origin),
		},
		RestartResult: fmt.Sprintf("%s: %s -> %s (%dms)", groupName, cur, p.origin, delay),
	})
	return true
}

func (s *GroupFailoverState) confirmCurrentAliveWithBackoff(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashapi.ProxyItem,
	cur string,
	p groupCheckParams,
) bool {
	if IsInfoPlaceholderNode(cur) {
		return false
	}
	if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
		return true
	}
	if ctx.Err() != nil {
		return false
	}

	totalRetries := p.confirmRetries
	if curProxy, ok := proxies[cur]; ok && strings.EqualFold(curProxy.Type, "URLTest") && p.confirmRetries > 0 && p.confirmDelay >= time.Second {
		totalRetries++
	}
	for retry := range totalRetries {
		waitDur := steppedRetryDelay(p.confirmDelay, retry)
		if waitDur > 0 {
			select {
			case <-time.After(waitDur):
			case <-ctx.Done():
				return false
			}
		}
		if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

func (s *GroupFailoverState) failoverToBestBackup(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashapi.ProxyItem,
	groupName string,
	grp clashapi.ProxyItem,
	cur string,
	wanGate func(context.Context) bool,
) {
	bestCand, bestDelay, found := s.selectBestHealthyCandidate(ctx, base, secret, proxies, groupName, grp, cur, wanGate)
	if !found {
		if s.OnNotify != nil {
			s.OnNotify(notify.Event{
				Type:     notify.EventSubOrNodeFail,
				Severity: notify.SeverityCritical,
				DedupKey: "failover:" + groupName,
				Title:    fmt.Sprintf("策略组 [%s] 故障切换失败", groupName),
				Body:     fmt.Sprintf("当前线路 [%s] 不可达且所有备选节点均探测失败，请检查机场订阅或节点健康状态。", cur),
				Resolved: false,
			})
		}
		return
	}
	if err := s.clashClient().SwitchSelectorAt(ctx, base, secret, groupName, bestCand); err != nil {
		if s.OnNotify != nil {
			s.OnNotify(notify.Event{
				Type:     notify.EventSubOrNodeFail,
				Severity: notify.SeverityCritical,
				DedupKey: "failover:" + groupName,
				Title:    fmt.Sprintf("策略组 [%s] 自动切换指令失败", groupName),
				Body:     fmt.Sprintf("尝试将 [%s] 切换至 [%s] 失败: %v", cur, bestCand, err),
				Resolved: false,
			})
		}
		return
	}

	proxies[groupName] = clashapi.ProxyItem{Type: grp.Type, Now: bestCand, All: grp.All}
	switchAt := s.now()
	s.mu.Lock()
	if s.failoverOrigin[groupName] == "" && !IsInfoPlaceholderNode(cur) {
		s.failoverOrigin[groupName] = cur
	}
	s.failoverCurrent[groupName] = bestCand
	s.failoverSince[groupName] = switchAt
	s.failoverDelay[groupName] = bestDelay
	s.recoverStreak[groupName] = 0
	origRecorded := s.failoverOrigin[groupName]
	s.mu.Unlock()

	if origRecorded == "" {
		origRecorded = cur
	}
	logger.Warn("[GroupFailover] 分流组 [%s] 当前线路 [%s] 不可达，已自动择优切换至 [%s] (delay=%dms, 原主选 [%s])",
		groupName, cur, bestCand, bestDelay, origRecorded)
	if s.OnNotify != nil {
		s.OnNotify(notify.Event{
			Type:     notify.EventSubOrNodeFail,
			Severity: notify.SeverityWarn,
			DedupKey: "failover:" + groupName,
			Title:    fmt.Sprintf("策略组 [%s] 已自动切备", groupName),
			Body:     fmt.Sprintf("原线路 [%s] 不可达，已自动切换至 [%s] (延迟 %dms)", cur, bestCand, bestDelay),
			Resolved: false,
		})
	}
	LogWatchdogEvent(WatchdogEvent{
		Time:   switchAt,
		Action: "GROUP_FAILOVER",
		CheckResult: HealthCheckResult{
			Healthy:      false,
			CheckTime:    switchAt,
			FailedReason: "outbound_unreachable",
			Details:      fmt.Sprintf("%s 当前线路 %s 超时", groupName, cur),
		},
		RestartResult: fmt.Sprintf("%s: %s -> %s (%dms)", groupName, cur, bestCand, bestDelay),
	})
}
