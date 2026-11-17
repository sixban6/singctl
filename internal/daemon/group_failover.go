package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

const (
	defaultGroupFailoverInterval = 300 * time.Second
	defaultGroupProbeTimeout     = 5000 * time.Millisecond
	defaultConfirmRetryDelay     = 5 * time.Second
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

type clashProxyItem struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type clashProxiesDocument struct {
	Proxies map[string]clashProxyItem `json:"proxies"`
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
	failoverOrigin  map[string]string    // group -> original target before failover (e.g. "Proxy" -> "#Auto")
	failoverCurrent map[string]string    // group -> target set by failover (e.g. "Proxy" -> "#VPS")
	failoverSince   map[string]time.Time // group -> timestamp when failover started
	failoverDelay   map[string]int       // group -> backup delay ms at switch time
	recoverStreak   map[string]int       // group -> consecutive healthy probes of origin

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
}

// NewGroupFailoverState creates a new failover state tracker.
func NewGroupFailoverState() *GroupFailoverState {
	return &GroupFailoverState{
		failoverOrigin:        make(map[string]string),
		failoverCurrent:       make(map[string]string),
		failoverSince:         make(map[string]time.Time),
		failoverDelay:         make(map[string]int),
		recoverStreak:         make(map[string]int),
		Enabled:               true,
		WatchedGroups:         slices.Clone(config.DefaultWatchdogFailoverGroups),
		ProbeURLs:             slices.Clone(config.DefaultWatchdogProbeURLs),
		ProbeTimeout:          defaultGroupProbeTimeout,
		AutoFailback:          true,
		FailbackHealthyStreak: 1,
		NowFn:                 time.Now,
	}
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

	// 若总开关关闭或移除了某些受控组，清理已不再受控组的残留状态
	for grp := range s.failoverOrigin {
		if !s.Enabled || !slices.Contains(s.WatchedGroups, grp) {
			delete(s.failoverOrigin, grp)
			delete(s.failoverCurrent, grp)
			delete(s.failoverSince, grp)
			delete(s.failoverDelay, grp)
			delete(s.recoverStreak, grp)
		}
	}
}

// RestoreSnapshot 在守护进程启动时从持久化运行快照恢复未完结的切备记忆，防止重启后丢失原主选节点。
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
		// 外层仅受守护进程生命周期 d.ctx 约束，单组超时在 Patrol 内部按组独立分配，避免前序慢组耗尽后序组预算
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
// dead targets (with stepped confirmation, local WAN gate, and best-latency selection),
// and restores the original target once it stably recovers.
func (s *GroupFailoverState) Patrol(ctx context.Context, endpoints []string, secret string) {
	s.mu.Lock()
	enabled := s.Enabled
	groups := slices.Clone(s.WatchedGroups)
	sbCfgPath := s.SingBoxConfigPath
	trackedCopy := make(map[string]string, len(s.failoverOrigin))
	for k, v := range s.failoverOrigin {
		trackedCopy[k] = v
	}
	s.mu.Unlock()

	if !enabled {
		return
	}
	if len(groups) == 0 {
		groups = slices.Clone(config.DefaultWatchdogFailoverGroups)
	}

	base, doc, err := fetchClashProxiesDoc(ctx, endpoints, secret)
	if err != nil || len(doc.Proxies) == 0 {
		return
	}

	// 动态计算当前路由真正活跃引用的策略组集合（跳过如闲置 #Nodes 等无流量经过的组，消除无效误报）
	activeGroups := ActiveRouteGroupsFromConfig(sbCfgPath, doc.Proxies, trackedCopy)

	var wanChecked bool
	var wanAlive bool
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
		wanAlive = CheckLocalWANConnectivity(gCtx, base, secret, doc.Proxies)
		return wanAlive
	}

	// 按依赖拓扑自底向上排序（例如 Proxy -> #VPS 时先巡检修复子组 #VPS；若 #VPS 内部切备成功恢复，父组 Proxy 无需再多余跳变）
	orderedGroups := orderGroupsBottomUp(groups, doc.Proxies)

	for _, groupName := range orderedGroups {
		if ctx.Err() != nil {
			return
		}
		if activeGroups != nil && !activeGroups[groupName] {
			continue
		}
		// 为每个受保护策略组分配独立的 75s 巡检预算，互不挤占
		grpCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		s.checkAndHealGroup(grpCtx, base, secret, doc.Proxies, groupName, checkWANOnce)
		cancel()
	}
}

func orderGroupsBottomUp(groups []string, proxies map[string]clashProxyItem) []string {
	inSet := make(map[string]bool, len(groups))
	for _, g := range groups {
		inSet[g] = true
	}
	visited := make(map[string]int, len(groups)) // 0=unvisited, 1=visiting, 2=done
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

// ActiveRouteGroupsFromConfig 解析 sing-box 配置文件中的 route.final 与 route.rules，
// 结合 Clash API 当前各 Selector 的 Now 指向，计算当前真正承载流量的活跃策略组集合。
// 若配置文件不存在或未配置路由（如离线单元测试），返回 nil 表示不过滤。
func ActiveRouteGroupsFromConfig(
	sbConfigPath string,
	proxies map[string]clashProxyItem,
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
		item, ok := proxies[cur]
		if !ok {
			continue
		}
		if strings.EqualFold(item.Type, "Selector") && item.Now != "" {
			enqueue(item.Now)
		}
	}
	return seen
}

func isDirectOutboundTag(tag string) bool {
	return strings.EqualFold(tag, "#DC") || strings.EqualFold(tag, "DirectConn") || strings.EqualFold(tag, "direct")
}

func isAggregateGroupTag(tag string, proxies map[string]clashProxyItem) bool {
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

func (s *GroupFailoverState) checkAndHealGroup(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashProxyItem,
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
	s.mu.Lock()
	origin := s.failoverOrigin[groupName]
	expectedCur := s.failoverCurrent[groupName]
	since := s.failoverSince[groupName]
	autoFailback := s.AutoFailback
	cooldown := s.FailbackCooldown
	needStreak := max(1, s.FailbackHealthyStreak)
	maxDelayMs := s.MaxFailbackDelayMs
	confirmRetries := max(0, s.ConfirmRetries)
	confirmDelay := s.ConfirmRetryDelay
	// 若用户在面板中手动切换到了其他分组，尊重用户手动选择并清除旧自动切换标记
	if origin != "" && expectedCur != "" && cur != expectedCur {
		s.clearGroupLocked(groupName)
		origin = ""
	}
	s.mu.Unlock()

	// 1. 若当前处于故障切备状态且开启自动回切，满足冷却窗与健康滞回门槛后切回原主选分组
	if autoFailback && origin != "" && origin != cur && slices.Contains(grp.All, origin) && !IsInfoPlaceholderNode(origin) {
		cooldownReady := cooldown <= 0 || since.IsZero() || now.Sub(since) >= cooldown
		if cooldownReady {
			if delay, ok := s.probeOutboundAlive(ctx, base, secret, origin); ok && (maxDelayMs <= 0 || delay <= maxDelayMs) {
				s.mu.Lock()
				s.recoverStreak[groupName]++
				streak := s.recoverStreak[groupName]
				s.mu.Unlock()

				if streak >= needStreak {
					if err := switchClashSelector(ctx, base, secret, groupName, origin); err == nil {
						proxies[groupName] = clashProxyItem{Type: grp.Type, Now: origin, All: grp.All}
						s.mu.Lock()
						s.clearGroupLocked(groupName)
						s.mu.Unlock()
						logger.Success("[GroupFailover] 分流组 [%s] 原主选线路 [%s] 已稳定恢复 (delay=%dms)，自动切回: %s -> %s",
							groupName, origin, delay, cur, origin)
						LogWatchdogEvent(WatchdogEvent{
							Time:   now,
							Action: "GROUP_FAILBACK",
							CheckResult: HealthCheckResult{
								Healthy:   true,
								CheckTime: now,
								Details:   fmt.Sprintf("%s 原线路 %s 恢复健康", groupName, origin),
							},
							RestartResult: fmt.Sprintf("%s: %s -> %s (%dms)", groupName, cur, origin, delay),
						})
						return
					}
				}
			} else if ctx.Err() == nil {
				s.mu.Lock()
				s.recoverStreak[groupName] = 0
				s.mu.Unlock()
			}
		}
	}

	// 2. 探测当前选中的目标线路是否存活（若当前选在机场伪提示节点上则直接走选备纠偏）
	if !IsInfoPlaceholderNode(cur) {
		if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
			return
		}
		if ctx.Err() != nil {
			return
		}

		totalRetries := confirmRetries
		// 若当前选中项本身是 URLTest 自动测速组（如 #Auto），额外多给 1 轮退避窗口让 sing-box 内核优先内部换点
		if curProxy, ok := proxies[cur]; ok && strings.EqualFold(curProxy.Type, "URLTest") && confirmRetries > 0 && confirmDelay >= time.Second {
			totalRetries++
		}

		for retry := 0; retry < totalRetries; retry++ {
			waitDur := steppedRetryDelay(confirmDelay, retry)
			if waitDur > 0 {
				select {
				case <-time.After(waitDur):
				case <-ctx.Done():
					return
				}
			}
			if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
				return
			}
			if ctx.Err() != nil {
				return
			}
		}
	}

	// 3. 本机宽带直连前置门控：若自家宽带/光猫已断网，严禁误判节点损坏乱切策略组
	if wanGate != nil && !wanGate(ctx) {
		logger.Warn("[GroupFailover] 检测到本机宽带直连异常，暂停策略组 [%s] 自动切换以避免误切", groupName)
		return
	}
	if ctx.Err() != nil {
		return
	}

	// 4. 当前线路确认不可达，并发测速挑选延迟最低的健康备选线路
	bestCand, bestDelay, found := s.selectBestHealthyCandidate(ctx, base, secret, proxies, groupName, grp, cur, wanGate)
	if !found {
		return
	}

	if err := switchClashSelector(ctx, base, secret, groupName, bestCand); err == nil {
		proxies[groupName] = clashProxyItem{Type: grp.Type, Now: bestCand, All: grp.All}
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
}

type scoredCandidate struct {
	name  string
	delay int
	score int
	order int
}

func (s *GroupFailoverState) selectBestHealthyCandidate(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashProxyItem,
	groupName string,
	grp clashProxyItem,
	cur string,
	wanGate func(context.Context) bool,
) (string, int, bool) {
	var primaryPool []string
	var fallbackNodesPool []string

	for _, raw := range grp.All {
		cand := strings.TrimSpace(raw)
		if cand == "" || cand == cur || isDirectOutboundTag(cand) || IsInfoPlaceholderNode(cand) {
			continue
		}
		// 对顶层策略组（如 Proxy / AI），优先选 #Auto / #VPS 等聚合组或直属有效节点，#Nodes 仅作兜底
		if !strings.EqualFold(groupName, "#Nodes") && strings.EqualFold(cand, "#Nodes") {
			fallbackNodesPool = append(fallbackNodesPool, cand)
			continue
		}
		primaryPool = append(primaryPool, cand)
	}

	if best, delay, ok := s.probeCandidatePoolBest(ctx, base, secret, proxies, primaryPool, wanGate); ok {
		return best, delay, true
	}
	if len(fallbackNodesPool) > 0 && ctx.Err() == nil {
		return s.probeCandidatePoolBest(ctx, base, secret, proxies, fallbackNodesPool, wanGate)
	}
	return "", 0, false
}

func (s *GroupFailoverState) probeCandidatePoolBest(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashProxyItem,
	pool []string,
	wanGate func(context.Context) bool,
) (string, int, bool) {
	if len(pool) == 0 {
		return "", 0, false
	}
	if len(pool) > maxCandidateProbeBatch {
		pool = pool[:maxCandidateProbeBatch]
	}

	// 先在串行安全上下文中确保候选子 Selector（如 #VPS）内部处在健康节点（并纳入状态机追踪）
	for _, cand := range pool {
		if ctx.Err() != nil {
			return "", 0, false
		}
		if subGrp, isSub := proxies[cand]; isSub && strings.EqualFold(subGrp.Type, "Selector") {
			s.ensureSubSelectorHealthyTracked(ctx, base, secret, proxies, cand, subGrp, wanGate)
		}
	}

	type indexedCand struct {
		idx  int
		name string
		agg  bool
	}
	items := make([]indexedCand, 0, len(pool))
	for i, cand := range pool {
		items = append(items, indexedCand{
			idx:  i,
			name: cand,
			agg:  isAggregateGroupTag(cand, proxies),
		})
	}

	var mu sync.Mutex
	var results []scoredCandidate
	sem := make(chan struct{}, candidateProbeConcurrency)
	var wg sync.WaitGroup

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(it indexedCand) {
			defer wg.Done()
			defer func() { <-sem }()
			delay, ok := s.probeOutboundAlive(ctx, base, secret, it.name)
			if !ok {
				return
			}
			score := delay
			// 聚合策略组 (#Auto / #VPS) 享有 80ms 亲和优先权，延迟相近时优先保持聚合组结构
			if it.agg {
				score = max(1, delay-80)
			}
			mu.Lock()
			results = append(results, scoredCandidate{
				name:  it.name,
				delay: delay,
				score: score,
				order: it.idx,
			})
			mu.Unlock()
		}(item)
	}
	wg.Wait()

	if len(results) == 0 {
		return "", 0, false
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].score != results[j].score {
			return results[i].score < results[j].score
		}
		return results[i].order < results[j].order
	})
	return results[0].name, results[0].delay, true
}

func (s *GroupFailoverState) ensureSubSelectorHealthyTracked(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashProxyItem,
	subName string,
	subGrp clashProxyItem,
	wanGate func(context.Context) bool,
) {
	cur := strings.TrimSpace(subGrp.Now)
	if cur != "" && !IsInfoPlaceholderNode(cur) {
		if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
			return
		}
		s.mu.Lock()
		retries := min(1, max(0, s.ConfirmRetries))
		delay := s.ConfirmRetryDelay
		s.mu.Unlock()
		for r := 0; r < retries; r++ {
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			}
			if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
				return
			}
		}
	}
	if ctx.Err() != nil {
		return
	}
	if wanGate != nil && !wanGate(ctx) {
		return
	}

	var cands []string
	for _, raw := range subGrp.All {
		cand := strings.TrimSpace(raw)
		if cand == "" || cand == cur || isDirectOutboundTag(cand) || IsInfoPlaceholderNode(cand) {
			continue
		}
		cands = append(cands, cand)
	}
	if len(cands) == 0 {
		return
	}
	if len(cands) > maxCandidateProbeBatch {
		cands = cands[:maxCandidateProbeBatch]
	}

	var mu sync.Mutex
	var results []scoredCandidate
	sem := make(chan struct{}, candidateProbeConcurrency)
	var wg sync.WaitGroup
	for i, cand := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			if d, ok := s.probeOutboundAlive(ctx, base, secret, name); ok {
				mu.Lock()
				results = append(results, scoredCandidate{name: name, delay: d, score: d, order: idx})
				mu.Unlock()
			}
		}(i, cand)
	}
	wg.Wait()
	if len(results) == 0 {
		return
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].score != results[j].score {
			return results[i].score < results[j].score
		}
		return results[i].order < results[j].order
	})
	best := results[0]
	if err := switchClashSelector(ctx, base, secret, subName, best.name); err == nil {
		proxies[subName] = clashProxyItem{Type: subGrp.Type, Now: best.name, All: subGrp.All}
		switchAt := s.now()
		s.mu.Lock()
		if slices.Contains(s.WatchedGroups, subName) {
			if s.failoverOrigin[subName] == "" && cur != "" && !IsInfoPlaceholderNode(cur) {
				s.failoverOrigin[subName] = cur
			}
			s.failoverCurrent[subName] = best.name
			s.failoverSince[subName] = switchAt
			s.failoverDelay[subName] = best.delay
			s.recoverStreak[subName] = 0
		}
		s.mu.Unlock()
	}
}

// probeOutboundAlive 并发竞速探测多个目标 URL，任一 URL 返回有效延迟即立即判定线路存活，
// 既将多 URL 探测耗时减半，又彻底消除单一探测目标偶发限流/抽风引发的误判。
func (s *GroupFailoverState) probeOutboundAlive(ctx context.Context, base, secret, target string) (int, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	s.mu.Lock()
	urls := slices.Clone(s.ProbeURLs)
	timeout := s.ProbeTimeout
	s.mu.Unlock()

	if len(urls) == 0 {
		urls = config.DefaultWatchdogProbeURLs
	}
	if timeout <= 0 {
		timeout = defaultGroupProbeTimeout
	}
	timeoutMs := max(500, int(timeout.Milliseconds()))

	probeCtx, cancel := context.WithTimeout(ctx, timeout+700*time.Millisecond)
	defer cancel()

	client := &http.Client{Timeout: timeout + 600*time.Millisecond}
	type probeRes struct {
		delay int
		ok    bool
	}
	resCh := make(chan probeRes, len(urls))

	for _, testURL := range urls {
		go func(u string) {
			reqURL := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d",
				strings.TrimRight(base, "/"),
				url.PathEscape(target),
				url.QueryEscape(u),
				timeoutMs,
			)
			req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, reqURL, nil)
			if err != nil {
				resCh <- probeRes{}
				return
			}
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			resp, err := client.Do(req)
			if err != nil {
				resCh <- probeRes{}
				return
			}
			var data struct {
				Delay int `json:"delay"`
			}
			decErr := json.NewDecoder(resp.Body).Decode(&data)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK && decErr == nil && data.Delay > 0 {
				resCh <- probeRes{delay: data.Delay, ok: true}
				return
			}
			resCh <- probeRes{}
		}(testURL)
	}

	for range len(urls) {
		select {
		case r := <-resCh:
			if r.ok {
				cancel()
				return r.delay, true
			}
		case <-ctx.Done():
			return 0, false
		}
	}
	return 0, false
}

// CheckLocalWANConnectivity 检查本机国内直连宽带是否在线（多目标并发竞速，2.5s 超时）：
// 优先通过 sing-box direct 直连出站（自带 fwmark 豁免 TProxy 回环）检测，同时并发直连国内权威端点兜底；
// 只要任一通道收到有效 HTTP 响应即判定自家宽带正常；仅当全部超时失败时才判定本机宽带断网。
func CheckLocalWANConnectivity(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashProxyItem,
) bool {
	wanCtx, cancel := context.WithTimeout(ctx, 2600*time.Millisecond)
	defer cancel()

	var directTag string
	for _, cand := range []string{"direct", "#DC", "DirectConn"} {
		if _, ok := proxies[cand]; ok {
			directTag = cand
			break
		}
	}

	client := &http.Client{
		Timeout: 2400 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	totalTasks := len(domesticWANProbeURLs)
	if directTag != "" && base != "" {
		totalTasks += 2
	}
	okCh := make(chan bool, totalTasks)

	if directTag != "" && base != "" {
		for _, u := range domesticWANProbeURLs[:2] {
			go func(testURL string) {
				reqURL := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=2200",
					strings.TrimRight(base, "/"),
					url.PathEscape(directTag),
					url.QueryEscape(testURL),
				)
				req, err := http.NewRequestWithContext(wanCtx, http.MethodGet, reqURL, nil)
				if err != nil {
					okCh <- false
					return
				}
				if secret != "" {
					req.Header.Set("Authorization", "Bearer "+secret)
				}
				resp, err := client.Do(req)
				if err != nil {
					okCh <- false
					return
				}
				var data struct {
					Delay int `json:"delay"`
				}
				decErr := json.NewDecoder(resp.Body).Decode(&data)
				_ = resp.Body.Close()
				okCh <- (resp.StatusCode == http.StatusOK && decErr == nil && data.Delay > 0)
			}(u)
		}
	}

	for _, u := range domesticWANProbeURLs {
		go func(testURL string) {
			req, err := http.NewRequestWithContext(wanCtx, http.MethodGet, testURL, nil)
			if err != nil {
				okCh <- false
				return
			}
			resp, err := client.Do(req)
			if err != nil {
				okCh <- false
				return
			}
			_ = resp.Body.Close()
			okCh <- (resp.StatusCode > 0 && resp.StatusCode < 500)
		}(u)
	}

	for range totalTasks {
		select {
		case ok := <-okCh:
			if ok {
				cancel()
				return true
			}
		case <-wanCtx.Done():
			return false
		}
	}
	return false
}

// InspectClashSelectors 查询 Clash API 当前所有可手动切换的 Selector 策略组及其容灾守护状态。
func InspectClashSelectors(
	ctx context.Context,
	endpoints []string,
	secret string,
	watched []string,
	active []FailoverActiveItem,
) ([]SelectorGroupSummary, error) {
	_, doc, err := fetchClashProxiesDoc(ctx, endpoints, secret)
	if err != nil {
		return nil, err
	}

	activeMap := make(map[string]FailoverActiveItem, len(active))
	for _, a := range active {
		activeMap[a.Group] = a
	}

	orderIndex := make(map[string]int, len(watched))
	for idx, g := range watched {
		orderIndex[g] = idx
	}

	var list []SelectorGroupSummary
	for name, item := range doc.Proxies {
		if !strings.EqualFold(item.Type, "Selector") {
			continue
		}
		isWatched := slices.Contains(watched, name)
		if strings.EqualFold(name, "GLOBAL") && !isWatched {
			continue
		}
		act, failed := activeMap[name]
		list = append(list, SelectorGroupSummary{
			Name:       name,
			Now:        item.Now,
			Candidates: len(item.All),
			Watched:    isWatched,
			FailedOver: failed,
			Origin:     act.Origin,
			Since:      act.Since,
		})
	}

	sort.Slice(list, func(i, j int) bool {
		idxI, okI := orderIndex[list[i].Name]
		idxJ, okJ := orderIndex[list[j].Name]
		switch {
		case okI && okJ:
			return idxI < idxJ
		case okI:
			return true
		case okJ:
			return false
		default:
			return list[i].Name < list[j].Name
		}
	})
	return list, nil
}

func fetchClashProxiesDoc(ctx context.Context, endpoints []string, secret string) (string, clashProxiesDocument, error) {
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	var lastErr error
	for _, base := range endpoints {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/proxies", nil)
		if err != nil {
			lastErr = err
			continue
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		var doc clashProxiesDocument
		decErr := json.NewDecoder(resp.Body).Decode(&doc)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && decErr == nil && len(doc.Proxies) > 0 {
			return base, doc, nil
		}
		lastErr = fmt.Errorf("status %d", resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no clash api endpoints reachable")
	}
	return "", clashProxiesDocument{}, lastErr
}

func switchClashSelector(ctx context.Context, base, secret, group, target string) error {
	client := &http.Client{Timeout: 2500 * time.Millisecond}
	body, err := json.Marshal(map[string]string{"name": target})
	if err != nil {
		return err
	}
	putURL := fmt.Sprintf("%s/proxies/%s", strings.TrimRight(base, "/"), url.PathEscape(group))
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, putURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d switching %s -> %s", resp.StatusCode, group, target)
	}
	return nil
}
