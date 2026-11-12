package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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
	defaultGroupFailoverInterval = 30 * time.Second
	groupProbeTimeout            = 2800 * time.Millisecond
)

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

// GroupFailoverState tracks automatic selector failover with anti-flap confirmation,
// cooldown, and latency hysteresis so groups smoothly fail over and recover without ping-ponging.
type GroupFailoverState struct {
	mu              sync.Mutex
	failoverOrigin  map[string]string    // group -> original target before failover (e.g. "Game" -> "#Auto")
	failoverCurrent map[string]string    // group -> target set by failover (e.g. "Game" -> "#VPS")
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
		ProbeTimeout:          groupProbeTimeout,
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
		s.ConfirmRetryDelay = 2 * time.Second
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
		ctx, cancel := context.WithTimeout(d.ctx, 35*time.Second)
		defer cancel()
		if d.failover == nil {
			return
		}
		d.failover.Patrol(ctx, singbox.ClashAPIEndpoints(), singbox.ClashAPISecret())
		nowStr := time.Now().Format(time.DateTime)
		active := d.failover.ActiveSnapshot()
		UpdateRuntimeState(func(snap *DaemonRuntimeSnapshot) {
			snap.LastFailoverAt = nowStr
			snap.ActiveFailovers = active
		})
	}()
}

// Patrol inspects watched Selector groups via the Clash API, automatically fails over
// dead targets (such as when all airport nodes in #Auto go down), and automatically
// restores the original target once it stably recovers.
func (s *GroupFailoverState) Patrol(ctx context.Context, endpoints []string, secret string) {
	s.mu.Lock()
	enabled := s.Enabled
	groups := slices.Clone(s.WatchedGroups)
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

	for _, groupName := range groups {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.checkAndHealGroup(ctx, base, secret, doc.Proxies, groupName)
	}
}

func isDirectOutboundTag(tag string) bool {
	return strings.EqualFold(tag, "#DC") || strings.EqualFold(tag, "DirectConn") || strings.EqualFold(tag, "direct")
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
	if autoFailback && origin != "" && origin != cur && slices.Contains(grp.All, origin) {
		cooldownReady := cooldown <= 0 || since.IsZero() || now.Sub(since) >= cooldown
		if cooldownReady {
			if delay, ok := s.probeOutboundAlive(ctx, base, secret, origin); ok && (maxDelayMs <= 0 || delay <= maxDelayMs) {
				s.mu.Lock()
				s.recoverStreak[groupName]++
				streak := s.recoverStreak[groupName]
				s.mu.Unlock()

				if streak >= needStreak {
					if err := switchClashSelector(ctx, base, secret, groupName, origin); err == nil {
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
			} else {
				s.mu.Lock()
				s.recoverStreak[groupName] = 0
				s.mu.Unlock()
			}
		}
	}

	// 2. 探测当前选中的目标线路是否存活（首次超时可按配置复测确认，过滤跨境瞬时丢包）
	if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
		return
	}
	for retry := 0; retry < confirmRetries; retry++ {
		if confirmDelay > 0 {
			select {
			case <-time.After(confirmDelay):
			case <-ctx.Done():
				return
			}
		}
		if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
			return
		}
	}

	// 3. 当前线路确认不可达，遍历候选列表寻找最佳可用备选线路
	for _, cand := range grp.All {
		cand = strings.TrimSpace(cand)
		if cand == "" || cand == cur || isDirectOutboundTag(cand) {
			continue
		}
		// 若备选本身也是 Selector (例如 #VPS)，先确保该子 Selector 内部处在可用节点上
		if subGrp, isSub := proxies[cand]; isSub && strings.EqualFold(subGrp.Type, "Selector") {
			s.ensureSubSelectorHealthy(ctx, base, secret, cand, subGrp)
		}

		if delay, ok := s.probeOutboundAlive(ctx, base, secret, cand); ok {
			if err := switchClashSelector(ctx, base, secret, groupName, cand); err == nil {
				switchAt := s.now()
				s.mu.Lock()
				if s.failoverOrigin[groupName] == "" {
					s.failoverOrigin[groupName] = cur
				}
				s.failoverCurrent[groupName] = cand
				s.failoverSince[groupName] = switchAt
				s.failoverDelay[groupName] = delay
				s.recoverStreak[groupName] = 0
				origRecorded := s.failoverOrigin[groupName]
				s.mu.Unlock()

				logger.Warn("[GroupFailover] 分流组 [%s] 当前线路 [%s] 不可达，已自动故障切换至 [%s] (delay=%dms, 原主选 [%s])",
					groupName, cur, cand, delay, origRecorded)
				LogWatchdogEvent(WatchdogEvent{
					Time:   switchAt,
					Action: "GROUP_FAILOVER",
					CheckResult: HealthCheckResult{
						Healthy:      false,
						CheckTime:    switchAt,
						FailedReason: "outbound_unreachable",
						Details:      fmt.Sprintf("%s 当前线路 %s 超时", groupName, cur),
					},
					RestartResult: fmt.Sprintf("%s: %s -> %s (%dms)", groupName, cur, cand, delay),
				})
				return
			}
		}
	}
}

func (s *GroupFailoverState) ensureSubSelectorHealthy(
	ctx context.Context,
	base, secret, subName string,
	subGrp clashProxyItem,
) {
	cur := strings.TrimSpace(subGrp.Now)
	if cur != "" {
		if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
			return
		}
	}
	for _, cand := range subGrp.All {
		cand = strings.TrimSpace(cand)
		if cand == "" || cand == cur || isDirectOutboundTag(cand) {
			continue
		}
		if _, ok := s.probeOutboundAlive(ctx, base, secret, cand); ok {
			_ = switchClashSelector(ctx, base, secret, subName, cand)
			return
		}
	}
}

func (s *GroupFailoverState) probeOutboundAlive(ctx context.Context, base, secret, target string) (int, bool) {
	s.mu.Lock()
	urls := slices.Clone(s.ProbeURLs)
	timeout := s.ProbeTimeout
	s.mu.Unlock()

	if len(urls) == 0 {
		urls = config.DefaultWatchdogProbeURLs
	}
	if timeout <= 0 {
		timeout = groupProbeTimeout
	}
	timeoutMs := max(500, int(timeout.Milliseconds()))
	client := &http.Client{Timeout: timeout + 700*time.Millisecond}

	for _, testURL := range urls {
		reqURL := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d",
			strings.TrimRight(base, "/"),
			url.PathEscape(target),
			url.QueryEscape(testURL),
			timeoutMs,
		)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			continue
		}
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var data struct {
			Delay int `json:"delay"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&data)
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && decErr == nil && data.Delay > 0 {
			return data.Delay, true
		}
	}
	return 0, false
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
