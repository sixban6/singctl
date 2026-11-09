package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/doctor"
	"singctl/internal/logger"
	"singctl/internal/singbox"
)

const (
	groupFailoverInterval = 30 * time.Second
	groupProbeTimeout     = 2800 * time.Millisecond
)

var (
	defaultWatchedSelectorGroups = []string{"#VPS", "Game-TCP", "Game-UDP", "Game", "Proxy", "AI"}
	defaultProbeURLs             = []string{
		"https://captive.apple.com/hotspot-detect.html",
		"http://www.gstatic.com/generate_204",
	}
)

type clashProxyItem struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

type clashProxiesDocument struct {
	Proxies map[string]clashProxyItem `json:"proxies"`
}

// GroupFailoverState tracks automatic selector failover so groups automatically
// restore to their primary selection once the primary outbound/group recovers.
type GroupFailoverState struct {
	mu              sync.Mutex
	failoverOrigin  map[string]string // group -> original target before failover (e.g. "Game" -> "#Auto")
	failoverCurrent map[string]string // group -> target set by failover (e.g. "Game" -> "#VPS")
	ProbeURLs       []string
	ProbeTimeout    time.Duration
}

// NewGroupFailoverState creates a new failover state tracker.
func NewGroupFailoverState() *GroupFailoverState {
	return &GroupFailoverState{
		failoverOrigin:  make(map[string]string),
		failoverCurrent: make(map[string]string),
		ProbeURLs:       defaultProbeURLs,
		ProbeTimeout:    groupProbeTimeout,
	}
}

func (d *Daemon) maybePatrolGroupFailoverAsync() {
	if d.config != nil && doctor.IsServerEnvironment(d.config) && len(d.config.Subs) == 0 {
		return
	}
	if !IsSingBoxRunning() {
		return
	}
	if !d.failoverRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.failoverRunning.Store(false)
		ctx, cancel := context.WithTimeout(d.ctx, 25*time.Second)
		defer cancel()
		if d.failover == nil {
			return
		}
		d.failover.Patrol(ctx, singbox.ClashAPIEndpoints(), singbox.ClashAPISecret())
	}()
}

// Patrol inspects watched Selector groups via the Clash API, automatically fails over
// dead targets (such as when all airport nodes in #Auto go down), and automatically
// restores the original target once it recovers.
func (s *GroupFailoverState) Patrol(ctx context.Context, endpoints []string, secret string) {
	base, doc, err := fetchClashProxiesDoc(ctx, endpoints, secret)
	if err != nil || len(doc.Proxies) == 0 {
		return
	}

	for _, groupName := range defaultWatchedSelectorGroups {
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

	s.mu.Lock()
	origin := s.failoverOrigin[groupName]
	expectedCur := s.failoverCurrent[groupName]
	// 若用户在面板中手动切换到了其他分组，尊重用户手动选择并清除旧自动切换标记
	if origin != "" && expectedCur != "" && cur != expectedCur {
		delete(s.failoverOrigin, groupName)
		delete(s.failoverCurrent, groupName)
		origin = ""
	}
	s.mu.Unlock()

	// 1. 若当前处于故障切备状态，优先探测原主选分组 (如 #Auto) 是否已恢复
	if origin != "" && origin != cur && slices.Contains(grp.All, origin) {
		if delay, ok := s.probeOutboundAlive(ctx, base, secret, origin); ok {
			if err := switchClashSelector(ctx, base, secret, groupName, origin); err == nil {
				s.mu.Lock()
				delete(s.failoverOrigin, groupName)
				delete(s.failoverCurrent, groupName)
				s.mu.Unlock()
				logger.Success("[GroupFailover] 分流组 [%s] 原主选线路 [%s] 已恢复健康 (delay=%dms)，自动切回: %s -> %s",
					groupName, origin, delay, cur, origin)
				LogWatchdogEvent(WatchdogEvent{
					Time:          time.Now(),
					Action:        "GROUP_FAILBACK",
					RestartResult: fmt.Sprintf("%s: %s -> %s (%dms)", groupName, cur, origin, delay),
				})
				return
			}
		}
	}

	// 2. 探测当前选中的目标线路是否存活
	if _, ok := s.probeOutboundAlive(ctx, base, secret, cur); ok {
		return
	}

	// 3. 当前线路两次确认探测均超时失败，遍历候选列表寻找最佳可用备选线路
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
				s.mu.Lock()
				if s.failoverOrigin[groupName] == "" {
					s.failoverOrigin[groupName] = cur
				}
				s.failoverCurrent[groupName] = cand
				origRecorded := s.failoverOrigin[groupName]
				s.mu.Unlock()

				logger.Warn("[GroupFailover] 分流组 [%s] 当前线路 [%s] 不可达，已自动故障切换至 [%s] (delay=%dms, 待 [%s] 恢复后自动切回)",
					groupName, cur, cand, delay, origRecorded)
				LogWatchdogEvent(WatchdogEvent{
					Time:          time.Now(),
					Action:        "GROUP_FAILOVER",
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
	urls := s.ProbeURLs
	if len(urls) == 0 {
		urls = defaultProbeURLs
	}
	timeout := s.ProbeTimeout
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
