// 文件职责：通过统一 clashapi 客户端执行候选节点并发 HTTPS 204 测速、本地 WAN 连通性校验及选择器状态汇总。
package daemon

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox/clashapi"
)

type scoredCandidate struct {
	name  string
	delay int
	score int
	order int
}

func (s *GroupFailoverState) selectBestHealthyCandidate(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashapi.ProxyItem,
	groupName string,
	grp clashapi.ProxyItem,
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
	proxies map[string]clashapi.ProxyItem,
	pool []string,
	wanGate func(context.Context) bool,
) (string, int, bool) {
	if len(pool) == 0 {
		return "", 0, false
	}
	if len(pool) > maxCandidateProbeBatch {
		pool = pool[:maxCandidateProbeBatch]
	}

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
	proxies map[string]clashapi.ProxyItem,
	subName string,
	subGrp clashapi.ProxyItem,
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
		for range retries {
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
	if err := s.clashClient().SwitchSelectorAt(ctx, base, secret, subName, best.name); err == nil {
		proxies[subName] = clashapi.ProxyItem{Type: subGrp.Type, Now: best.name, All: subGrp.All}
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

	cli := s.clashClient()
	type probeRes struct {
		delay int
		ok    bool
	}
	resCh := make(chan probeRes, len(urls))

	for _, testURL := range urls {
		go func(u string) {
			d, err := cli.ProbeDelayAt(probeCtx, base, secret, target, u, timeoutMs)
			if err == nil && d > 0 {
				resCh <- probeRes{delay: d, ok: true}
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

// CheckLocalWANConnectivity 检查本机国内直连宽带是否在线（多目标并发竞速，2.5s 超时）。
func CheckLocalWANConnectivity(
	ctx context.Context,
	base, secret string,
	proxies map[string]clashapi.ProxyItem,
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

	directHTTP := &http.Client{
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
				d, err := defaultClashClient.ProbeDelayAt(wanCtx, base, secret, directTag, testURL, 2200)
				okCh <- (err == nil && d > 0)
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
			resp, err := directHTTP.Do(req)
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
	_, proxies, err := defaultClashClient.ResolveProxiesAcross(ctx, endpoints, secret)
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
	for name, item := range proxies {
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
