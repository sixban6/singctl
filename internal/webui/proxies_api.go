// 文件职责：提供客户端 WebUI 策略组拓扑快照构建、节点手动切换、并发延迟测速与运行模式切换接口。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
	"slices"
	"strings"
	"sync"
	"time"
)

func (s *Server) buildSbProxiesSnapshot(ctx context.Context, base, secret string) (SbProxiesSnapshot, error) {
	code, rawProxies, err := doClashRequest(ctx, sharedClashHTTPClient, http.MethodGet, base+"/proxies", secret, nil)
	if err != nil || code != http.StatusOK {
		if err == nil {
			err = fmt.Errorf("clash /proxies returned HTTP %d", code)
		}
		return SbProxiesSnapshot{}, err
	}
	var proxiesDoc sbClashProxiesResp
	if err := json.Unmarshal(rawProxies, &proxiesDoc); err != nil {
		return SbProxiesSnapshot{}, fmt.Errorf("parse clash /proxies: %w", err)
	}

	mode := "rule"
	if cCode, rawCfg, cErr := doClashRequest(ctx, sharedClashHTTPClient, http.MethodGet, base+"/configs", secret, nil); cErr == nil && cCode == http.StatusOK {
		var cfgDoc sbClashConfigsResp
		if json.Unmarshal(rawCfg, &cfgDoc) == nil && strings.TrimSpace(cfgDoc.Mode) != "" {
			mode = strings.ToLower(strings.TrimSpace(cfgDoc.Mode))
		}
	}

	usageMap := s.buildRoutingGroupUsageMap()
	failoverMap := make(map[string]daemon.FailoverActiveItem)
	for _, act := range daemon.LoadRuntimeSnapshot().ActiveFailovers {
		failoverMap[act.Group] = act
	}

	var groups []SbProxyGroup
	referencedNodes := make(map[string]bool)

	for name, item := range proxiesDoc.Proxies {
		if !isClashProxyGroupType(item.Type) {
			continue
		}
		if strings.EqualFold(name, "GLOBAL") && !strings.EqualFold(mode, "global") {
			continue
		}

		chain, leaf, leafDelay := resolveProxyOutboundChain(proxiesDoc.Proxies, item.Now)
		usedBy := usageMap[name]
		act, hasFailover := failoverMap[name]
		// 若用户已在 Clash 中手动切换到其他节点，不展示陈旧的容灾徽章
		isFailedOver := hasFailover && strings.TrimSpace(item.Now) != "" && act.Current == item.Now

		groups = append(groups, SbProxyGroup{
			Name:          name,
			Type:          canonicalGroupType(item.Type),
			CanSelect:     strings.EqualFold(item.Type, "Selector"),
			Now:           item.Now,
			ResolvedChain: chain,
			ResolvedNode:  leaf,
			ResolvedDelay: leafDelay,
			All:           slices.Clone(item.All),
			UsedBy:        usedBy,
			UsedByCount:   len(usedBy),
			FailedOver:    isFailedOver,
			FailoverFrom:  ternaryStr(isFailedOver, act.Origin, ""),
			FailoverSince: ternaryStr(isFailedOver, act.Since, ""),
		})

		for _, child := range item.All {
			referencedNodes[child] = true
		}
		if item.Now != "" {
			referencedNodes[item.Now] = true
		}
		if leaf != "" {
			referencedNodes[leaf] = true
		}
	}

	slices.SortFunc(groups, func(a, b SbProxyGroup) int {
		if c := cmp.Compare(groupSortWeight(a.Name, a.Type, mode), groupSortWeight(b.Name, b.Type, mode)); c != 0 {
			return c
		}
		return cmp.Compare(a.Name, b.Name)
	})

	nodes := make(map[string]SbProxyNodeMeta, len(referencedNodes))
	for name := range referencedNodes {
		raw, ok := proxiesDoc.Proxies[name]
		if !ok {
			nodes[name] = SbProxyNodeMeta{Name: name, Type: "Unknown"}
			continue
		}
		delay, tested := latestProxyDelay(raw)
		nodes[name] = SbProxyNodeMeta{
			Name:   name,
			Type:   raw.Type,
			Delay:  delay,
			Tested: tested,
			UDP:    raw.UDP,
		}
	}

	primaryGroup, primaryNode, primaryDelay := pickPrimaryGroupSummary(groups, mode)

	return SbProxiesSnapshot{
		Running:      true,
		Mode:         mode,
		PrimaryGroup: primaryGroup,
		PrimaryNode:  primaryNode,
		PrimaryDelay: primaryDelay,
		Groups:       groups,
		Nodes:        nodes,
	}, nil
}

func (s *Server) buildRoutingGroupUsageMap() map[string][]string {
	out := make(map[string][]string)
	cfg := s.readConfigOrEmpty()
	rawSB, _ := os.ReadFile(s.sbConfigPath())
	report := singbox.BuildClientRoutingReport(cfg, string(rawSB))
	for _, item := range report.Items {
		if !item.Enabled || strings.TrimSpace(item.EffectiveDest) == "" {
			continue
		}
		dest := item.EffectiveDest
		if !slices.Contains(out[dest], item.Name) {
			out[dest] = append(out[dest], item.Name)
		}
	}
	return out
}

func isClashProxyGroupType(typ string) bool {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "selector", "urltest", "fallback", "loadbalance":
		return true
	default:
		return false
	}
}

func canonicalGroupType(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "selector":
		return "Selector"
	case "urltest":
		return "URLTest"
	case "fallback":
		return "Fallback"
	case "loadbalance":
		return "LoadBalance"
	default:
		return typ
	}
}

func groupSortWeight(name, typ, mode string) int {
	if strings.EqualFold(name, "GLOBAL") {
		if strings.EqualFold(mode, "global") {
			return 0
		}
		return 50
	}
	if strings.EqualFold(typ, "Selector") {
		switch {
		case strings.EqualFold(name, "Proxy"):
			return 1
		case strings.EqualFold(name, "AI"):
			return 2
		case strings.EqualFold(name, "#VPS"):
			return 3
		case strings.EqualFold(name, "#Nodes"):
			return 4
		default:
			return 10
		}
	}
	if name == "#Auto" {
		return 20
	}
	return 30
}

func latestProxyDelay(item sbProxyRawItem) (int, bool) {
	if len(item.History) == 0 {
		return 0, false
	}
	last := item.History[len(item.History)-1]
	if last.Delay > 0 {
		return last.Delay, true
	}
	return 0, true
}

func resolveProxyOutboundChain(proxies map[string]sbProxyRawItem, initialNow string) (chain []string, leaf string, delay int) {
	cur := strings.TrimSpace(initialNow)
	if cur == "" {
		return nil, "", 0
	}
	seen := make(map[string]bool, 8)
	for range 8 {
		if cur == "" || seen[cur] {
			break
		}
		seen[cur] = true
		chain = append(chain, cur)

		item, ok := proxies[cur]
		if !ok || !isClashProxyGroupType(item.Type) {
			leaf = cur
			break
		}
		next := strings.TrimSpace(item.Now)
		if next == "" {
			leaf = cur
			break
		}
		cur = next
	}
	if leaf == "" && len(chain) > 0 {
		leaf = chain[len(chain)-1]
	}
	if leaf != "" {
		if d, ok := latestProxyDelay(proxies[leaf]); ok && d > 0 {
			delay = d
		}
	}
	if delay == 0 {
		for i := len(chain) - 1; i >= 0; i-- {
			if d, ok := latestProxyDelay(proxies[chain[i]]); ok && d > 0 {
				delay = d
				break
			}
		}
	}
	return chain, leaf, delay
}

func pickPrimaryGroupSummary(groups []SbProxyGroup, mode string) (groupName, nodeName string, delay int) {
	if len(groups) == 0 {
		return "", "", 0
	}
	findByName := func(target string) (SbProxyGroup, bool) {
		for _, g := range groups {
			if g.Name == target {
				return g, true
			}
		}
		return SbProxyGroup{}, false
	}
	var chosen SbProxyGroup
	var found bool
	if strings.EqualFold(mode, "global") {
		chosen, found = findByName("GLOBAL")
	}
	if !found {
		chosen, found = findByName("Proxy")
	}
	if !found {
		for _, g := range groups {
			if g.CanSelect {
				chosen, found = g, true
				break
			}
		}
	}
	if !found {
		chosen = groups[0]
	}
	return chosen.Name, cmp.Or(chosen.ResolvedNode, chosen.Now), chosen.ResolvedDelay
}

func isUtilityDirectOrBlockTag(tag string) bool {
	switch strings.ToLower(strings.TrimSpace(tag)) {
	case "", "#dc", "directconn", "direct", "direct-out", "block", "block-out", "dns-out", "reject":
		return true
	default:
		return false
	}
}

func ternaryStr(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func (s *Server) handleSbProxiesGet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, SbProxiesSnapshot{
			Running: false,
			Mode:    "rule",
			Groups:  []SbProxyGroup{},
			Nodes:   map[string]SbProxyNodeMeta{},
			Error:   err.Error(),
		})
		return
	}

	snap, err := s.buildSbProxiesSnapshot(ctx, base, secret)
	if err != nil {
		writeJSON(w, http.StatusOK, SbProxiesSnapshot{
			Running: false,
			Mode:    "rule",
			Groups:  []SbProxyGroup{},
			Nodes:   map[string]SbProxyNodeMeta{},
			Error:   err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleSbProxySwitchPut(w http.ResponseWriter, r *http.Request) {
	var body sbProxySwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	group := strings.TrimSpace(body.Group)
	target := strings.TrimSpace(body.Target)
	if group == "" || target == "" {
		writeJSONError(w, http.StatusBadRequest, "group 与 target 不能为空")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	code, rawProxies, err := doClashRequest(ctx, sharedClashHTTPClient, http.MethodGet, base+"/proxies", secret, nil)
	if err != nil || code != http.StatusOK {
		writeJSONError(w, http.StatusBadGateway, "读取策略组信息失败")
		return
	}
	var proxiesDoc sbClashProxiesResp
	if err := json.Unmarshal(rawProxies, &proxiesDoc); err != nil {
		writeJSONError(w, http.StatusBadGateway, "解析策略组信息失败")
		return
	}

	grp, exists := proxiesDoc.Proxies[group]
	if !exists {
		writeJSONError(w, http.StatusNotFound, fmt.Sprintf("策略组「%s」不存在", group))
		return
	}
	if !strings.EqualFold(grp.Type, "Selector") {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("「%s」为 %s 自动优选分组，不可手动固定节点", group, grp.Type))
		return
	}
	if !slices.Contains(grp.All, target) {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("节点「%s」不属于策略组「%s」", target, group))
		return
	}

	putURL := fmt.Sprintf("%s/proxies/%s", base, url.PathEscape(group))
	putCode, putBody, putErr := doClashRequest(ctx, sharedClashHTTPClient, http.MethodPut, putURL, secret, map[string]string{"name": target})
	if putErr != nil || putCode < 200 || putCode >= 300 {
		msg := strings.TrimSpace(string(putBody))
		if putErr != nil {
			msg = putErr.Error()
		}
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("切换节点失败 (HTTP %d): %s", putCode, msg))
		return
	}

	// 仅当看门狗快照中确实存在该组的过时容灾记录时再写入状态文件，保持界面一致同时避免冗余落盘
	for _, act := range daemon.LoadRuntimeSnapshot().ActiveFailovers {
		if act.Group == group && act.Current != target {
			daemon.UpdateRuntimeState(func(snap *daemon.DaemonRuntimeSnapshot) {
				filtered := snap.ActiveFailovers[:0]
				for _, item := range snap.ActiveFailovers {
					if item.Group == group && item.Current != target {
						continue
					}
					filtered = append(filtered, item)
				}
				if len(filtered) == 0 {
					snap.ActiveFailovers = nil
				} else {
					snap.ActiveFailovers = filtered
				}
			})
			break
		}
	}

	snapshot, snapErr := s.buildSbProxiesSnapshot(ctx, base, secret)
	if snapErr != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"group":   group,
			"target":  target,
			"message": fmt.Sprintf("已将「%s」切换至 %s", group, target),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"group":    group,
		"target":   target,
		"message":  fmt.Sprintf("已将「%s」切换至 %s", group, target),
		"snapshot": snapshot,
	})
}

func (s *Server) handleSbProxyDelayPost(w http.ResponseWriter, r *http.Request) {
	var body sbProxyDelayRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}

	group := strings.TrimSpace(body.Group)
	node := strings.TrimSpace(body.Node)
	if group == "" && node == "" {
		writeJSONError(w, http.StatusBadRequest, "请指定待测速的 group 或 node")
		return
	}

	testURL := strings.TrimSpace(body.URL)
	if testURL == "" {
		testURL = defaultClashDelayURL
	} else if err := validateProbeURL(testURL); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	timeoutMs := body.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = defaultClashDelayTimeout
	}
	timeoutMs = min(8000, max(500, timeoutMs))

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	var targets []string
	if node != "" {
		if isUtilityDirectOrBlockTag(node) {
			writeJSONError(w, http.StatusBadRequest, "内置直连/阻断出站不支持测速")
			return
		}
		targets = []string{node}
	} else {
		code, rawProxies, err := doClashRequest(ctx, sharedClashHTTPClient, http.MethodGet, base+"/proxies", secret, nil)
		if err != nil || code != http.StatusOK {
			writeJSONError(w, http.StatusBadGateway, "获取节点列表失败")
			return
		}
		var proxiesDoc sbClashProxiesResp
		if err := json.Unmarshal(rawProxies, &proxiesDoc); err != nil {
			writeJSONError(w, http.StatusBadGateway, "解析节点列表失败")
			return
		}

		seen := make(map[string]bool)
		addTarget := func(name string) {
			name = strings.TrimSpace(name)
			if name == "" || seen[name] || isUtilityDirectOrBlockTag(name) {
				return
			}
			seen[name] = true
			targets = append(targets, name)
		}

		if group == "__all__" {
			for gName, item := range proxiesDoc.Proxies {
				if !isClashProxyGroupType(item.Type) || strings.EqualFold(gName, "GLOBAL") {
					continue
				}
				for _, child := range item.All {
					if cItem, ok := proxiesDoc.Proxies[child]; ok && isClashProxyGroupType(cItem.Type) {
						continue
					}
					addTarget(child)
				}
			}
			// 兜底：若某些分组仅包含子分组，也纳入子分组探测
			for gName, item := range proxiesDoc.Proxies {
				if isClashProxyGroupType(item.Type) && !strings.EqualFold(gName, "GLOBAL") {
					addTarget(gName)
				}
			}
		} else {
			grp, exists := proxiesDoc.Proxies[group]
			if !exists {
				writeJSONError(w, http.StatusNotFound, fmt.Sprintf("策略组「%s」不存在", group))
				return
			}
			for _, child := range grp.All {
				addTarget(child)
			}
		}
	}

	delays := make(map[string]int, len(targets))
	if len(targets) > 0 {
		httpClient := sharedClashStreamClient
		jobs := make(chan string, len(targets))
		for _, t := range targets {
			jobs <- t
		}
		close(jobs)

		var mu sync.Mutex
		var wg sync.WaitGroup
		workers := min(maxClashDelayConcurrency, len(targets))
		for range workers {
			wg.Go(func() {
				for targetName := range jobs {
					if ctx.Err() != nil {
						return
					}
					delay := probeSingleClashNodeDelay(ctx, httpClient, base, secret, targetName, testURL, timeoutMs)
					mu.Lock()
					delays[targetName] = delay
					mu.Unlock()
				}
			})
		}
		wg.Wait()
	}

	okCount := 0
	for _, d := range delays {
		if d > 0 {
			okCount++
		}
	}

	snapshot, _ := s.buildSbProxiesSnapshot(ctx, base, secret)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"url":         testURL,
		"delays":      delays,
		"testedCount": len(targets),
		"okCount":     okCount,
		"snapshot":    snapshot,
	})
}

func probeSingleClashNodeDelay(ctx context.Context, client *http.Client, base, secret, target, testURL string, timeoutMs int) int {
	reqURL := fmt.Sprintf("%s/proxies/%s/delay?url=%s&timeout=%d",
		base,
		url.PathEscape(target),
		url.QueryEscape(testURL),
		timeoutMs,
	)
	code, raw, err := doClashRequest(ctx, client, http.MethodGet, reqURL, secret, nil)
	if err != nil || code != http.StatusOK {
		return 0
	}
	var res struct {
		Delay int `json:"delay"`
	}
	if json.Unmarshal(raw, &res) != nil || res.Delay <= 0 {
		return 0
	}
	return res.Delay
}

func (s *Server) handleSbModePut(w http.ResponseWriter, r *http.Request) {
	var body sbModeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "请求格式错误: "+err.Error())
		return
	}
	mode := strings.ToLower(strings.TrimSpace(body.Mode))
	switch mode {
	case "rule", "global", "direct":
	default:
		writeJSONError(w, http.StatusBadRequest, "mode 仅支持 rule / global / direct")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	code, raw, err := doClashRequest(ctx, sharedClashHTTPClient, http.MethodPatch, base+"/configs", secret, map[string]string{"mode": mode})
	if err != nil || code < 200 || code >= 300 {
		msg := strings.TrimSpace(string(raw))
		if err != nil {
			msg = err.Error()
		}
		writeJSONError(w, http.StatusBadGateway, fmt.Sprintf("切换运行模式失败 (HTTP %d): %s", code, msg))
		return
	}

	snapshot, _ := s.buildSbProxiesSnapshot(ctx, base, secret)
	modeLabel := map[string]string{
		"rule":   "智能分流 (Rule)",
		"global": "全局代理 (Global)",
		"direct": "全局直连 (Direct)",
	}[mode]
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"mode":     mode,
		"message":  "运行模式已切换为 " + modeLabel,
		"snapshot": snapshot,
	})
}

const (
	trafficIdleStopWindow   = 15 * time.Second
	trafficCacheFreshWindow = 4 * time.Second
	trafficMemRetryCooldown = 5 * time.Minute
)

func validateProbeURL(raw string) error {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("测速 URL 必须为合法的 http/https 地址")
	}
	if parsed.User != nil {
		return errors.New("测速 URL 不允许包含认证凭据")
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parsed.Hostname()), "."))
	if host == "" {
		return errors.New("测速 URL 缺少合法主机名")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return errors.New("出于安全策略禁止测速本机或内网保留域名")
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedProbeIP(ip) {
		return errors.New("出于安全策略禁止测速回环、内网或链路本地 IP 地址")
	}
	return nil
}

func isBlockedProbeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		// CGNAT 100.64.0.0/10
		if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
			return true
		}
		// THIS-NET 0.0.0.0/8 & Benchmarking 198.18.0.0/15
		if ip4[0] == 0 || (ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)) {
			return true
		}
	}
	return false
}
