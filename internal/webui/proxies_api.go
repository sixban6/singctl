package webui

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/daemon"
	"singctl/internal/singbox"
)

const (
	defaultClashDelayURL     = "https://www.gstatic.com/generate_204"
	defaultClashDelayTimeout = 3500
	maxClashDelayConcurrency = 6
)

var errClashUnreachable = errors.New("sing-box 控制接口当前不可达，请确认核心已启动")

type sbProxyHistoryEntry struct {
	Time  string `json:"time,omitempty"`
	Delay int    `json:"delay"`
}

type sbProxyRawItem struct {
	Type    string                `json:"type"`
	Now     string                `json:"now,omitempty"`
	All     []string              `json:"all,omitempty"`
	History []sbProxyHistoryEntry `json:"history,omitempty"`
	UDP     bool                  `json:"udp,omitempty"`
}

type sbClashProxiesResp struct {
	Proxies map[string]sbProxyRawItem `json:"proxies"`
}

type sbClashConfigsResp struct {
	Mode string `json:"mode"`
}

// SbProxyNodeMeta 描述单个出站节点的实时元信息与最新测速结果。
type SbProxyNodeMeta struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Delay  int    `json:"delay"`
	Tested bool   `json:"tested,omitempty"`
	UDP    bool   `json:"udp,omitempty"`
}

// SbProxyGroup 描述一个策略组（Selector / URLTest / Fallback）的完整视图与关联业务分流信息。
type SbProxyGroup struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	CanSelect     bool     `json:"canSelect"`
	Now           string   `json:"now,omitempty"`
	ResolvedChain []string `json:"resolvedChain,omitempty"`
	ResolvedNode  string   `json:"resolvedNode,omitempty"`
	ResolvedDelay int      `json:"resolvedDelay,omitempty"`
	All           []string `json:"all"`
	UsedBy        []string `json:"usedBy,omitempty"`
	UsedByCount   int      `json:"usedByCount,omitempty"`
	FailedOver    bool     `json:"failedOver,omitempty"`
	FailoverFrom  string   `json:"failoverFrom,omitempty"`
	FailoverSince string   `json:"failoverSince,omitempty"`
}

// SbProxiesSnapshot 供原生 sing-box 节点控制页面使用的策略组全景快照。
type SbProxiesSnapshot struct {
	Running      bool                       `json:"running"`
	Mode         string                     `json:"mode"`
	PrimaryGroup string                     `json:"primaryGroup,omitempty"`
	PrimaryNode  string                     `json:"primaryNode,omitempty"`
	PrimaryDelay int                        `json:"primaryDelay,omitempty"`
	Groups       []SbProxyGroup             `json:"groups"`
	Nodes        map[string]SbProxyNodeMeta `json:"nodes"`
	Error        string                     `json:"error,omitempty"`
}

type sbProxySwitchRequest struct {
	Group  string `json:"group"`
	Target string `json:"target"`
}

type sbProxyDelayRequest struct {
	Group     string `json:"group,omitempty"`
	Node      string `json:"node,omitempty"`
	URL       string `json:"url,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type sbModeRequest struct {
	Mode string `json:"mode"`
}

type sbTrafficResponse struct {
	Running       bool   `json:"running"`
	Up            int64  `json:"up"`
	Down          int64  `json:"down"`
	UploadTotal   int64  `json:"uploadTotal"`
	DownloadTotal int64  `json:"downloadTotal"`
	Connections   int    `json:"connections"`
	Memory        int64  `json:"memory"`
	Error         string `json:"error,omitempty"`
}

func sbConfigFingerprint(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
}

func (s *Server) invalidateClashCache() {
	s.clashMu.Lock()
	s.clashEndpoint = ""
	s.clashSecret = ""
	s.clashCachedAt = time.Time{}
	s.clashMu.Unlock()
}

func (s *Server) clashEndpointAndSecret(ctx context.Context) (string, string, error) {
	sbPath := s.sbConfigPath()
	fp := sbConfigFingerprint(sbPath)

	s.clashMu.Lock()
	if s.clashEndpoint != "" && s.clashFingerprint == fp && time.Since(s.clashCachedAt) < 30*time.Second {
		ep, sec := s.clashEndpoint, s.clashSecret
		s.clashMu.Unlock()
		return ep, sec, nil
	}
	s.clashMu.Unlock()

	endpoints := singbox.ClashAPIEndpointsForConfig(sbPath)
	secret := singbox.ClashAPISecretForConfig(sbPath)

	client := &http.Client{Timeout: 1200 * time.Millisecond}
	for _, base := range endpoints {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/version", nil)
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			s.clashMu.Lock()
			s.clashFingerprint = fp
			s.clashEndpoint = base
			s.clashSecret = secret
			s.clashCachedAt = time.Now()
			s.clashMu.Unlock()
			return base, secret, nil
		}
	}

	s.invalidateClashCache()
	return "", "", errClashUnreachable
}

func doClashRequest(ctx context.Context, client *http.Client, method, fullURL, secret string, payload any) (int, []byte, error) {
	var bodyReader io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

func (s *Server) buildSbProxiesSnapshot(ctx context.Context, base, secret string) (SbProxiesSnapshot, error) {
	client := &http.Client{Timeout: 2500 * time.Millisecond}

	code, rawProxies, err := doClashRequest(ctx, client, http.MethodGet, base+"/proxies", secret, nil)
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
	if cCode, rawCfg, cErr := doClashRequest(ctx, client, http.MethodGet, base+"/configs", secret, nil); cErr == nil && cCode == http.StatusOK {
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
	cfg, err := config.Load(configPathFor(s))
	if err != nil || cfg == nil {
		cfg = &config.Config{}
	}
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
		switch name {
		case "Proxy":
			return 1
		case "#VPS":
			return 2
		case "AI":
			return 3
		case "#Nodes":
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

	client := &http.Client{Timeout: 3 * time.Second}
	code, rawProxies, err := doClashRequest(ctx, client, http.MethodGet, base+"/proxies", secret, nil)
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
	putCode, putBody, putErr := doClashRequest(ctx, client, http.MethodPut, putURL, secret, map[string]string{"name": target})
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
		infoClient := &http.Client{Timeout: 3 * time.Second}
		code, rawProxies, err := doClashRequest(ctx, infoClient, http.MethodGet, base+"/proxies", secret, nil)
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
		httpClient := &http.Client{Timeout: time.Duration(timeoutMs+1000) * time.Millisecond}
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

	client := &http.Client{Timeout: 3 * time.Second}
	code, raw, err := doClashRequest(ctx, client, http.MethodPatch, base+"/configs", secret, map[string]string{"mode": mode})
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

func (s *Server) handleSbTrafficGet(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	s.trafficMu.Lock()
	s.trafficLastReqAt = now
	if !s.trafficSampledAt.IsZero() && now.Sub(s.trafficSampledAt) < trafficCacheFreshWindow {
		snap := s.trafficState
		if snap.Running && !s.trafficRunning {
			s.startTrafficSamplerLocked()
		}
		s.trafficMu.Unlock()
		writeJSON(w, http.StatusOK, snap)
		return
	}
	s.trafficMu.Unlock()

	snap := s.sampleClashTrafficOnce(r.Context())

	s.trafficMu.Lock()
	s.trafficLastReqAt = time.Now()
	s.trafficState = snap
	s.trafficSampledAt = time.Now()
	if snap.Running && !s.trafficRunning {
		s.startTrafficSamplerLocked()
	}
	s.trafficMu.Unlock()

	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) sampleClashTrafficOnce(parentCtx context.Context) sbTrafficResponse {
	ctx, cancel := context.WithTimeout(parentCtx, 2200*time.Millisecond)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		return sbTrafficResponse{
			Running: false,
			Error:   err.Error(),
		}
	}

	s.trafficMu.Lock()
	skipMem := time.Now().Before(s.trafficMemUnsupportedUntil)
	s.trafficMu.Unlock()

	var (
		connUp, connDown int64
		connCount        int
		connOK           bool
		rateUp, rateDown int64
		tickOK           bool
		memInuse         int64
		memOK            bool
		wg               sync.WaitGroup
	)

	// 1. 活跃连接总数与累计流量
	wg.Go(func() {
		connUp, connDown, connCount, connOK = fetchClashConnections(ctx, base, secret)
	})

	// 2. 瞬时上下行速率（Clash /traffic 为流式 NDJSON，读取首条后立即释放连接）
	wg.Go(func() {
		tickCtx, tickCancel := context.WithTimeout(ctx, 1400*time.Millisecond)
		defer tickCancel()
		var tick struct {
			Up   int64 `json:"up"`
			Down int64 `json:"down"`
		}
		if readFirstClashStreamObject(tickCtx, base+"/traffic", secret, &tick) {
			rateUp = tick.Up
			rateDown = tick.Down
			tickOK = true
		}
	})

	// 3. sing-box 内核内存占用（若内核不支持 /memory 则冷却退避，避免阻塞采样）
	if !skipMem {
		wg.Go(func() {
			memCtx, memCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			defer memCancel()
			var mem struct {
				Inuse int64 `json:"inuse"`
			}
			if readFirstClashStreamObject(memCtx, base+"/memory", secret, &mem) {
				memInuse = mem.Inuse
				memOK = true
			}
		})
	}

	wg.Wait()

	if connOK && !skipMem {
		s.trafficMu.Lock()
		if memOK {
			s.trafficMemUnsupportedUntil = time.Time{}
		} else {
			s.trafficMemUnsupportedUntil = time.Now().Add(trafficMemRetryCooldown)
		}
		s.trafficMu.Unlock()
	}

	if !connOK && !tickOK {
		s.invalidateClashCache()
		return sbTrafficResponse{
			Running: false,
			Error:   errClashUnreachable.Error(),
		}
	}

	return sbTrafficResponse{
		Running:       true,
		Up:            rateUp,
		Down:          rateDown,
		UploadTotal:   connUp,
		DownloadTotal: connDown,
		Connections:   connCount,
		Memory:        memInuse,
	}
}

func (s *Server) startTrafficSamplerLocked() {
	if s.trafficRunning {
		return
	}
	s.trafficRunning = true
	go s.runTrafficSampler()
}

func (s *Server) runTrafficSampler() {
	streamCtx, streamCancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() {
		streamCancel()
		wg.Wait()
		s.trafficMu.Lock()
		s.trafficRunning = false
		s.trafficMu.Unlock()
	}()

	// 后台持续读取 Clash /traffic 流式 NDJSON 推送实时速率
	wg.Go(func() {
		consecutiveFail := 0
		for streamCtx.Err() == nil {
			probeCtx, probeCancel := context.WithTimeout(streamCtx, 1500*time.Millisecond)
			base, secret, err := s.clashEndpointAndSecret(probeCtx)
			probeCancel()
			if err != nil {
				consecutiveFail++
				if consecutiveFail >= 2 {
					return
				}
				select {
				case <-streamCtx.Done():
					return
				case <-time.After(time.Second):
					continue
				}
			}

			req, reqErr := http.NewRequestWithContext(streamCtx, http.MethodGet, base+"/traffic", nil)
			if reqErr != nil {
				return
			}
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			resp, doErr := (&http.Client{}).Do(req)
			if doErr != nil || resp.StatusCode != http.StatusOK {
				if resp != nil {
					_ = resp.Body.Close()
				}
				consecutiveFail++
				if consecutiveFail >= 2 {
					return
				}
				select {
				case <-streamCtx.Done():
					return
				case <-time.After(time.Second):
					continue
				}
			}
			consecutiveFail = 0
			dec := json.NewDecoder(resp.Body)
			for streamCtx.Err() == nil {
				var tick struct {
					Up   int64 `json:"up"`
					Down int64 `json:"down"`
				}
				if dec.Decode(&tick) != nil {
					break
				}
				s.trafficMu.Lock()
				s.trafficState.Running = true
				s.trafficState.Up = tick.Up
				s.trafficState.Down = tick.Down
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
			}
			_ = resp.Body.Close()
			select {
			case <-streamCtx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	})

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	consecutiveConnFail := 0
	tickCount := 0
	for range ticker.C {
		s.trafficMu.Lock()
		idle := time.Since(s.trafficLastReqAt) > trafficIdleStopWindow
		skipMem := time.Now().Before(s.trafficMemUnsupportedUntil)
		s.trafficMu.Unlock()
		if idle {
			return
		}

		tickCount++
		ctx, cancel := context.WithTimeout(streamCtx, 1500*time.Millisecond)
		base, secret, err := s.clashEndpointAndSecret(ctx)
		if err != nil {
			cancel()
			consecutiveConnFail++
			if consecutiveConnFail >= 2 {
				s.trafficMu.Lock()
				s.trafficState = sbTrafficResponse{Running: false, Error: err.Error()}
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
				return
			}
			continue
		}

		connUp, connDown, connCount, connOK := fetchClashConnections(ctx, base, secret)
		if !connOK {
			cancel()
			consecutiveConnFail++
			if consecutiveConnFail >= 2 {
				s.invalidateClashCache()
				s.trafficMu.Lock()
				s.trafficState = sbTrafficResponse{Running: false, Error: errClashUnreachable.Error()}
				s.trafficSampledAt = time.Now()
				s.trafficMu.Unlock()
				return
			}
			continue
		}
		consecutiveConnFail = 0

		var memInuse int64
		var hasMemUpdate bool
		if !skipMem && tickCount%5 == 0 {
			memCtx, memCancel := context.WithTimeout(ctx, 250*time.Millisecond)
			var mem struct {
				Inuse int64 `json:"inuse"`
			}
			if readFirstClashStreamObject(memCtx, base+"/memory", secret, &mem) {
				memInuse = mem.Inuse
				hasMemUpdate = true
			} else {
				s.trafficMu.Lock()
				s.trafficMemUnsupportedUntil = time.Now().Add(trafficMemRetryCooldown)
				s.trafficMu.Unlock()
			}
			memCancel()
		}
		cancel()

		s.trafficMu.Lock()
		s.trafficState.Running = true
		s.trafficState.Error = ""
		s.trafficState.UploadTotal = connUp
		s.trafficState.DownloadTotal = connDown
		s.trafficState.Connections = connCount
		if hasMemUpdate {
			s.trafficState.Memory = memInuse
		}
		s.trafficSampledAt = time.Now()
		s.trafficMu.Unlock()
	}
}

func fetchClashConnections(ctx context.Context, base, secret string) (upTotal, downTotal int64, count int, ok bool) {
	c := &http.Client{Timeout: 1200 * time.Millisecond}
	code, raw, reqErr := doClashRequest(ctx, c, http.MethodGet, base+"/connections", secret, nil)
	if reqErr != nil || code != http.StatusOK {
		return 0, 0, 0, false
	}
	var connDoc struct {
		UploadTotal   int64 `json:"uploadTotal"`
		DownloadTotal int64 `json:"downloadTotal"`
		Connections   []any `json:"connections"`
	}
	if json.Unmarshal(raw, &connDoc) != nil {
		return 0, 0, 0, false
	}
	return connDoc.UploadTotal, connDoc.DownloadTotal, len(connDoc.Connections), true
}

func readFirstClashStreamObject(ctx context.Context, fullURL, secret string, dst any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return false
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(dst) == nil
}
