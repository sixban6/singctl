// 文件职责：提供客户端 WebUI 策略组拓扑快照构建、节点手动切换、并发延迟测速与运行模式切换接口（委托 clashapi）。
package webui

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"singctl/internal/daemon"
	"singctl/internal/singbox"
	"singctl/internal/singbox/clashapi"
)

const (
	trafficIdleStopWindow   = 15 * time.Second
	trafficCacheFreshWindow = 4 * time.Second
	trafficMemRetryCooldown = 5 * time.Minute
)

func (s *Server) buildSbProxiesSnapshot(ctx context.Context, base, secret string) (SbProxiesSnapshot, error) {
	cli := s.clashClient()
	proxies, err := cli.ProxiesAt(ctx, base, secret)
	if err != nil {
		return SbProxiesSnapshot{}, err
	}

	mode := "rule"
	if m, mErr := cli.ModeAt(ctx, base, secret); mErr == nil && m != "" {
		mode = m
	}

	usageMap := s.buildRoutingGroupUsageMap()
	failoverMap := make(map[string]daemon.FailoverActiveItem)
	for _, act := range daemon.LoadRuntimeSnapshot().ActiveFailovers {
		failoverMap[act.Group] = act
	}

	var groups []SbProxyGroup
	referencedNodes := make(map[string]bool)

	for name, item := range proxies {
		if !clashapi.IsProxyGroupType(item.Type) {
			continue
		}
		if strings.EqualFold(name, "GLOBAL") && !strings.EqualFold(mode, "global") {
			continue
		}

		chain, leaf, leafDelay := clashapi.ResolveOutboundChain(proxies, item.Now)
		usedBy := usageMap[name]
		act, hasFailover := failoverMap[name]
		isFailedOver := hasFailover && strings.TrimSpace(item.Now) != "" && act.Current == item.Now

		groups = append(groups, SbProxyGroup{
			Name:          name,
			Type:          clashapi.CanonicalGroupType(item.Type),
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
		raw, ok := proxies[name]
		if !ok {
			nodes[name] = SbProxyNodeMeta{Name: name, Type: "Unknown"}
			continue
		}
		delay, tested := clashapi.LatestProxyDelay(raw)
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

func formatClashCallErr(prefix string, err error) string {
	if se, ok := errors.AsType[*clashapi.StatusError](err); ok {
		return fmt.Sprintf("%s (HTTP %d): %s", prefix, se.StatusCode, se.Body)
	}
	return fmt.Sprintf("%s: %v", prefix, err)
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

	cli := s.clashClient()
	proxies, err := cli.ProxiesAt(ctx, base, secret)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "读取策略组信息失败")
		return
	}

	grp, exists := proxies[group]
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

	if putErr := cli.SwitchSelectorAt(ctx, base, secret, group, target); putErr != nil {
		writeJSONError(w, http.StatusBadGateway, formatClashCallErr("切换节点失败", putErr))
		return
	}

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
		testURL = clashapi.DefaultDelayProbeURL
	} else if err := clashapi.ValidateProbeURL(testURL); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	timeoutMs := body.TimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = clashapi.DefaultDelayTimeoutMs
	}
	timeoutMs = min(8000, max(500, timeoutMs))

	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()

	base, secret, err := s.clashEndpointAndSecret(ctx)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	cli := s.clashClient()
	targets, statusCode, errMsg := collectDelayTargets(ctx, cli, base, secret, group, node)
	if statusCode != 0 {
		writeJSONError(w, statusCode, errMsg)
		return
	}

	delays := cli.ProbeDelaysBatchAt(ctx, base, secret, targets, testURL, timeoutMs, clashapi.DefaultDelayConcurrency)
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

func collectDelayTargets(ctx context.Context, cli *clashapi.Client, base, secret, group, node string) ([]string, int, string) {
	if node != "" {
		if isUtilityDirectOrBlockTag(node) {
			return nil, http.StatusBadRequest, "内置直连/阻断出站不支持测速"
		}
		return []string{node}, 0, ""
	}

	proxies, err := cli.ProxiesAt(ctx, base, secret)
	if err != nil {
		return nil, http.StatusBadGateway, "获取节点列表失败"
	}

	var targets []string
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
		for gName, item := range proxies {
			if !clashapi.IsProxyGroupType(item.Type) || strings.EqualFold(gName, "GLOBAL") {
				continue
			}
			for _, child := range item.All {
				if cItem, ok := proxies[child]; ok && clashapi.IsProxyGroupType(cItem.Type) {
					continue
				}
				addTarget(child)
			}
		}
		for gName, item := range proxies {
			if clashapi.IsProxyGroupType(item.Type) && !strings.EqualFold(gName, "GLOBAL") {
				addTarget(gName)
			}
		}
		return targets, 0, ""
	}

	grp, exists := proxies[group]
	if !exists {
		return nil, http.StatusNotFound, fmt.Sprintf("策略组「%s」不存在", group)
	}
	for _, child := range grp.All {
		addTarget(child)
	}
	return targets, 0, ""
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

	if patchErr := s.clashClient().PatchModeAt(ctx, base, secret, mode); patchErr != nil {
		writeJSONError(w, http.StatusBadGateway, formatClashCallErr("切换运行模式失败", patchErr))
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
