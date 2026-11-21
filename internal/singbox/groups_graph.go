// 文件职责：提供策略组拓扑环路检测、悬空出站引用自愈、预览报告生成与在线配置重编译入口。
package singbox

import (
	"cmp"
	"encoding/json"
	"fmt"
	"singctl/internal/config"
	log "singctl/internal/logger"
	"slices"
	"strings"
)

func insertGroupBeforeNodesOrDirect(members []string, newGroup, directTag string) []string {
	for i, m := range members {
		if m == "#Nodes" || m == directTag {
			out := make([]string, 0, len(members)+1)
			out = append(out, members[:i]...)
			out = append(out, newGroup)
			out = append(out, members[i:]...)
			return out
		}
	}
	return append(members, newGroup)
}

func orderCompiledGroups(groups []map[string]any) []map[string]any {
	var topGroups, hashGroups []map[string]any
	for _, g := range groups {
		tag := stringField(g, "tag")
		if strings.HasPrefix(tag, "#") {
			hashGroups = append(hashGroups, g)
		} else {
			topGroups = append(topGroups, g)
		}
	}
	return append(topGroups, hashGroups...)
}

func detectOutboundCycle(groups []map[string]any) []string {
	adj := make(map[string][]string, len(groups))
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		tag := stringField(g, "tag")
		names = append(names, tag)
		adj[tag] = anySliceToStrings(g["outbounds"])
	}

	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state := make(map[string]int, len(groups))
	var stack []string

	var dfs func(u string) []string
	dfs = func(u string) []string {
		state[u] = visiting
		stack = append(stack, u)
		for _, v := range adj[u] {
			if _, isGroup := adj[v]; !isGroup {
				continue
			}
			if state[v] == visiting {
				idx := slices.Index(stack, v)
				cycle := append(slices.Clone(stack[idx:]), v)
				return cycle
			}
			if state[v] == unvisited {
				if cyc := dfs(v); len(cyc) > 0 {
					return cyc
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[u] = visited
		return nil
	}

	for _, name := range names {
		if state[name] == unvisited {
			if cyc := dfs(name); len(cyc) > 0 {
				return cyc
			}
		}
	}
	return nil
}

func healDanglingOutboundRefs(
	root map[string]any,
	validTags map[string]bool,
	primaryGroup, directTag string,
	report *GroupsPreviewReport,
) {
	if routeMap, ok := root["route"].(map[string]any); ok {
		if finalTag := strings.TrimSpace(stringField(routeMap, "final")); finalTag != "" && !validTags[finalTag] {
			routeMap["final"] = primaryGroup
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("route.final 原引用 [%s] 已不存在，已自动重绑定至 [%s]", finalTag, primaryGroup))
		}
		if rules, ok := routeMap["rules"].([]any); ok {
			for _, item := range rules {
				rm, ok := item.(map[string]any)
				if !ok {
					continue
				}
				ob := strings.TrimSpace(stringField(rm, "outbound"))
				if ob != "" && !validTags[ob] {
					replacement := primaryGroup
					if ob == "direct" {
						replacement = directTag
					}
					rm["outbound"] = replacement
					report.Warnings = append(report.Warnings,
						fmt.Sprintf("路由规则原出站 [%s] 已不存在，已自动重绑定至 [%s]", ob, replacement))
				}
			}
		}
	}

	if dnsMap, ok := root["dns"].(map[string]any); ok {
		if servers, ok := dnsMap["servers"].([]any); ok {
			for _, item := range servers {
				sm, ok := item.(map[string]any)
				if !ok {
					continue
				}
				detour := strings.TrimSpace(stringField(sm, "detour"))
				if detour != "" && !validTags[detour] {
					serverTag := cmp.Or(strings.TrimSpace(stringField(sm, "tag")), "dns")
					if primaryGroup != directTag {
						sm["detour"] = primaryGroup
						report.Warnings = append(report.Warnings,
							fmt.Sprintf("DNS [%s] 原出口 [%s] 已不存在，已自动跟随默认兜底组 [%s]", serverTag, detour, primaryGroup))
					} else {
						delete(sm, "detour")
						report.Warnings = append(report.Warnings,
							fmt.Sprintf("DNS [%s] 原出口 [%s] 已不存在，已自动回退为直连", serverTag, detour))
					}
				}
			}
		}
	}
}

func extractEffectiveRoutingConventions(root map[string]any, directTag string) (defaultOutbound, dnsDetour string) {
	if routeMap, ok := root["route"].(map[string]any); ok {
		defaultOutbound = strings.TrimSpace(stringField(routeMap, "final"))
	}
	if dnsMap, ok := root["dns"].(map[string]any); ok {
		if servers, ok := dnsMap["servers"].([]any); ok {
			for _, item := range servers {
				sm, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if strings.TrimSpace(stringField(sm, "tag")) == "dns_proxy" {
					dnsDetour = strings.TrimSpace(stringField(sm, "detour"))
					break
				}
			}
		}
	}
	if dnsDetour == "" {
		dnsDetour = directTag
	}
	return defaultOutbound, dnsDetour
}

func buildPreviewFromGroupMaps(
	groups []map[string]any,
	leafSet map[string]LeafOutboundInfo,
	customized map[string]bool,
	fallbackInfo map[string]string,
	attachedRecord map[string][]string,
) []CompiledGroupPreview {
	// 反向统计所有被父组引用的挂载关系（覆盖内置组及未在 attachedRecord 中的引用）
	parentRefs := make(map[string][]string)
	for _, g := range groups {
		pTag := stringField(g, "tag")
		for _, child := range anySliceToStrings(g["outbounds"]) {
			if !slices.Contains(parentRefs[child], pTag) {
				parentRefs[child] = append(parentRefs[child], pTag)
			}
		}
	}

	out := make([]CompiledGroupPreview, 0, len(groups))
	for _, g := range groups {
		name := stringField(g, "tag")
		typ := strings.ToLower(stringField(g, "type"))
		members := anySliceToStrings(g["outbounds"])
		leafCnt := 0
		for _, m := range members {
			if _, isLeaf := leafSet[m]; isLeaf {
				leafCnt++
			}
		}
		fbTag := ""
		if fallbackInfo != nil {
			fbTag = fallbackInfo[name]
		}
		attached := parentRefs[name]
		if len(attached) == 0 && attachedRecord != nil {
			attached = attachedRecord[name]
		}
		out = append(out, CompiledGroupPreview{
			Name:           name,
			Type:           typ,
			Builtin:        slices.Contains(builtinGroupNames, name),
			Customized:     customized != nil && customized[name],
			FallbackUsed:   fbTag != "",
			FallbackTag:    fbTag,
			Default:        stringField(g, "default"),
			AttachedTo:     attached,
			Members:        members,
			LeafMatchCount: leafCnt,
			TotalCount:     len(members),
		})
	}
	return out
}

// InjectGroupsForPlatform 在 ConfigGenerator 生成流水线中自动加载并编译同目录下的 groups.yaml。
func (g *ConfigGenerator) InjectGroupsForPlatform(rawJSON, _ string) (string, error) {
	if g == nil || g.config == nil {
		return rawJSON, nil
	}
	gPath := g.config.GroupsPath()
	if gPath == "" {
		return rawJSON, nil
	}
	gc, exists, err := config.LoadGroupsFile(gPath)
	if err != nil {
		return "", err
	}
	if !exists || gc.IsEmpty() {
		return rawJSON, nil
	}
	subOrigins := ResolveSubNodeOrigins(g.config, g.cacheDir)
	compiled, report, err := CompileGroupsIntoConfigJSON(rawJSON, gc, subOrigins, extractSubNames(g.config))
	if err != nil {
		return "", err
	}
	if !g.silent && report != nil {
		log.Info("声明式策略组 (groups.yaml) 编译生效: mode=%s, 活跃策略组=%d 个", report.Mode, len(report.Groups))
		for _, w := range report.Warnings {
			log.Warn("⚠️ [groups.yaml] %s", w)
		}
	}
	return compiled, nil
}

// RecompileLiveConfigWithGroups 基于现有运行中的 config.json 底层节点池，离线毫秒级重编译 groups.yaml、
// custom_rules 与客户端智能分流策略，无需重新联网拉取远程订阅即可实现预览与 SIGHUP 无损热应用。
func RecompileLiveConfigWithGroups(
	rawSBJSON string,
	cfg *config.Config,
	gc *config.GroupsConfig,
	cacheDir string,
) (string, *GroupsPreviewReport, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(rawSBJSON), &root); err != nil {
		return "", nil, fmt.Errorf("解析当前 sing-box 配置失败: %w", err)
	}

	rawOutbounds, _ := root["outbounds"].([]any)
	var leafMaps []map[string]any
	var leafTags []string
	var specialMaps []map[string]any
	for _, item := range rawOutbounds {
		om, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := strings.TrimSpace(stringField(om, "tag"))
		typ := strings.ToLower(strings.TrimSpace(stringField(om, "type")))
		if tag == "" {
			continue
		}
		switch typ {
		case "selector", "urltest":
			continue
		case "direct", "block", "dns":
			specialMaps = append(specialMaps, om)
		default:
			leafMaps = append(leafMaps, om)
			leafTags = append(leafTags, tag)
		}
	}

	// 先还原标准内置 5 组骨架，确保用户从 groups.yaml 删除旧分组后不留残影
	skeletonGroups := buildStandardBuiltinSkeleton(leafTags)
	cleanOutbounds := make([]any, 0, len(skeletonGroups)+len(leafMaps)+len(specialMaps))
	for _, sg := range skeletonGroups {
		cleanOutbounds = append(cleanOutbounds, sg)
	}
	for _, lm := range leafMaps {
		cleanOutbounds = append(cleanOutbounds, lm)
	}
	for _, sm := range specialMaps {
		cleanOutbounds = append(cleanOutbounds, sm)
	}
	root["outbounds"] = cleanOutbounds

	resetBytes, err := json.Marshal(root)
	if err != nil {
		return "", nil, err
	}

	subOrigins := ResolveSubNodeOrigins(cfg, cacheDir)
	compiledJSON, report, err := CompileGroupsIntoConfigJSON(string(resetBytes), gc, subOrigins, extractSubNames(cfg))
	if err != nil {
		return "", nil, err
	}

	if cfg != nil {
		if len(cfg.CustomRules.Outbounds) > 0 {
			var cRoot map[string]any
			if err := json.Unmarshal([]byte(compiledJSON), &cRoot); err == nil {
				if err := applyCustomOutboundRules(cRoot, cfg.CustomRules.Outbounds); err != nil {
					return "", nil, err
				}
				if b, mErr := json.MarshalIndent(cRoot, "", "  "); mErr == nil {
					compiledJSON = string(b)
				}
			}
		}
		updatedTR, err := ApplyTrafficRoutingToConfigJSON(compiledJSON, cfg.TrafficRouting, cfg.CustomRules)
		if err != nil {
			return "", nil, err
		}
		compiledJSON = updatedTR
	}

	return compiledJSON, report, nil
}
