// 文件职责：提供策略组拓扑环路检测、悬空出站引用自愈、父组自动挂载、预览报告生成与在线配置重编译入口。
package singbox

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"singctl/internal/config"
	log "singctl/internal/logger"
	"singctl/internal/singbox/sboption"
)

func buildValidTagSet(groups, leaves []sboption.Outbound, specialTags, endpointTags map[string]bool) map[string]bool {
	valid := make(map[string]bool, len(groups)+len(leaves)+len(specialTags)+len(endpointTags))
	for _, g := range groups {
		valid[g.Tag] = true
	}
	for _, l := range leaves {
		valid[l.Tag] = true
	}
	maps.Copy(valid, specialTags)
	maps.Copy(valid, endpointTags)
	return valid
}

func resolvePrimaryGroupTag(validTags map[string]bool, groups []sboption.Outbound, directFallback string) string {
	if validTags["Proxy"] {
		return "Proxy"
	}
	if len(groups) > 0 {
		return groups[0].Tag
	}
	return directFallback
}

func resolveAttachTargets(spec config.GroupSpec, groupIndexByName map[string]int) []string {
	if spec.AttachTo.Set {
		return spec.AttachTo.Items
	}
	if _, hasProxy := groupIndexByName["Proxy"]; hasProxy {
		return []string{"Proxy"}
	}
	return nil
}

func attachUserGroupsToParents(
	workingGroups []sboption.Outbound,
	groupIndexByName map[string]int,
	newUserGroupOrder []string,
	userGroupSet map[string]config.GroupSpec,
	directFallback string,
	attachedRecord map[string][]string,
) {
	for _, newName := range newUserGroupOrder {
		targets := resolveAttachTargets(userGroupSet[newName], groupIndexByName)
		for _, parentTag := range targets {
			pIdx, exists := groupIndexByName[parentTag]
			if !exists || parentTag == newName || !strings.EqualFold(workingGroups[pIdx].Type, config.GroupTypeSelector) {
				continue
			}
			if !slices.Contains(workingGroups[pIdx].Outbounds, newName) {
				workingGroups[pIdx].Outbounds = insertGroupBeforeNodesOrDirect(workingGroups[pIdx].Outbounds, newName, directFallback)
			}
			attachedRecord[newName] = append(attachedRecord[newName], parentTag)
		}
	}
}

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
	return append(slices.Clone(members), newGroup)
}

func orderCompiledGroupOutbounds(groups []sboption.Outbound) []sboption.Outbound {
	var topGroups, hashGroups []sboption.Outbound
	for _, g := range groups {
		if strings.HasPrefix(g.Tag, "#") {
			hashGroups = append(hashGroups, g)
		} else {
			topGroups = append(topGroups, g)
		}
	}
	return append(topGroups, hashGroups...)
}

func detectOutboundCycle(groups []sboption.Outbound) []string {
	adj := make(map[string][]string, len(groups))
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Tag)
		adj[g.Tag] = g.Outbounds
	}

	state := make(map[string]int, len(groups))
	var stack []string
	for _, name := range names {
		if state[name] != 0 {
			continue
		}
		if cyc := dfsGroupCycle(name, adj, state, &stack); len(cyc) > 0 {
			return cyc
		}
	}
	return nil
}

func dfsGroupCycle(u string, adj map[string][]string, state map[string]int, stack *[]string) []string {
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)
	state[u] = visiting
	*stack = append(*stack, u)
	for _, v := range adj[u] {
		if _, isGroup := adj[v]; !isGroup {
			continue
		}
		if state[v] == visiting {
			idx := slices.Index(*stack, v)
			return append(slices.Clone((*stack)[idx:]), v)
		}
		if state[v] == unvisited {
			if cyc := dfsGroupCycle(v, adj, state, stack); len(cyc) > 0 {
				return cyc
			}
		}
	}
	*stack = (*stack)[:len(*stack)-1]
	state[u] = visited
	return nil
}

func healDanglingOutboundRefsInDoc(
	doc *sboption.Document,
	validTags map[string]bool,
	primaryGroup, directTag string,
	report *GroupsPreviewReport,
) {
	healRouteOutboundRefsInDoc(doc.Route, validTags, primaryGroup, directTag, report)
	healDNSServerDetoursInDoc(doc.DNS, validTags, primaryGroup, directTag, report)
}

func healRouteOutboundRefsInDoc(
	route *sboption.RouteOptions,
	validTags map[string]bool,
	primaryGroup, directTag string,
	report *GroupsPreviewReport,
) {
	if route == nil {
		return
	}
	if finalTag := strings.TrimSpace(route.Final); finalTag != "" && !validTags[finalTag] {
		route.Final = primaryGroup
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("route.final 原引用 [%s] 已不存在，已自动重绑定至 [%s]", finalTag, primaryGroup))
	}
	for i := range route.Rules {
		ob := strings.TrimSpace(route.Rules[i].Outbound)
		if ob == "" || validTags[ob] {
			continue
		}
		replacement := primaryGroup
		if ob == "direct" {
			replacement = directTag
		}
		route.Rules[i].Outbound = replacement
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("路由规则原出站 [%s] 已不存在，已自动重绑定至 [%s]", ob, replacement))
	}
}

func healDNSServerDetoursInDoc(
	dns *sboption.DNSOptions,
	validTags map[string]bool,
	primaryGroup, directTag string,
	report *GroupsPreviewReport,
) {
	if dns == nil {
		return
	}
	for i := range dns.Servers {
		detour := strings.TrimSpace(dns.Servers[i].Detour)
		if detour == "" || validTags[detour] {
			continue
		}
		serverTag := cmp.Or(strings.TrimSpace(dns.Servers[i].Tag), "dns")
		if primaryGroup != directTag {
			dns.Servers[i].Detour = primaryGroup
			report.Warnings = append(report.Warnings,
				fmt.Sprintf("DNS [%s] 原出口 [%s] 已不存在，已自动跟随默认兜底组 [%s]", serverTag, detour, primaryGroup))
			continue
		}
		dns.Servers[i].Detour = ""
		report.Warnings = append(report.Warnings,
			fmt.Sprintf("DNS [%s] 原出口 [%s] 已不存在，已自动回退为直连", serverTag, detour))
	}
}

func extractEffectiveRoutingConventionsFromDoc(doc *sboption.Document, directTag string) (defaultOutbound, dnsDetour string) {
	if doc.Route != nil {
		defaultOutbound = strings.TrimSpace(doc.Route.Final)
	}
	if doc.DNS != nil {
		for _, srv := range doc.DNS.Servers {
			if strings.TrimSpace(srv.Tag) == "dns_proxy" {
				dnsDetour = strings.TrimSpace(srv.Detour)
				break
			}
		}
	}
	if dnsDetour == "" {
		dnsDetour = directTag
	}
	return defaultOutbound, dnsDetour
}

func buildPreviewFromGroupOutbounds(
	groups []sboption.Outbound,
	leafSet map[string]LeafOutboundInfo,
	customized map[string]bool,
	fallbackInfo map[string]string,
	attachedRecord map[string][]string,
) []CompiledGroupPreview {
	parentRefs := make(map[string][]string)
	for _, g := range groups {
		for _, child := range g.Outbounds {
			if !slices.Contains(parentRefs[child], g.Tag) {
				parentRefs[child] = append(parentRefs[child], g.Tag)
			}
		}
	}

	out := make([]CompiledGroupPreview, 0, len(groups))
	for _, g := range groups {
		members := slices.Clone(g.Outbounds)
		leafCnt := countMatchingLeaves(members, leafSet)
		fbTag := ""
		if fallbackInfo != nil {
			fbTag = fallbackInfo[g.Tag]
		}
		attached := parentRefs[g.Tag]
		if len(attached) == 0 && attachedRecord != nil {
			attached = attachedRecord[g.Tag]
		}
		out = append(out, CompiledGroupPreview{
			Name:           g.Tag,
			Type:           strings.ToLower(strings.TrimSpace(g.Type)),
			Builtin:        slices.Contains(builtinGroupNames, g.Tag),
			Customized:     customized != nil && customized[g.Tag],
			FallbackUsed:   fbTag != "",
			FallbackTag:    fbTag,
			Default:        g.Default,
			AttachedTo:     attached,
			Members:        members,
			LeafMatchCount: leafCnt,
			TotalCount:     len(members),
		})
	}
	return out
}

func countMatchingLeaves(members []string, leafSet map[string]LeafOutboundInfo) int {
	cnt := 0
	for _, m := range members {
		if _, ok := leafSet[m]; ok {
			cnt++
		}
	}
	return cnt
}

func (g *ConfigGenerator) injectGroupsInDoc(doc *sboption.Document) (bool, error) {
	if g == nil || g.config == nil || doc == nil {
		return false, nil
	}
	gPath := g.config.GroupsPath()
	if gPath == "" {
		return false, nil
	}
	gc, exists, err := config.LoadGroupsFile(gPath)
	if err != nil || !exists || gc.IsEmpty() {
		return false, err
	}
	subOrigins := ResolveSubNodeOrigins(g.config, g.cacheDir)
	report, mutated, err := compileGroupsIntoDoc(doc, gc, subOrigins, extractSubNames(g.config))
	if err != nil {
		return false, err
	}
	if !g.silent && report != nil {
		log.Info("声明式策略组 (groups.yaml) 编译生效: mode=%s, 活跃策略组=%d 个", report.Mode, len(report.Groups))
		for _, w := range report.Warnings {
			log.Warn("⚠️ [groups.yaml] %s", w)
		}
	}
	return mutated, nil
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
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", err
	}
	if _, err := g.injectGroupsInDoc(doc); err != nil {
		return "", err
	}
	return doc.MarshalPretty()
}

// RecompileLiveConfigWithGroups 基于现有运行中的 config.json 底层节点池，离线单树重编译 groups.yaml、
// custom_rules 与客户端智能分流策略，无需重新联网拉取远程订阅即可实现预览与 SIGHUP 无损热应用。
func RecompileLiveConfigWithGroups(
	rawSBJSON string,
	cfg *config.Config,
	gc *config.GroupsConfig,
	cacheDir string,
) (string, *GroupsPreviewReport, error) {
	doc, err := sboption.ParseDocument([]byte(rawSBJSON))
	if err != nil {
		return "", nil, fmt.Errorf("解析当前 sing-box 配置失败: %w", err)
	}

	leafObs, specialObs, leafTags := extractNonGroupOutbounds(doc.Outbounds)
	skeletonGroups := buildStandardBuiltinSkeleton(leafTags)
	cleanOutbounds := make([]sboption.Outbound, 0, len(skeletonGroups)+len(leafObs)+len(specialObs))
	cleanOutbounds = append(cleanOutbounds, skeletonGroups...)
	cleanOutbounds = append(cleanOutbounds, leafObs...)
	cleanOutbounds = append(cleanOutbounds, specialObs...)
	doc.Outbounds = cleanOutbounds

	subOrigins := ResolveSubNodeOrigins(cfg, cacheDir)
	report, _, err := compileGroupsIntoDoc(doc, gc, subOrigins, extractSubNames(cfg))
	if err != nil {
		return "", nil, err
	}

	if cfg != nil {
		if len(cfg.CustomRules.Outbounds) > 0 {
			if err := applyCustomOutboundRulesInDoc(doc, cfg.CustomRules.Outbounds); err != nil {
				return "", nil, err
			}
		}
		applyTrafficRoutingToDoc(doc, cfg.TrafficRouting, cfg.CustomRules, "")
	}

	out, err := doc.MarshalPretty()
	if err != nil {
		return "", nil, err
	}
	return out, report, nil
}

func extractNonGroupOutbounds(outbounds []sboption.Outbound) (leafObs, specialObs []sboption.Outbound, leafTags []string) {
	for _, ob := range outbounds {
		tag := strings.TrimSpace(ob.Tag)
		typ := strings.ToLower(strings.TrimSpace(ob.Type))
		if tag == "" {
			continue
		}
		switch typ {
		case "selector", "urltest":
			continue
		case "direct", "block", "dns":
			specialObs = append(specialObs, ob)
		default:
			leafObs = append(leafObs, ob)
			leafTags = append(leafTags, tag)
		}
	}
	return leafObs, specialObs, leafTags
}
