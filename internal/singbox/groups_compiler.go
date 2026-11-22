// 文件职责：实现客户端策略组（groups.yaml）强类型编译主流水线，完成订阅来源解析、内置骨架组装与分组出站注入。
package singbox

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"

	"github.com/sixban6/singgen/pkg/singgen"
)

const (
	// DefaultURLTestURL 是内置自动测速组 (#Auto) 与缺省 urltest 组的默认测速地址。
	DefaultURLTestURL       = "https://captive.apple.com/hotspot-detect.html"
	defaultURLTestURL       = DefaultURLTestURL
	defaultURLTestInterval  = "3m"
	defaultURLTestTolerance = 80
	builtinExcludeKeywords  = `网站|地址|剩余|过期|时间|有效|官网|流量|到期`
	builtinAutoExcludeRegex = `网站|地址|剩余|过期|时间|有效|官网|流量|到期|[2-9]倍|[0-9]{2,}倍|倍率|[2-9][xX]|[xX][2-9]`
)

var (
	builtinVPSRe    = regexp.MustCompile(`(?i)sec_`)
	builtinAutoExRe = regexp.MustCompile(`(?i)(` + builtinAutoExcludeRegex + `)`)
	builtinNodesEx  = regexp.MustCompile(`(?i)(` + builtinExcludeKeywords + `)`)
)

// LeafOutboundInfo 描述一个底层真实代理出站节点的元信息（不含任何 IP/密钥凭据）。
type LeafOutboundInfo struct {
	Tag  string   `json:"tag"`
	Type string   `json:"type"`
	Subs []string `json:"subs,omitempty"`
}

// CompiledGroupPreview 描述单个策略组编译后的命中预览详情。
type CompiledGroupPreview struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	Builtin        bool     `json:"builtin"`
	Customized     bool     `json:"customized"`
	FallbackUsed   bool     `json:"fallbackUsed,omitempty"`
	FallbackTag    string   `json:"fallbackTag,omitempty"`
	Default        string   `json:"default,omitempty"`
	AttachedTo     []string `json:"attachedTo,omitempty"`
	Failover       bool     `json:"failover,omitempty"`
	Members        []string `json:"members"`
	LeafMatchCount int      `json:"leafMatchCount"`
	TotalCount     int      `json:"totalCount"`
}

// GroupsPreviewReport 汇总声明式分组编译与干跑预览结果。
type GroupsPreviewReport struct {
	Mode            string                 `json:"mode"`
	DefaultOutbound string                 `json:"defaultOutbound,omitempty"`
	DNSDetour       string                 `json:"dnsDetour,omitempty"`
	TotalLeafNodes  int                    `json:"totalLeafNodes"`
	LeafNodes       []LeafOutboundInfo     `json:"leafNodes"`
	SubNames        []string               `json:"subNames,omitempty"`
	Groups          []CompiledGroupPreview `json:"groups"`
	Warnings        []string               `json:"warnings,omitempty"`
}

var builtinGroupNames = []string{"Proxy", "AI", "#VPS", "#Auto", "#Nodes"}

func isNonLeafOutboundType(obType string) bool {
	switch strings.ToLower(strings.TrimSpace(obType)) {
	case "selector", "urltest", "direct", "block", "dns":
		return true
	default:
		return false
	}
}

// ResolveSubNodeOrigins 离线解析各命名订阅源对应的节点 Tag 归属映射 (nodeTag -> []subName)。
func ResolveSubNodeOrigins(cfg *config.Config, cacheDir string) map[string][]string {
	if cfg == nil || len(cfg.Subs) == 0 {
		return nil
	}
	if len(cfg.Subs) == 1 {
		subName := cmp.Or(strings.TrimSpace(cfg.Subs[0].Name), "main")
		return map[string][]string{"*": {subName}}
	}
	dir := cmp.Or(strings.TrimSpace(cacheDir), singgen.DefaultCacheDir())
	if dir == "" {
		return nil
	}

	origins := make(map[string][]string)
	ctx := context.Background()
	for _, sub := range cfg.Subs {
		subName := strings.TrimSpace(sub.Name)
		subURL := strings.TrimSpace(sub.URL)
		if subName == "" || subURL == "" {
			continue
		}
		sum := sha256.Sum256([]byte(subURL))
		cacheFile := filepath.Join(dir, hex.EncodeToString(sum[:16])+".sub")
		if _, err := os.Stat(cacheFile); err != nil {
			continue
		}
		for _, tag := range collectSubNodeTagsFromCache(ctx, sub, cacheFile) {
			if !slices.Contains(origins[tag], subName) {
				origins[tag] = append(origins[tag], subName)
			}
		}
	}
	return origins
}

func collectSubNodeTagsFromCache(ctx context.Context, sub config.Subscription, cacheFile string) []string {
	opts := []singgen.Option{singgen.WithEmojiRemoval(sub.RemoveEmoji)}
	if hasSubNodeRules(sub) {
		if tags, ok := collectRuleFilteredSubTags(ctx, sub, cacheFile, opts); ok {
			return tags
		}
	}
	nodes, err := singgen.ParseNodes(ctx, cacheFile, opts...)
	if err != nil {
		return nil
	}
	tags := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if tag := strings.TrimSpace(n.Tag); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func collectRuleFilteredSubTags(ctx context.Context, sub config.Subscription, cacheFile string, opts []singgen.Option) ([]string, bool) {
	fp, err := newRuleFilteringParser(sub, nil)
	if err != nil {
		return nil, false
	}
	p := singgen.NewPipeline(
		singgen.WithPipelineOptions(opts...),
		singgen.WithCustomParser(fp),
	)
	res, err := p.Execute(ctx, cacheFile)
	if err != nil || res == nil {
		return nil, false
	}
	var tags []string
	for _, ob := range res.Outbounds {
		if ob.Tag != "" && !isNonLeafOutboundType(ob.Type) {
			tags = append(tags, ob.Tag)
		}
	}
	return tags, true
}

func extractSubNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Subs))
	for i, s := range cfg.Subs {
		n := strings.TrimSpace(s.Name)
		if n == "" && len(cfg.Subs) == 1 && i == 0 {
			n = "main"
		}
		if n != "" && !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

func nodeBelongsToSubs(tag string, subOrigins map[string][]string) []string {
	if len(subOrigins) == 0 {
		return nil
	}
	if wildcard, ok := subOrigins["*"]; ok {
		return slices.Clone(wildcard)
	}
	if list, ok := subOrigins[tag]; ok {
		return slices.Clone(list)
	}
	if idx := strings.LastIndexByte(tag, '_'); idx > 0 {
		if list, ok := subOrigins[tag[:idx]]; ok {
			return slices.Clone(list)
		}
	}
	return nil
}

func partitionBuiltinLeafPools(leafTags []string) (vpsMembers, autoMembers, nodeMembers []string) {
	for _, tag := range leafTags {
		if builtinVPSRe.MatchString(tag) {
			vpsMembers = append(vpsMembers, tag)
		}
		if !builtinAutoExRe.MatchString(tag) {
			autoMembers = append(autoMembers, tag)
		}
		if !builtinNodesEx.MatchString(tag) {
			nodeMembers = append(nodeMembers, tag)
		}
	}
	if len(autoMembers) == 0 && len(leafTags) > 0 {
		autoMembers = slices.Clone(leafTags)
	}
	if len(nodeMembers) == 0 && len(leafTags) > 0 {
		nodeMembers = slices.Clone(leafTags)
	}
	return vpsMembers, autoMembers, nodeMembers
}

// buildStandardBuiltinSkeleton 根据底层真实节点列表重建标准 SingCtl 内置 5 组骨架。
func buildStandardBuiltinSkeleton(leafTags []string) []sboption.Outbound {
	vpsMembers, autoMembers, nodeMembers := partitionBuiltinLeafPools(leafTags)
	var proxyCandidates, aiCandidates []string
	var poolGroups []sboption.Outbound

	if len(vpsMembers) > 0 {
		proxyCandidates = append(proxyCandidates, "#VPS")
		aiCandidates = append(aiCandidates, "#VPS")
		poolGroups = append(poolGroups, sboption.Outbound{Tag: "#VPS", Type: "selector", Outbounds: vpsMembers})
	}
	if len(autoMembers) > 0 {
		proxyCandidates = append(proxyCandidates, "#Auto")
		poolGroups = append(poolGroups, sboption.Outbound{
			Tag:                       "#Auto",
			Type:                      "urltest",
			Outbounds:                 autoMembers,
			URL:                       defaultURLTestURL,
			Interval:                  defaultURLTestInterval,
			Tolerance:                 defaultURLTestTolerance,
			InterruptExistConnections: new(false),
		})
	}
	if len(nodeMembers) > 0 {
		proxyCandidates = append(proxyCandidates, "#Nodes")
		aiCandidates = append(aiCandidates, "#Nodes")
		poolGroups = append(poolGroups, sboption.Outbound{Tag: "#Nodes", Type: "selector", Outbounds: nodeMembers})
	}
	if slices.Contains(proxyCandidates, "#Auto") {
		aiCandidates = append(aiCandidates, "#Auto")
	}
	proxyCandidates = append(proxyCandidates, "#DC")
	if len(aiCandidates) == 0 {
		aiCandidates = append(aiCandidates, "#DC")
	}

	out := []sboption.Outbound{
		{Tag: "Proxy", Type: "selector", Outbounds: proxyCandidates, InterruptExistConnections: new(true)},
		{Tag: "AI", Type: "selector", Outbounds: aiCandidates, InterruptExistConnections: new(true)},
	}
	return append(out, poolGroups...)
}

type classifiedOutbounds struct {
	existingGroups   []sboption.Outbound
	leafOutbounds    []sboption.Outbound
	specialOutbounds []sboption.Outbound
	leafInfos        []LeafOutboundInfo
	leafSet          map[string]LeafOutboundInfo
	specialTags      map[string]bool
	endpointTags     map[string]bool
	directFallback   string
}

func classifyDocOutbounds(doc *sboption.Document, subOrigins map[string][]string) classifiedOutbounds {
	c := classifiedOutbounds{
		leafSet:        make(map[string]LeafOutboundInfo),
		specialTags:    make(map[string]bool),
		endpointTags:   make(map[string]bool),
		directFallback: "#DC",
	}
	for _, ob := range doc.Outbounds {
		tag := strings.TrimSpace(ob.Tag)
		typ := strings.ToLower(strings.TrimSpace(ob.Type))
		if tag == "" {
			continue
		}
		switch typ {
		case "selector", "urltest":
			c.existingGroups = append(c.existingGroups, ob.Clone())
		case "direct", "block", "dns":
			c.specialOutbounds = append(c.specialOutbounds, ob.Clone())
			c.specialTags[tag] = true
		default:
			c.leafOutbounds = append(c.leafOutbounds, ob)
			normProto, _ := config.NormalizeOutboundProtocol(typ)
			info := LeafOutboundInfo{
				Tag:  tag,
				Type: cmp.Or(normProto, typ),
				Subs: nodeBelongsToSubs(tag, subOrigins),
			}
			c.leafInfos = append(c.leafInfos, info)
			c.leafSet[tag] = info
		}
	}
	ensureDirectFallbackOutbound(&c)
	for _, ep := range doc.Endpoints {
		if t := strings.TrimSpace(ep.Tag); t != "" {
			c.endpointTags[t] = true
		}
	}
	return c
}

func ensureDirectFallbackOutbound(c *classifiedOutbounds) {
	if c.specialTags["#DC"] {
		return
	}
	for _, sp := range c.specialOutbounds {
		if strings.EqualFold(sp.Type, "direct") {
			c.directFallback = sp.Tag
			return
		}
	}
	c.specialOutbounds = append(c.specialOutbounds, sboption.Outbound{Tag: "#DC", Type: "direct"})
	c.specialTags["#DC"] = true
}

func leafMatchesGroupSpec(leaf LeafOutboundInfo, spec config.GroupSpec, matchRe, excludeRe *regexp.Regexp) bool {
	if len(spec.FromSub) > 0 && !leafMatchesFromSub(leaf.Subs, spec.FromSub) {
		return false
	}
	if len(spec.Protocol) > 0 && !slices.ContainsFunc(spec.Protocol, func(want string) bool { return strings.EqualFold(want, leaf.Type) }) {
		return false
	}
	if excludeRe != nil && excludeRe.MatchString(leaf.Tag) {
		return false
	}
	if matchRe != nil && !matchRe.MatchString(leaf.Tag) {
		return false
	}
	return true
}

func leafMatchesFromSub(gotSubs, wantSubs []string) bool {
	for _, want := range wantSubs {
		trimmed := strings.TrimSpace(want)
		if slices.ContainsFunc(gotSubs, func(got string) bool { return strings.EqualFold(trimmed, got) }) {
			return true
		}
	}
	return false
}

func collectGroupSpecMembers(
	spec config.GroupSpec,
	prevMembers []string,
	leafInfos []LeafOutboundInfo,
	matchRe, excludeRe *regexp.Regexp,
	validTargetExists func(string) bool,
	report *GroupsPreviewReport,
) []string {
	name := spec.EffectiveName()
	var members []string
	addMember := func(m string) {
		m = strings.TrimSpace(m)
		if m == "" || m == name || slices.Contains(members, m) {
			return
		}
		members = append(members, m)
	}

	usedAllPlaceholder := false
	for _, u := range spec.Use {
		if u == "{all}" {
			usedAllPlaceholder = true
			continue
		}
		if validTargetExists(u) {
			addMember(u)
			continue
		}
		report.Warnings = append(report.Warnings, fmt.Sprintf("分组 [%s] 引用的目标 %q 当前不存在，已自动跳过", name, u))
	}

	hasFilterCriteria := len(spec.EffectiveMatch()) > 0 || len(spec.Exclude) > 0 || len(spec.FromSub) > 0 || len(spec.Protocol) > 0
	if !hasFilterCriteria && !usedAllPlaceholder && len(spec.Use) > 0 {
		return members
	}
	if !hasFilterCriteria && !usedAllPlaceholder && len(prevMembers) > 0 {
		for _, pm := range prevMembers {
			if validTargetExists(pm) {
				addMember(pm)
			}
		}
		return members
	}
	for _, leaf := range leafInfos {
		if leafMatchesGroupSpec(leaf, spec, matchRe, excludeRe) {
			addMember(leaf.Tag)
		}
	}
	return members
}

func resolveEmptyGroupFallback(
	name, rawFallback, directFallback string,
	validTargetExists func(string) bool,
	fallbackInfo map[string]string,
	report *GroupsPreviewReport,
) string {
	chosen := directFallback
	for _, cand := range []string{strings.TrimSpace(rawFallback), "#Auto", "#VPS", directFallback} {
		if cand != "" && cand != name && validTargetExists(cand) {
			chosen = cand
			break
		}
	}
	fallbackInfo[name] = chosen
	report.Warnings = append(report.Warnings, fmt.Sprintf("分组 [%s] 当前匹配到 0 个节点，已自动启用防断网兜底出站 [%s]", name, chosen))
	return chosen
}

func applyGroupOutboundParams(out *sboption.Outbound, spec config.GroupSpec, prevGroup sboption.Outbound, report *GroupsPreviewReport) {
	if out.Type == config.GroupTypeURLTest {
		out.URL = cmp.Or(strings.TrimSpace(spec.URL), prevGroup.URL, defaultURLTestURL)
		out.Interval = cmp.Or(strings.TrimSpace(spec.Interval), prevGroup.Interval, defaultURLTestInterval)
		out.Tolerance = cmp.Or(spec.Tolerance, prevGroup.Tolerance, defaultURLTestTolerance)
		out.InterruptExistConnections = resolveInterruptFlag(spec.InterruptExistConnections, prevGroup.InterruptExistConnections, true)
		return
	}

	out.InterruptExistConnections = resolveInterruptFlag(spec.InterruptExistConnections, prevGroup.InterruptExistConnections, false)
	wantDefault := cmp.Or(strings.TrimSpace(spec.Default), prevGroup.Default)
	if wantDefault != "" && slices.Contains(out.Outbounds, wantDefault) {
		out.Default = wantDefault
		return
	}
	if strings.TrimSpace(spec.Default) != "" {
		report.Warnings = append(report.Warnings, fmt.Sprintf("分组 [%s] 指定的 default=%q 不在候选列表中，已自动忽略", out.Tag, spec.Default))
	}
}

func resolveInterruptFlag(specFlag, prevFlag *bool, defaultFalse bool) *bool {
	if specFlag != nil {
		return new(*specFlag)
	}
	if prevFlag != nil {
		return new(*prevFlag)
	}
	if defaultFalse {
		return new(false)
	}
	return nil
}

func compileSingleGroupSpec(
	spec config.GroupSpec,
	prevGroup sboption.Outbound,
	leafInfos []LeafOutboundInfo,
	directFallback string,
	validTargetExists func(string) bool,
	fallbackInfo map[string]string,
	report *GroupsPreviewReport,
) (sboption.Outbound, error) {
	matchRe, err := config.CompileGroupMatcher(spec.EffectiveMatch())
	if err != nil {
		return sboption.Outbound{}, err
	}
	excludeRe, err := config.CompileGroupMatcher(spec.Exclude)
	if err != nil {
		return sboption.Outbound{}, err
	}

	name := spec.EffectiveName()
	members := collectGroupSpecMembers(spec, prevGroup.Outbounds, leafInfos, matchRe, excludeRe, validTargetExists, report)
	if len(members) == 0 {
		members = []string{resolveEmptyGroupFallback(name, spec.Fallback, directFallback, validTargetExists, fallbackInfo, report)}
	}

	out := sboption.Outbound{
		Tag:       name,
		Type:      spec.EffectiveType(),
		Outbounds: members,
	}
	applyGroupOutboundParams(&out, spec, prevGroup, report)
	return out, nil
}

// CompileGroupsIntoConfigJSON 将 groups.yaml 编译注入到 sing-box 配置 JSON 中，并返回预览详情报告。
func CompileGroupsIntoConfigJSON(
	rawJSON string,
	gc *config.GroupsConfig,
	subOrigins map[string][]string,
	subNames []string,
) (string, *GroupsPreviewReport, error) {
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", nil, fmt.Errorf("解析 sing-box JSON 失败: %w", err)
	}
	report, mutated, err := compileGroupsIntoDoc(doc, gc, subOrigins, subNames)
	if err != nil {
		return "", nil, err
	}
	if !mutated {
		return rawJSON, report, nil
	}
	encoded, err := doc.MarshalPretty()
	if err != nil {
		return "", nil, fmt.Errorf("序列化编译后的 sing-box 配置失败: %w", err)
	}
	return encoded, report, nil
}

func healEmptyGroupsDoc(doc *sboption.Document, cls classifiedOutbounds, report *GroupsPreviewReport) bool {
	validInit := buildValidTagSet(cls.existingGroups, cls.leafOutbounds, cls.specialTags, cls.endpointTags)
	primaryInit := resolvePrimaryGroupTag(validInit, cls.existingGroups, cls.directFallback)
	prevWarns := len(report.Warnings)
	healDanglingOutboundRefsInDoc(doc, validInit, primaryInit, cls.directFallback, report)
	report.DefaultOutbound, report.DNSDetour = extractEffectiveRoutingConventionsFromDoc(doc, cls.directFallback)
	report.Groups = buildPreviewFromGroupOutbounds(cls.existingGroups, cls.leafSet, nil, nil, nil)
	return len(report.Warnings) > prevWarns
}

func seedWorkingGroups(
	mode string,
	existingGroups []sboption.Outbound,
	specs []config.GroupSpec,
) (
	workingGroups []sboption.Outbound,
	groupIndexByName map[string]int,
	userGroupSet map[string]config.GroupSpec,
	newUserGroupOrder []string,
) {
	groupIndexByName = make(map[string]int)
	if mode == config.GroupsModeMerge {
		for _, eg := range existingGroups {
			groupIndexByName[eg.Tag] = len(workingGroups)
			workingGroups = append(workingGroups, eg.Clone())
		}
	}

	userGroupSet = make(map[string]config.GroupSpec, len(specs))
	newUserGroupOrder = make([]string, 0, len(specs))
	for _, spec := range specs {
		name := spec.EffectiveName()
		userGroupSet[name] = spec
		if _, exists := groupIndexByName[name]; exists {
			continue
		}
		groupIndexByName[name] = len(workingGroups)
		workingGroups = append(workingGroups, sboption.Outbound{Tag: name, Type: spec.EffectiveType()})
		newUserGroupOrder = append(newUserGroupOrder, name)
	}
	return workingGroups, groupIndexByName, userGroupSet, newUserGroupOrder
}

func finalizeCompiledGroupsInDoc(
	doc *sboption.Document,
	cls classifiedOutbounds,
	workingGroups []sboption.Outbound,
	userGroupSet map[string]config.GroupSpec,
	customizedSet map[string]bool,
	fallbackInfo map[string]string,
	attachedRecord map[string][]string,
	report *GroupsPreviewReport,
) {
	finalOutbounds := make([]sboption.Outbound, 0, len(workingGroups)+len(cls.leafOutbounds)+len(cls.specialOutbounds))
	finalOutbounds = append(finalOutbounds, workingGroups...)
	finalOutbounds = append(finalOutbounds, cls.leafOutbounds...)
	finalOutbounds = append(finalOutbounds, cls.specialOutbounds...)
	doc.Outbounds = finalOutbounds

	validAllTags := buildValidTagSet(workingGroups, cls.leafOutbounds, cls.specialTags, cls.endpointTags)
	primaryGroup := resolvePrimaryGroupTag(validAllTags, workingGroups, cls.directFallback)
	healDanglingOutboundRefsInDoc(doc, validAllTags, primaryGroup, cls.directFallback, report)
	report.DefaultOutbound, report.DNSDetour = extractEffectiveRoutingConventionsFromDoc(doc, cls.directFallback)

	report.Groups = buildPreviewFromGroupOutbounds(workingGroups, cls.leafSet, customizedSet, fallbackInfo, attachedRecord)
	for i := range report.Groups {
		spec, ok := userGroupSet[report.Groups[i].Name]
		if ok && spec.Failover && report.Groups[i].Type == config.GroupTypeSelector {
			report.Groups[i].Failover = true
		}
	}
}

func compileGroupsIntoDoc(
	doc *sboption.Document,
	gc *config.GroupsConfig,
	subOrigins map[string][]string,
	subNames []string,
) (*GroupsPreviewReport, bool, error) {
	cls := classifyDocOutbounds(doc, subOrigins)
	report := &GroupsPreviewReport{
		Mode:           gc.EffectiveMode(),
		TotalLeafNodes: len(cls.leafInfos),
		LeafNodes:      cls.leafInfos,
		SubNames:       subNames,
	}
	if gc == nil || gc.IsEmpty() {
		return report, healEmptyGroupsDoc(doc, cls, report), nil
	}

	mode := gc.EffectiveMode()
	workingGroups, groupIndexByName, userGroupSet, newUserGroupOrder := seedWorkingGroups(mode, cls.existingGroups, gc.Groups)
	validTargetExists := func(tag string) bool {
		_, isGrp := groupIndexByName[tag]
		_, isLeaf := cls.leafSet[tag]
		return isGrp || isLeaf || cls.specialTags[tag] || cls.endpointTags[tag]
	}

	customizedSet := make(map[string]bool, len(gc.Groups))
	fallbackInfo := make(map[string]string)
	for _, spec := range gc.Groups {
		name := spec.EffectiveName()
		customizedSet[name] = true
		idx := groupIndexByName[name]
		compiledGrp, err := compileSingleGroupSpec(spec, workingGroups[idx], cls.leafInfos, cls.directFallback, validTargetExists, fallbackInfo, report)
		if err != nil {
			return nil, false, err
		}
		workingGroups[idx] = compiledGrp
	}

	attachedRecord := make(map[string][]string)
	if mode == config.GroupsModeMerge {
		attachUserGroupsToParents(workingGroups, groupIndexByName, newUserGroupOrder, userGroupSet, cls.directFallback, attachedRecord)
		workingGroups = orderCompiledGroupOutbounds(workingGroups)
	}
	if cyclePath := detectOutboundCycle(workingGroups); len(cyclePath) > 0 {
		return nil, false, fmt.Errorf("策略组引用存在循环依赖: %s", strings.Join(cyclePath, " -> "))
	}

	finalizeCompiledGroupsInDoc(doc, cls, workingGroups, userGroupSet, customizedSet, fallbackInfo, attachedRecord, report)
	return report, true, nil
}
