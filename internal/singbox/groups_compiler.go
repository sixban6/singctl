package singbox

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"singctl/internal/config"
	log "singctl/internal/logger"

	"github.com/sixban6/singgen/pkg/singgen"
)

const (
	defaultURLTestURL       = "https://captive.apple.com/hotspot-detect.html"
	defaultURLTestInterval  = "3m"
	defaultURLTestTolerance = 80
	builtinExcludeKeywords  = `网站|地址|剩余|过期|时间|有效|官网|流量|到期`
	builtinAutoExcludeRegex = `网站|地址|剩余|过期|时间|有效|官网|流量|到期|[2-9]倍|[0-9]{2,}倍|倍率|[2-9][xX]|[xX][2-9]`
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
// 单订阅场景无需解析缓存，直接将该订阅名（默认 "main"）赋予全部底层节点；
// 多订阅场景优先读取 singgen 本地订阅缓存文件，零网络阻塞。
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
		opts := []singgen.Option{
			singgen.WithEmojiRemoval(sub.RemoveEmoji),
		}
		if hasSubNodeRules(sub) {
			if fp, err := newRuleFilteringParser(sub, nil); err == nil {
				p := singgen.NewPipeline(
					singgen.WithPipelineOptions(opts...),
					singgen.WithCustomParser(fp),
				)
				if res, pErr := p.Execute(ctx, cacheFile); pErr == nil && res != nil {
					for _, ob := range res.Outbounds {
						if ob.Tag != "" && !isNonLeafOutboundType(ob.Type) {
							if !slices.Contains(origins[ob.Tag], subName) {
								origins[ob.Tag] = append(origins[ob.Tag], subName)
							}
						}
					}
					continue
				}
			}
		}
		nodes, err := singgen.ParseNodes(ctx, cacheFile, opts...)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			tag := strings.TrimSpace(n.Tag)
			if tag != "" && !slices.Contains(origins[tag], subName) {
				origins[tag] = append(origins[tag], subName)
			}
		}
	}
	return origins
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
	// 兼容 DeduplicateOutbounds 重命名后的后缀节点 (如 NodeA_1 -> NodeA)
	if idx := strings.LastIndexByte(tag, '_'); idx > 0 {
		base := tag[:idx]
		if list, ok := subOrigins[base]; ok {
			return slices.Clone(list)
		}
	}
	return nil
}

// buildStandardBuiltinSkeleton 根据底层真实节点列表重建标准 SingCtl 内置 5 组骨架。
func buildStandardBuiltinSkeleton(leafTags []string) []map[string]any {
	vpsRe := regexp.MustCompile(`(?i)sec_`)
	autoExRe := regexp.MustCompile(`(?i)(` + builtinAutoExcludeRegex + `)`)
	nodesExRe := regexp.MustCompile(`(?i)(` + builtinExcludeKeywords + `)`)

	var vpsMembers, autoMembers, nodeMembers []string
	for _, tag := range leafTags {
		if vpsRe.MatchString(tag) {
			vpsMembers = append(vpsMembers, tag)
		}
		if !autoExRe.MatchString(tag) {
			autoMembers = append(autoMembers, tag)
		}
		if !nodesExRe.MatchString(tag) {
			nodeMembers = append(nodeMembers, tag)
		}
	}
	if len(autoMembers) == 0 && len(leafTags) > 0 {
		autoMembers = slices.Clone(leafTags)
	}
	if len(nodeMembers) == 0 && len(leafTags) > 0 {
		nodeMembers = slices.Clone(leafTags)
	}

	proxyCandidates := []string{}
	aiCandidates := []string{}
	var poolGroups []map[string]any

	if len(vpsMembers) > 0 {
		proxyCandidates = append(proxyCandidates, "#VPS")
		aiCandidates = append(aiCandidates, "#VPS")
		poolGroups = append(poolGroups, map[string]any{
			"tag":       "#VPS",
			"type":      "selector",
			"outbounds": stringsToAnySlice(vpsMembers),
		})
	}
	if len(autoMembers) > 0 {
		proxyCandidates = append(proxyCandidates, "#Auto")
		poolGroups = append(poolGroups, map[string]any{
			"tag":                         "#Auto",
			"type":                        "urltest",
			"outbounds":                   stringsToAnySlice(autoMembers),
			"url":                         defaultURLTestURL,
			"interval":                    defaultURLTestInterval,
			"tolerance":                   defaultURLTestTolerance,
			"interrupt_exist_connections": false,
		})
	}
	if len(nodeMembers) > 0 {
		proxyCandidates = append(proxyCandidates, "#Nodes")
		aiCandidates = append(aiCandidates, "#Nodes")
		poolGroups = append(poolGroups, map[string]any{
			"tag":       "#Nodes",
			"type":      "selector",
			"outbounds": stringsToAnySlice(nodeMembers),
		})
	}
	if slices.Contains(proxyCandidates, "#Auto") {
		aiCandidates = append(aiCandidates, "#Auto")
	}
	proxyCandidates = append(proxyCandidates, "#DC")
	if len(aiCandidates) == 0 {
		aiCandidates = append(aiCandidates, "#DC")
	}

	out := []map[string]any{
		{
			"tag":                         "Proxy",
			"type":                        "selector",
			"outbounds":                   stringsToAnySlice(proxyCandidates),
			"interrupt_exist_connections": true,
		},
		{
			"tag":                         "AI",
			"type":                        "selector",
			"outbounds":                   stringsToAnySlice(aiCandidates),
			"interrupt_exist_connections": true,
		},
	}
	out = append(out, poolGroups...)
	return out
}

func stringsToAnySlice(items []string) []any {
	out := make([]any, len(items))
	for i, s := range items {
		out[i] = s
	}
	return out
}

func anySliceToStrings(raw any) []string {
	switch v := raw.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

// CompileGroupsIntoConfigJSON 将 groups.yaml 编译注入到 sing-box 配置 JSON 中，并返回预览详情报告。
func CompileGroupsIntoConfigJSON(
	rawJSON string,
	gc *config.GroupsConfig,
	subOrigins map[string][]string,
	subNames []string,
) (string, *GroupsPreviewReport, error) {
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", nil, fmt.Errorf("解析 sing-box JSON 失败: %w", err)
	}

	rawOutbounds, _ := root["outbounds"].([]any)
	var existingGroups []map[string]any
	var leafMaps []map[string]any
	var specialOutbounds []map[string]any
	var leafInfos []LeafOutboundInfo
	var leafTags []string
	leafSet := make(map[string]LeafOutboundInfo)
	specialTags := make(map[string]bool)

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
			existingGroups = append(existingGroups, maps.Clone(om))
		case "direct", "block", "dns":
			specialOutbounds = append(specialOutbounds, maps.Clone(om))
			specialTags[tag] = true
		default:
			leafMaps = append(leafMaps, om)
			normProto, _ := config.NormalizeOutboundProtocol(typ)
			if normProto == "" {
				normProto = typ
			}
			subs := nodeBelongsToSubs(tag, subOrigins)
			info := LeafOutboundInfo{
				Tag:  tag,
				Type: normProto,
				Subs: subs,
			}
			leafInfos = append(leafInfos, info)
			leafTags = append(leafTags, tag)
			leafSet[tag] = info
		}
	}

	// 确保始终存在直连兜底出站 #DC
	directFallback := "#DC"
	if !specialTags["#DC"] {
		foundDirect := ""
		for _, sp := range specialOutbounds {
			if strings.EqualFold(stringField(sp, "type"), "direct") {
				foundDirect = stringField(sp, "tag")
				break
			}
		}
		if foundDirect != "" {
			directFallback = foundDirect
		} else {
			dcMap := map[string]any{"tag": "#DC", "type": "direct"}
			specialOutbounds = append(specialOutbounds, dcMap)
			specialTags["#DC"] = true
		}
	}

	// 收集 endpoint tags (例如 Tailscale ts-node)，防止误伤合法 endpoint 引用
	endpointTags := make(map[string]bool)
	if eps, ok := root["endpoints"].([]any); ok {
		for _, ep := range eps {
			if em, ok := ep.(map[string]any); ok {
				if t := strings.TrimSpace(stringField(em, "tag")); t != "" {
					endpointTags[t] = true
				}
			}
		}
	}

	report := &GroupsPreviewReport{
		Mode:           gc.EffectiveMode(),
		TotalLeafNodes: len(leafInfos),
		LeafNodes:      leafInfos,
		SubNames:       subNames,
	}

	// 当 groups.yaml 未配置任何规则 (空 merge 模式) 时，修复可能悬空的引用后返回原骨架及状态预览
	if gc == nil || gc.IsEmpty() {
		validInit := make(map[string]bool)
		for _, eg := range existingGroups {
			validInit[stringField(eg, "tag")] = true
		}
		for _, lm := range leafMaps {
			validInit[stringField(lm, "tag")] = true
		}
		for st := range specialTags {
			validInit[st] = true
		}
		for ep := range endpointTags {
			validInit[ep] = true
		}
		primaryInit := directFallback
		if validInit["Proxy"] {
			primaryInit = "Proxy"
		} else if len(existingGroups) > 0 {
			primaryInit = stringField(existingGroups[0], "tag")
		}
		prevWarns := len(report.Warnings)
		healDanglingOutboundRefs(root, validInit, primaryInit, directFallback, report)
		report.DefaultOutbound, report.DNSDetour = extractEffectiveRoutingConventions(root, directFallback)
		report.Groups = buildPreviewFromGroupMaps(existingGroups, leafSet, nil, nil, nil)
		if len(report.Warnings) > prevWarns {
			encoded, err := json.MarshalIndent(root, "", "  ")
			if err != nil {
				return "", nil, err
			}
			return string(encoded), report, nil
		}
		return rawJSON, report, nil
	}

	mode := gc.EffectiveMode()
	var workingGroups []map[string]any
	groupIndexByName := make(map[string]int)

	if mode == config.GroupsModeMerge {
		for _, eg := range existingGroups {
			tag := stringField(eg, "tag")
			groupIndexByName[tag] = len(workingGroups)
			workingGroups = append(workingGroups, maps.Clone(eg))
		}
	}

	// 第一遍：预注册所有用户声明的分组占位，支持任意顺序的前向引用 (如 Streaming 在 #JP 之前定义)
	userGroupSet := make(map[string]config.GroupSpec, len(gc.Groups))
	newUserGroupOrder := make([]string, 0, len(gc.Groups))
	for _, spec := range gc.Groups {
		name := spec.EffectiveName()
		userGroupSet[name] = spec
		if _, exists := groupIndexByName[name]; !exists {
			groupIndexByName[name] = len(workingGroups)
			workingGroups = append(workingGroups, map[string]any{
				"tag":  name,
				"type": spec.EffectiveType(),
			})
			newUserGroupOrder = append(newUserGroupOrder, name)
		}
	}

	validTargetExists := func(tag string) bool {
		if _, ok := groupIndexByName[tag]; ok {
			return true
		}
		if _, ok := leafSet[tag]; ok {
			return true
		}
		return specialTags[tag] || endpointTags[tag]
	}

	customizedSet := make(map[string]bool, len(gc.Groups))
	fallbackInfo := make(map[string]string)
	attachedRecord := make(map[string][]string)

	// 第二遍：逐个求值用户定义的分组候选成员与属性
	for _, spec := range gc.Groups {
		name := spec.EffectiveName()
		typ := spec.EffectiveType()
		customizedSet[name] = true
		gMap := workingGroups[groupIndexByName[name]]
		prevMembers := anySliceToStrings(gMap["outbounds"])

		matchRe, err := config.CompileGroupMatcher(spec.EffectiveMatch())
		if err != nil {
			return "", nil, err
		}
		excludeRe, err := config.CompileGroupMatcher(spec.Exclude)
		if err != nil {
			return "", nil, err
		}

		hasFilterCriteria := len(spec.EffectiveMatch()) > 0 ||
			len(spec.Exclude) > 0 ||
			len(spec.FromSub) > 0 ||
			len(spec.Protocol) > 0

		var members []string
		addMember := func(m string) {
			if m == "" || m == name || slices.Contains(members, m) {
				return
			}
			members = append(members, m)
		}

		// 1) 显式 use 引用（支持 "{all}" 展开或引用子分组/节点）
		usedAllPlaceholder := false
		for _, u := range spec.Use {
			if u == "{all}" {
				usedAllPlaceholder = true
				continue
			}
			if validTargetExists(u) {
				addMember(u)
			} else {
				warn := fmt.Sprintf("分组 [%s] 引用的目标 %q 当前不存在，已自动跳过", name, u)
				report.Warnings = append(report.Warnings, warn)
			}
		}

		// 2) 节点池自动匹配：当配置了过滤条件、使用了 {all}、或未写 use 时，从底层节点池筛选
		if hasFilterCriteria || usedAllPlaceholder || len(spec.Use) == 0 {
			// 若是对已有内置分组做纯参数微调（既没写 use 也没写任何过滤条件），保留其既有成员列表
			if !hasFilterCriteria && !usedAllPlaceholder && len(spec.Use) == 0 && len(prevMembers) > 0 {
				for _, pm := range prevMembers {
					if validTargetExists(pm) {
						addMember(pm)
					}
				}
			} else {
				for _, leaf := range leafInfos {
					if len(spec.FromSub) > 0 {
						subMatched := false
						for _, wantSub := range spec.FromSub {
							for _, gotSub := range leaf.Subs {
								if strings.EqualFold(strings.TrimSpace(wantSub), gotSub) {
									subMatched = true
									break
								}
							}
							if subMatched {
								break
							}
						}
						if !subMatched {
							continue
						}
					}
					if len(spec.Protocol) > 0 {
						protoMatched := false
						for _, wantProto := range spec.Protocol {
							if strings.EqualFold(wantProto, leaf.Type) {
								protoMatched = true
								break
							}
						}
						if !protoMatched {
							continue
						}
					}
					if excludeRe != nil && excludeRe.MatchString(leaf.Tag) {
						continue
					}
					if matchRe != nil && !matchRe.MatchString(leaf.Tag) {
						continue
					}
					addMember(leaf.Tag)
				}
			}
		}

		// 3) 零节点自动兜底保护（杜绝 sing-box outbounds is empty 崩溃断网）
		if len(members) == 0 {
			fbCandidates := []string{strings.TrimSpace(spec.Fallback), "#Auto", "#VPS", directFallback}
			chosenFB := directFallback
			for _, cand := range fbCandidates {
				if cand != "" && cand != name && validTargetExists(cand) {
					chosenFB = cand
					break
				}
			}
			members = []string{chosenFB}
			fallbackInfo[name] = chosenFB
			warn := fmt.Sprintf("分组 [%s] 当前匹配到 0 个节点，已自动启用防断网兜底出站 [%s]", name, chosenFB)
			report.Warnings = append(report.Warnings, warn)
		}

		// 重建干净的分组属性表（避免 selector 改 urltest 或反之残留冲突字段）
		newMap := map[string]any{
			"tag":       name,
			"type":      typ,
			"outbounds": stringsToAnySlice(members),
		}
		if typ == config.GroupTypeURLTest {
			newMap["url"] = cmp.Or(strings.TrimSpace(spec.URL), stringField(gMap, "url"), defaultURLTestURL)
			newMap["interval"] = cmp.Or(strings.TrimSpace(spec.Interval), stringField(gMap, "interval"), defaultURLTestInterval)
			tol := spec.Tolerance
			if tol <= 0 {
				if oldTol, ok := gMap["tolerance"].(float64); ok && int(oldTol) > 0 {
					tol = int(oldTol)
				} else if oldTolInt, ok := gMap["tolerance"].(int); ok && oldTolInt > 0 {
					tol = oldTolInt
				} else {
					tol = defaultURLTestTolerance
				}
			}
			newMap["tolerance"] = tol
			if spec.InterruptExistConnections != nil {
				newMap["interrupt_exist_connections"] = *spec.InterruptExistConnections
			} else if oldIEC, ok := gMap["interrupt_exist_connections"].(bool); ok {
				newMap["interrupt_exist_connections"] = oldIEC
			} else {
				newMap["interrupt_exist_connections"] = false
			}
		} else {
			if spec.InterruptExistConnections != nil {
				newMap["interrupt_exist_connections"] = *spec.InterruptExistConnections
			} else if oldIEC, ok := gMap["interrupt_exist_connections"].(bool); ok {
				newMap["interrupt_exist_connections"] = oldIEC
			}
			wantDefault := cmp.Or(strings.TrimSpace(spec.Default), stringField(gMap, "default"))
			if wantDefault != "" && slices.Contains(members, wantDefault) {
				newMap["default"] = wantDefault
			} else if strings.TrimSpace(spec.Default) != "" {
				report.Warnings = append(report.Warnings,
					fmt.Sprintf("分组 [%s] 指定的 default=%q 不在候选列表中，已自动忽略", name, spec.Default))
			}
		}
		workingGroups[groupIndexByName[name]] = newMap
	}

	// 第三遍：智能挂载 (attach_to) —— merge 模式下新建分组默认挂载进顶层 Proxy（排在 #Nodes 或 #DC 之前）
	if mode == config.GroupsModeMerge {
		for _, newName := range newUserGroupOrder {
			spec := userGroupSet[newName]
			var targets []string
			if spec.AttachTo.Set {
				targets = spec.AttachTo.Items
			} else {
				if _, hasProxy := groupIndexByName["Proxy"]; hasProxy {
					targets = []string{"Proxy"}
				}
			}
			for _, parentTag := range targets {
				pIdx, exists := groupIndexByName[parentTag]
				if !exists || parentTag == newName {
					continue
				}
				parentMap := workingGroups[pIdx]
				if strings.ToLower(stringField(parentMap, "type")) != config.GroupTypeSelector {
					continue
				}
				pMembers := anySliceToStrings(parentMap["outbounds"])
				if !slices.Contains(pMembers, newName) {
					pMembers = insertGroupBeforeNodesOrDirect(pMembers, newName, directFallback)
					parentMap["outbounds"] = stringsToAnySlice(pMembers)
				}
				attachedRecord[newName] = append(attachedRecord[newName], parentTag)
			}
		}
	}

	// 第四遍：排序整理 —— merge 模式下让顶层控制组 (Proxy / AI 及业务组) 排在前面，# 底层池排在后面；
	// replace 模式下严格保持 YAML 编写顺序（约定：未定义 Proxy 时，排在第 1 位的分组即为默认兜底组）。
	if mode == config.GroupsModeMerge {
		workingGroups = orderCompiledGroups(workingGroups)
	}

	// 第五遍：拓扑环路安全检测（防止 A -> B -> A 循环引用导致 sing-box 启动失败）
	if cyclePath := detectOutboundCycle(workingGroups); len(cyclePath) > 0 {
		return "", nil, fmt.Errorf("策略组引用存在循环依赖: %s", strings.Join(cyclePath, " -> "))
	}

	// 组装最终 outbounds: [策略组...] + [底层节点...] + [#DC 等特殊出站...]
	finalOutbounds := make([]any, 0, len(workingGroups)+len(leafMaps)+len(specialOutbounds))
	validAllTags := make(map[string]bool)
	for _, gm := range workingGroups {
		finalOutbounds = append(finalOutbounds, gm)
		validAllTags[stringField(gm, "tag")] = true
	}
	for _, lm := range leafMaps {
		finalOutbounds = append(finalOutbounds, lm)
		validAllTags[stringField(lm, "tag")] = true
	}
	for _, sm := range specialOutbounds {
		finalOutbounds = append(finalOutbounds, sm)
		validAllTags[stringField(sm, "tag")] = true
	}
	for ep := range endpointTags {
		validAllTags[ep] = true
	}
	root["outbounds"] = finalOutbounds

	// 第六遍：修复悬空路由/DNS 引用（例如 replace 模式删掉了内置 AI / #VPS / Proxy，或删除了曾被引用的旧自定义组）
	primaryGroup := directFallback
	if validAllTags["Proxy"] {
		primaryGroup = "Proxy"
	} else if len(workingGroups) > 0 {
		primaryGroup = stringField(workingGroups[0], "tag")
	}
	healDanglingOutboundRefs(root, validAllTags, primaryGroup, directFallback, report)
	report.DefaultOutbound, report.DNSDetour = extractEffectiveRoutingConventions(root, directFallback)

	report.Groups = buildPreviewFromGroupMaps(workingGroups, leafSet, customizedSet, fallbackInfo, attachedRecord)
	for i := range report.Groups {
		if spec, ok := userGroupSet[report.Groups[i].Name]; ok && spec.Failover && report.Groups[i].Type == config.GroupTypeSelector {
			report.Groups[i].Failover = true
		}
	}

	encoded, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("序列化编译后的 sing-box 配置失败: %w", err)
	}
	return string(encoded), report, nil
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
