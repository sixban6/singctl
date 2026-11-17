package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"singctl/internal/logger"
)

// BaseSnapshotPath 返回与 config.json 同目录的受管基线快照路径（例如 /etc/sing-box/.config.json.singctl-base）。
// 该文件仅记录上次由 SingCtl 纯模板+订阅生成的标准配置，用于三路比对提取用户的手动修改。
func BaseSnapshotPath(sbConfigPath string) string {
	clean := strings.TrimSpace(sbConfigPath)
	if clean == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(clean), "."+filepath.Base(clean)+".singctl-base")
}

// LoadBaseSnapshot 读取受管基线快照内容（不存在时返回空字符串与 nil）。
func LoadBaseSnapshot(sbConfigPath string) (string, error) {
	p := BaseSnapshotPath(sbConfigPath)
	if p == "" {
		return "", nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// SaveBaseSnapshot 以 0600 权限原子写入受管基线快照。
func SaveBaseSnapshot(sbConfigPath, content string) error {
	p := BaseSnapshotPath(sbConfigPath)
	if p == "" || strings.TrimSpace(content) == "" {
		return nil
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".singctl-base.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		return err
	}
	cleanup = false
	_ = os.Chmod(p, 0600)
	return nil
}

// EnsureInitialBaseSnapshot 在用户通过 WebUI 编辑器首次保存手动修改前调用：
// 若磁盘尚无基线文件且原 config.json 存在，则立即将修改前的原配置固化为初始基线。
func EnsureInitialBaseSnapshot(sbConfigPath string) {
	basePath := BaseSnapshotPath(sbConfigPath)
	if basePath == "" {
		return
	}
	if _, err := os.Stat(basePath); err == nil {
		return
	}
	origBytes, err := os.ReadFile(sbConfigPath)
	if err != nil || len(bytes.TrimSpace(origBytes)) == 0 {
		return
	}
	_ = SaveBaseSnapshot(sbConfigPath, string(origBytes))
}

// PrepareRegeneratedConfig 根据 preserveManual 开关决定是否将磁盘现有 config.json 中的用户手改项
// 三路合并至新生成的配置中，并在存在手改冲突时自动留存 .manual-bak (0600) 兜底备份。
func PrepareRegeneratedConfig(ctx context.Context, sbConfigPath, freshJSON string, preserveManual bool) (string, int) {
	if !preserveManual || strings.TrimSpace(sbConfigPath) == "" {
		return freshJSON, 0
	}
	curBytes, err := os.ReadFile(sbConfigPath)
	if err != nil || len(bytes.TrimSpace(curBytes)) == 0 {
		return freshJSON, 0
	}
	baseJSON, _ := LoadBaseSnapshot(sbConfigPath)
	merged, changes, mergeErr := MergeManualConfig(baseJSON, string(curBytes), freshJSON)
	if mergeErr != nil || changes == 0 {
		return freshJSON, 0
	}
	if checkErr := CheckSingBoxConfigContent(ctx, merged); checkErr != nil {
		bakPath := sbConfigPath + ".manual-bak"
		_ = os.WriteFile(bakPath, curBytes, 0600)
		_ = os.Chmod(bakPath, 0600)
		logger.Warn("合并 config.json 手动修改后未通过 sing-box check (%v)，已将原配置备份至 %s 并回退标准模板", checkErr, bakPath)
		return freshJSON, 0
	}
	return merged, changes
}

// MergeManualConfig 执行三路结构化 JSON 合并 (Base + Current -> Fresh)：
//   - 订阅节点与策略组候选池正常跟随 Fresh 更新；
//   - 用户在 Current 中相对 Base 新增或修改的 inbounds、自建 outbounds、route/dns 规则、log/ntp/endpoints 等自动保留。
func MergeManualConfig(baseJSON, currentJSON, freshJSON string) (string, int, error) {
	if strings.TrimSpace(currentJSON) == "" {
		return freshJSON, 0, nil
	}

	var curRoot map[string]any
	if err := json.Unmarshal([]byte(currentJSON), &curRoot); err != nil {
		return "", 0, fmt.Errorf("parse current config.json: %w", err)
	}
	var freshRoot map[string]any
	if err := json.Unmarshal([]byte(freshJSON), &freshRoot); err != nil {
		return "", 0, fmt.Errorf("parse fresh config.json: %w", err)
	}
	if curRoot == nil || freshRoot == nil {
		return freshJSON, 0, nil
	}

	// 始终复用当前运行态的 Clash API / Service Secret，避免每次生成随机密钥导致无意义重载或面板断连
	preserveRuntimeSecrets(curRoot, freshRoot)

	// 若升级后首次运行尚无历史 Base 快照，仅安全保留确定性的用户增量（如自定义新增 tag 的 inbound / ntp / endpoints）
	if strings.TrimSpace(baseJSON) == "" {
		changes := mergeWithoutBase(curRoot, freshRoot)
		if changes == 0 {
			out, err := PrettyJSON(mustMarshalJSON(freshRoot))
			if err != nil {
				return freshJSON, 0, nil
			}
			return out, 0, nil
		}
		out, err := PrettyJSON(mustMarshalJSON(freshRoot))
		if err != nil {
			return "", 0, err
		}
		return out, changes, nil
	}

	var baseRoot map[string]any
	if err := json.Unmarshal([]byte(baseJSON), &baseRoot); err != nil || baseRoot == nil {
		return freshJSON, 0, nil
	}
	preserveRuntimeSecrets(curRoot, baseRoot)

	changes := 0

	// 1. 顶层普通模块 (log, ntp, certificate, endpoints, services 及用户自定义扩展键)
	specialTopKeys := map[string]bool{
		"dns":          true,
		"inbounds":     true,
		"outbounds":    true,
		"route":        true,
		"experimental": true,
	}
	allTopKeys := collectMapKeys(baseRoot, curRoot)
	for _, k := range allTopKeys {
		if specialTopKeys[k] {
			continue
		}
		bVal, bOk := baseRoot[k]
		cVal, cOk := curRoot[k]
		if canonicalEqual(bVal, cVal) && bOk == cOk {
			continue
		}
		if !cOk && bOk {
			if _, fOk := freshRoot[k]; fOk && canonicalEqual(freshRoot[k], bVal) {
				delete(freshRoot, k)
				changes++
			}
			continue
		}
		if cMap, cIsMap := cVal.(map[string]any); cIsMap {
			bMap, _ := bVal.(map[string]any)
			fMap, fIsMap := freshRoot[k].(map[string]any)
			if !fIsMap || fMap == nil {
				freshRoot[k] = deepCopyAny(cMap)
				changes++
			} else {
				changes += mergeObject3Way(bMap, cMap, fMap)
			}
		} else if k == "endpoints" {
			bSlice, _ := bVal.([]any)
			cSlice, _ := cVal.([]any)
			fSlice, _ := freshRoot[k].([]any)
			mergedSlice, cnt := mergeTaggedSlice3Way(bSlice, cSlice, fSlice, "tag")
			if cnt > 0 {
				freshRoot[k] = mergedSlice
				changes += cnt
			}
		} else {
			if fVal, fOk := freshRoot[k]; !fOk || canonicalEqual(fVal, bVal) {
				freshRoot[k] = deepCopyAny(cVal)
				changes++
			}
		}
	}

	// 2. experimental (保留用户对 cache_file / default_mode / v2ray_api 等的手动修改)
	bExp, _ := baseRoot["experimental"].(map[string]any)
	cExp, _ := curRoot["experimental"].(map[string]any)
	fExp, _ := freshRoot["experimental"].(map[string]any)
	if cExp != nil {
		if fExp == nil {
			freshRoot["experimental"] = deepCopyAny(cExp)
			changes++
		} else {
			changes += mergeObject3Way(bExp, cExp, fExp)
		}
	}

	// 3. inbounds (按 tag 三路合并：保留用户新增如 :7890 mixed 端口或修改的监听参数)
	bIn, _ := baseRoot["inbounds"].([]any)
	cIn, _ := curRoot["inbounds"].([]any)
	fIn, _ := freshRoot["inbounds"].([]any)
	if !canonicalEqual(bIn, cIn) {
		mergedIn, cnt := mergeTaggedSlice3Way(bIn, cIn, fIn, "tag")
		if cnt > 0 {
			freshRoot["inbounds"] = mergedIn
			changes += cnt
		}
	}

	// 4. outbounds (核心：更新订阅节点，同时保留用户自建 outbound 及在策略组中的手动调整)
	bOut, _ := baseRoot["outbounds"].([]any)
	cOut, _ := curRoot["outbounds"].([]any)
	fOut, _ := freshRoot["outbounds"].([]any)
	mergedOut, outCnt := mergeOutbounds3Way(bOut, cOut, fOut, extractTaggedSet(freshRoot["endpoints"]))
	if outCnt > 0 {
		freshRoot["outbounds"] = mergedOut
		changes += outCnt
	}
	validOutbounds := extractTaggedSet(freshRoot["outbounds"])
	maps.Copy(validOutbounds, extractTaggedSet(freshRoot["endpoints"]))

	// 5. route (保留用户新增/修改的 rule_set、route.rules 及顶层路由属性)
	bRoute, _ := baseRoot["route"].(map[string]any)
	cRoute, _ := curRoot["route"].(map[string]any)
	fRoute, _ := freshRoot["route"].(map[string]any)
	if cRoute != nil && fRoute != nil {
		changes += mergeRoute3Way(bRoute, cRoute, fRoute, validOutbounds)
	}

	// 6. dns (保留用户新增/修改的 dns.servers、dns.rules 及策略字段)
	bDNS, _ := baseRoot["dns"].(map[string]any)
	cDNS, _ := curRoot["dns"].(map[string]any)
	fDNS, _ := freshRoot["dns"].(map[string]any)
	if cDNS != nil && fDNS != nil {
		changes += mergeDNS3Way(bDNS, cDNS, fDNS, validOutbounds)
	}

	out, err := PrettyJSON(mustMarshalJSON(freshRoot))
	if err != nil {
		return "", 0, err
	}
	return out, changes, nil
}

func preserveRuntimeSecrets(curRoot, dstRoot map[string]any) {
	var curSecret string
	if cExp, ok := curRoot["experimental"].(map[string]any); ok {
		if cClash, ok := cExp["clash_api"].(map[string]any); ok {
			curSecret, _ = cClash["secret"].(string)
			curSecret = strings.TrimSpace(curSecret)
		}
	}
	if curSecret == "" {
		return
	}
	if dExp, ok := dstRoot["experimental"].(map[string]any); ok {
		if dClash, ok := dExp["clash_api"].(map[string]any); ok {
			if _, has := dClash["secret"]; has {
				dClash["secret"] = curSecret
			}
		}
	}
	if dSvcs, ok := dstRoot["services"].([]any); ok {
		for _, item := range dSvcs {
			svc, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if typ, _ := svc["type"].(string); strings.EqualFold(strings.TrimSpace(typ), "api") {
				if _, has := svc["secret"]; has {
					svc["secret"] = curSecret
				}
			}
		}
	}
}

func mergeWithoutBase(curRoot, freshRoot map[string]any) int {
	changes := 0
	// 仅合并确定不会与旧版废弃节点冲突的用户新增 inbound (按全新 tag 识别) 与 ntp/endpoints
	cIn, _ := curRoot["inbounds"].([]any)
	fIn, _ := freshRoot["inbounds"].([]any)
	freshInTags := extractTaggedSet(fIn)
	for _, item := range cIn {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := strField(m, "tag")
		if tag != "" && !freshInTags[tag] {
			fIn = append(fIn, deepCopyAny(m))
			freshInTags[tag] = true
			changes++
		}
	}
	if changes > 0 {
		freshRoot["inbounds"] = fIn
	}
	for _, k := range []string{"ntp", "certificate"} {
		if cVal, cOk := curRoot[k]; cOk {
			if _, fOk := freshRoot[k]; !fOk {
				freshRoot[k] = deepCopyAny(cVal)
				changes++
			}
		}
	}
	return changes
}

func mergeObject3Way(baseObj, curObj, freshObj map[string]any) int {
	if curObj == nil || freshObj == nil {
		return 0
	}
	changes := 0
	for _, k := range collectMapKeys(baseObj, curObj) {
		var bVal any
		var bOk bool
		if baseObj != nil {
			bVal, bOk = baseObj[k]
		}
		cVal, cOk := curObj[k]
		if canonicalEqual(bVal, cVal) && bOk == cOk {
			continue
		}
		if !cOk && bOk {
			if fVal, fOk := freshObj[k]; fOk && canonicalEqual(fVal, bVal) {
				delete(freshObj, k)
				changes++
			}
			continue
		}
		cSub, cIsMap := cVal.(map[string]any)
		fSub, fIsMap := freshObj[k].(map[string]any)
		if cIsMap && fIsMap && fSub != nil {
			var bSub map[string]any
			if bVal != nil {
				bSub, _ = bVal.(map[string]any)
			}
			changes += mergeObject3Way(bSub, cSub, fSub)
			continue
		}
		if fVal, fOk := freshObj[k]; !fOk || canonicalEqual(fVal, bVal) {
			freshObj[k] = deepCopyAny(cVal)
			changes++
		}
	}
	return changes
}

func mergeTaggedSlice3Way(baseSlice, curSlice, freshSlice []any, tagKey string) ([]any, int) {
	baseByKey := indexSliceByTagOrJSON(baseSlice, tagKey)
	curByKey, curOrder := indexSliceWithOrder(curSlice, tagKey)
	freshByKey, _ := indexSliceWithOrder(freshSlice, tagKey)

	changes := 0
	out := make([]any, 0, len(freshSlice)+len(curSlice))
	keptKeys := make(map[string]bool, len(freshSlice))

	for _, item := range freshSlice {
		k := itemIdentity(item, tagKey)
		bItem, inBase := baseByKey[k]
		cItem, inCur := curByKey[k]

		// 用户在 Current 中主动删除了原本在 Base 中存在的条目
		if inBase && !inCur {
			if canonicalEqual(item, bItem) {
				changes++
				continue
			}
		}

		// 用户修改了该条目
		if inBase && inCur && !canonicalEqual(bItem, cItem) {
			bMap, bOk := bItem.(map[string]any)
			cMap, cOk := cItem.(map[string]any)
			fMap, fOk := deepCopyAny(item).(map[string]any)
			if bOk && cOk && fOk {
				cnt := mergeObject3Way(bMap, cMap, fMap)
				if cnt > 0 {
					changes += cnt
				}
				out = append(out, fMap)
				keptKeys[k] = true
				continue
			}
		}

		out = append(out, deepCopyAny(item))
		keptKeys[k] = true
	}

	// 插入用户在 Current 中新增（不在 Base 且尚未在 Fresh 中）的条目，保持相对锚点位置
	for idx, k := range curOrder {
		if _, inBase := baseByKey[k]; inBase || keptKeys[k] {
			continue
		}
		cItem := curByKey[k]
		if _, inFresh := freshByKey[k]; inFresh {
			continue
		}
		out = insertAtRelativeAnchor(out, curOrder, idx, cItem, tagKey)
		keptKeys[k] = true
		changes++
	}

	return out, changes
}

func mergeOutbounds3Way(baseOut, curOut, freshOut []any, endpointTags map[string]bool) ([]any, int) {
	baseByTag := make(map[string]map[string]any, len(baseOut))
	for _, item := range baseOut {
		if m, ok := item.(map[string]any); ok {
			if tag := strField(m, "tag"); tag != "" {
				baseByTag[tag] = m
			}
		}
	}
	curByTag := make(map[string]map[string]any, len(curOut))
	var curOrder []string
	for _, item := range curOut {
		if m, ok := item.(map[string]any); ok {
			if tag := strField(m, "tag"); tag != "" {
				curByTag[tag] = m
				curOrder = append(curOrder, tag)
			}
		}
	}

	changes := 0
	out := make([]any, 0, len(freshOut)+4)
	presentTags := make(map[string]bool, len(freshOut)+len(endpointTags))
	maps.Copy(presentTags, endpointTags)

	// 先收集所有 Fresh 原有 tag + 用户自建新增 tag（不在 Base 中的 outbound）
	for _, item := range freshOut {
		if m, ok := item.(map[string]any); ok {
			if tag := strField(m, "tag"); tag != "" {
				presentTags[tag] = true
			}
		}
	}
	var userAddedTags []string
	for _, tag := range curOrder {
		if _, inBase := baseByTag[tag]; !inBase && !presentTags[tag] {
			presentTags[tag] = true
			userAddedTags = append(userAddedTags, tag)
		}
	}

	// 处理 Fresh 中的策略组与节点
	for _, item := range freshOut {
		fMap, ok := deepCopyAny(item).(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		tag := strField(fMap, "tag")
		bMap, inBase := baseByTag[tag]
		cMap, inCur := curByTag[tag]
		if !inBase || !inCur || canonicalEqual(bMap, cMap) {
			out = append(out, fMap)
			continue
		}

		typ := strings.ToLower(strField(fMap, "type"))
		if typ == "selector" || typ == "urltest" {
			cnt := mergeGroupOutbound3Way(bMap, cMap, fMap, presentTags)
			changes += cnt
			out = append(out, fMap)
			continue
		}

		// 普通节点或内置出站：仅当 Fresh 未更新该字段 (fresh[k] == base[k]) 时应用用户手改字段
		changes += mergeObject3Way(bMap, cMap, fMap)
		out = append(out, fMap)
	}

	// 追加用户自建 outbound（如自建 socks / wireguard / 自定义策略组）
	for _, tag := range userAddedTags {
		cMap := deepCopyAny(curByTag[tag]).(map[string]any)
		typ := strings.ToLower(strField(cMap, "type"))
		if typ == "selector" || typ == "urltest" {
			cleaned := filterValidStrings(sliceStrings(cMap["outbounds"]), presentTags)
			if len(cleaned) == 0 {
				presentTags[tag] = false
				continue
			}
			cMap["outbounds"] = cleaned
			if def := strField(cMap, "default"); def != "" && !slices.Contains(cleaned, def) {
				delete(cMap, "default")
			}
		}
		out = append(out, cMap)
		changes++
	}

	// 最终引用完整性校验：确保所有策略组不引用已下线的失效节点
	validTags := make(map[string]bool, len(out)+len(endpointTags))
	maps.Copy(validTags, endpointTags)
	for _, item := range out {
		if m, ok := item.(map[string]any); ok {
			if tag := strField(m, "tag"); tag != "" {
				validTags[tag] = true
			}
		}
	}
	for _, item := range out {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ := strings.ToLower(strField(m, "type"))
		if typ != "selector" && typ != "urltest" {
			continue
		}
		cleaned := filterValidStrings(sliceStrings(m["outbounds"]), validTags)
		if len(cleaned) > 0 {
			m["outbounds"] = stringSliceToAny(cleaned)
		}
		if def := strField(m, "default"); def != "" && !slices.Contains(cleaned, def) {
			delete(m, "default")
		}
	}

	return out, changes
}

func mergeGroupOutbound3Way(bMap, cMap, fMap map[string]any, validTags map[string]bool) int {
	changes := 0
	for _, k := range collectMapKeys(bMap, cMap) {
		if k == "outbounds" || k == "tag" || k == "type" {
			continue
		}
		bVal, bOk := bMap[k]
		cVal, cOk := cMap[k]
		if canonicalEqual(bVal, cVal) && bOk == cOk {
			continue
		}
		if !cOk && bOk {
			if fVal, fOk := fMap[k]; fOk && canonicalEqual(fVal, bVal) {
				delete(fMap, k)
				changes++
			}
			continue
		}
		if k == "default" {
			if defStr, ok := cVal.(string); ok && !validTags[strings.TrimSpace(defStr)] {
				continue
			}
		}
		if fVal, fOk := fMap[k]; !fOk || canonicalEqual(fVal, bVal) {
			fMap[k] = deepCopyAny(cVal)
			changes++
		}
	}

	baseMembers := sliceStrings(bMap["outbounds"])
	curMembers := sliceStrings(cMap["outbounds"])
	freshMembers := sliceStrings(fMap["outbounds"])

	if !slices.Equal(baseMembers, curMembers) {
		baseSet := toSet(baseMembers)
		curSet := toSet(curMembers)

		// 移除用户从该组中手动剔除的成员
		nextMembers := make([]string, 0, len(freshMembers)+len(curMembers))
		removedAny := false
		for _, m := range freshMembers {
			if baseSet[m] && !curSet[m] {
				removedAny = true
				continue
			}
			nextMembers = append(nextMembers, m)
		}
		// 追加用户手动挂入该组的成员（如自建节点 tag）
		addedAny := false
		for _, m := range curMembers {
			if !baseSet[m] && validTags[m] && !slices.Contains(nextMembers, m) {
				nextMembers = append(nextMembers, m)
				addedAny = true
			}
		}
		if len(nextMembers) > 0 && (removedAny || addedAny) {
			fMap["outbounds"] = stringSliceToAny(nextMembers)
			changes++
		}
	}
	return changes
}

func mergeRoute3Way(bRoute, cRoute, fRoute map[string]any, validOutbounds map[string]bool) int {
	changes := 0

	// 1. route.rule_set
	var bRS, cRS, fRS []any
	if bRoute != nil {
		bRS, _ = bRoute["rule_set"].([]any)
	}
	cRS, _ = cRoute["rule_set"].([]any)
	fRS, _ = fRoute["rule_set"].([]any)
	if !canonicalEqual(bRS, cRS) {
		mergedRS, cnt := mergeTaggedSlice3Way(bRS, cRS, fRS, "tag")
		if cnt > 0 {
			fRoute["rule_set"] = mergedRS
			changes += cnt
		}
	}
	validRuleSets := extractTaggedSet(fRoute["rule_set"])

	// 2. route 标量与子属性
	for _, k := range collectMapKeys(bRoute, cRoute) {
		if k == "rules" || k == "rule_set" {
			continue
		}
		var bVal any
		var bOk bool
		if bRoute != nil {
			bVal, bOk = bRoute[k]
		}
		cVal, cOk := cRoute[k]
		if canonicalEqual(bVal, cVal) && bOk == cOk {
			continue
		}
		if !cOk && bOk {
			if fVal, fOk := fRoute[k]; fOk && canonicalEqual(fVal, bVal) {
				delete(fRoute, k)
				changes++
			}
			continue
		}
		if k == "final" {
			if outTag, ok := cVal.(string); ok && outTag != "" && !validOutbounds[outTag] {
				continue
			}
		}
		if fVal, fOk := fRoute[k]; !fOk || canonicalEqual(fVal, bVal) {
			fRoute[k] = deepCopyAny(cVal)
			changes++
		}
	}

	// 3. route.rules
	var bRules []any
	if bRoute != nil {
		bRules, _ = bRoute["rules"].([]any)
	}
	cRules, _ := cRoute["rules"].([]any)
	fRules, _ := fRoute["rules"].([]any)
	if !canonicalEqual(bRules, cRules) {
		mergedRules, cnt := mergeOrderedRules3Way(bRules, cRules, fRules, func(rule map[string]any) bool {
			if outTag := strField(rule, "outbound"); outTag != "" && !validOutbounds[outTag] {
				return false
			}
			return hasValidRuleSetRefs(rule, validRuleSets)
		})
		if cnt > 0 {
			fRoute["rules"] = mergedRules
			changes += cnt
		}
	}
	return changes
}

func mergeDNS3Way(bDNS, cDNS, fDNS map[string]any, validOutbounds map[string]bool) int {
	changes := 0

	// 1. dns.servers
	var bSrvs, cSrvs, fSrvs []any
	if bDNS != nil {
		bSrvs, _ = bDNS["servers"].([]any)
	}
	cSrvs, _ = cDNS["servers"].([]any)
	fSrvs, _ = fDNS["servers"].([]any)
	if !canonicalEqual(bSrvs, cSrvs) {
		mergedSrvs, cnt := mergeTaggedSlice3Way(bSrvs, cSrvs, fSrvs, "tag")
		if cnt > 0 {
			// 过滤引用了失效 detour 的自定义 DNS server
			cleanedSrvs := make([]any, 0, len(mergedSrvs))
			for _, item := range mergedSrvs {
				if m, ok := item.(map[string]any); ok {
					if det := strField(m, "detour"); det != "" && !validOutbounds[det] {
						continue
					}
				}
				cleanedSrvs = append(cleanedSrvs, item)
			}
			if len(cleanedSrvs) > 0 {
				fDNS["servers"] = cleanedSrvs
				changes += cnt
			}
		}
	}
	validServers := extractTaggedSet(fDNS["servers"])

	// 2. dns 标量属性
	for _, k := range collectMapKeys(bDNS, cDNS) {
		if k == "servers" || k == "rules" {
			continue
		}
		var bVal any
		var bOk bool
		if bDNS != nil {
			bVal, bOk = bDNS[k]
		}
		cVal, cOk := cDNS[k]
		if canonicalEqual(bVal, cVal) && bOk == cOk {
			continue
		}
		if !cOk && bOk {
			if fVal, fOk := fDNS[k]; fOk && canonicalEqual(fVal, bVal) {
				delete(fDNS, k)
				changes++
			}
			continue
		}
		if k == "final" {
			if srvTag, ok := cVal.(string); ok && srvTag != "" && !validServers[srvTag] {
				continue
			}
		}
		if fVal, fOk := fDNS[k]; !fOk || canonicalEqual(fVal, bVal) {
			fDNS[k] = deepCopyAny(cVal)
			changes++
		}
	}

	// 3. dns.rules
	var bRules []any
	if bDNS != nil {
		bRules, _ = bDNS["rules"].([]any)
	}
	cRules, _ := cDNS["rules"].([]any)
	fRules, _ := fDNS["rules"].([]any)
	if !canonicalEqual(bRules, cRules) {
		mergedRules, cnt := mergeOrderedRules3Way(bRules, cRules, fRules, func(rule map[string]any) bool {
			if srvTag := strField(rule, "server"); srvTag != "" && !validServers[srvTag] {
				return false
			}
			return true
		})
		if cnt > 0 {
			fDNS["rules"] = mergedRules
			changes += cnt
		}
	}
	return changes
}

func mergeOrderedRules3Way(baseRules, curRules, freshRules []any, isValid func(map[string]any) bool) ([]any, int) {
	baseCounts := make(map[string]int, len(baseRules))
	for _, r := range baseRules {
		baseCounts[canonicalKey(r)]++
	}
	curCounts := make(map[string]int, len(curRules))
	for _, r := range curRules {
		curCounts[canonicalKey(r)]++
	}

	// 统计用户在 Current 中主动删除的 Base 规则
	deletedCounts := make(map[string]int)
	for k, bCnt := range baseCounts {
		if cCnt := curCounts[k]; cCnt < bCnt {
			deletedCounts[k] = bCnt - cCnt
		}
	}

	changes := 0
	out := make([]any, 0, len(freshRules)+len(curRules))
	for _, r := range freshRules {
		k := canonicalKey(r)
		if deletedCounts[k] > 0 && !isEssentialBootstrapRule(r) {
			deletedCounts[k]--
			changes++
			continue
		}
		out = append(out, deepCopyAny(r))
	}

	// 找出用户在 Current 中新增的规则 (出现次数超过 Base) 并按前驱锚点精确插入
	seenInCur := make(map[string]int, len(curRules))
	curKeys := make([]string, len(curRules))
	for i, r := range curRules {
		curKeys[i] = canonicalKey(r)
	}

	for idx, r := range curRules {
		k := curKeys[idx]
		seenInCur[k]++
		if seenInCur[k] <= baseCounts[k] {
			continue
		}
		if rm, ok := r.(map[string]any); ok && isValid != nil && !isValid(rm) {
			continue
		}
		// 若 Fresh 已经天然包含完全一致的规则，则不重复插入
		if containsCanonical(out, k) {
			continue
		}
		out = insertRuleByNeighborAnchor(out, curKeys, idx, deepCopyAny(r))
		changes++
	}

	return out, changes
}

func isEssentialBootstrapRule(r any) bool {
	m, ok := r.(map[string]any)
	if !ok {
		return false
	}
	act := strField(m, "action")
	return act == "sniff" || act == "hijack-dns"
}

func insertRuleByNeighborAnchor(out []any, curKeys []string, curIdx int, newRule any) []any {
	// 优先紧跟在 Current 中前一条已存在于 out 的锚点规则之后
	for prev := curIdx - 1; prev >= 0; prev-- {
		anchorKey := curKeys[prev]
		for i := len(out) - 1; i >= 0; i-- {
			if canonicalKey(out[i]) == anchorKey {
				res := make([]any, 0, len(out)+1)
				res = append(res, out[:i+1]...)
				res = append(res, newRule)
				res = append(res, out[i+1:]...)
				return res
			}
		}
	}
	// 其次插在后一条锚点规则之前
	for next := curIdx + 1; next < len(curKeys); next++ {
		anchorKey := curKeys[next]
		for i, item := range out {
			if canonicalKey(item) == anchorKey {
				res := make([]any, 0, len(out)+1)
				res = append(res, out[:i]...)
				res = append(res, newRule)
				res = append(res, out[i:]...)
				return res
			}
		}
	}
	// 默认插在 sniff / hijack-dns 引导规则之后，保证高优先级生效
	insertPos := 0
	for insertPos < len(out) && isEssentialBootstrapRule(out[insertPos]) {
		insertPos++
	}
	res := make([]any, 0, len(out)+1)
	res = append(res, out[:insertPos]...)
	res = append(res, newRule)
	res = append(res, out[insertPos:]...)
	return res
}

func insertAtRelativeAnchor(out []any, curOrder []string, curIdx int, newItem any, tagKey string) []any {
	for prev := curIdx - 1; prev >= 0; prev-- {
		anchor := curOrder[prev]
		for i := len(out) - 1; i >= 0; i-- {
			if itemIdentity(out[i], tagKey) == anchor {
				res := make([]any, 0, len(out)+1)
				res = append(res, out[:i+1]...)
				res = append(res, deepCopyAny(newItem))
				res = append(res, out[i+1:]...)
				return res
			}
		}
	}
	return append(out, deepCopyAny(newItem))
}

func hasValidRuleSetRefs(rule map[string]any, validRuleSets map[string]bool) bool {
	if len(validRuleSets) == 0 {
		if _, has := rule["rule_set"]; has {
			return false
		}
		return true
	}
	if rawRS, has := rule["rule_set"]; has {
		for _, tag := range extractStringOrSliceAny(rawRS) {
			if !validRuleSets[tag] {
				return false
			}
		}
	}
	if subRules, ok := rule["rules"].([]any); ok {
		for _, sr := range subRules {
			if sm, ok := sr.(map[string]any); ok {
				if !hasValidRuleSetRefs(sm, validRuleSets) {
					return false
				}
			}
		}
	}
	return true
}

func indexSliceByTagOrJSON(items []any, tagKey string) map[string]any {
	m := make(map[string]any, len(items))
	for _, it := range items {
		m[itemIdentity(it, tagKey)] = it
	}
	return m
}

func indexSliceWithOrder(items []any, tagKey string) (map[string]any, []string) {
	m := make(map[string]any, len(items))
	order := make([]string, 0, len(items))
	for _, it := range items {
		k := itemIdentity(it, tagKey)
		if _, exists := m[k]; !exists {
			order = append(order, k)
		}
		m[k] = it
	}
	return m, order
}

func itemIdentity(item any, tagKey string) string {
	if m, ok := item.(map[string]any); ok && tagKey != "" {
		if tag := strField(m, tagKey); tag != "" {
			return "tag:" + tag
		}
	}
	return "json:" + canonicalKey(item)
}

func extractTaggedSet(raw any) map[string]bool {
	set := make(map[string]bool)
	slice, ok := raw.([]any)
	if !ok {
		return set
	}
	for _, item := range slice {
		if m, ok := item.(map[string]any); ok {
			if tag := strField(m, "tag"); tag != "" {
				set[tag] = true
			}
		}
	}
	return set
}

func strField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}

func sliceStrings(raw any) []string {
	switch v := raw.(type) {
	case []string:
		return slices.Clone(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	default:
		return nil
	}
}

func filterValidStrings(list []string, valid map[string]bool) []string {
	out := make([]string, 0, len(list))
	for _, s := range list {
		if valid[s] && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func stringSliceToAny(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

func toSet(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, s := range list {
		m[s] = true
	}
	return m
}

func collectMapKeys(a, b map[string]any) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var keys []string
	for k := range a {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range b {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	return keys
}

func canonicalKey(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func canonicalEqual(a, b any) bool {
	return canonicalKey(a) == canonicalKey(b)
}

func containsCanonical(slice []any, targetKey string) bool {
	for _, item := range slice {
		if canonicalKey(item) == targetKey {
			return true
		}
	}
	return false
}

func deepCopyAny(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

func mustMarshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
