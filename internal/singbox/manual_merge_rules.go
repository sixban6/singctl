// 文件职责：实现有序路由/DNS 规则三路锚点插入、规则集引用合法性裁剪与通用 JSON 深拷贝工具函数。
package singbox

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

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
	outKeys := make([]string, 0, len(freshRules)+len(curRules))
	outKeySet := make(map[string]bool, len(freshRules)+len(curRules))
	for _, r := range freshRules {
		k := canonicalKey(r)
		if deletedCounts[k] > 0 && !isEssentialBootstrapRule(r) {
			deletedCounts[k]--
			changes++
			continue
		}
		out = append(out, deepCopyAny(r))
		outKeys = append(outKeys, k)
		outKeySet[k] = true
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
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if isValid != nil && !isValid(rm) {
			continue
		}
		// 若 Fresh 已经天然包含完全一致的规则，则不重复插入
		if outKeySet[k] {
			continue
		}
		out, outKeys = insertRuleByNeighborAnchor(out, outKeys, curKeys, idx, deepCopyAny(r), k)
		outKeySet[k] = true
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

func insertRuleByNeighborAnchor(out []any, outKeys, curKeys []string, curIdx int, newRule any, newKey string) ([]any, []string) {
	insertAt := func(pos int) ([]any, []string) {
		res := make([]any, 0, len(out)+1)
		res = append(res, out[:pos]...)
		res = append(res, newRule)
		res = append(res, out[pos:]...)

		keys := make([]string, 0, len(outKeys)+1)
		keys = append(keys, outKeys[:pos]...)
		keys = append(keys, newKey)
		keys = append(keys, outKeys[pos:]...)
		return res, keys
	}

	// 优先紧跟在 Current 中前一条已存在于 out 的锚点规则之后
	for prev := curIdx - 1; prev >= 0; prev-- {
		anchorKey := curKeys[prev]
		for i := len(outKeys) - 1; i >= 0; i-- {
			if outKeys[i] == anchorKey {
				return insertAt(i + 1)
			}
		}
	}
	// 其次插在后一条锚点规则之前
	for next := curIdx + 1; next < len(curKeys); next++ {
		anchorKey := curKeys[next]
		for i, itemKey := range outKeys {
			if itemKey == anchorKey {
				return insertAt(i)
			}
		}
	}
	// 默认插在 sniff / hijack-dns 引导规则之后，保证高优先级生效
	insertPos := 0
	for insertPos < len(out) && isEssentialBootstrapRule(out[insertPos]) {
		insertPos++
	}
	return insertAt(insertPos)
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

func deepCopyAny(v any) any {
	switch x := v.(type) {
	case nil, string, float64, bool, int, int64:
		return x
	case map[string]any:
		cp := make(map[string]any, len(x))
		for k, val := range x {
			cp[k] = deepCopyAny(val)
		}
		return cp
	case []any:
		cp := make([]any, len(x))
		for i, val := range x {
			cp[i] = deepCopyAny(val)
		}
		return cp
	case []string:
		return slices.Clone(x)
	case map[string]string:
		return maps.Clone(x)
	default:
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
}

func mustMarshalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
