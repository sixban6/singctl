// 文件职责：负责统一自定义与第三方规则集 (.srs) 的权威下载地址规范化，自动将历史 sixban6/rulesets 链接迁移至本仓库托管通道或官方上游。
package singbox

import (
	"strings"

	"singctl/internal/constant"
	"singctl/internal/singbox/sboption"
)

const metaCubeXDouyinRuleSetURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/douyin.srs"

var legacyRuleSetPrefixes = []string{
	"https://github.com/sixban6/rulesets/raw/refs/heads/main/rule/",
	"https://github.com/sixban6/rulesets/raw/main/rule/",
	"https://raw.githubusercontent.com/sixban6/rulesets/main/rule/",
	"https://raw.githubusercontent.com/sixban6/rulesets/refs/heads/main/rule/",
}

var legacyRuleSetFileTargets = map[string]string{
	"direct_cn.srs":     constant.RuleSetReleaseBaseURL + "/direct_cn.srs",
	"hok.srs":           constant.RuleSetReleaseBaseURL + "/hok.srs",
	"wx_shortvideo.srs": constant.RuleSetReleaseBaseURL + "/wx_video.srs",
	"douyin.srs":        metaCubeXDouyinRuleSetURL,
}

// CanonicalizeRuleSetURL 将历史自定义规则集链接规范化为权威下载地址。
// 支持直连 URL 与 GitHub 镜像前缀（保留原有镜像前缀）；未命中迁移映射时原样返回。
func CanonicalizeRuleSetURL(rawURL string) (string, bool) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return rawURL, false
	}

	prefix := ""
	inner := trimmed
	if idx := strings.LastIndex(trimmed, "https://"); idx > 0 {
		prefix = trimmed[:idx]
		inner = trimmed[idx:]
	}

	for _, legacyPrefix := range legacyRuleSetPrefixes {
		rest, ok := strings.CutPrefix(inner, legacyPrefix)
		if !ok {
			continue
		}
		target, exists := legacyRuleSetFileTargets[rest]
		if !exists {
			return rawURL, false
		}
		return prefix + target, true
	}
	return rawURL, false
}

// RewriteLegacyRuleSetURLsInDoc 将强类型配置树中所有旧版自定义规则集链接原地规范化为权威地址。
func RewriteLegacyRuleSetURLsInDoc(doc *sboption.Document) bool {
	if doc == nil || doc.Route == nil || len(doc.Route.RuleSet) == 0 {
		return false
	}
	changed := false
	for i := range doc.Route.RuleSet {
		rawURL := strings.TrimSpace(doc.Route.RuleSet[i].URL)
		if rawURL == "" {
			continue
		}
		if rewritten, ok := CanonicalizeRuleSetURL(rawURL); ok {
			doc.Route.RuleSet[i].URL = rewritten
			changed = true
		}
	}
	return changed
}
