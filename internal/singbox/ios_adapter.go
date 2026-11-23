// 文件职责：承载 iOS SFI 客户端专属沙盒兼容性裁剪、GitHub 镜像前缀剥离、50MB 内存红线规则集筛选及静态兼容校验。
//
// 架构设计原则：
//   - 单一职责原则（SRP）：把苹果 SFI 扩展进程的特殊约束（禁用 external_ui、default_mark、
//     裁剪 geosite-ad2、按内核版本切换 http_clients/download_detour）独立收敛在此文件，
//     在 *sboption.Document 上完成纯内存类型化变换。
package singbox

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"singctl/internal/constant"
	"singctl/internal/singbox/sboption"
)

// AdaptIOSConfig 对生成给 iOS SFI / 移动端客户端的默认 (v1.14+) 配置进行沙盒兼容、镜像剥离与内存裁剪。
func AdaptIOSConfig(rawJSON, mirrorURL string) (string, error) {
	return AdaptIOSConfigForVersion(rawJSON, mirrorURL, constant.SingBoxTargetTemplateVersion)
}

// AdaptIOSConfigForVersion 按指定的 sing-box 目标版本（如 "v1.14" 或向下兼容的 "v1.12"/"v1.13"）
// 执行移动端沙盒兼容与规则集下载通道适配。
func AdaptIOSConfigForVersion(rawJSON, mirrorURL, singBoxVer string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("ios adapt: parse config JSON: %w", err)
	}
	adaptIOSConfigInDoc(doc, mirrorURL, singBoxVer)
	return doc.MarshalCompact()
}

// adaptIOSConfigInDoc 直接在 *sboption.Document 内存树上完成 iOS SFI 沙盒裁剪，零冗余 JSON 往返。
func adaptIOSConfigInDoc(doc *sboption.Document, mirrorURL, singBoxVer string) {
	if doc == nil {
		return
	}
	sanitizeLegacyTransportProtocolInDoc(doc)

	isLegacy := isLegacySingBoxPre114(singBoxVer)
	doc.Services = nil
	if isLegacy {
		doc.HTTPClients = nil
	}

	if doc.Experimental != nil {
		if ca := doc.Experimental.ClashAPI; ca != nil {
			ca.ExternalUI = ""
			ca.ExternalUIDownloadURL = ""
			ca.ExternalUIDownloadDetour = ""
		}
		if cf := doc.Experimental.CacheFile; cf != nil {
			enabled := true
			if cf.Enabled != nil {
				enabled = *cf.Enabled
			}
			doc.Experimental.CacheFile = &sboption.CacheFileOptions{Enabled: new(enabled)}
		}
	}

	if doc.DNS != nil {
		doc.DNS.Optimistic = nil
		if doc.DNS.DisableCache != nil && *doc.DNS.DisableCache {
			doc.DNS.IndependentCache = nil
		}
		if doc.DNS.Rules != nil {
			doc.DNS.Rules = stripRuleSetTagFromDNSRules(doc.DNS.Rules, "geosite-ad2")
		}
	}

	if doc.Route == nil {
		doc.HTTPClients = nil
		return
	}

	doc.Route.DefaultMark = 0
	if isLegacy {
		doc.Route.DefaultHTTPClient = ""
	}
	if doc.Route.Rules != nil {
		doc.Route.Rules = stripRuleSetTagFromRouteRules(doc.Route.Rules, "geosite-ad2")
	}

	referenced := make(map[string]bool)
	collectReferencedRouteRuleSets(doc.Route.Rules, referenced)
	if doc.DNS != nil {
		collectReferencedDNSRuleSets(doc.DNS.Rules, referenced)
	}

	hasRemoteRS := false
	preferredDetour := pickPreferredIOSDetour(doc.Outbounds)

	if doc.Route.RuleSet != nil {
		keptRS := make([]sboption.RuleSet, 0, len(doc.Route.RuleSet))
		for _, rs := range doc.Route.RuleSet {
			tag := strings.TrimSpace(rs.Tag)
			if tag == "geosite-ad2" {
				continue
			}
			if len(referenced) > 0 && tag != "" && !referenced[tag] {
				continue
			}
			cp := rs.Clone()
			if cp.Type == "remote" || strings.TrimSpace(cp.URL) != "" {
				hasRemoteRS = true
				if cleanedURL := stripMirrorPrefix(cp.URL, mirrorURL); cleanedURL != "" {
					cp.URL = cleanedURL
				}
				if isLegacy {
					cp.HTTPClient = ""
					if preferredDetour != "" {
						cp.DownloadDetour = preferredDetour
					}
				} else {
					cp.DownloadDetour = ""
					cp.HTTPClient = ""
				}
			}
			keptRS = append(keptRS, cp)
		}
		doc.Route.RuleSet = keptRS
	}

	if !isLegacy {
		if hasRemoteRS {
			if preferredDetour != "" && !isEmptyDirectOutboundTag(doc.Outbounds, preferredDetour) {
				doc.HTTPClients = []sboption.HTTPClient{
					{Tag: "hc-proxy", Detour: preferredDetour},
				}
				doc.Route.DefaultHTTPClient = "hc-proxy"
			} else {
				doc.HTTPClients = []sboption.HTTPClient{
					{Tag: "hc-direct"},
				}
				doc.Route.DefaultHTTPClient = "hc-direct"
			}
		} else {
			doc.HTTPClients = nil
			doc.Route.DefaultHTTPClient = ""
		}
	}
}

func isLegacySingBoxPre114(ver string) bool {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(ver), "v"), "V"))
	if s == "" {
		return false
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minorPart := parts[1]
	if idx := strings.IndexAny(minorPart, "-+_ "); idx >= 0 {
		minorPart = minorPart[:idx]
	}
	minor, err2 := strconv.Atoi(minorPart)
	if err1 != nil || err2 != nil {
		return false
	}
	return major < 1 || (major == 1 && minor < 14)
}

func isEmptyDirectOutboundTag(outbounds []sboption.Outbound, targetTag string) bool {
	if targetTag == "" {
		return true
	}
	for _, ob := range outbounds {
		if strings.TrimSpace(ob.Tag) != targetTag {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(ob.Type), "direct") {
			return false
		}
		return ob.Server == "" && ob.ServerPort == 0 && len(ob.Extra) == 0
	}
	return false
}

func stripRuleSetTagFromRouteRules(rules []sboption.RouteRule, dropTag string) []sboption.RouteRule {
	out := make([]sboption.RouteRule, 0, len(rules))
	for _, r := range rules {
		cp := r.Clone()
		if r.Rules != nil {
			cp.Rules = stripRuleSetTagFromRouteRules(r.Rules, dropTag)
			if len(cp.Rules) == 0 || (r.Type == "logical" && r.Mode == "and" && len(cp.Rules) < len(r.Rules)) {
				continue
			}
		}
		if !cp.RuleSet.IsEmpty() && slices.Contains(cp.RuleSet.Slice(), dropTag) {
			filtered := make([]string, 0, cp.RuleSet.Len())
			for _, t := range cp.RuleSet.Slice() {
				if t != dropTag {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				continue
			}
			cp.RuleSet = sboption.Listable[string]{Items: filtered, Scalar: cp.RuleSet.Scalar}
		}
		out = append(out, cp)
	}
	return out
}

func stripRuleSetTagFromDNSRules(rules []sboption.DNSRule, dropTag string) []sboption.DNSRule {
	out := make([]sboption.DNSRule, 0, len(rules))
	for _, r := range rules {
		cp := r.Clone()
		if r.Rules != nil {
			cp.Rules = stripRuleSetTagFromDNSRules(r.Rules, dropTag)
			if len(cp.Rules) == 0 || (r.Type == "logical" && r.Mode == "and" && len(cp.Rules) < len(r.Rules)) {
				continue
			}
		}
		if !cp.RuleSet.IsEmpty() && slices.Contains(cp.RuleSet.Slice(), dropTag) {
			filtered := make([]string, 0, cp.RuleSet.Len())
			for _, t := range cp.RuleSet.Slice() {
				if t != dropTag {
					filtered = append(filtered, t)
				}
			}
			if len(filtered) == 0 {
				continue
			}
			cp.RuleSet = sboption.Listable[string]{Items: filtered, Scalar: cp.RuleSet.Scalar}
		}
		out = append(out, cp)
	}
	return out
}

func collectReferencedRouteRuleSets(rules []sboption.RouteRule, out map[string]bool) {
	for _, r := range rules {
		for _, tag := range r.RuleSet.Slice() {
			out[tag] = true
		}
		if len(r.Rules) > 0 {
			collectReferencedRouteRuleSets(r.Rules, out)
		}
	}
}

func collectReferencedDNSRuleSets(rules []sboption.DNSRule, out map[string]bool) {
	for _, r := range rules {
		for _, tag := range r.RuleSet.Slice() {
			out[tag] = true
		}
		if len(r.Rules) > 0 {
			collectReferencedDNSRuleSets(r.Rules, out)
		}
	}
}

func pickPreferredIOSDetour(outbounds []sboption.Outbound) string {
	var tags []string
	var firstGroup string
	for _, ob := range outbounds {
		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			continue
		}
		tags = append(tags, tag)
		typ := strings.ToLower(strings.TrimSpace(ob.Type))
		if firstGroup == "" && (typ == "selector" || typ == "urltest" || typ == "fallback") {
			firstGroup = tag
		}
	}
	for _, candidate := range []string{"Proxy", "#Auto"} {
		if slices.Contains(tags, candidate) {
			return candidate
		}
	}
	if firstGroup != "" {
		return firstGroup
	}
	if slices.Contains(tags, "#DC") {
		return "#DC"
	}
	return ""
}

func stripMirrorPrefix(rawURL, mirrorURL string) string {
	u := strings.TrimSpace(rawURL)
	if u == "" {
		return ""
	}
	if m := strings.TrimRight(strings.TrimSpace(mirrorURL), "/"); m != "" {
		if rest, ok := strings.CutPrefix(u, m+"/"); ok && (strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://")) {
			u = rest
		} else if rest, ok := strings.CutPrefix(u, m); ok && (strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://")) {
			u = rest
		}
	}
	for _, marker := range []string{"/https://", "/http://"} {
		if schemeIdx := strings.Index(u, "://"); schemeIdx >= 0 {
			searchFrom := schemeIdx + 3
			if relIdx := strings.Index(u[searchFrom:], marker); relIdx >= 0 {
				prefix := u[:searchFrom+relIdx]
				if !strings.Contains(prefix, "?") && !strings.Contains(prefix, "#") {
					u = strings.TrimPrefix(u[searchFrom+relIdx:], "/")
					break
				}
			}
		}
	}
	return u
}

// CheckIOSCompatibility 校验生成的配置是否适合导入 iOS SFI(沙盒环境)。
func CheckIOSCompatibility(jsonStr string) error {
	doc, err := sboption.ParseDocument([]byte(jsonStr))
	if err != nil {
		return fmt.Errorf("ios check: invalid JSON: %w", err)
	}
	if doc.Route != nil && doc.Route.DefaultMark != 0 {
		return fmt.Errorf("ios check: route.default_mark (%d) 在 iOS SFI 沙盒中不受支持", doc.Route.DefaultMark)
	}
	if doc.Experimental != nil {
		if doc.Experimental.ClashAPI != nil {
			if ui := strings.TrimSpace(doc.Experimental.ClashAPI.ExternalUI); ui != "" {
				return fmt.Errorf("ios check: clash_api.external_ui (%q) 指向沙盒外路径，iOS SFI 无法读取", ui)
			}
		}
		if doc.Experimental.CacheFile != nil {
			if cfPath := strings.TrimSpace(doc.Experimental.CacheFile.Path); cfPath != "" {
				return fmt.Errorf("ios check: cache_file.path (%q) 指向沙盒外路径，iOS SFI 无法读取", cfPath)
			}
		}
	}
	if len(doc.Services) > 0 {
		return fmt.Errorf("ios check: services 字段在 iOS SFI 中不兼容（包含 %d 项）", len(doc.Services))
	}
	if doc.Route != nil {
		for _, rs := range doc.Route.RuleSet {
			if rs.Type == "local" || strings.TrimSpace(rs.Path) != "" {
				return fmt.Errorf("ios check: 规则集 %q 使用了 type=local 或本地 path, iPhone 沙盒无法读取本地路径, 请用 --platform ios 重新生成(自动保留远程规则集)", rs.Tag)
			}
		}
	}
	return nil
}
