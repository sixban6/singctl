// 文件职责：承载 iOS SFI 客户端专属沙盒兼容性裁剪、GitHub 镜像前缀剥离、50MB 内存红线规则集筛选及静态兼容校验。
//
// 架构设计原则：
//   - 单一职责原则（SRP）：把苹果 SFI 扩展进程的特殊约束（禁用 external_ui、default_mark、
//     裁剪 geosite-ad2、按内核版本切换 http_clients/download_detour）独立收敛在此文件，
//     使手机端兼容逻辑的演进与路由器客户端完全解耦。
package singbox

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// AdaptIOSConfig 对生成给 iOS SFI / 移动端客户端的默认 (v1.14+) 配置进行沙盒兼容、镜像剥离与内存裁剪：
//   - 移除 services / route.default_mark 与 clash_api.external_ui* 等不兼容或冗余字段；
//   - 清理 dns.optimistic、独立缓存冲突及 v1.14 cache_file 持久化扩展字段；
//   - 剔除体积最大的 geosite-ad2 与未被规则引用的僵尸规则集，控低冷启动 RSS（<50MB）；
//   - 剥离国内 GitHub 反代镜像前缀（含显式 mirrorURL 与通用反代模式），并将远程规则集统一切换到
//     v1.14+ 标准 http_clients + route.default_http_client（消除 1.14 弃用 / 1.16 移除的 download_detour 告警）。
func AdaptIOSConfig(rawJSON, mirrorURL string) (string, error) {
	return AdaptIOSConfigForVersion(rawJSON, mirrorURL, "v1.14")
}

// AdaptIOSConfigForVersion 按指定的 sing-box 目标版本（如 "v1.14" 或向下兼容的 "v1.12"/"v1.13"）
// 执行移动端沙盒兼容与规则集下载通道适配。
func AdaptIOSConfigForVersion(rawJSON, mirrorURL, singBoxVer string) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &root); err != nil {
		return "", fmt.Errorf("ios adapt: parse config JSON: %w", err)
	}
	if root == nil {
		return rawJSON, nil
	}
	adaptIOSConfigInRoot(root, mirrorURL, singBoxVer)

	data, err := json.Marshal(root)
	if err != nil {
		return "", fmt.Errorf("ios adapt: marshal config JSON: %w", err)
	}
	return string(data), nil
}

// adaptIOSConfigInRoot 直接在内存树上完成 iOS SFI 沙盒裁剪，避免编译流水线内冗余 JSON 往返。
func adaptIOSConfigInRoot(root map[string]any, mirrorURL, singBoxVer string) {
	if root == nil {
		return
	}
	sanitizeLegacyTransportProtocolRules(root)

	isLegacy := isLegacySingBoxPre114(singBoxVer)

	delete(root, "services")
	if isLegacy {
		delete(root, "http_clients")
	}

	if expMap, ok := root["experimental"].(map[string]any); ok && expMap != nil {
		if clashAPI, ok := expMap["clash_api"].(map[string]any); ok && clashAPI != nil {
			delete(clashAPI, "external_ui")
			delete(clashAPI, "external_ui_download_url")
			delete(clashAPI, "external_ui_download_detour")
		}
		if cf, ok := expMap["cache_file"].(map[string]any); ok && cf != nil {
			enabled := true
			if b, ok := cf["enabled"].(bool); ok {
				enabled = b
			}
			expMap["cache_file"] = map[string]any{"enabled": enabled}
		}
	}

	var dnsRules any
	var hasDNS bool
	if dnsMap, ok := root["dns"].(map[string]any); ok && dnsMap != nil {
		hasDNS = true
		delete(dnsMap, "optimistic")
		if dc, ok := dnsMap["disable_cache"].(bool); ok && dc {
			delete(dnsMap, "independent_cache")
		}
		if rawRules, ok := dnsMap["rules"].([]any); ok {
			cleanedDNS := stripRuleSetTagFromRules(rawRules, "geosite-ad2")
			dnsMap["rules"] = cleanedDNS
			dnsRules = cleanedDNS
		}
	}

	hasRemoteRS := false
	preferredDetour := pickPreferredIOSDetour(root["outbounds"])

	if routeMap, ok := root["route"].(map[string]any); ok && routeMap != nil {
		delete(routeMap, "default_mark")
		if isLegacy {
			delete(routeMap, "default_http_client")
		}
		var cleanedRoute []any
		if rawRules, ok := routeMap["rules"].([]any); ok {
			cleanedRoute = stripRuleSetTagFromRules(rawRules, "geosite-ad2")
			routeMap["rules"] = cleanedRoute
		}

		referenced := make(map[string]bool)
		collectReferencedRuleSetTags(cleanedRoute, referenced)
		if hasDNS {
			if dr, ok := dnsRules.([]any); ok {
				collectReferencedRuleSetTags(dr, referenced)
			}
		}

		if rawRS, ok := routeMap["rule_set"].([]any); ok {
			keptRS := make([]any, 0, len(rawRS))
			for _, item := range rawRS {
				rm, ok := item.(map[string]any)
				if !ok || rm == nil {
					continue
				}
				tag, _ := rm["tag"].(string)
				tag = strings.TrimSpace(tag)
				if tag == "geosite-ad2" {
					continue
				}
				if len(referenced) > 0 && tag != "" && !referenced[tag] {
					continue
				}
				typ, _ := rm["type"].(string)
				rawURL, _ := rm["url"].(string)
				if typ == "remote" || strings.TrimSpace(rawURL) != "" {
					hasRemoteRS = true
					if cleanedURL := stripMirrorPrefix(rawURL, mirrorURL); cleanedURL != "" {
						rm["url"] = cleanedURL
					}
					if isLegacy {
						delete(rm, "http_client")
						if preferredDetour != "" {
							rm["download_detour"] = preferredDetour
						}
					} else {
						delete(rm, "download_detour")
						delete(rm, "http_client")
					}
				}
				keptRS = append(keptRS, rm)
			}
			routeMap["rule_set"] = keptRS
		}

		if !isLegacy {
			if hasRemoteRS {
				if preferredDetour != "" && !isEmptyDirectOutboundTag(root["outbounds"], preferredDetour) {
					root["http_clients"] = []map[string]any{
						{"tag": "hc-proxy", "detour": preferredDetour},
					}
					routeMap["default_http_client"] = "hc-proxy"
				} else {
					// 当兜底为直连（如空 direct #DC）时必须省略 detour，防止 sing-box 1.14+ 报 empty direct 致命错误
					root["http_clients"] = []map[string]any{
						{"tag": "hc-direct"},
					}
					routeMap["default_http_client"] = "hc-direct"
				}
			} else {
				delete(root, "http_clients")
				delete(routeMap, "default_http_client")
			}
		}
	} else {
		delete(root, "http_clients")
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

func isEmptyDirectOutboundTag(rawOutbounds any, targetTag string) bool {
	if targetTag == "" {
		return true
	}
	list, ok := rawOutbounds.([]any)
	if !ok {
		return false
	}
	for _, item := range list {
		om, ok := item.(map[string]any)
		if !ok || om == nil {
			continue
		}
		tag := strings.TrimSpace(fmt.Sprint(om["tag"]))
		if tag != targetTag {
			continue
		}
		typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(om["type"])))
		if typ != "direct" {
			return false
		}
		for k, v := range om {
			if k == "type" || k == "tag" || v == nil {
				continue
			}
			return false
		}
		return true
	}
	return false
}

func stripRuleSetTagFromRules(rules []any, dropTag string) []any {
	out := make([]any, 0, len(rules))
	for _, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok || rm == nil {
			out = append(out, item)
			continue
		}
		if rawSub, hasSub := rm["rules"].([]any); hasSub {
			cleanedSub := stripRuleSetTagFromRules(rawSub, dropTag)
			if len(cleanedSub) == 0 {
				continue
			}
			rm["rules"] = cleanedSub
		}
		if rawRS, hasRS := rm["rule_set"]; hasRS {
			tags := extractStringOrSliceAny(rawRS)
			if slices.Contains(tags, dropTag) {
				filtered := make([]string, 0, len(tags))
				for _, t := range tags {
					if t != dropTag {
						filtered = append(filtered, t)
					}
				}
				if len(filtered) == 0 {
					continue
				}
				if len(filtered) == 1 {
					if _, wasStr := rawRS.(string); wasStr {
						rm["rule_set"] = filtered[0]
					} else {
						rm["rule_set"] = filtered
					}
				} else {
					rm["rule_set"] = filtered
				}
			}
		}
		out = append(out, rm)
	}
	return out
}

func extractStringOrSliceAny(raw any) []string {
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	}
	return nil
}

func collectReferencedRuleSetTags(rules []any, out map[string]bool) {
	for _, item := range rules {
		rm, ok := item.(map[string]any)
		if !ok || rm == nil {
			continue
		}
		for _, tag := range extractStringOrSliceAny(rm["rule_set"]) {
			out[tag] = true
		}
		if sub, ok := rm["rules"].([]any); ok {
			collectReferencedRuleSetTags(sub, out)
		}
	}
}

func pickPreferredIOSDetour(rawOutbounds any) string {
	list, ok := rawOutbounds.([]any)
	if !ok {
		return ""
	}
	var tags []string
	var firstGroup string
	for _, item := range list {
		om, ok := item.(map[string]any)
		if !ok || om == nil {
			continue
		}
		tag := strings.TrimSpace(fmt.Sprint(om["tag"]))
		if tag == "" || om["tag"] == nil {
			continue
		}
		tags = append(tags, tag)
		typ := strings.ToLower(strings.TrimSpace(fmt.Sprint(om["type"])))
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
// 检查项: rule_set 不能包含 type=local 或本地 path 条目、不得设置 route.default_mark、
// 不得包含外置 clash_api.external_ui / cache_file.path 或 1.14 services 字段。
func CheckIOSCompatibility(jsonStr string) error {
	var cfg struct {
		Route struct {
			DefaultMark int `json:"default_mark"`
			RuleSet     []struct {
				Type string `json:"type"`
				Tag  string `json:"tag"`
				Path string `json:"path"`
			} `json:"rule_set"`
		} `json:"route"`
		Experimental struct {
			ClashAPI struct {
				ExternalUI string `json:"external_ui"`
			} `json:"clash_api"`
			CacheFile struct {
				Path string `json:"path"`
			} `json:"cache_file"`
		} `json:"experimental"`
		Services []any `json:"services"`
	}
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return fmt.Errorf("ios check: invalid JSON: %w", err)
	}
	if cfg.Route.DefaultMark != 0 {
		return fmt.Errorf("ios check: route.default_mark (%d) 在 iOS SFI 沙盒中不受支持", cfg.Route.DefaultMark)
	}
	if ui := strings.TrimSpace(cfg.Experimental.ClashAPI.ExternalUI); ui != "" {
		return fmt.Errorf("ios check: clash_api.external_ui (%q) 指向沙盒外路径，iOS SFI 无法读取", ui)
	}
	if cfPath := strings.TrimSpace(cfg.Experimental.CacheFile.Path); cfPath != "" {
		return fmt.Errorf("ios check: cache_file.path (%q) 指向沙盒外路径，iOS SFI 无法读取", cfPath)
	}
	if len(cfg.Services) > 0 {
		return fmt.Errorf("ios check: services 字段在 iOS SFI 中不兼容（包含 %d 项）", len(cfg.Services))
	}
	for _, rs := range cfg.Route.RuleSet {
		if rs.Type == "local" || strings.TrimSpace(rs.Path) != "" {
			return fmt.Errorf("ios check: 规则集 %q 使用了 type=local 或本地 path, iPhone 沙盒无法读取本地路径, 请用 --platform ios 重新生成(自动保留远程规则集)", rs.Tag)
		}
	}
	return nil
}
