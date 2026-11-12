package deploy

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/constant"
)

// ErrWarpTunnelUnavailable 当配置需要走 WARP 出口但本地 127.0.0.1:40000 隧道不可用时返回（防黑洞保护）
var ErrWarpTunnelUnavailable = errors.New("WARP 本地隧道 (127.0.0.1:40000) 未启动或未就绪，已拦截切换以防断网")

// WarpPresetDef 描述内置 WARP 分流场景预设
type WarpPresetDef struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Group          string   `json:"group"`      // ai | streaming | social
	GroupLabel     string   `json:"groupLabel"` // 分组显示名称
	Description    string   `json:"description"`
	DomainsSummary string   `json:"domainsSummary"`
	DefaultEnabled bool     `json:"defaultEnabled"`
	RuleSets       []string `json:"ruleSets,omitempty"`
	DomainSuffixes []string `json:"domainSuffixes,omitempty"`
}

// WarpPresetState 包含预设元信息及当前是否走 WARP
type WarpPresetState struct {
	WarpPresetDef
	Enabled bool `json:"enabled"`
}

type optionalRuleSetSpec struct {
	Tag string
	URL string
}

var baseRuleSetTags = []string{
	"rule-github",
	"rule-youtube",
	"rule-google-domain",
	"rule-openai",
	"rule-anthropic",
	"rule-x",
	"rule-porn",
	"rule-google-ip",
	"rule-reddit",
}

var optionalRuleSetSpecs = map[string]optionalRuleSetSpec{
	"rule-gemini": {
		Tag: "rule-gemini",
		URL: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google-gemini.srs",
	},
	"rule-netflix": {
		Tag: "rule-netflix",
		URL: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs",
	},
	"rule-disney": {
		Tag: "rule-disney",
		URL: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/disney.srs",
	},
	"rule-tiktok": {
		Tag: "rule-tiktok",
		URL: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/tiktok.srs",
	},
	"rule-spotify": {
		Tag: "rule-spotify",
		URL: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/spotify.srs",
	},
}

var warpPresetRegistry = []WarpPresetDef{
	// 1. AI 大模型
	{
		ID:             "openai",
		Name:           "OpenAI / ChatGPT",
		Group:          "ai",
		GroupLabel:     "AI 大模型",
		Description:    "避免机房 IP 被 Cloudflare / OpenAI 风控拦截或降智",
		DomainsSummary: "rule-openai + chatgpt.com / oaistatic.com / oaiusercontent.com",
		RuleSets:       []string{"rule-openai"},
		DomainSuffixes: []string{"chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
	},
	{
		ID:             "anthropic",
		Name:           "Claude (Anthropic)",
		Group:          "ai",
		GroupLabel:     "AI 大模型",
		Description:    "改善 Claude Web 与 API 地区/机房 IP 封号风险",
		DomainsSummary: "rule-anthropic + claude.ai / anthropic.com",
		RuleSets:       []string{"rule-anthropic"},
		DomainSuffixes: []string{"claude.ai", "anthropic.com"},
	},
	{
		ID:             "gemini",
		Name:           "Google Gemini / AI Studio",
		Group:          "ai",
		GroupLabel:     "AI 大模型",
		Description:    "独立分流 Gemini 对话与 AI Studio 接口",
		DomainsSummary: "rule-gemini + gemini.google.com / aistudio.google.com",
		RuleSets:       []string{"rule-gemini"},
		DomainSuffixes: []string{"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com"},
	},
	{
		ID:             "perplexity",
		Name:           "Perplexity & Cursor",
		Group:          "ai",
		GroupLabel:     "AI 大模型",
		Description:    "Perplexity 检索与 Cursor AI 编程客户端服务分流",
		DomainsSummary: "perplexity.ai / pplx.ai / cursor.sh / cursor.com",
		DomainSuffixes: []string{"perplexity.ai", "pplx.ai", "cursor.sh", "cursor.com"},
	},

	// 2. 流媒体与成人内容
	{
		ID:             "missav",
		Name:           "MissAV（含镜像与视频流 CDN）",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "同步覆盖 MissAV 主站、自动跳转镜像站及 HLS 视频/封面 CDN",
		DomainsSummary: "missav.ws / .ai / .com / .live + surrit.com / nineyu.com",
		DomainSuffixes: []string{"missav.ws", "missav.ai", "missav.com", "missav.live", "surrit.com", "nineyu.com"},
	},
	{
		ID:             "netflix",
		Name:           "Netflix",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "解锁非自制剧区域限制与 Fast 测速",
		DomainsSummary: "rule-netflix + netflix.com / nflxvideo.net / fast.com",
		RuleSets:       []string{"rule-netflix"},
		DomainSuffixes: []string{"netflix.com", "nflxvideo.net", "fast.com"},
	},
	{
		ID:             "disney",
		Name:           "Disney+",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "解锁 Disney+ 影视库访问",
		DomainsSummary: "rule-disney + disneyplus.com / bamgrid.com",
		RuleSets:       []string{"rule-disney"},
		DomainSuffixes: []string{"disneyplus.com", "bamgrid.com"},
	},
	{
		ID:             "youtube",
		Name:           "YouTube（免送中/免弹登录）",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "解决部分 VPS IP 被判送中或强迫登录看视频的问题",
		DomainsSummary: "rule-youtube",
		RuleSets:       []string{"rule-youtube"},
	},
	{
		ID:             "tiktok",
		Name:           "TikTok",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "国际版短视频分流",
		DomainsSummary: "rule-tiktok + tiktok.com / tiktokv.com / byteoversea.com",
		RuleSets:       []string{"rule-tiktok"},
		DomainSuffixes: []string{"tiktok.com", "tiktokv.com", "byteoversea.com"},
	},
	{
		ID:             "spotify",
		Name:           "Spotify",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "音乐流媒体与音频 CDN 分流",
		DomainsSummary: "rule-spotify + spotify.com / scdn.co",
		RuleSets:       []string{"rule-spotify"},
		DomainSuffixes: []string{"spotify.com", "scdn.co"},
	},
	{
		ID:             "porn",
		Name:           "成人站点合集 (Geosite Porn)",
		Group:          "streaming",
		GroupLabel:     "流媒体与成人内容",
		Description:    "全量 Geosite 成人站群规则集走 WARP 出口",
		DomainsSummary: "rule-porn (category-porn.srs)",
		RuleSets:       []string{"rule-porn"},
	},

	// 3. 社交与防风控
	{
		ID:             "reddit",
		Name:           "Reddit",
		Group:          "social",
		GroupLabel:     "社交与防风控",
		Description:    "默认开启 WARP：绕过机房 IP 对 Reddit 匿名浏览的封锁",
		DomainsSummary: "rule-reddit",
		DefaultEnabled: true,
		RuleSets:       []string{"rule-reddit"},
	},
	{
		ID:             "x",
		Name:           "X (Twitter)",
		Group:          "social",
		GroupLabel:     "社交与防风控",
		Description:    "缓解敏感内容/登录风控与媒体图床加载受限",
		DomainsSummary: "rule-x + x.com / twitter.com / twimg.com",
		RuleSets:       []string{"rule-x"},
		DomainSuffixes: []string{"x.com", "twitter.com", "twimg.com"},
	},
	{
		ID:             "google",
		Name:           "Google 搜索（防弹人机验证）",
		Group:          "social",
		GroupLabel:     "社交与防风控",
		Description:    "解决脏机房 IP 频繁弹出 Google reCAPTCHA 验证码的问题",
		DomainsSummary: "rule-google-domain + rule-google-ip",
		RuleSets:       []string{"rule-google-domain", "rule-google-ip"},
	},
	{
		ID:             "github",
		Name:           "GitHub",
		Group:          "social",
		GroupLabel:     "社交与防风控",
		Description:    "独立分流 GitHub 网页、Raw 与 Release 资产访问",
		DomainsSummary: "rule-github",
		RuleSets:       []string{"rule-github"},
	},
}

// GetWarpPresets 返回全部 15 项内置预设的只读副本
func GetWarpPresets() []WarpPresetDef {
	out := make([]WarpPresetDef, len(warpPresetRegistry))
	for i, p := range warpPresetRegistry {
		p.RuleSets = slices.Clone(p.RuleSets)
		p.DomainSuffixes = slices.Clone(p.DomainSuffixes)
		out[i] = p
	}
	return out
}

// BuildPresetStateList 结合当前配置计算所有内置预设的启用状态
func BuildPresetStateList(wr config.WarpRoutingConfig) []WarpPresetState {
	out := make([]WarpPresetState, 0, len(warpPresetRegistry))
	for _, p := range warpPresetRegistry {
		enabled := wr.IsPresetEnabled(p.ID, p.DefaultEnabled)
		out = append(out, WarpPresetState{
			WarpPresetDef: WarpPresetDef{
				ID:             p.ID,
				Name:           p.Name,
				Group:          p.Group,
				GroupLabel:     p.GroupLabel,
				Description:    p.Description,
				DomainsSummary: p.DomainsSummary,
				DefaultEnabled: p.DefaultEnabled,
				RuleSets:       slices.Clone(p.RuleSets),
				DomainSuffixes: slices.Clone(p.DomainSuffixes),
			},
			Enabled: enabled,
		})
	}
	return out
}

// FindPresetByHost 根据目标域名识别最匹配的内置预设 ID（若无则返回空串）
func FindPresetByHost(host string) (WarpPresetDef, bool) {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if h == "" {
		return WarpPresetDef{}, false
	}
	for _, p := range warpPresetRegistry {
		for _, suffix := range p.DomainSuffixes {
			if config.MatchDomainRule(suffix, h) {
				return p, true
			}
		}
	}
	return WarpPresetDef{}, false
}

// NeedsWarpTunnel 判断该分流配置在运行时是否会将任何流量导向 WARP 出站
func NeedsWarpTunnel(wr config.WarpRoutingConfig) bool {
	mode := wr.NormalizedMode()
	if mode == config.WarpModeBypass {
		return false
	}
	if mode == config.WarpModeGlobalWarp {
		return true
	}
	if len(wr.WarpDomains) > 0 || len(wr.WarpCIDRs) > 0 {
		return true
	}
	for _, p := range warpPresetRegistry {
		if wr.IsPresetEnabled(p.ID, p.DefaultEnabled) {
			return true
		}
	}
	return false
}

// CheckWarpSocksPort 检查本地 127.0.0.1:40000 SOCKS5 端口是否可连接
func CheckWarpSocksPort() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 1500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ApplyWarpRoutingToServerConfigJSON 将 WarpRoutingConfig 编译并无损注入服务端 sing-box config.json 中，
// 仅重编 route.rules / route.final / 按需增删可选 rule_set，完整保留 inbounds 凭据与 telemetry。
func ApplyWarpRoutingToServerConfigJSON(rawJSON []byte, rawWR config.WarpRoutingConfig) ([]byte, error) {
	wr, err := config.NormalizeWarpRouting(rawWR)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		return nil, fmt.Errorf("解析 sing-box config.json 失败: %w", err)
	}
	if doc == nil {
		return nil, errors.New("sing-box config.json 内容为空")
	}

	ensureWarpAndDCOutbounds(doc)

	routeMap, _ := doc["route"].(map[string]any)
	if routeMap == nil {
		routeMap = make(map[string]any)
	}

	// 1. 收集启用的 WARP 预设对应的 rule_set 和 domain_suffix
	mode := wr.NormalizedMode()
	var warpRuleSets []string
	var warpPresetSuffixes []string
	neededOptionalRuleSets := make(map[string]bool)

	if mode != config.WarpModeBypass {
		for _, p := range warpPresetRegistry {
			if !wr.IsPresetEnabled(p.ID, p.DefaultEnabled) {
				continue
			}
			for _, rs := range p.RuleSets {
				if !slices.Contains(warpRuleSets, rs) {
					warpRuleSets = append(warpRuleSets, rs)
				}
				if _, isOpt := optionalRuleSetSpecs[rs]; isOpt {
					neededOptionalRuleSets[rs] = true
				}
			}
			for _, sfx := range p.DomainSuffixes {
				if !slices.Contains(warpPresetSuffixes, sfx) {
					warpPresetSuffixes = append(warpPresetSuffixes, sfx)
				}
			}
		}
	}

	// 2. 更新 route.rule_set：保留已有非可选集合，按需增删可选集合
	existingRuleSets := extractSliceOfMaps(routeMap["rule_set"])
	updatedRuleSets := make([]map[string]any, 0, len(existingRuleSets)+len(neededOptionalRuleSets))
	presentTags := make(map[string]bool)

	for _, item := range existingRuleSets {
		tag, _ := item["tag"].(string)
		if _, isOpt := optionalRuleSetSpecs[tag]; isOpt && !neededOptionalRuleSets[tag] {
			// 未启用的可选规则集不再保留，节省小内存 VPS 规则内存
			continue
		}
		if tag != "" {
			presentTags[tag] = true
		}
		updatedRuleSets = append(updatedRuleSets, item)
	}
	// 按固定注册表顺序注入新增的可选 rule_set，保证输出确定性
	for _, p := range warpPresetRegistry {
		for _, rs := range p.RuleSets {
			if !neededOptionalRuleSets[rs] || presentTags[rs] {
				continue
			}
			spec := optionalRuleSetSpecs[rs]
			updatedRuleSets = append(updatedRuleSets, map[string]any{
				"tag":             spec.Tag,
				"type":            "remote",
				"format":          "binary",
				"download_detour": "DC",
				"url":             spec.URL,
			})
			presentTags[rs] = true
		}
	}
	if len(updatedRuleSets) > 0 {
		routeMap["rule_set"] = updatedRuleSets
	}

	// 3. 构建基础头部动作规则（sniff / hijack-dns / ip_is_private reject），防止私网/回环 SSRF 穿透
	existingRules := extractSliceOfMaps(routeMap["rules"])
	newRules := extractBaseProtectionRules(existingRules)

	// 4. 计算未走 WARP 的基础内置 rule_set（必须保持明确出口为 DC，尤其在 global_warp 下仍按基础分流或仅对未命中走 WARP？
	// 注意：在 global_warp 模式下，未勾选为 WARP 的基础服务也应默认跟从兜底 WARP，仅显式 DirectDomains/DirectCIDRs 走 DC！
	// 而在 split / bypass 模式下，剩余基础 rule_set 归入 DC。）
	var remainingDirectRuleSets []string
	for _, baseTag := range baseRuleSetTags {
		if !presentTags[baseTag] {
			continue
		}
		if slices.Contains(warpRuleSets, baseTag) {
			continue
		}
		remainingDirectRuleSets = append(remainingDirectRuleSets, baseTag)
	}

	if mode == config.WarpModeBypass {
		if len(remainingDirectRuleSets) > 0 {
			newRules = append(newRules, map[string]any{
				"rule_set": remainingDirectRuleSets,
				"outbound": "DC",
			})
		}
		routeMap["final"] = "DC"
	} else {
		// 优先级 A：自定义强制原生直出白名单 (最高用户优先级，在 global_warp 下也必定走 DC)
		if r := buildDomainRouteRule(wr.DirectDomains, "DC"); r != nil {
			newRules = append(newRules, r)
		}
		if len(wr.DirectCIDRs) > 0 {
			newRules = append(newRules, map[string]any{
				"ip_cidr":  slices.Clone(wr.DirectCIDRs),
				"outbound": "DC",
			})
		}

		// 优先级 B：自定义强制走 WARP 域名与 IP/CIDR
		if r := buildDomainRouteRule(wr.WarpDomains, "WARP"); r != nil {
			newRules = append(newRules, r)
		}
		if len(wr.WarpCIDRs) > 0 {
			newRules = append(newRules, map[string]any{
				"ip_cidr":  slices.Clone(wr.WarpCIDRs),
				"outbound": "WARP",
			})
		}

		// 优先级 C：已启用走 WARP 的场景预设（rule_set 与内置后缀如 MissAV/CDN）
		if len(warpRuleSets) > 0 {
			newRules = append(newRules, map[string]any{
				"rule_set": warpRuleSets,
				"outbound": "WARP",
			})
		}
		if len(warpPresetSuffixes) > 0 {
			newRules = append(newRules, map[string]any{
				"domain_suffix": warpPresetSuffixes,
				"outbound":      "WARP",
			})
		}

		// 优先级 D：split 模式下剩余基础 rule_set 显式归属 DC；global_warp 模式下其余流量全部交给 final: WARP
		if mode == config.WarpModeSplit && len(remainingDirectRuleSets) > 0 {
			newRules = append(newRules, map[string]any{
				"rule_set": remainingDirectRuleSets,
				"outbound": "DC",
			})
		}

		if mode == config.WarpModeGlobalWarp {
			routeMap["final"] = "WARP"
		} else {
			routeMap["final"] = "DC"
		}
	}

	routeMap["rules"] = newRules
	doc["route"] = routeMap

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化 sing-box config.json 失败: %w", err)
	}
	return append(out, '\n'), nil
}

func ensureWarpAndDCOutbounds(doc map[string]any) {
	outbounds := extractSliceOfMaps(doc["outbounds"])
	hasDC := false
	hasWARP := false
	for _, ob := range outbounds {
		tag, _ := ob["tag"].(string)
		if tag == "DC" {
			hasDC = true
		}
		if tag == "WARP" {
			hasWARP = true
		}
	}
	if !hasDC {
		outbounds = append(outbounds, map[string]any{
			"tag":  "DC",
			"type": "direct",
		})
	}
	if !hasWARP {
		outbounds = append(outbounds, map[string]any{
			"tag":         "WARP",
			"type":        "socks",
			"server":      "127.0.0.1",
			"server_port": 40000,
		})
	}
	if len(outbounds) > 0 {
		doc["outbounds"] = outbounds
	}
}

func extractSliceOfMaps(v any) []map[string]any {
	rawSlice, ok := v.([]any)
	if !ok {
		if mSlice, ok2 := v.([]map[string]any); ok2 {
			return mSlice
		}
		return nil
	}
	out := make([]map[string]any, 0, len(rawSlice))
	for _, item := range rawSlice {
		if m, ok := item.(map[string]any); ok && m != nil {
			out = append(out, m)
		}
	}
	return out
}

func extractBaseProtectionRules(existing []map[string]any) []map[string]any {
	var base []map[string]any
	hasSniff := false
	hasHijack := false
	hasPrivateReject := false

	for _, r := range existing {
		action, _ := r["action"].(string)
		ipPriv, _ := r["ip_is_private"].(bool)
		switch {
		case action == "sniff":
			hasSniff = true
			base = append(base, r)
		case action == "hijack-dns":
			hasHijack = true
			base = append(base, r)
		case ipPriv && action == "reject":
			hasPrivateReject = true
			base = append(base, r)
		}
	}

	if !hasSniff {
		base = append([]map[string]any{{
			"action":  "sniff",
			"timeout": "1s",
		}}, base...)
	}
	if !hasHijack {
		base = append(base, map[string]any{
			"action": "hijack-dns",
			"mode":   "or",
			"type":   "logical",
			"rules": []map[string]any{
				{"port": 53},
				{"protocol": "dns"},
			},
		})
	}
	if !hasPrivateReject {
		base = append(base, map[string]any{
			"ip_is_private": true,
			"action":        "reject",
		})
	}
	return base
}

func buildDomainRouteRule(rules []string, outbound string) map[string]any {
	if len(rules) == 0 {
		return nil
	}
	var suffixes, exacts, keywords []string
	for _, item := range rules {
		switch {
		case strings.HasPrefix(item, "full:"):
			exacts = append(exacts, strings.TrimPrefix(item, "full:"))
		case strings.HasPrefix(item, "keyword:"):
			keywords = append(keywords, strings.TrimPrefix(item, "keyword:"))
		default:
			suffixes = append(suffixes, strings.TrimPrefix(item, "domain:"))
		}
	}
	if len(suffixes) == 0 && len(exacts) == 0 && len(keywords) == 0 {
		return nil
	}
	m := map[string]any{
		"outbound": outbound,
	}
	if len(suffixes) > 0 {
		m["domain_suffix"] = suffixes
	}
	if len(exacts) > 0 {
		m["domain"] = exacts
	}
	if len(keywords) > 0 {
		m["domain_keyword"] = keywords
	}
	return m
}

// ExpectedTargetOutbound 根据当前 WARP 分流配置推断特定目标 (host, dstIP, ruleTag) 应当命中 "WARP" 还是 "Direct"
func ExpectedTargetOutbound(wr config.WarpRoutingConfig, host, dstIP, ruleTag string) string {
	mode := wr.NormalizedMode()
	if mode == config.WarpModeBypass {
		return "Direct"
	}

	// 1. Direct 白名单最高优先
	for _, r := range wr.DirectDomains {
		if config.MatchDomainRule(r, host) {
			return "Direct"
		}
	}
	for _, r := range wr.DirectCIDRs {
		if config.MatchCIDRRule(r, dstIP) {
			return "Direct"
		}
	}

	// 2. 自定义 WARP 规则
	for _, r := range wr.WarpDomains {
		if config.MatchDomainRule(r, host) {
			return "WARP"
		}
	}
	for _, r := range wr.WarpCIDRs {
		if config.MatchCIDRRule(r, dstIP) {
			return "WARP"
		}
	}

	// 3. 预设匹配（包括域名后缀与 rule_set tag 提示）
	lowerRule := strings.ToLower(ruleTag)
	for _, p := range warpPresetRegistry {
		enabled := wr.IsPresetEnabled(p.ID, p.DefaultEnabled)
		matched := false
		for _, sfx := range p.DomainSuffixes {
			if config.MatchDomainRule(sfx, host) {
				matched = true
				break
			}
		}
		if !matched && lowerRule != "" {
			for _, rs := range p.RuleSets {
				if strings.Contains(lowerRule, strings.ToLower(rs)) {
					matched = true
					break
				}
			}
		}
		if matched {
			if enabled {
				return "WARP"
			}
			if mode == config.WarpModeGlobalWarp {
				return "WARP"
			}
			return "Direct"
		}
	}

	if mode == config.WarpModeGlobalWarp {
		return "WARP"
	}
	return "Direct"
}

// LiveWarpApplyDeps 为 ApplyLiveWarpRouting 提供可测试的外部系统调用依赖注入
type LiveWarpApplyDeps struct {
	CheckWarpPort   func() bool
	ValidateConfig  func(tmpPath string) error
	IsServiceActive func() bool
	ReloadService   func(wasActive bool) error
	RestoreService  func(wasActive bool) error
}

// ApplyLiveWarpRouting 对现有 sing-box config.json 执行防黑洞门禁、预检、0600 原子替换与 SIGHUP 零断流热重载（失败自动回滚）
func ApplyLiveWarpRouting(singboxConfigPath string, rawWR config.WarpRoutingConfig, deps *LiveWarpApplyDeps) (bool, error) {
	cfgPath := cmp.Or(strings.TrimSpace(singboxConfigPath), constant.SingBoxConfigFile)
	wr, err := config.NormalizeWarpRouting(rawWR)
	if err != nil {
		return false, err
	}

	checkPort := CheckWarpSocksPort
	validateFn := defaultValidateSingBoxConfig
	isActiveFn := defaultIsSingBoxActive
	reloadFn := defaultReloadSingBoxService
	restoreFn := defaultRestoreSingBoxService
	if deps != nil {
		if deps.CheckWarpPort != nil {
			checkPort = deps.CheckWarpPort
		}
		if deps.ValidateConfig != nil {
			validateFn = deps.ValidateConfig
		}
		if deps.IsServiceActive != nil {
			isActiveFn = deps.IsServiceActive
		}
		if deps.ReloadService != nil {
			reloadFn = deps.ReloadService
		}
		if deps.RestoreService != nil {
			restoreFn = deps.RestoreService
		}
	}

	// 1. 防黑洞门禁
	if NeedsWarpTunnel(wr) && !checkPort() {
		return false, ErrWarpTunnelUnavailable
	}

	// 2. 读取现网 config.json 并编译新 route 段
	oldBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		return false, fmt.Errorf("读取 %s 失败: %w", cfgPath, err)
	}
	newBytes, err := ApplyWarpRoutingToServerConfigJSON(oldBytes, wr)
	if err != nil {
		return false, err
	}
	if bytes.Equal(bytes.TrimSpace(oldBytes), bytes.TrimSpace(newBytes)) {
		return false, nil
	}

	// 3. 写入 0600 临时文件执行 sing-box check 离线预检
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return false, fmt.Errorf("创建配置目录失败: %w", err)
	}
	tmpPath := fmt.Sprintf("%s.%d.warp.tmp", cfgPath, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, newBytes, 0600); err != nil {
		return false, fmt.Errorf("写入临时配置失败: %w", err)
	}
	_ = os.Chmod(tmpPath, 0600)
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := validateFn(tmpPath); err != nil {
		return false, fmt.Errorf("sing-box 配置预检未通过（已拦截写入防断网）: %w", err)
	}

	// 4. 备份旧配置（0600）并原子替换目标配置
	bakPath := fmt.Sprintf("%s.%d.warp.bak", cfgPath, time.Now().UnixNano())
	if wErr := os.WriteFile(bakPath, oldBytes, 0600); wErr == nil {
		_ = os.Chmod(bakPath, 0600)
		pruneWarpConfigBackups(cfgPath, 3)
	}

	wasActive := isActiveFn()
	if err := os.Rename(tmpPath, cfgPath); err != nil {
		return false, fmt.Errorf("原子替换 %s 失败: %w", cfgPath, err)
	}
	cleanupTmp = false
	_ = os.Chmod(cfgPath, 0600)

	// 5. SIGHUP 热重载；一旦失败立即原子回滚旧配置
	if err := reloadFn(wasActive); err != nil {
		_ = writeFileAtomic0600(cfgPath, oldBytes)
		_ = restoreFn(wasActive)
		return false, fmt.Errorf("sing-box 热重载失败，已自动回滚至原配置确保不断连: %w", err)
	}

	return true, nil
}

func pruneWarpConfigBackups(cfgPath string, keep int) {
	matches, _ := filepath.Glob(cfgPath + ".*.warp.bak")
	if len(matches) <= keep {
		return
	}
	slices.Sort(matches)
	slices.Reverse(matches)
	for i := keep; i < len(matches); i++ {
		_ = os.Remove(matches[i])
	}
}

func writeFileAtomic0600(path string, data []byte) error {
	tmp := fmt.Sprintf("%s.%d.rollback.tmp", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if wErr := os.WriteFile(path, data, 0600); wErr != nil {
			return wErr
		}
		_ = os.Chmod(path, 0600)
	}
	return nil
}

func defaultValidateSingBoxConfig(tmpPath string) error {
	bin, err := locateSingBoxBin()
	if err != nil {
		// 本地无 sing-box 二进制时不阻断单元测试或仅配置编辑场景，生产环境均有 /usr/local/bin/sing-box
		if _, statErr := os.Stat(constant.SingBoxConfigFile); os.IsNotExist(statErr) {
			return nil
		}
		return fmt.Errorf("未找到 sing-box 可执行文件: %w", err)
	}
	if out, err := exec.Command(bin, "check", "-c", tmpPath).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func locateSingBoxBin() (string, error) {
	if p, err := exec.LookPath("sing-box"); err == nil {
		return p, nil
	}
	for _, candidate := range []string{constant.SingBoxInstallDir, "/usr/bin/sing-box"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", os.ErrNotExist
}

func defaultIsSingBoxActive() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	out, err := exec.Command("systemctl", "is-active", "sing-box").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func defaultReloadSingBoxService(wasActive bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	if !wasActive {
		return exec.Command("systemctl", "restart", "sing-box").Run()
	}
	// 利用 sing-box.service 的 ExecReload=/bin/kill -HUP $MAINPID 实现零断流重载
	if err := exec.Command("systemctl", "reload", "sing-box").Run(); err != nil {
		if rErr := exec.Command("systemctl", "restart", "sing-box").Run(); rErr != nil {
			return rErr
		}
	}
	// 短暂确认服务仍处于 active
	for range 5 {
		if defaultIsSingBoxActive() {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return errors.New("reload 后 sing-box 未处于 active 状态")
}

func defaultRestoreSingBoxService(wasActive bool) error {
	if _, err := exec.LookPath("systemctl"); err != nil || !wasActive {
		return nil
	}
	return exec.Command("systemctl", "restart", "sing-box").Run()
}
