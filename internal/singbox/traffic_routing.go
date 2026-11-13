package singbox

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"singctl/internal/config"
)

// TrafficCategoryInfo 描述客户端智能分流的分组分类元信息。
type TrafficCategoryInfo struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	DefaultDest string `json:"defaultDest"`
}

// TrafficPresetDef 定义单条内置分流预设规则。
type TrafficPresetDef struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Category       string   `json:"category"`
	CategoryLabel  string   `json:"categoryLabel"`
	Description    string   `json:"description"`
	DomainsSummary string   `json:"domainsSummary"`
	DefaultOn      bool     `json:"defaultOn"`
	PreferVPS      bool     `json:"preferVPS"`
	PreferAuto     bool     `json:"preferAuto,omitempty"`
	DomainSuffixes []string `json:"domainSuffixes,omitempty"`
	RuleSets       []string `json:"ruleSets,omitempty"`
}

// ClientRoutingGroupInfo 描述 sing-box config.json 中的可选策略组。
type ClientRoutingGroupInfo struct {
	Tag     string `json:"tag"`
	Type    string `json:"type"`
	Default string `json:"default,omitempty"`
	Count   int    `json:"count"`
}

// ClientRoutingPresetState 表示向前端展示的单条分流项完整状态。
type ClientRoutingPresetState struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Category        string `json:"category"`
	CategoryLabel   string `json:"categoryLabel"`
	Description     string `json:"description"`
	DomainsSummary  string `json:"domainsSummary"`
	DefaultOn       bool   `json:"defaultOn"`
	DefaultOutbound string `json:"defaultOutbound"`
	Enabled         bool   `json:"enabled"`
	SelectedGroup   string `json:"selectedGroup"`
	EffectiveDest   string `json:"effectiveDest"`
	Customized      bool   `json:"customized"`
}

// ClientRoutingReport 聚合客户端「智能分流开关中心」所需全部状态。
type ClientRoutingReport struct {
	Groups       []ClientRoutingGroupInfo   `json:"groups"`
	DirectTag    string                     `json:"directTag"`
	Categories   []TrafficCategoryInfo      `json:"categories"`
	Items        []ClientRoutingPresetState `json:"items"`
	EnabledCount int                        `json:"enabledCount"`
	CustomCount  int                        `json:"customCount"`
	TotalCount   int                        `json:"totalCount"`
	HasConfig    bool                       `json:"hasConfig"`
	LastError    string                     `json:"lastError,omitempty"`
}

var clientRoutingCategories = []TrafficCategoryInfo{
	{
		ID:          "ai",
		Label:       "AI 大模型",
		Description: "OpenAI、Claude、Gemini 等 AI 服务，默认走 #VPS 分组以降低共享机场风控封号风险",
		DefaultDest: "#VPS",
	},
	{
		ID:          "streaming",
		Label:       "流媒体与影音",
		Description: "YouTube、Netflix、Disney+ 等国际影音站点，默认走 Proxy，可按平台切换专享节点组",
		DefaultDest: "Proxy",
	},
	{
		ID:          "gaming",
		Label:       "游戏与主机",
		Description: "Steam、Epic、PlayStation、Xbox 与海外手游加速，默认走 Proxy，支持单独切换节点组或直连",
		DefaultDest: "Proxy",
	},
	{
		ID:          "social",
		Label:       "社交、开发与支付",
		Description: "Google、Telegram、X、GitHub 与海外支付，默认走 Proxy（匹配顺序在 AI 专项之后）",
		DefaultDest: "Proxy",
	},
	{
		ID:          "office",
		Label:       "跨国办公与生态",
		Description: "Apple 与 Microsoft / OneDrive 默认直连 (#DC) 保障系统更新速度；需解锁或海外加速时可开启",
		DefaultDest: "直连 #DC",
	},
}

var clientRoutingPresets = []TrafficPresetDef{
	// 1. AI 大模型 (全部默认开启，默认推荐走 #VPS -> AI -> Proxy)
	{
		ID:             "openai",
		Name:           "OpenAI / ChatGPT",
		Category:       "ai",
		CategoryLabel:  "AI 大模型",
		Description:    "ChatGPT 网页端、API 接口与静态资源 CDN",
		DomainsSummary: "openai.com / chatgpt.com / oaistatic.com / oaiusercontent.com",
		DefaultOn:      true,
		PreferVPS:      true,
		DomainSuffixes: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"},
	},
	{
		ID:             "claude",
		Name:           "Claude (Anthropic)",
		Category:       "ai",
		CategoryLabel:  "AI 大模型",
		Description:    "Claude 网页端与 Anthropic API 接口（对出口 IP 纯净度敏感）",
		DomainsSummary: "anthropic.com / claude.ai / claude.com",
		DefaultOn:      true,
		PreferVPS:      true,
		DomainSuffixes: []string{"anthropic.com", "claude.ai", "claude.com"},
	},
	{
		ID:             "gemini",
		Name:           "Gemini / AI Studio",
		Category:       "ai",
		CategoryLabel:  "AI 大模型",
		Description:    "Google Gemini、AI Studio、NotebookLM 与 DeepMind（优先于通用 Google 分流）",
		DomainsSummary: "gemini.google.com / aistudio.google.com / notebooklm.google.com / deepmind.*",
		DefaultOn:      true,
		PreferVPS:      true,
		DomainSuffixes: []string{
			"gemini.google.com",
			"aistudio.google.com",
			"generativelanguage.googleapis.com",
			"makersuite.google.com",
			"deepmind.com",
			"deepmind.google",
			"bard.google.com",
			"notebooklm.google.com",
		},
	},
	{
		ID:             "ai_dev",
		Name:           "Cursor / Perplexity / Grok",
		Category:       "ai",
		CategoryLabel:  "AI 大模型",
		Description:    "AI 编程 IDE 与新一代 AI 搜索引擎",
		DomainsSummary: "cursor.sh / cursor.com / perplexity.ai / grok.com / x.ai / z.ai",
		DefaultOn:      true,
		PreferVPS:      true,
		DomainSuffixes: []string{"cursor.sh", "cursor.com", "perplexity.ai", "x.ai", "grok.com", "z.ai"},
	},
	{
		ID:             "ai_other",
		Name:           "其他 AI 平台兜底",
		Category:       "ai",
		CategoryLabel:  "AI 大模型",
		Description:    "Poe、Copilot、HuggingFace 等社区维护 AI 规则集合集",
		DomainsSummary: "规则集 geosite-chat",
		DefaultOn:      true,
		PreferVPS:      true,
		RuleSets:       []string{"geosite-chat"},
	},

	// 2. 流媒体与影音 (全部默认开启，默认走 Proxy)
	{
		ID:             "youtube",
		Name:           "YouTube",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "YouTube 视频流与 GoogleVideo CDN（优先于通用 Google 分流）",
		DomainsSummary: "规则集 geosite-youtube",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-youtube"},
	},
	{
		ID:             "netflix",
		Name:           "Netflix",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "Netflix 全平台域名与媒体 IP 段（建议指派解锁节点组）",
		DomainsSummary: "规则集 geosite-netflix + geoip-netflix",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-netflix", "geoip-netflix"},
	},
	{
		ID:             "disney",
		Name:           "Disney+",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "Disney+ 流媒体认证与视频分流",
		DomainsSummary: "规则集 geosite-disney",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-disney"},
	},
	{
		ID:             "hbo_prime",
		Name:           "HBO / Prime Video",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "Max (HBO) 与 Amazon Prime Video",
		DomainsSummary: "规则集 geosite-hbo + geosite-primevideo",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-hbo", "geosite-primevideo"},
	},
	{
		ID:             "tiktok",
		Name:           "TikTok",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "TikTok 国际版短视频（常需指定特定地区节点组）",
		DomainsSummary: "规则集 geosite-tiktok",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-tiktok"},
	},
	{
		ID:             "spotify",
		Name:           "Spotify",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "Spotify 音乐流媒体",
		DomainsSummary: "规则集 geosite-spotify",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-spotify"},
	},
	{
		ID:             "missav",
		Name:           "MissAV",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "主站镜像域名与后台视频切片 CDN（常因 Cloudflare 阻断需换特定节点）",
		DomainsSummary: "missav.ws / .ai / .com / .live + surrit.com / nineyu.com",
		DefaultOn:      true,
		DomainSuffixes: []string{"missav.ws", "missav.ai", "missav.com", "missav.live", "surrit.com", "nineyu.com"},
	},
	{
		ID:             "porn",
		Name:           "成人站点合集",
		Category:       "streaming",
		CategoryLabel:  "流媒体与影音",
		Description:    "常见海外成人影音域名集合",
		DomainsSummary: "规则集 geosite-porn",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-porn"},
	},

	// 3. 游戏与主机 (全部默认开启，默认走 Proxy)
	{
		ID:             "steam",
		Name:           "Steam",
		Category:       "gaming",
		CategoryLabel:  "游戏与主机",
		Description:    "Steam 商店、社区与创意工坊（如只需全速直连下载可一键关闭）",
		DomainsSummary: "规则集 geosite-steam",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-steam"},
	},
	{
		ID:             "epic",
		Name:           "Epic Games",
		Category:       "gaming",
		CategoryLabel:  "游戏与主机",
		Description:    "Epic 商店登录与领游戏接口",
		DomainsSummary: "规则集 geosite-epic",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-epic"},
	},
	{
		ID:             "playstation",
		Name:           "PlayStation",
		Category:       "gaming",
		CategoryLabel:  "游戏与主机",
		Description:    "PSN 商店、奖杯同步与云存档服务",
		DomainsSummary: "规则集 geosite-playstation",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-playstation"},
	},
	{
		ID:             "xbox",
		Name:           "Xbox Live",
		Category:       "gaming",
		CategoryLabel:  "游戏与主机",
		Description:    "Xbox 主机服务、Game Pass 与联机认证",
		DomainsSummary: "规则集 geosite-xbox",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-xbox"},
	},
	{
		ID:             "hok",
		Name:           "王者荣耀海外 (HoK)",
		Category:       "gaming",
		CategoryLabel:  "游戏与主机",
		Description:    "Honor of Kings 国际服登录与资源更新 CDN（默认走 #Auto 低延迟组与 HK ECS 解析）",
		DomainsSummary: "geosite-hok + sgameglobal.com / ovscdns.com / apdcdn.com",
		DefaultOn:      true,
		PreferAuto:     true,
		RuleSets:       []string{"geosite-hok"},
		DomainSuffixes: []string{"sgameglobal.com", "ovscdns.com", "apdcdn.com"},
	},

	// 4. 社交、开发与支付 (全部默认开启，默认走 Proxy)
	{
		ID:             "google",
		Name:           "Google 搜索与服务",
		Category:       "social",
		CategoryLabel:  "社交、开发与支付",
		Description:    "Google Search、Gmail、Drive、Play 等全家桶服务",
		DomainsSummary: "规则集 geosite-google + geoip-google",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-google", "geoip-google"},
	},
	{
		ID:             "telegram",
		Name:           "Telegram",
		Category:       "social",
		CategoryLabel:  "社交、开发与支付",
		Description:    "Telegram 域名与核心服务器 IP 段",
		DomainsSummary: "规则集 geosite-telegram + geoip-telegram",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-telegram", "geoip-telegram"},
	},
	{
		ID:             "x_twitter",
		Name:           "X (Twitter)",
		Category:       "social",
		CategoryLabel:  "社交、开发与支付",
		Description:    "X / Twitter 与图床媒体 CDN",
		DomainsSummary: "规则集 geosite-x",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-x"},
	},
	{
		ID:             "github",
		Name:           "GitHub / SourceHut",
		Category:       "social",
		CategoryLabel:  "社交、开发与支付",
		Description:    "GitHub 代码托管、Releases 下载与 SourceHut",
		DomainsSummary: "规则集 geosite-github + geosite-sourcehut",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-github", "geosite-sourcehut"},
	},
	{
		ID:             "paypal_crypto",
		Name:           "PayPal & 加密货币",
		Category:       "social",
		CategoryLabel:  "社交、开发与支付",
		Description:    "PayPal 国际支付与常见加密货币平台",
		DomainsSummary: "规则集 geosite-paypal + geosite-cryptocurrency",
		DefaultOn:      true,
		RuleSets:       []string{"geosite-paypal", "geosite-cryptocurrency"},
	},

	// 5. 跨国办公与生态 (默认关闭 = 直连 #DC；打开则默认走 Proxy)
	{
		ID:             "apple",
		Name:           "Apple 服务",
		Category:       "office",
		CategoryLabel:  "跨国办公与生态",
		Description:    "iCloud、App Store 与系统更新（默认直连跑满国内 CDN；需美区/Apple AI 时开启）",
		DomainsSummary: "规则集 geosite-apple + geoip-apple",
		DefaultOn:      false,
		RuleSets:       []string{"geosite-apple", "geoip-apple"},
	},
	{
		ID:             "microsoft",
		Name:           "Microsoft & OneDrive",
		Category:       "office",
		CategoryLabel:  "跨国办公与生态",
		Description:    "Windows 更新、Office 365 与 OneDrive 同步（默认直连 #DC；限速卡顿时开启）",
		DomainsSummary: "规则集 geosite-microsoft + geosite-onedrive",
		DefaultOn:      false,
		RuleSets:       []string{"geosite-microsoft", "geosite-onedrive"},
	},
}

// ClientRoutingCategories 返回分类元数据副本。
func ClientRoutingCategories() []TrafficCategoryInfo {
	return slices.Clone(clientRoutingCategories)
}

// AllClientRoutingPresets 返回客户端智能分流全部内置预设副本。
func AllClientRoutingPresets() []TrafficPresetDef {
	out := make([]TrafficPresetDef, len(clientRoutingPresets))
	for i, p := range clientRoutingPresets {
		p.DomainSuffixes = slices.Clone(p.DomainSuffixes)
		p.RuleSets = slices.Clone(p.RuleSets)
		out[i] = p
	}
	return out
}

// LookupClientRoutingPreset 根据 ID 查找内置预设定义。
func LookupClientRoutingPreset(id string) (TrafficPresetDef, bool) {
	key := strings.ToLower(strings.TrimSpace(id))
	for _, p := range clientRoutingPresets {
		if p.ID == key {
			p.DomainSuffixes = slices.Clone(p.DomainSuffixes)
			p.RuleSets = slices.Clone(p.RuleSets)
			return p, true
		}
	}
	return TrafficPresetDef{}, false
}

// DefaultClientRoutingGroups 当磁盘尚无 config.json 时提供的标准客户端策略组列表。
func DefaultClientRoutingGroups() []ClientRoutingGroupInfo {
	return []ClientRoutingGroupInfo{
		{Tag: "Proxy", Type: "selector"},
		{Tag: "#VPS", Type: "selector"},
		{Tag: "AI", Type: "selector"},
		{Tag: "#Auto", Type: "urltest"},
		{Tag: "#Nodes", Type: "selector"},
	}
}

// InspectClientRoutingOutbounds 从 sing-box config.json 中提取全部可切换代理策略组与直连出站 tag。
func InspectClientRoutingOutbounds(rawJSON string) (groups []ClientRoutingGroupInfo, directTag string) {
	directTag = "#DC"
	if strings.TrimSpace(rawJSON) == "" {
		return DefaultClientRoutingGroups(), directTag
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return DefaultClientRoutingGroups(), directTag
	}
	return inspectOutboundsFromMap(doc)
}

func inspectOutboundsFromMap(doc map[string]any) (groups []ClientRoutingGroupInfo, directTag string) {
	directTag = "#DC"
	rawOutbounds, _ := doc["outbounds"].([]any)
	seen := make(map[string]bool)
	firstDirect := ""
	hasHashDC := false

	for _, item := range rawOutbounds {
		om, ok := item.(map[string]any)
		if !ok {
			continue
		}
		typ, _ := om["type"].(string)
		tag := strings.TrimSpace(stringField(om, "tag"))
		if tag == "" {
			continue
		}
		switch typ {
		case "direct":
			if tag == "#DC" {
				hasHashDC = true
			}
			if firstDirect == "" {
				firstDirect = tag
			}
		case "selector", "urltest":
			if seen[tag] {
				continue
			}
			seen[tag] = true
			defTag := strings.TrimSpace(stringField(om, "default"))
			memberList, _ := om["outbounds"].([]any)
			groups = append(groups, ClientRoutingGroupInfo{
				Tag:     tag,
				Type:    typ,
				Default: defTag,
				Count:   len(memberList),
			})
		}
	}
	if hasHashDC {
		directTag = "#DC"
	} else if firstDirect != "" {
		directTag = firstDirect
	}
	if len(groups) == 0 {
		groups = DefaultClientRoutingGroups()
	}
	return groups, directTag
}

// ResolvePresetDefaultOutbound 根据预设属性与实际存在的策略组列表解析推荐默认分组。
// AI 类按 `#VPS` -> `AI` -> `Proxy` 逐级回退；HoK 默认 `#Auto` -> `Proxy` -> `#VPS`；
// 其他业务默认 `Proxy`（若无则回退首个可用代理组）。
func ResolvePresetDefaultOutbound(preferVPS, preferAuto bool, groupTags []string) string {
	candidates := []string{"Proxy", "#VPS", "#Auto"}
	fallback := "Proxy"
	switch {
	case preferVPS:
		candidates = []string{"#VPS", "AI", "Proxy"}
		fallback = "#VPS"
	case preferAuto:
		candidates = []string{"#Auto", "Proxy", "#VPS"}
		fallback = "#Auto"
	}
	for _, candidate := range candidates {
		if slices.Contains(groupTags, candidate) {
			return candidate
		}
	}
	if len(groupTags) > 0 {
		return groupTags[0]
	}
	return fallback
}

// BuildClientRoutingReport 结合 singctl.yaml 与当前 sing-box config.json 生成界面渲染所需的全景报告。
func BuildClientRoutingReport(cfg *config.Config, rawConfigJSON string) ClientRoutingReport {
	var tr config.TrafficRoutingConfig
	if cfg != nil {
		tr = cfg.TrafficRouting.Normalized()
	}

	groups, directTag := InspectClientRoutingOutbounds(rawConfigJSON)
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}

	items := make([]ClientRoutingPresetState, 0, len(clientRoutingPresets))
	enabledCount := 0
	customCount := 0
	for _, p := range clientRoutingPresets {
		defOutbound := ResolvePresetDefaultOutbound(p.PreferVPS, p.PreferAuto, groupTags)
		enabled, configuredGroup := tr.PresetState(p.ID, p.DefaultOn, defOutbound)
		// 若配置中的目标策略组在当前订阅生成的 config.json 中不存在，展示并生效时回退安全默认组
		selectedGroup := configuredGroup
		if !slices.Contains(groupTags, selectedGroup) {
			selectedGroup = defOutbound
		}
		effectiveDest := selectedGroup
		if !enabled {
			effectiveDest = directTag
		}
		if enabled {
			enabledCount++
		}
		customized := false
		if ov, ok := tr.Presets[p.ID]; ok {
			if ov.Enabled != nil && *ov.Enabled != p.DefaultOn {
				customized = true
			}
			if ov.Outbound != "" && ov.Outbound != defOutbound {
				customized = true
			}
		}
		if customized {
			customCount++
		}
		items = append(items, ClientRoutingPresetState{
			ID:              p.ID,
			Name:            p.Name,
			Category:        p.Category,
			CategoryLabel:   p.CategoryLabel,
			Description:     p.Description,
			DomainsSummary:  p.DomainsSummary,
			DefaultOn:       p.DefaultOn,
			DefaultOutbound: defOutbound,
			Enabled:         enabled,
			SelectedGroup:   selectedGroup,
			EffectiveDest:   effectiveDest,
			Customized:      customized,
		})
	}

	return ClientRoutingReport{
		Groups:       groups,
		DirectTag:    directTag,
		Categories:   ClientRoutingCategories(),
		Items:        items,
		EnabledCount: enabledCount,
		CustomCount:  customCount,
		TotalCount:   len(items),
		HasConfig:    strings.TrimSpace(rawConfigJSON) != "",
	}
}

// ApplyTrafficRoutingToConfigJSON 将客户端「智能分流开关中心」策略幂等地编译注入 sing-box config.json。
// 该函数同时清理 singgen 模板中同源规则集/域名条目的散落重复项，使开启选组或关闭直连（#DC）均 100% 精准生效，
// 并同时同步 dns.rules（开启走 dns_proxy，关闭走 dns_local）。
func ApplyTrafficRoutingToConfigJSON(rawJSON string, tr config.TrafficRoutingConfig, cr config.CustomRulesConfig) (string, error) {
	if strings.TrimSpace(rawJSON) == "" {
		return rawJSON, nil
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return "", fmt.Errorf("解析 sing-box config.json 失败: %w", err)
	}

	routeMap, ok := doc["route"].(map[string]any)
	if !ok {
		routeMap = map[string]any{}
		doc["route"] = routeMap
	}

	groups, directTag := inspectOutboundsFromMap(doc)
	groupTags := make([]string, len(groups))
	for i, g := range groups {
		groupTags[i] = g.Tag
	}

	existingRouteRules, _ := routeMap["rules"].([]any)
	normTR := tr.Normalized()
	preserveNativeHoK := shouldPreserveNativeHoK(normTR, groupTags, existingRouteRules)

	definedRuleSets := collectDefinedRuleSetTags(routeMap)
	managedSuffixes, managedRuleSets := collectManagedSignatures(preserveNativeHoK)
	customRouteSet := buildCustomRuleSignatures(cr)

	// 1. 剥离 route.rules 中由本模块接管的散落预设规则，并定位插入槽位（广告拦截 geosite-ad1/ad2 之后、cn/!cn 之前）
	strippedRouteRules := stripManagedRouteRules(existingRouteRules, managedSuffixes, managedRuleSets, customRouteSet)
	managedRouteRules := compileManagedRouteRules(normTR, groupTags, directTag, definedRuleSets, preserveNativeHoK)
	insertRouteIdx := findTrafficRouteInsertIndex(strippedRouteRules)

	finalRouteRules := make([]any, 0, len(strippedRouteRules)+len(managedRouteRules))
	finalRouteRules = append(finalRouteRules, strippedRouteRules[:insertRouteIdx]...)
	for _, mr := range managedRouteRules {
		finalRouteRules = append(finalRouteRules, mr)
	}
	finalRouteRules = append(finalRouteRules, strippedRouteRules[insertRouteIdx:]...)
	routeMap["rules"] = finalRouteRules

	// 2. 同步编译并注入 dns.rules（仅处理明确存在的 DNS server tag）
	if dnsMap, ok := doc["dns"].(map[string]any); ok {
		proxyDNS, directDNS := resolveClientDNSTags(dnsMap)
		if proxyDNS != "" || directDNS != "" {
			existingDNSRules, _ := dnsMap["rules"].([]any)
			strippedDNSRules := stripManagedDNSRules(existingDNSRules, managedSuffixes, managedRuleSets, customRouteSet)
			managedDNSRules := compileManagedDNSRules(normTR, proxyDNS, directDNS, definedRuleSets, preserveNativeHoK)
			insertDNSIdx := findTrafficDNSInsertIndex(strippedDNSRules)

			finalDNSRules := make([]any, 0, len(strippedDNSRules)+len(managedDNSRules))
			finalDNSRules = append(finalDNSRules, strippedDNSRules[:insertDNSIdx]...)
			for _, dr := range managedDNSRules {
				finalDNSRules = append(finalDNSRules, dr)
			}
			finalDNSRules = append(finalDNSRules, strippedDNSRules[insertDNSIdx:]...)
			dnsMap["rules"] = finalDNSRules
		}
	}

	return PrettyJSON(mustMarshalRawJSON(doc))
}

func mustMarshalRawJSON(doc map[string]any) string {
	b, _ := json.Marshal(doc)
	return string(b)
}

func stringField(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

func collectDefinedRuleSetTags(routeMap map[string]any) map[string]bool {
	out := make(map[string]bool)
	rawRS, _ := routeMap["rule_set"].([]any)
	for _, item := range rawRS {
		if rm, ok := item.(map[string]any); ok {
			if tag := strings.TrimSpace(stringField(rm, "tag")); tag != "" {
				out[tag] = true
			}
		}
	}
	return out
}

func shouldPreserveNativeHoK(tr config.TrafficRoutingConfig, groupTags []string, existingRouteRules []any) bool {
	defOut := ResolvePresetDefaultOutbound(false, true, groupTags)
	enabled, out := tr.PresetState("hok", true, defOut)
	if !enabled || (out != "" && out != defOut) {
		return false
	}
	// 仅当现存配置仍保有原生单 string "geosite-hok" -> defOut (#Auto) 规则时原样保留（含 203.80.96.0/24 HK ECS）；
	// 若曾切换直连或其他组后恢复默认，则走受管重建流程将其写回 #Auto。
	for _, r := range existingRouteRules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if rs := extractStringOrSlice(rm["rule_set"]); slices.Equal(rs, []string{"geosite-hok"}) && stringField(rm, "outbound") == defOut {
			return true
		}
	}
	return false
}

func collectManagedSignatures(preserveNativeHoK bool) (suffixes map[string]bool, ruleSets map[string]bool) {
	suffixes = make(map[string]bool)
	ruleSets = make(map[string]bool)
	for _, p := range clientRoutingPresets {
		if preserveNativeHoK && p.ID == "hok" {
			continue
		}
		for _, d := range p.DomainSuffixes {
			suffixes[strings.ToLower(strings.TrimSpace(d))] = true
		}
		for _, rs := range p.RuleSets {
			ruleSets[strings.ToLower(strings.TrimSpace(rs))] = true
		}
	}
	return suffixes, ruleSets
}

func isManagedSuffix(raw string, managed map[string]bool) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if managed[s] {
		return true
	}
	// singgen 模板包含 download.sgameglobal.com / res.sgameglobal.com 等子域，仅当 HoK 被接管时统一收敛至 sgameglobal.com
	return managed["sgameglobal.com"] && (s == "sgameglobal.com" || strings.HasSuffix(s, ".sgameglobal.com"))
}

func extractStringOrSlice(raw any) []string {
	switch v := raw.(type) {
	case string:
		if s := strings.TrimSpace(v); s != "" {
			return []string{s}
		}
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if t := strings.TrimSpace(s); t != "" {
					out = append(out, t)
				}
			}
		}
		return out
	}
	return nil
}

type customSignature struct {
	routeJSONs map[string]bool
	dnsJSONs   map[string]bool
}

func buildCustomRuleSignatures(cr config.CustomRulesConfig) customSignature {
	sig := customSignature{
		routeJSONs: make(map[string]bool, len(cr.Route)),
		dnsJSONs:   make(map[string]bool, len(cr.DNS)),
	}
	for _, r := range cr.Route {
		if b, err := json.Marshal(r); err == nil {
			sig.routeJSONs[string(b)] = true
		}
	}
	for _, d := range cr.DNS {
		if b, err := json.Marshal(d); err == nil {
			sig.dnsJSONs[string(b)] = true
		}
	}
	return sig
}

func isProtectedCustomRule(rm map[string]any, known map[string]bool) bool {
	if len(known) == 0 {
		return false
	}
	b, err := json.Marshal(rm)
	if err != nil {
		return false
	}
	return known[string(b)]
}

func hasOnlyAllowedKeys(rm map[string]any, allowed map[string]bool) bool {
	for k := range rm {
		if !allowed[k] {
			return false
		}
	}
	return true
}

var allowedPureRouteRuleKeys = map[string]bool{
	"action":        true,
	"outbound":      true,
	"domain_suffix": true,
	"rule_set":      true,
}

var allowedPureDNSRuleKeys = map[string]bool{
	"action":        true,
	"server":        true,
	"client_subnet": true,
	"domain_suffix": true,
	"rule_set":      true,
}

func stripManagedFromPureRule(rm map[string]any, suffixes, ruleSets map[string]bool) (keep bool, updated map[string]any) {
	clone := make(map[string]any, len(rm))
	for k, v := range rm {
		clone[k] = v
	}

	hasRemainingMatcher := false
	hasManagedList := false
	changed := false

	if rawDS, exists := clone["domain_suffix"]; exists {
		hasManagedList = true
		ds := extractStringOrSlice(rawDS)
		filtered := make([]string, 0, len(ds))
		for _, item := range ds {
			if !isManagedSuffix(item, suffixes) {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
		}
		if len(filtered) > 0 {
			clone["domain_suffix"] = filtered
			hasRemainingMatcher = true
		} else {
			delete(clone, "domain_suffix")
		}
	}

	if rawRS, exists := clone["rule_set"]; exists {
		hasManagedList = true
		rs := extractStringOrSlice(rawRS)
		filtered := make([]string, 0, len(rs))
		for _, item := range rs {
			if !ruleSets[strings.ToLower(strings.TrimSpace(item))] {
				filtered = append(filtered, item)
			} else {
				changed = true
			}
		}
		if len(filtered) > 0 {
			clone["rule_set"] = filtered
			hasRemainingMatcher = true
		} else {
			delete(clone, "rule_set")
		}
	}

	if !hasManagedList || !changed {
		return true, rm
	}
	if !hasRemainingMatcher {
		return false, nil
	}
	return true, clone
}

func stripManagedRouteRules(rules []any, suffixes, ruleSets map[string]bool, crSig customSignature) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		action := strings.ToLower(strings.TrimSpace(stringField(rm, "action")))
		if (action != "" && action != "route") ||
			!hasOnlyAllowedKeys(rm, allowedPureRouteRuleKeys) ||
			isProtectedCustomRule(rm, crSig.routeJSONs) {
			out = append(out, r)
			continue
		}
		keep, updated := stripManagedFromPureRule(rm, suffixes, ruleSets)
		if keep {
			out = append(out, updated)
		}
	}
	return out
}

func stripManagedDNSRules(rules []any, suffixes, ruleSets map[string]bool, crSig customSignature) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			out = append(out, r)
			continue
		}
		action := strings.ToLower(strings.TrimSpace(stringField(rm, "action")))
		if (action != "" && action != "route") ||
			!hasOnlyAllowedKeys(rm, allowedPureDNSRuleKeys) ||
			isProtectedCustomRule(rm, crSig.dnsJSONs) {
			out = append(out, r)
			continue
		}
		keep, updated := stripManagedFromPureRule(rm, suffixes, ruleSets)
		if keep {
			out = append(out, updated)
		}
	}
	return out
}

type compiledMatcherRule struct {
	isRuleSet bool
	values    []string
	target    string
}

func compileManagedRouteRules(tr config.TrafficRoutingConfig, groupTags []string, directTag string, definedRuleSets map[string]bool, preserveNativeHoK bool) []map[string]any {
	var staged []compiledMatcherRule
	appendStaged := func(isRuleSet bool, values []string, outbound string) {
		if len(values) == 0 || outbound == "" {
			return
		}
		if n := len(staged); n > 0 && staged[n-1].isRuleSet == isRuleSet && staged[n-1].target == outbound {
			for _, v := range values {
				if !slices.Contains(staged[n-1].values, v) {
					staged[n-1].values = append(staged[n-1].values, v)
				}
			}
			return
		}
		staged = append(staged, compiledMatcherRule{
			isRuleSet: isRuleSet,
			values:    slices.Clone(values),
			target:    outbound,
		})
	}

	for _, p := range clientRoutingPresets {
		if preserveNativeHoK && p.ID == "hok" {
			continue
		}
		defOutbound := ResolvePresetDefaultOutbound(p.PreferVPS, p.PreferAuto, groupTags)
		enabled, selectedGroup := tr.PresetState(p.ID, p.DefaultOn, defOutbound)
		targetOutbound := selectedGroup
		if !slices.Contains(groupTags, targetOutbound) {
			targetOutbound = defOutbound
		}
		if !enabled {
			targetOutbound = directTag
		}

		// sing-box 单条规则同时填 domain_suffix 与 rule_set 表示 AND；因此拆分为独立规则，并仅对相邻同类型同出站合并
		if len(p.DomainSuffixes) > 0 {
			appendStaged(false, p.DomainSuffixes, targetOutbound)
		}
		if len(p.RuleSets) > 0 {
			filteredRS := filterExistingRuleSets(p.RuleSets, definedRuleSets, false)
			appendStaged(true, filteredRS, targetOutbound)
		}
	}

	out := make([]map[string]any, 0, len(staged))
	for _, s := range staged {
		key := "domain_suffix"
		if s.isRuleSet {
			key = "rule_set"
		}
		out = append(out, map[string]any{
			"action":   "route",
			key:        s.values,
			"outbound": s.target,
		})
	}
	return out
}

func compileManagedDNSRules(tr config.TrafficRoutingConfig, proxyDNS, directDNS string, definedRuleSets map[string]bool, preserveNativeHoK bool) []map[string]any {
	var staged []compiledMatcherRule
	appendStaged := func(isRuleSet bool, values []string, server string) {
		if len(values) == 0 || server == "" {
			return
		}
		if n := len(staged); n > 0 && staged[n-1].isRuleSet == isRuleSet && staged[n-1].target == server {
			for _, v := range values {
				if !slices.Contains(staged[n-1].values, v) {
					staged[n-1].values = append(staged[n-1].values, v)
				}
			}
			return
		}
		staged = append(staged, compiledMatcherRule{
			isRuleSet: isRuleSet,
			values:    slices.Clone(values),
			target:    server,
		})
	}

	for _, p := range clientRoutingPresets {
		if preserveNativeHoK && p.ID == "hok" {
			continue
		}
		enabled, _ := tr.PresetState(p.ID, p.DefaultOn, "")
		targetDNS := proxyDNS
		if !enabled {
			targetDNS = directDNS
		}
		if targetDNS == "" {
			continue
		}
		if len(p.DomainSuffixes) > 0 {
			appendStaged(false, p.DomainSuffixes, targetDNS)
		}
		if len(p.RuleSets) > 0 {
			// DNS pre-match 仅匹配域名类 geosite-* 规则集，跳过纯 IP 类的 geoip-*
			filteredRS := filterExistingRuleSets(p.RuleSets, definedRuleSets, true)
			appendStaged(true, filteredRS, targetDNS)
		}
	}

	out := make([]map[string]any, 0, len(staged))
	for _, s := range staged {
		key := "domain_suffix"
		if s.isRuleSet {
			key = "rule_set"
		}
		out = append(out, map[string]any{
			key:      s.values,
			"server": s.target,
		})
	}
	return out
}

func filterExistingRuleSets(tags []string, defined map[string]bool, dnsDomainOnly bool) []string {
	if len(defined) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if dnsDomainOnly && strings.HasPrefix(strings.ToLower(tag), "geoip-") {
			continue
		}
		if defined[tag] {
			out = append(out, tag)
		}
	}
	return out
}

func resolveClientDNSTags(dnsMap map[string]any) (proxyTag, directTag string) {
	rawServers, _ := dnsMap["servers"].([]any)
	var allTags []string
	for _, item := range rawServers {
		sm, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tag := strings.TrimSpace(stringField(sm, "tag"))
		if tag != "" {
			allTags = append(allTags, tag)
		}
	}
	for _, candidate := range []string{"dns_local", "local", "direct"} {
		if slices.Contains(allTags, candidate) {
			directTag = candidate
			break
		}
	}
	for _, candidate := range []string{"dns_proxy", "remote", "dns_remote"} {
		if slices.Contains(allTags, candidate) {
			proxyTag = candidate
			break
		}
	}
	if proxyTag == "" {
		if f := strings.TrimSpace(stringField(dnsMap, "final")); f != "" && f != directTag {
			proxyTag = f
		}
	}
	return proxyTag, directTag
}

func findTrafficRouteInsertIndex(rules []any) int {
	// 首选锚点：广告拦截 rule (geosite-ad1 / geosite-ad2) 之后（保留私网/custom_rules/去广告在最前）
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if strings.EqualFold(stringField(rm, "action"), "reject") {
			for _, tag := range extractStringOrSlice(rm["rule_set"]) {
				if tag == "geosite-ad1" || tag == "geosite-ad2" {
					return i + 1
				}
			}
		}
	}
	// 次选锚点：通用国内/非国内兜底规则之前
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		for _, tag := range extractStringOrSlice(rm["rule_set"]) {
			if tag == "geosite-cn" || tag == "geosite-geolocation-!cn" || tag == "geoip-cn" {
				return i
			}
		}
	}
	// 保底锚点：跳过前序系统级规则 (sniff / hijack-dns / clash_mode / ip_is_private / reject)
	idx := 0
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(stringField(rm, "action")))
		_, hasClash := rm["clash_mode"]
		_, hasPrivate := rm["ip_is_private"]
		if action == "sniff" || action == "hijack-dns" || action == "reject" || hasClash || hasPrivate {
			idx = i + 1
		}
	}
	return idx
}

func findTrafficDNSInsertIndex(rules []any) int {
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		for _, tag := range extractStringOrSlice(rm["rule_set"]) {
			if tag == "geosite-cn" || tag == "geosite-geolocation-!cn" {
				return i
			}
		}
	}
	idx := 0
	for i, r := range rules {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if _, hasClash := rm["clash_mode"]; hasClash || strings.EqualFold(stringField(rm, "action"), "reject") {
			idx = i + 1
		}
	}
	return idx
}
