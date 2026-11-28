// 文件职责：维护客户端智能分流预设目录（AI/流媒体/游戏/社交/办公等）及默认策略组解析规则。
package singbox

import (
	"slices"
	"strings"

	"singctl/internal/config"
	"singctl/internal/singbox/sboption"
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
	CustomRules  []config.TrafficCustomRule `json:"customRules,omitempty"`
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
		Name:           "Cursor / Perplexity / Grok / AI 服务",
		Category:       "ai",
		CategoryLabel:  "AI 大模型",
		Description:    "AI 编程 IDE、新兴 AI 搜索引擎与代理服务",
		DomainsSummary: "cursor.sh / cursor.com / perplexity.ai / grok.com / x.ai / z.ai / usemagpie.ai / exa.ai / models.dev",
		DefaultOn:      true,
		PreferVPS:      true,
		DomainSuffixes: []string{"cursor.sh", "cursor.com", "perplexity.ai", "x.ai", "grok.com", "z.ai", "usemagpie.ai", "exa.ai", "models.dev"},
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
		{Tag: "AI", Type: "selector"},
		{Tag: "#VPS", Type: "selector"},
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
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return DefaultClientRoutingGroups(), directTag
	}
	return inspectOutboundsFromDoc(doc)
}

func inspectOutboundsFromDoc(doc *sboption.Document) (groups []ClientRoutingGroupInfo, directTag string) {
	directTag = "#DC"
	if doc == nil {
		return DefaultClientRoutingGroups(), directTag
	}
	seen := make(map[string]bool)
	firstDirect := ""
	hasHashDC := false

	for _, ob := range doc.Outbounds {
		tag := strings.TrimSpace(ob.Tag)
		if tag == "" {
			continue
		}
		switch ob.Type {
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
			groups = append(groups, ClientRoutingGroupInfo{
				Tag:     tag,
				Type:    ob.Type,
				Default: strings.TrimSpace(ob.Default),
				Count:   len(ob.Outbounds),
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
