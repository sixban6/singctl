// 文件职责：定义服务端 WARP 内置分流场景预设声明表、预设状态列表渲染、域名预设匹配与本地 SOCKS5 探活辅助。
package deploy

import (
	"net"
	"slices"
	"strings"
	"time"

	"singctl/internal/config"
)

// WarpPresetDef 描述内置 WARP 分流场景预设。
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

// WarpPresetState 包含预设元信息及当前是否走 WARP。
type WarpPresetState struct {
	WarpPresetDef
	Enabled bool `json:"enabled"`
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

// BuildPresetStateList 结合当前配置计算所有内置预设的启用状态。
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

// FindPresetByHost 根据目标域名识别最匹配的内置预设。
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

// NeedsWarpTunnel 判断该分流配置在运行时是否会将任何流量导向 WARP 出站。
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

// CheckWarpSocksPort 检查本地 127.0.0.1:40000 SOCKS5 端口是否可连接。
func CheckWarpSocksPort() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 1500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
