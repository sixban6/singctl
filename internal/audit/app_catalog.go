// 文件职责：声明式细粒度应用与品类识别词典（优先精准匹配常见 App，未命中回退规则集与内置服务特征）。
package audit

import (
	"cmp"
	"net"
	"strings"
)

// AppCategory 定义设备画像中的应用大类枚举。
type AppCategory string

const (
	AppCategoryVideo       AppCategory = "video"
	AppCategorySocial      AppCategory = "social"
	AppCategoryAIDev       AppCategory = "ai_dev"
	AppCategoryShopping    AppCategory = "shopping"
	AppCategoryGamingMusic AppCategory = "gaming_music"
	AppCategorySystem      AppCategory = "system"
	AppCategoryOther       AppCategory = "other"
)

// AppCatalogEntry 描述单个已识别应用的展示名、所属品类及是否属于系统/后台底座。
type AppCatalogEntry struct {
	Name          string
	Category      AppCategory
	CategoryLabel string
	IsInfra       bool
}

type appCategoryMeta struct {
	Category AppCategory
	IsInfra  bool
}

var categoryDisplayLabels = map[AppCategory]string{
	AppCategoryVideo:       "视频娱乐",
	AppCategorySocial:      "社交社区",
	AppCategoryAIDev:       "AI与开发",
	AppCategoryShopping:    "购物生活",
	AppCategoryGamingMusic: "游戏音乐",
	AppCategorySystem:      "系统与底座",
	AppCategoryOther:       "其他网站",
}

// CategoryDisplayLabel 返回应用品类的中文显示名称。
func CategoryDisplayLabel(cat AppCategory) string {
	return cmp.Or(categoryDisplayLabels[cat], "其他网站")
}

// fineAppSuffixCatalog 按最具体域名后缀优先（最长后缀先命中）拆分子业务，解决单一大厂多 App 混同问题。
var fineAppSuffixCatalog = map[string]string{
	// 腾讯系拆分
	"weixin.qq.com":      "微信",
	"wx.qq.com":          "微信",
	"weixinbridge.com":   "微信",
	"servicewechat.com":  "微信",
	"wechat.com":         "微信",
	"wxgateway.com":      "微信",
	"tenpay.com":         "微信",
	"v.qq.com":           "腾讯视频",
	"video.qq.com":       "腾讯视频",
	"vv.video.qq.com":    "腾讯视频",
	"wetvinfo.com":       "腾讯视频",
	"y.qq.com":           "QQ音乐",
	"qqmusic.qq.com":     "QQ音乐",
	"game.qq.com":        "腾讯游戏",
	"pvp.qq.com":         "腾讯游戏",
	"iegcom.com":         "腾讯游戏",
	"connect.qq.com":     "QQ",
	"im.qq.com":          "QQ",
	"qzone.qq.com":       "QQ",
	"qpic.cn":            "QQ",
	"qlogo.cn":           "QQ",
	"gtimg.cn":           "QQ",
	"qq.com":             "QQ",

	// 字节跳动系拆分
	"douyin.com":     "抖音",
	"douyinvod.com":  "抖音",
	"douyinpic.com":  "抖音",
	"douyincdn.com":  "抖音",
	"iesdouyin.com":  "抖音",
	"amemv.com":      "抖音",
	"tiktok.com":     "TikTok",
	"tiktokv.com":    "TikTok",
	"tiktokcdn.com":  "TikTok",
	"ttwstatic.com":  "TikTok",
	"feishu.cn":      "飞书",
	"feishucdn.com":  "飞书",
	"larksuite.com":  "飞书",
	"larkoffice.com": "飞书",
	"toutiao.com":    "今日头条",
	"toutiaocdn.com": "今日头条",
	"snssdk.com":     "今日头条",

	// 视频娱乐
	"youtube.com":     "YouTube",
	"googlevideo.com": "YouTube",
	"ytimg.com":       "YouTube",
	"youtu.be":        "YouTube",
	"ggpht.com":       "YouTube",
	"bilibili.com":    "哔哩哔哩 Bilibili",
	"bilivideo.com":   "哔哩哔哩 Bilibili",
	"bilivideo.cn":    "哔哩哔哩 Bilibili",
	"hdslb.com":       "哔哩哔哩 Bilibili",
	"biliapi.net":     "哔哩哔哩 Bilibili",
	"kuaishou.com":    "快手",
	"yximgs.com":      "快手",
	"gifshow.com":     "快手",
	"iqiyi.com":       "爱奇艺",
	"qiyipic.com":     "爱奇艺",
	"qy.net":          "爱奇艺",
	"youku.com":       "优酷",
	"ykimg.com":       "优酷",
	"netflix.com":     "Netflix",
	"nflxvideo.net":   "Netflix",
	"nflximg.net":     "Netflix",
	"nflxext.com":     "Netflix",
	"disneyplus.com":  "Disney+",
	"bamgrid.com":     "Disney+",
	"hbomax.com":      "HBO",
	"max.com":         "HBO",
	"primevideo.com":  "Prime Video",
	"twitch.tv":       "Twitch",
	"ttvnw.net":       "Twitch",

	// 社交社区
	"xiaohongshu.com":  "小红书",
	"xhscdn.com":       "小红书",
	"xhscdn.net":       "小红书",
	"zhihu.com":        "知乎",
	"zhimg.com":        "知乎",
	"weibo.com":        "微博",
	"weibo.cn":         "微博",
	"weibocdn.com":     "微博",
	"x.com":            "X (Twitter)",
	"twitter.com":      "X (Twitter)",
	"twimg.com":        "X (Twitter)",
	"t.co":             "X (Twitter)",
	"telegram.org":     "Telegram",
	"t.me":             "Telegram",
	"tdesktop.com":     "Telegram",
	"telegra.ph":       "Telegram",
	"discord.com":      "Discord",
	"discordapp.com":   "Discord",
	"discord.gg":       "Discord",
	"discord.media":    "Discord",
	"reddit.com":       "Reddit",
	"redd.it":          "Reddit",
	"redditmedia.com":  "Reddit",
	"redditstatic.com": "Reddit",
	"instagram.com":    "Instagram",
	"cdninstagram.com": "Instagram",
	"whatsapp.com":     "WhatsApp",
	"whatsapp.net":     "WhatsApp",
	"facebook.com":     "Meta / Facebook",
	"fbcdn.net":        "Meta / Facebook",
	"meta.ai":          "Meta / Facebook",

	// AI 与开发
	"openai.com":                        "OpenAI / ChatGPT",
	"chatgpt.com":                       "OpenAI / ChatGPT",
	"oaistatic.com":                     "OpenAI / ChatGPT",
	"oaiusercontent.com":                "OpenAI / ChatGPT",
	"anthropic.com":                     "Claude / Anthropic",
	"claude.ai":                         "Claude / Anthropic",
	"gemini.google.com":                 "Gemini",
	"aistudio.google.com":               "Gemini",
	"generativelanguage.googleapis.com": "Gemini",
	"grok.com":                          "xAI / Grok",
	"x.ai":                              "xAI / Grok",
	"github.com":                        "GitHub",
	"githubusercontent.com":             "GitHub",
	"githubassets.com":                  "GitHub",
	"github.io":                         "GitHub",
	"dingtalk.com":                      "钉钉",
	"notion.so":                         "Notion",
	"notion.site":                       "Notion",
	"notion-static.com":                 "Notion",
	"cursor.sh":                         "Cursor",
	"cursor.com":                        "Cursor",
	"stackoverflow.com":                 "StackOverflow",
	"sstatic.net":                       "StackOverflow",

	// 购物与生活
	"taobao.com":        "淘宝 / 天猫",
	"tmall.com":         "淘宝 / 天猫",
	"tbcdn.cn":          "淘宝 / 天猫",
	"alipay.com":        "支付宝",
	"alipayobjects.com": "支付宝",
	"jd.com":            "京东 JD",
	"360buyimg.com":     "京东 JD",
	"jd.hk":             "京东 JD",
	"pinduoduo.com":     "拼多多 PDD",
	"yangkeduo.com":     "拼多多 PDD",
	"pddpic.com":        "拼多多 PDD",
	"meituan.com":       "美团 Meituan",
	"meituan.net":       "美团 Meituan",
	"dianping.com":      "美团 Meituan",
	"ctrip.com":         "携程 Ctrip",
	"didiglobal.com":    "滴滴",
	"xiaojukeji.com":    "滴滴",

	// 游戏与音乐
	"steampowered.com":           "Steam",
	"steamstatic.com":            "Steam",
	"steamcontent.com":           "Steam",
	"steamcommunity.com":           "Steam",
	"playstation.com":            "PlayStation",
	"playstation.net":            "PlayStation",
	"sonyentertainmentnetwork.com": "PlayStation",
	"nintendo.com":               "Nintendo",
	"nintendo.net":               "Nintendo",
	"nintendowifi.net":           "Nintendo",
	"mihoyo.com":                 "米哈游",
	"hoyoverse.com":              "米哈游",
	"spotify.com":                "Spotify",
	"scdn.co":                    "Spotify",
	"music.apple.com":            "Apple Music",
	"music.163.com":              "网易云音乐",
	"music.126.net":              "网易云音乐",

	// 系统与后台底座
	"icloud.com":            "iCloud",
	"icloud-content.com":    "iCloud",
	"apple.com":             "Apple",
	"apple.com.cn":          "Apple",
	"mzstatic.com":          "Apple",
	"aaplimg.com":           "Apple",
	"cdn-apple.com":         "Apple",
	"onedrive.com":          "OneDrive",
	"sharepoint.com":        "OneDrive",
	"1drv.ms":               "OneDrive",
	"microsoft.com":         "Microsoft",
	"windowsupdate.com":     "Microsoft",
	"live.com":              "Microsoft",
	"msn.com":               "Microsoft",
	"trafficmanager.net":    "Microsoft",
	"azureedge.net":         "Microsoft",
	"google.com":            "Google",
	"gstatic.com":           "Google",
	"googleapis.com":        "Google",
	"1e100.net":             "Google",
	"cloudflare.com":        "Cloudflare",
	"cloudflare-dns.com":    "Cloudflare",
	"cloudflareclient.com":  "Cloudflare",
	"tailscale.com":         "Tailscale 组网",
	"tailscale.io":          "Tailscale 组网",
	"alidns.com":            "阿里公共 DNS",
	"dnspod.cn":             "腾讯 DNSPod",
	"doh.pub":               "腾讯 DNSPod",
	"dns.google":            "Google DNS",
	"mi.com":                "小米 / 米家",
	"miui.com":              "小米 / 米家",
	"xiaomi.com":            "小米 / 米家",
	"aliyun.com":            "阿里云",
	"aliyuncs.com":          "阿里云",
	"myqcloud.com":          "腾讯云",
	"tencent-cloud.com":     "腾讯云",
}

var catalogNameAlias = map[string]string{
	"OpenAI":     "OpenAI / ChatGPT",
	"AI / ChatGPT": "OpenAI / ChatGPT",
	"Tailscale":  "Tailscale 组网",
	"微信":         "微信",
	"腾讯 / 微信":    "腾讯 / 微信",
}

var catalogAppMeta = map[string]appCategoryMeta{
	"YouTube":          {AppCategoryVideo, false},
	"哔哩哔哩 Bilibili":    {AppCategoryVideo, false},
	"抖音":               {AppCategoryVideo, false},
	"TikTok":           {AppCategoryVideo, false},
	"快手":               {AppCategoryVideo, false},
	"腾讯视频":             {AppCategoryVideo, false},
	"爱奇艺":              {AppCategoryVideo, false},
	"优酷":               {AppCategoryVideo, false},
	"Netflix":          {AppCategoryVideo, false},
	"Disney+":          {AppCategoryVideo, false},
	"HBO":              {AppCategoryVideo, false},
	"Prime Video":      {AppCategoryVideo, false},
	"Twitch":           {AppCategoryVideo, false},
	"微信":               {AppCategorySocial, false},
	"QQ":               {AppCategorySocial, false},
	"腾讯 / 微信":          {AppCategorySocial, false},
	"腾讯 Tencent":       {AppCategorySocial, false},
	"今日头条":             {AppCategorySocial, false},
	"字节 / 抖音":          {AppCategoryVideo, false},
	"字节跳动 ByteDance":   {AppCategoryVideo, false},
	"小红书":              {AppCategorySocial, false},
	"知乎":               {AppCategorySocial, false},
	"微博":               {AppCategorySocial, false},
	"X (Twitter)":      {AppCategorySocial, false},
	"Telegram":         {AppCategorySocial, false},
	"Discord":          {AppCategorySocial, false},
	"Reddit":           {AppCategorySocial, false},
	"Instagram":        {AppCategorySocial, false},
	"WhatsApp":         {AppCategorySocial, false},
	"Meta / Facebook":  {AppCategorySocial, false},
	"Meta":             {AppCategorySocial, false},
	"OpenAI / ChatGPT": {AppCategoryAIDev, false},
	"Claude / Anthropic": {AppCategoryAIDev, false},
	"Gemini":           {AppCategoryAIDev, false},
	"xAI / Grok":       {AppCategoryAIDev, false},
	"GitHub":           {AppCategoryAIDev, false},
	"飞书":               {AppCategoryAIDev, false},
	"钉钉":               {AppCategoryAIDev, false},
	"Notion":           {AppCategoryAIDev, false},
	"Cursor":           {AppCategoryAIDev, false},
	"StackOverflow":    {AppCategoryAIDev, false},
	"Brave":            {AppCategoryAIDev, false},
	"TradingView":      {AppCategoryAIDev, false},
	"SourceHut":        {AppCategoryAIDev, false},
	"百度 Baidu":         {AppCategoryOther, false},
	"淘宝 / 天猫":          {AppCategoryShopping, false},
	"阿里 / 淘宝":          {AppCategoryShopping, false},
	"阿里 Alibaba":       {AppCategoryShopping, false},
	"支付宝":              {AppCategoryShopping, false},
	"京东 JD":            {AppCategoryShopping, false},
	"拼多多 PDD":          {AppCategoryShopping, false},
	"美团 Meituan":       {AppCategoryShopping, false},
	"携程 Ctrip":         {AppCategoryShopping, false},
	"滴滴":               {AppCategoryShopping, false},
	"PayPal":           {AppCategoryShopping, false},
	"中国银行机构":           {AppCategoryShopping, false},
	"加密货币 Crypto":      {AppCategoryShopping, false},
	"Steam":            {AppCategoryGamingMusic, false},
	"PlayStation":      {AppCategoryGamingMusic, false},
	"Nintendo":         {AppCategoryGamingMusic, false},
	"米哈游":              {AppCategoryGamingMusic, false},
	"腾讯游戏":             {AppCategoryGamingMusic, false},
	"Spotify":          {AppCategoryGamingMusic, false},
	"Apple Music":      {AppCategoryGamingMusic, false},
	"网易云音乐":            {AppCategoryGamingMusic, false},
	"QQ音乐":             {AppCategoryGamingMusic, false},
	"Apple":            {AppCategorySystem, true},
	"iCloud":           {AppCategorySystem, true},
	"Google":           {AppCategorySystem, true},
	"Microsoft":        {AppCategorySystem, true},
	"OneDrive":         {AppCategorySystem, true},
	"Cloudflare":       {AppCategorySystem, true},
	"Tailscale 组网":     {AppCategorySystem, true},
	"阿里公共 DNS":         {AppCategorySystem, true},
	"腾讯 DNSPod":        {AppCategorySystem, true},
	"Cloudflare DNS":   {AppCategorySystem, true},
	"Google DNS":       {AppCategorySystem, true},
	"114 DNS":          {AppCategorySystem, true},
	"小米 / 米家":          {AppCategorySystem, true},
	"涂鸦智能 Tuya":        {AppCategorySystem, true},
	"智能家居云 (PSmart)":   {AppCategorySystem, true},
	"内置防 PCDN 规则集":     {AppCategorySystem, true},
	"中国电信/运营商":         {AppCategorySystem, true},
	"阿里云":              {AppCategorySystem, true},
	"腾讯云":              {AppCategorySystem, true},
}

func lookupFineAppSuffix(host string) string {
	cur := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if cur == "" || net.ParseIP(cur) != nil {
		return ""
	}
	for {
		if app, ok := fineAppSuffixCatalog[cur]; ok {
			return app
		}
		dot := strings.IndexByte(cur, '.')
		if dot < 0 || dot+1 >= len(cur) {
			break
		}
		cur = cur[dot+1:]
	}
	return ""
}

// ClassifyApp 对连接目标执行细粒度应用与品类识别（优先具体 App，未命中时无缝回退既有规则集与内置特征）。
func ClassifyApp(target, destIP, ruleStr string, rawHints ...string) AppCatalogEntry {
	name := lookupFineAppSuffix(target)
	if name == "" {
		name = IdentifyApp(target, destIP, ruleStr, rawHints...)
	}
	if canonical, aliased := catalogNameAlias[name]; aliased {
		name = canonical
	}
	if name == "" {
		return AppCatalogEntry{
			Name:          "",
			Category:      AppCategoryOther,
			CategoryLabel: CategoryDisplayLabel(AppCategoryOther),
			IsInfra:       false,
		}
	}
	meta, ok := catalogAppMeta[name]
	if !ok {
		meta = appCategoryMeta{Category: AppCategoryOther, IsInfra: false}
	}
	return AppCatalogEntry{
		Name:          name,
		Category:      meta.Category,
		CategoryLabel: CategoryDisplayLabel(meta.Category),
		IsInfra:       meta.IsInfra,
	}
}
