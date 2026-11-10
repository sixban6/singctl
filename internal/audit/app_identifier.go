package audit

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/constant"
)

// ruleSetAppDisplayNames 将本地 sing-box 规则集 tag 映射为直观易读的应用/服务名称。
var ruleSetAppDisplayNames = map[string]string{
	"geosite-telegram":       "Telegram",
	"geoip-telegram":         "Telegram",
	"geosite-baidu":          "百度 Baidu",
	"geosite-ali":            "阿里 Alibaba",
	"geosite-tencent":        "腾讯 Tencent",
	"geosite-bytedance":      "字节跳动 ByteDance",
	"geosite-tiktok":         "TikTok",
	"geosite-bili":           "哔哩哔哩 Bilibili",
	"geosite-jd":             "京东 JD",
	"geosite-pdd":            "拼多多 PDD",
	"geosite-meituan":        "美团 Meituan",
	"geosite-ctrip":          "携程 Ctrip",
	"geosite-bank-cn":        "中国银行机构",
	"geosite-apple":          "Apple",
	"geoip-apple":            "Apple",
	"geosite-icloud":         "iCloud",
	"geosite-google":         "Google",
	"geoip-google":           "Google",
	"geosite-youtube":        "YouTube",
	"geosite-github":         "GitHub",
	"geosite-microsoft":      "Microsoft",
	"geosite-onedrive":       "OneDrive",
	"geosite-chat":           "AI / ChatGPT",
	"geosite-openai":         "OpenAI",
	"geosite-anthropic":      "Claude / Anthropic",
	"geosite-netflix":        "Netflix",
	"geoip-netflix":          "Netflix",
	"geosite-disney":         "Disney+",
	"geosite-hbo":            "HBO",
	"geosite-primevideo":     "Prime Video",
	"geosite-spotify":        "Spotify",
	"geosite-x":              "X (Twitter)",
	"geosite-twitter":        "X (Twitter)",
	"geosite-steam":          "Steam",
	"geosite-epic":           "Epic Games",
	"geosite-playstation":    "PlayStation",
	"geosite-xbox":           "Xbox",
	"geosite-hok":            "王者荣耀",
	"geosite-paypal":         "PayPal",
	"geosite-cryptocurrency": "加密货币 Crypto",
	"geosite-sourcehut":      "SourceHut",
	"geosite-ctm_cn":         "中国电信/运营商",
}

// orderedAppRuleSetTags 定义匹配优先级（越靠前越具体，优先于泛化规则集）。
var orderedAppRuleSetTags = []string{
	"geosite-telegram", "geoip-telegram",
	"geosite-youtube", "geosite-onedrive", "geosite-github",
	"geosite-chat", "geosite-tiktok", "geosite-bili",
	"geosite-hok", "geosite-steam", "geosite-epic", "geosite-playstation", "geosite-xbox",
	"geosite-netflix", "geoip-netflix", "geosite-disney", "geosite-hbo", "geosite-primevideo", "geosite-spotify",
	"geosite-x", "geosite-paypal", "geosite-cryptocurrency", "geosite-sourcehut",
	"geosite-jd", "geosite-pdd", "geosite-meituan", "geosite-ctrip", "geosite-bank-cn",
	"geosite-baidu", "geosite-bytedance", "geosite-tencent", "geosite-ali",
	"geosite-apple", "geoip-apple", "geosite-microsoft", "geosite-google", "geoip-google",
	"geosite-ctm_cn",
}

type persistedAppIndex struct {
	Fingerprint   string            `json:"fingerprint"`
	ExactDomains  map[string]string `json:"exactDomains"`
	SuffixDomains map[string]string `json:"suffixDomains"`
	Keywords      []keywordAppEntry `json:"keywords"`
	CIDRs         []cidrAppEntry    `json:"cidrs"`
}

type keywordAppEntry struct {
	Keyword string `json:"k"`
	App     string `json:"a"`
}

type cidrAppEntry struct {
	CIDR string `json:"c"`
	App  string `json:"a"`
}

type compiledCIDRRule struct {
	net *net.IPNet
	app string
}

type appIdentifierCache struct {
	mu            sync.RWMutex
	fingerprint   string
	exactDomains  map[string]string
	suffixDomains map[string]string
	keywords      []keywordAppEntry
	cidrs         []compiledCIDRRule
	building      bool
}

var globalAppCache = &appIdentifierCache{
	exactDomains:  make(map[string]string),
	suffixDomains: make(map[string]string),
}

func defaultAppIndexCachePath() string {
	return filepath.Join(os.TempDir(), "singctl-ruleset-app-index.json")
}

// IdentifyApp 根据本地下载的 sing-box 规则集 (.srs)、连接命中规则及内置常见服务特征识别目标所属应用。
func IdentifyApp(target, destIP, ruleStr string) string {
	target = strings.ToLower(strings.TrimSpace(target))
	destIP = strings.TrimSpace(destIP)

	// 1. 优先尝试从本地已下载的 sing-box rule_sets 索引匹配精确域名后缀或 GeoIP 网段
	idx := getOrLoadAppIndex()
	if idx != nil {
		if app := idx.match(target, destIP); app != "" {
			return app
		}
	}

	// 2. 内置常见基础服务/智能硬件云快速识别（补充未单独拆出 srs 的常见服务）
	if app := matchBuiltinService(target, destIP); app != "" {
		return app
	}

	// 3. 回退解析 sing-box Clash API 返回的单条 rule_set 标签
	if app := extractSingleRuleSetApp(ruleStr); app != "" {
		return app
	}
	return ""
}

func (c *appIdentifierCache) match(target, destIP string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 域名匹配：先精确匹配，再逐级后缀匹配 (例如 a.b.baidu.com -> b.baidu.com -> baidu.com)
	if target != "" && net.ParseIP(target) == nil {
		if app, ok := c.exactDomains[target]; ok {
			return app
		}
		cur := target
		for {
			if app, ok := c.suffixDomains[cur]; ok {
				return app
			}
			dot := strings.IndexByte(cur, '.')
			if dot < 0 || dot+1 >= len(cur) {
				break
			}
			cur = cur[dot+1:]
		}
		for _, kw := range c.keywords {
			if kw.Keyword != "" && strings.Contains(target, kw.Keyword) {
				return kw.App
			}
		}
	}

	// IP / GeoIP 匹配
	for _, ipCandidate := range []string{destIP, target} {
		if ipCandidate == "" {
			continue
		}
		ip := net.ParseIP(ipCandidate)
		if ip == nil {
			continue
		}
		for _, cr := range c.cidrs {
			if cr.net != nil && cr.net.Contains(ip) {
				return cr.app
			}
		}
	}
	return ""
}

func getOrLoadAppIndex() *appIdentifierCache {
	ruleSetDir := filepath.Join(constant.SingBoxConfigDir, "rule_sets")
	fp := computeRuleSetDirFingerprint(ruleSetDir)
	if fp == "" {
		return nil
	}

	globalAppCache.mu.RLock()
	if globalAppCache.fingerprint == fp && (len(globalAppCache.suffixDomains) > 0 || len(globalAppCache.cidrs) > 0) {
		globalAppCache.mu.RUnlock()
		return globalAppCache
	}
	isBuilding := globalAppCache.building
	globalAppCache.mu.RUnlock()

	// 尝试从 /tmp/singctl-ruleset-app-index.json 快速载入已编译索引
	cacheFile := defaultAppIndexCachePath()
	if data, err := os.ReadFile(cacheFile); err == nil && len(data) > 0 {
		var p persistedAppIndex
		if json.Unmarshal(data, &p) == nil && p.Fingerprint == fp {
			applyPersistedIndex(globalAppCache, &p)
			return globalAppCache
		}
	}

	// 若尚未构建磁盘索引，启动后台异步反编译构建，不阻塞当前 HTTP/CLI 请求
	if !isBuilding {
		globalAppCache.mu.Lock()
		if !globalAppCache.building {
			globalAppCache.building = true
			go buildAppIndexInBackground(ruleSetDir, fp, cacheFile)
		}
		globalAppCache.mu.Unlock()
	}
	return globalAppCache
}

// WarmupAppIndex 供 CLI 或测试同步预热本地规则集应用索引。
func WarmupAppIndex(ruleSetDir string) {
	if ruleSetDir == "" {
		ruleSetDir = filepath.Join(constant.SingBoxConfigDir, "rule_sets")
	}
	fp := computeRuleSetDirFingerprint(ruleSetDir)
	if fp == "" {
		return
	}
	globalAppCache.mu.RLock()
	ready := globalAppCache.fingerprint == fp && (len(globalAppCache.suffixDomains) > 0 || len(globalAppCache.cidrs) > 0)
	globalAppCache.mu.RUnlock()
	if ready {
		return
	}

	cacheFile := defaultAppIndexCachePath()
	if data, err := os.ReadFile(cacheFile); err == nil && len(data) > 0 {
		var p persistedAppIndex
		if json.Unmarshal(data, &p) == nil && p.Fingerprint == fp {
			applyPersistedIndex(globalAppCache, &p)
			return
		}
	}
	buildAppIndexInBackground(ruleSetDir, fp, cacheFile)
}

func computeRuleSetDirFingerprint(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return ""
	}
	var maxMod int64
	var count int
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".srs") {
			continue
		}
		count++
		if info, err := e.Info(); err == nil {
			if m := info.ModTime().Unix(); m > maxMod {
				maxMod = m
			}
		}
	}
	if count == 0 {
		return ""
	}
	return strconv.Itoa(count) + ":" + filepath.Base(dir) + ":" + time.Unix(maxMod, 0).UTC().Format("20060102150405")
}

type decompiledSRS struct {
	Rules []struct {
		Domain        []string `json:"domain"`
		DomainSuffix  []string `json:"domain_suffix"`
		DomainKeyword []string `json:"domain_keyword"`
		IPCIDR        []string `json:"ip_cidr"`
	} `json:"rules"`
}

func buildAppIndexInBackground(ruleSetDir, fp, cacheFile string) {
	defer func() {
		globalAppCache.mu.Lock()
		globalAppCache.building = false
		globalAppCache.mu.Unlock()
	}()

	sbBin, err := exec.LookPath("sing-box")
	if err != nil {
		for _, candidate := range []string{"/usr/bin/sing-box", "/usr/local/bin/sing-box", "/etc/sing-box/sing-box"} {
			if _, statErr := os.Stat(candidate); statErr == nil {
				sbBin = candidate
				break
			}
		}
	}
	if sbBin == "" {
		return
	}

	p := &persistedAppIndex{
		Fingerprint:   fp,
		ExactDomains:  make(map[string]string),
		SuffixDomains: make(map[string]string),
	}

	for _, tag := range orderedAppRuleSetTags {
		appName, ok := ruleSetAppDisplayNames[tag]
		if !ok {
			continue
		}
		srsPath := filepath.Join(ruleSetDir, tag+".srs")
		info, err := os.Stat(srsPath)
		if err != nil || info.Size() == 0 || info.Size() > 256*1024 {
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(ctx, sbBin, "rule-set", "decompile", srsPath, "-o", "/dev/stdout").Output()
		cancel()
		if err != nil || len(out) == 0 {
			continue
		}

		var parsed decompiledSRS
		if err := json.Unmarshal(out, &parsed); err != nil {
			continue
		}

		for _, r := range parsed.Rules {
			for _, d := range r.Domain {
				d = strings.ToLower(strings.TrimSpace(d))
				if d != "" {
					if _, exists := p.ExactDomains[d]; !exists {
						p.ExactDomains[d] = appName
					}
				}
			}
			for _, ds := range r.DomainSuffix {
				ds = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ds), "."))
				if ds != "" {
					if _, exists := p.SuffixDomains[ds]; !exists {
						p.SuffixDomains[ds] = appName
					}
				}
			}
			for _, kw := range r.DomainKeyword {
				kw = strings.ToLower(strings.TrimSpace(kw))
				if len(kw) >= 3 {
					p.Keywords = append(p.Keywords, keywordAppEntry{Keyword: kw, App: appName})
				}
			}
			for _, cidr := range r.IPCIDR {
				cidr = strings.TrimSpace(cidr)
				if cidr != "" {
					p.CIDRs = append(p.CIDRs, cidrAppEntry{CIDR: cidr, App: appName})
				}
			}
		}
	}

	if len(p.SuffixDomains) == 0 && len(p.CIDRs) == 0 {
		return
	}

	applyPersistedIndex(globalAppCache, p)

	if encoded, err := json.Marshal(p); err == nil {
		tmp := cacheFile + ".tmp"
		if os.WriteFile(tmp, encoded, 0600) == nil {
			_ = os.Rename(tmp, cacheFile)
		}
	}
}

func applyPersistedIndex(dst *appIdentifierCache, p *persistedAppIndex) {
	if dst == nil || p == nil {
		return
	}
	var compiled []compiledCIDRRule
	for _, ce := range p.CIDRs {
		if _, ipNet, err := net.ParseCIDR(ce.CIDR); err == nil && ipNet != nil {
			compiled = append(compiled, compiledCIDRRule{net: ipNet, app: ce.App})
		}
	}
	dst.mu.Lock()
	dst.fingerprint = p.Fingerprint
	dst.exactDomains = p.ExactDomains
	dst.suffixDomains = p.SuffixDomains
	dst.keywords = p.Keywords
	dst.cidrs = compiled
	dst.mu.Unlock()
}

func matchBuiltinService(target, destIP string) string {
	// 1. 常见知名公网 DNS / 组网 IP
	for _, ipStr := range []string{destIP, target} {
		switch ipStr {
		case "223.5.5.5", "223.6.6.6":
			return "阿里公共 DNS"
		case "119.29.29.29", "119.28.28.28":
			return "腾讯 DNSPod"
		case "1.1.1.1", "1.0.0.1":
			return "Cloudflare DNS"
		case "8.8.8.8", "8.8.4.4":
			return "Google DNS"
		case "114.114.114.114":
			return "114 DNS"
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			// Tailscale CGNAT 100.64.0.0/10
			if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
				return "Tailscale 组网"
			}
			// Apple 17.0.0.0/8
			if ip4 := ip.To4(); ip4 != nil && ip4[0] == 17 {
				return "Apple"
			}
		}
	}

	// 2. 常见域名特征兜底（即使本地尚未生成 .srs 缓存也能立刻识别）
	switch {
	case strings.Contains(target, "telegram") || strings.HasSuffix(target, ".t.me"):
		return "Telegram"
	case strings.Contains(target, "baidu") || strings.HasSuffix(target, ".bdimg.com") || strings.HasSuffix(target, ".bdstatic.com"):
		return "百度 Baidu"
	case strings.Contains(target, "qq.com") || strings.Contains(target, "weixin") || strings.Contains(target, "wechat") || strings.Contains(target, "tencent") || strings.Contains(target, "qpic.cn") || strings.Contains(target, "gtimg.cn"):
		return "腾讯 / 微信"
	case strings.Contains(target, "alicdn") || strings.Contains(target, "aliyun") || strings.Contains(target, "taobao") || strings.Contains(target, "tmall") || strings.Contains(target, "alipay"):
		return "阿里 / 淘宝"
	case strings.Contains(target, "bytedance") || strings.Contains(target, "douyin") || strings.Contains(target, "snssdk") || strings.Contains(target, "toutiao") || strings.Contains(target, "volces.com") || strings.Contains(target, "byteimg"):
		return "字节 / 抖音"
	case strings.Contains(target, "bilibili") || strings.HasSuffix(target, ".bilivideo.com") || strings.HasSuffix(target, ".hdslb.com"):
		return "哔哩哔哩 Bilibili"
	case strings.Contains(target, "xiaohongshu") || strings.Contains(target, "xhscdn"):
		return "小红书"
	case strings.Contains(target, "xiaomi") || strings.Contains(target, "mi.com") || strings.Contains(target, "miui.com") || strings.Contains(target, "mijia"):
		return "小米 / 米家"
	case strings.Contains(target, "psmartcloud"):
		return "智能家居云 (PSmart)"
	case strings.Contains(target, "tuya"):
		return "涂鸦智能 Tuya"
	case strings.Contains(target, "apple.com") || strings.Contains(target, "icloud.com") || strings.Contains(target, "mzstatic.com") || strings.Contains(target, "aaplimg.com"):
		return "Apple"
	case strings.Contains(target, "google") || strings.Contains(target, "gstatic.com") || strings.Contains(target, "1e100.net"):
		return "Google"
	case strings.Contains(target, "github"):
		return "GitHub"
	case strings.Contains(target, "microsoft") || strings.Contains(target, "live.com") || strings.Contains(target, "office"):
		return "Microsoft"
	case strings.Contains(target, "tailscale"):
		return "Tailscale"
	case strings.Contains(target, "cloudflare"):
		return "Cloudflare"
	}
	return ""
}

func extractSingleRuleSetApp(ruleStr string) string {
	// 例如: "rule_set=geosite-chat => route(AI)"
	if !strings.Contains(ruleStr, "rule_set=") || strings.Contains(ruleStr, "rule_set=[") {
		return ""
	}
	after := strings.SplitN(ruleStr, "rule_set=", 2)[1]
	tag := strings.Fields(after)[0]
	return ruleSetAppDisplayNames[tag]
}
