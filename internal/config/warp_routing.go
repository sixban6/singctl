package config

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

const (
	WarpModeSplit      = "split"
	WarpModeGlobalWarp = "global_warp"
	WarpModeBypass     = "bypass"
)

// WarpRoutingConfig 定义服务端 WARP 智能分流策略（持久化于 singctl.yaml server.warp_routing）
type WarpRoutingConfig struct {
	Mode          string          `yaml:"mode,omitempty" json:"mode"`
	Presets       map[string]bool `yaml:"presets,omitempty" json:"presets,omitempty"`
	WarpDomains   []string        `yaml:"warp_domains,omitempty" json:"warpDomains"`
	WarpCIDRs     []string        `yaml:"warp_cidrs,omitempty" json:"warpCidrs"`
	DirectDomains []string        `yaml:"direct_domains,omitempty" json:"directDomains"`
	DirectCIDRs   []string        `yaml:"direct_cidrs,omitempty" json:"directCidrs"`
}

// IsEmpty 判断分流配置是否处于完全未定制的默认态
func (w WarpRoutingConfig) IsEmpty() bool {
	mode := strings.TrimSpace(w.Mode)
	if mode != "" && mode != WarpModeSplit {
		return false
	}
	return len(w.Presets) == 0 &&
		len(w.WarpDomains) == 0 &&
		len(w.WarpCIDRs) == 0 &&
		len(w.DirectDomains) == 0 &&
		len(w.DirectCIDRs) == 0
}

// IsZero 供 yaml.v3 omitempty 判断是否省略空结构体
func (w WarpRoutingConfig) IsZero() bool {
	return w.IsEmpty()
}

// NormalizedMode 返回规范化后的全局分流模式
func (w WarpRoutingConfig) NormalizedMode() string {
	switch strings.ToLower(strings.TrimSpace(w.Mode)) {
	case "", WarpModeSplit:
		return WarpModeSplit
	case WarpModeGlobalWarp:
		return WarpModeGlobalWarp
	case WarpModeBypass:
		return WarpModeBypass
	default:
		return WarpModeSplit
	}
}

// IsPresetEnabled 返回指定预设的生效状态（未显式覆盖时使用 defaultOn）
func (w WarpRoutingConfig) IsPresetEnabled(id string, defaultOn bool) bool {
	if w.Presets != nil {
		if v, ok := w.Presets[strings.ToLower(strings.TrimSpace(id))]; ok {
			return v
		}
	}
	return defaultOn
}

// Clone 深拷贝配置
func (w WarpRoutingConfig) Clone() WarpRoutingConfig {
	out := WarpRoutingConfig{
		Mode:          w.NormalizedMode(),
		WarpDomains:   slices.Clone(w.WarpDomains),
		WarpCIDRs:     slices.Clone(w.WarpCIDRs),
		DirectDomains: slices.Clone(w.DirectDomains),
		DirectCIDRs:   slices.Clone(w.DirectCIDRs),
	}
	if w.Presets != nil {
		out.Presets = maps.Clone(w.Presets)
	}
	return out
}

// CleanWarpDomainRule 清理并校验域名分流规则。
// 支持直接粘贴完整 URL（自动剥离协议、路径、查询参数、端口与通配前缀），
// 以及 full:（精确域名）和 keyword:（关键词）修饰符；默认编译为 domain_suffix。
func CleanWarpDomainRule(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("域名规则不能为空")
	}
	// 先做基础安全拦截：任何空白/引号/控制字符/Shell 元字符一律拒绝
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("规则 %q 包含非法控制字符", raw)
		}
		switch r {
		case ' ', '\t', '\r', '\n', '"', '\'', '`', ';', '|', '&', '$', '<', '>', '(', ')', '{', '}', '[', ']', '\\':
			return "", fmt.Errorf("规则 %q 包含非法字符 %q", raw, r)
		}
	}

	lower := strings.ToLower(s)
	prefix := ""
	switch {
	case strings.HasPrefix(lower, "full:"):
		prefix = "full:"
		lower = strings.TrimPrefix(lower, "full:")
	case strings.HasPrefix(lower, "domain:"):
		// 统一规范为默认后缀匹配
		lower = strings.TrimPrefix(lower, "domain:")
	case strings.HasPrefix(lower, "keyword:"):
		kw := strings.TrimPrefix(lower, "keyword:")
		if kw == "" || len(kw) > 128 {
			return "", fmt.Errorf("关键词规则 %q 长度必须在 1~128 之间", raw)
		}
		for _, r := range kw {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_') {
				return "", fmt.Errorf("关键词规则 %q 仅支持字母、数字、连字符、下划线或点号", raw)
			}
		}
		return "keyword:" + kw, nil
	}

	host := lower
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil || parsed.Host == "" {
			return "", fmt.Errorf("无法解析 URL %q 中的域名", raw)
		}
		host = parsed.Host
	} else {
		// 处理未带 scheme 的 "missav.ws/dm13/cn?x=1"
		if idx := strings.IndexAny(host, "/?#"); idx >= 0 {
			host = host[:idx]
		}
	}

	// 去掉 userinfo@
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	// 去掉端口
	if colon := strings.LastIndex(host, ":"); colon >= 0 && !strings.Contains(host[colon+1:], "]") {
		host = host[:colon]
	}

	host = strings.TrimPrefix(host, "*.")
	host = strings.Trim(host, ".")

	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("域名 %q 格式无效或长度超限", raw)
	}
	if strings.Contains(host, "..") {
		return "", fmt.Errorf("域名 %q 格式无效（包含连续点号）", raw)
	}
	// 如果粘贴的是纯 IP 地址，提示走 CIDR 或当作 IP 处理由调用方识别
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("域名 %q 包含无效标签", raw)
		}
		for i, r := range label {
			isAlphaNum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			isMidChar := r == '-' || r == '_'
			if !isAlphaNum && !isMidChar {
				return "", fmt.Errorf("域名 %q 包含非法字符 %q", raw, r)
			}
			if (i == 0 || i == len(label)-1) && r == '-' {
				return "", fmt.Errorf("域名 %q 标签不能以连字符开头或结尾", raw)
			}
		}
	}

	return prefix + host, nil
}

// CleanWarpCIDRRule 清理并校验 IP 或 CIDR 规则（单 IP 自动补全 /32 或 /128）
func CleanWarpCIDRRule(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("IP/CIDR 规则不能为空")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", fmt.Errorf("无效的 CIDR %q: %w", raw, err)
		}
		return p.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", fmt.Errorf("无效的 IP 地址 %q: %w", raw, err)
	}
	addr = addr.Unmap()
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String(), nil
}

// NormalizeWarpRouting 对 WarpRoutingConfig 进行全局模式、预设表与域名/CIDR 规则的归一化与安全校验
func NormalizeWarpRouting(in WarpRoutingConfig) (WarpRoutingConfig, error) {
	mode := strings.ToLower(strings.TrimSpace(in.Mode))
	switch mode {
	case "", WarpModeSplit:
		mode = WarpModeSplit
	case WarpModeGlobalWarp, WarpModeBypass:
	default:
		return WarpRoutingConfig{}, fmt.Errorf("不支持的分流模式 %q（仅支持 split / global_warp / bypass）", in.Mode)
	}

	out := WarpRoutingConfig{
		Mode:          mode,
		WarpDomains:   []string{},
		WarpCIDRs:     []string{},
		DirectDomains: []string{},
		DirectCIDRs:   []string{},
	}

	if len(in.Presets) > 0 {
		out.Presets = make(map[string]bool, len(in.Presets))
		for k, v := range in.Presets {
			id := strings.ToLower(strings.TrimSpace(k))
			if id == "" {
				continue
			}
			for _, r := range id {
				if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
					return WarpRoutingConfig{}, fmt.Errorf("预设 ID %q 包含非法字符", k)
				}
			}
			out.Presets[id] = v
		}
	}

	cleanDomains := func(items []string) ([]string, error) {
		res := make([]string, 0, len(items))
		for _, item := range items {
			if strings.TrimSpace(item) == "" {
				continue
			}
			cleaned, err := CleanWarpDomainRule(item)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(res, cleaned) {
				res = append(res, cleaned)
			}
		}
		return res, nil
	}

	cleanCIDRs := func(items []string) ([]string, error) {
		res := make([]string, 0, len(items))
		for _, item := range items {
			if strings.TrimSpace(item) == "" {
				continue
			}
			cleaned, err := CleanWarpCIDRRule(item)
			if err != nil {
				return nil, err
			}
			if !slices.Contains(res, cleaned) {
				res = append(res, cleaned)
			}
		}
		return res, nil
	}

	var err error
	if out.WarpDomains, err = cleanDomains(in.WarpDomains); err != nil {
		return WarpRoutingConfig{}, err
	}
	if out.DirectDomains, err = cleanDomains(in.DirectDomains); err != nil {
		return WarpRoutingConfig{}, err
	}
	if out.WarpCIDRs, err = cleanCIDRs(in.WarpCIDRs); err != nil {
		return WarpRoutingConfig{}, err
	}
	if out.DirectCIDRs, err = cleanCIDRs(in.DirectCIDRs); err != nil {
		return WarpRoutingConfig{}, err
	}
	return out, nil
}

// ExtractRootDomain 从域名中提取适合规则收敛的主域名（如 cdn.missav.ws -> missav.ws）；若为 IP 则原样返回
func ExtractRootDomain(host string) string {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if h == "" {
		return ""
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.Unmap().String()
	}
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	lastTwo := parts[len(parts)-2] + "." + parts[len(parts)-1]
	// 常见双段公共后缀，保留 3 段作为主域
	switch lastTwo {
	case "co.uk", "org.uk", "ac.uk", "co.jp", "ne.jp", "or.jp",
		"com.cn", "net.cn", "org.cn", "gov.cn", "com.hk", "com.tw", "com.sg", "com.au", "com.br":
		if len(parts) >= 3 {
			return parts[len(parts)-3] + "." + lastTwo
		}
	}
	return lastTwo
}

// MatchDomainRule 判断主机名是否命中指定 WARP 域名规则（无前缀为 suffix，full: 为精确，keyword: 为关键词）
func MatchDomainRule(rule, host string) bool {
	r := strings.ToLower(strings.TrimSpace(rule))
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if r == "" || h == "" {
		return false
	}
	if exact, ok := strings.CutPrefix(r, "full:"); ok {
		return h == exact
	}
	if kw, ok := strings.CutPrefix(r, "keyword:"); ok {
		return strings.Contains(h, kw)
	}
	suffix := strings.TrimPrefix(strings.TrimPrefix(r, "domain:"), ".")
	return h == suffix || strings.HasSuffix(h, "."+suffix)
}

// MatchCIDRRule 判断目标 IP 是否命中指定 IP/CIDR 规则
func MatchCIDRRule(rule, dstIP string) bool {
	r := strings.TrimSpace(rule)
	ipStr := strings.TrimSpace(dstIP)
	if r == "" || ipStr == "" {
		return false
	}
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if strings.Contains(r, "/") {
		p, err := netip.ParsePrefix(r)
		return err == nil && p.Contains(addr)
	}
	targetAddr, err := netip.ParseAddr(r)
	return err == nil && targetAddr.Unmap() == addr
}

// EffectiveTargetLabel 返回便于展示的目标标识
func EffectiveTargetLabel(host, dstIP string) string {
	return cmp.Or(strings.TrimSpace(host), strings.TrimSpace(dstIP), "unknown")
}
