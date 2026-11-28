package config

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

const (
	TrafficMatchDomainSuffix = "domain_suffix"
	TrafficMatchDomain       = "domain"
	TrafficMatchIPCIDR       = "ip_cidr"
	TrafficOutboundDirect    = "direct"
)

// TrafficRuleOverride 定义单条客户端智能分流预设的持久化覆盖配置。
// Enabled 为 nil 时沿用该预设的推荐默认开关（如 AI/流媒体/游戏/社交默认开启，办公生态默认直连）；
// Outbound 为空时沿用该预设的推荐默认分组（AI 默认 #VPS 逐级回退，其他默认 Proxy）。
type TrafficRuleOverride struct {
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Outbound string `yaml:"outbound,omitempty" json:"outbound,omitempty"`
}

// TrafficCustomRule 定义用户在审计页或快捷分流中创建的单条定向出口持久化规则。
type TrafficCustomRule struct {
	Target    string `yaml:"target" json:"target"`
	MatchType string `yaml:"match_type,omitempty" json:"matchType,omitempty"`
	Outbound  string `yaml:"outbound" json:"outbound"`
	SourceIP  string `yaml:"source_ip,omitempty" json:"sourceIp,omitempty"`
	Note      string `yaml:"note,omitempty" json:"note,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty" json:"createdAt,omitempty"`
}

// TrafficRoutingConfig 定义客户端「智能分流中心」策略（持久化于 singctl.yaml traffic_routing）。
type TrafficRoutingConfig struct {
	Presets map[string]TrafficRuleOverride `yaml:"presets,omitempty" json:"presets,omitempty"`
	Rules   []TrafficCustomRule            `yaml:"rules,omitempty" json:"rules,omitempty"`
}

// IsEmpty 判断客户端智能分流配置是否处于完全未定制的默认态。
func (t TrafficRoutingConfig) IsEmpty() bool {
	norm := t.Normalized()
	return len(norm.Presets) == 0 && len(norm.Rules) == 0
}

// IsZero 供 yaml.v3 omitempty 判断是否省略空结构体。
func (t TrafficRoutingConfig) IsZero() bool {
	return t.IsEmpty()
}

// Clone 深拷贝配置（含 *bool 指针与自定义规则切片独立拷贝，避免并发共享写）。
func (t TrafficRoutingConfig) Clone() TrafficRoutingConfig {
	if len(t.Presets) == 0 && len(t.Rules) == 0 {
		return TrafficRoutingConfig{}
	}
	var cloned map[string]TrafficRuleOverride
	if len(t.Presets) > 0 {
		cloned = make(map[string]TrafficRuleOverride, len(t.Presets))
		for k, ov := range t.Presets {
			var enabledPtr *bool
			if ov.Enabled != nil {
				v := *ov.Enabled
				enabledPtr = &v
			}
			cloned[k] = TrafficRuleOverride{
				Enabled:  enabledPtr,
				Outbound: ov.Outbound,
			}
		}
	}
	return TrafficRoutingConfig{
		Presets: cloned,
		Rules:   slices.Clone(t.Rules),
	}
}

// CleanTrafficOutboundName 校验并清理策略组名称（禁止控制字符或过长输入）。
func CleanTrafficOutboundName(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	if len(s) > 64 {
		return "", fmt.Errorf("策略组名称过长 (最多 64 字符)")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("策略组名称 %q 包含非法控制字符", raw)
		}
	}
	return s, nil
}

func ruleIdentityKey(r TrafficCustomRule) string {
	return r.MatchType + "|" + r.Target + "|" + r.SourceIP
}

// Normalized 返回键名规范化且剔除空覆盖后的副本。
func (t TrafficRoutingConfig) Normalized() TrafficRoutingConfig {
	if len(t.Presets) == 0 && len(t.Rules) == 0 {
		return TrafficRoutingConfig{}
	}
	var outPresets map[string]TrafficRuleOverride
	if len(t.Presets) > 0 {
		keys := make([]string, 0, len(t.Presets))
		for k := range t.Presets {
			keys = append(keys, k)
		}
		slices.Sort(keys)

		outPresets = make(map[string]TrafficRuleOverride, len(keys))
		for _, rawKey := range keys {
			id := strings.ToLower(strings.TrimSpace(rawKey))
			if id == "" {
				continue
			}
			ov := t.Presets[rawKey]
			ob, err := CleanTrafficOutboundName(ov.Outbound)
			if err != nil {
				continue
			}
			if ov.Enabled == nil && ob == "" {
				continue
			}
			var enabledPtr *bool
			if ov.Enabled != nil {
				v := *ov.Enabled
				enabledPtr = &v
			}
			outPresets[id] = TrafficRuleOverride{
				Enabled:  enabledPtr,
				Outbound: ob,
			}
		}
	}

	var outRules []TrafficCustomRule
	if len(t.Rules) > 0 {
		idxByKey := make(map[string]int, len(t.Rules))
		for _, r := range t.Rules {
			normRule, err := NormalizeTrafficCustomRule(r)
			if err != nil {
				continue
			}
			key := ruleIdentityKey(normRule)
			if idx, dup := idxByKey[key]; dup {
				outRules[idx] = normRule
				continue
			}
			idxByKey[key] = len(outRules)
			outRules = append(outRules, normRule)
		}
	}

	if len(outPresets) == 0 && len(outRules) == 0 {
		return TrafficRoutingConfig{}
	}
	return TrafficRoutingConfig{
		Presets: outPresets,
		Rules:   outRules,
	}
}

// PresetState 返回指定预设的生效开关与偏好目标策略组（未设置偏好分组时回退 fallbackOutbound）。
func (t TrafficRoutingConfig) PresetState(id string, defaultOn bool, fallbackOutbound string) (enabled bool, outbound string) {
	key := strings.ToLower(strings.TrimSpace(id))
	enabled = defaultOn
	outbound = strings.TrimSpace(fallbackOutbound)
	if len(t.Presets) == 0 {
		return enabled, outbound
	}
	ov, ok := t.Presets[key]
	if !ok {
		return enabled, outbound
	}
	if ov.Enabled != nil {
		enabled = *ov.Enabled
	}
	outbound = cmp.Or(strings.TrimSpace(ov.Outbound), outbound)
	return enabled, outbound
}

func isValidRouteDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if len(lbl) == 0 || len(lbl) > 63 {
			return false
		}
		for i := 0; i < len(lbl); i++ {
			c := lbl[i]
			isAlnum := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
			if !isAlnum && c != '-' && c != '_' {
				return false
			}
		}
		if lbl[0] == '-' || lbl[len(lbl)-1] == '-' {
			return false
		}
	}
	return true
}

func normalizeCustomRuleTarget(rawTarget, rawMatchType string) (target, matchType string, err error) {
	mt := strings.ToLower(strings.TrimSpace(rawMatchType))
	switch mt {
	case "", TrafficMatchDomainSuffix, TrafficMatchDomain, TrafficMatchIPCIDR:
	default:
		return "", "", fmt.Errorf("不支持的匹配类型: %s", rawMatchType)
	}

	s := strings.TrimSpace(rawTarget)
	if s == "" {
		return "", "", fmt.Errorf("目标域名或 IP 不能为空")
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", "", fmt.Errorf("目标包含非法控制字符")
		}
	}
	if strings.ContainsAny(s, ";|&$`\"'\\<> \t\n\r") {
		return "", "", fmt.Errorf("目标格式包含非法字符: %s", rawTarget)
	}

	// 先识别直接传入的 IP 或 CIDR，避免带端口拆分破坏 IPv6。
	if pfx, pErr := netip.ParsePrefix(s); pErr == nil {
		if mt == TrafficMatchDomain || mt == TrafficMatchDomainSuffix {
			return "", "", fmt.Errorf("网段目标 %s 不支持按域名规则匹配", s)
		}
		addr := pfx.Addr()
		bits := pfx.Bits()
		if addr.Is4In6() && bits >= 96 {
			addr = addr.Unmap()
			bits -= 96
		}
		return netip.PrefixFrom(addr, bits).Masked().String(), TrafficMatchIPCIDR, nil
	}
	if addr, aErr := netip.ParseAddr(s); aErr == nil {
		if mt == TrafficMatchDomain || mt == TrafficMatchDomainSuffix {
			return "", "", fmt.Errorf("IP 目标 %s 不支持按域名规则匹配", s)
		}
		u := addr.Unmap()
		return netip.PrefixFrom(u, u.BitLen()).String(), TrafficMatchIPCIDR, nil
	}

	// 处理 URL、通配符或 host:port 形式域名。
	if idx := strings.Index(s, "://"); idx >= 0 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/?#"); idx >= 0 {
		s = s[:idx]
	}
	if host, _, splitErr := net.SplitHostPort(s); splitErr == nil {
		s = host
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, "*")
	s = strings.Trim(s, ".")
	s = strings.ToLower(s)

	if addr, aErr := netip.ParseAddr(s); aErr == nil {
		if mt == TrafficMatchDomain || mt == TrafficMatchDomainSuffix {
			return "", "", fmt.Errorf("IP 目标 %s 不支持按域名规则匹配", s)
		}
		u := addr.Unmap()
		return netip.PrefixFrom(u, u.BitLen()).String(), TrafficMatchIPCIDR, nil
	}
	if mt == TrafficMatchIPCIDR {
		return "", "", fmt.Errorf("域名目标 %s 不能使用 ip_cidr 匹配", s)
	}
	if !isValidRouteDomain(s) {
		return "", "", fmt.Errorf("无效的目标域名或 IP/CIDR: %s", rawTarget)
	}
	if mt == "" {
		mt = TrafficMatchDomainSuffix
	}
	return s, mt, nil
}

// NormalizeTrafficCustomRule 校验并归一化单条审计自定义出口规则的匹配类型、目标格式与可选来源设备 IP。
func NormalizeTrafficCustomRule(raw TrafficCustomRule) (TrafficCustomRule, error) {
	target, matchType, err := normalizeCustomRuleTarget(raw.Target, raw.MatchType)
	if err != nil {
		return TrafficCustomRule{}, err
	}
	outbound, err := CleanTrafficOutboundName(raw.Outbound)
	if err != nil {
		return TrafficCustomRule{}, err
	}
	if outbound == "" {
		return TrafficCustomRule{}, fmt.Errorf("目标出口不能为空")
	}
	if strings.EqualFold(outbound, TrafficOutboundDirect) {
		outbound = TrafficOutboundDirect
	}

	sourceIP := ""
	if strings.TrimSpace(raw.SourceIP) != "" {
		sourceIP = normalizeAuditDirectDeviceIP(raw.SourceIP)
		if sourceIP == "" {
			return TrafficCustomRule{}, fmt.Errorf("来源设备 IP 无效: %s", raw.SourceIP)
		}
	}

	note := strings.TrimSpace(raw.Note)
	if len(note) > 120 {
		note = note[:120]
	}

	return TrafficCustomRule{
		Target:    target,
		MatchType: matchType,
		Outbound:  outbound,
		SourceIP:  sourceIP,
		Note:      note,
		CreatedAt: strings.TrimSpace(raw.CreatedAt),
	}, nil
}

// UpsertRule 幂等新增或按 (matchType, target, sourceIp) 唯一键原地更新自定义出口规则。
func (t *TrafficRoutingConfig) UpsertRule(raw TrafficCustomRule) (TrafficCustomRule, error) {
	if t == nil {
		return TrafficCustomRule{}, fmt.Errorf("nil TrafficRoutingConfig")
	}
	norm, err := NormalizeTrafficCustomRule(raw)
	if err != nil {
		return TrafficCustomRule{}, err
	}
	if norm.CreatedAt == "" {
		norm.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	key := ruleIdentityKey(norm)
	for i := range t.Rules {
		existing, errEx := NormalizeTrafficCustomRule(t.Rules[i])
		if errEx != nil {
			continue
		}
		if ruleIdentityKey(existing) == key {
			if norm.Note == "" {
				norm.Note = existing.Note
			}
			t.Rules[i] = norm
			return norm, nil
		}
	}
	t.Rules = append(t.Rules, norm)
	return norm, nil
}

// RemoveRule 按 (target, matchType, sourceIp) 删除一条自定义出口规则，若未命中返回 false。
func (t *TrafficRoutingConfig) RemoveRule(target, matchType, sourceIP string) bool {
	if t == nil || len(t.Rules) == 0 {
		return false
	}
	normTarget, normType, err := normalizeCustomRuleTarget(target, matchType)
	if err != nil {
		return false
	}
	normSrc := ""
	if strings.TrimSpace(sourceIP) != "" {
		normSrc = normalizeAuditDirectDeviceIP(sourceIP)
		if normSrc == "" {
			return false
		}
	}
	wantKey := normType + "|" + normTarget + "|" + normSrc

	kept := make([]TrafficCustomRule, 0, len(t.Rules))
	removed := false
	for _, r := range t.Rules {
		nr, errNorm := NormalizeTrafficCustomRule(r)
		if errNorm != nil {
			continue
		}
		if ruleIdentityKey(nr) == wantKey {
			removed = true
			continue
		}
		kept = append(kept, nr)
	}
	if removed {
		t.Rules = kept
	}
	return removed
}
