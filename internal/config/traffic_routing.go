package config

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
)

// TrafficRuleOverride 定义单条客户端智能分流预设的持久化覆盖配置。
// Enabled 为 nil 时沿用该预设的推荐默认开关（如 AI/流媒体/游戏/社交默认开启，办公生态默认直连）；
// Outbound 为空时沿用该预设的推荐默认分组（AI 默认 #VPS 逐级回退，其他默认 Proxy）。
type TrafficRuleOverride struct {
	Enabled  *bool  `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Outbound string `yaml:"outbound,omitempty" json:"outbound,omitempty"`
}

// TrafficRoutingConfig 定义客户端「智能分流中心」策略（持久化于 singctl.yaml traffic_routing）。
type TrafficRoutingConfig struct {
	Presets map[string]TrafficRuleOverride `yaml:"presets,omitempty" json:"presets,omitempty"`
}

// IsEmpty 判断客户端智能分流配置是否处于完全未定制的默认态。
func (t TrafficRoutingConfig) IsEmpty() bool {
	return len(t.Normalized().Presets) == 0
}

// IsZero 供 yaml.v3 omitempty 判断是否省略空结构体。
func (t TrafficRoutingConfig) IsZero() bool {
	return t.IsEmpty()
}

// Clone 深拷贝配置（含 *bool 指针独立拷贝，避免并发共享写）。
func (t TrafficRoutingConfig) Clone() TrafficRoutingConfig {
	if len(t.Presets) == 0 {
		return TrafficRoutingConfig{}
	}
	cloned := make(map[string]TrafficRuleOverride, len(t.Presets))
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
	return TrafficRoutingConfig{Presets: cloned}
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

// Normalized 返回键名规范化且剔除空覆盖后的副本。
func (t TrafficRoutingConfig) Normalized() TrafficRoutingConfig {
	if len(t.Presets) == 0 {
		return TrafficRoutingConfig{}
	}
	keys := make([]string, 0, len(t.Presets))
	for k := range t.Presets {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	out := make(map[string]TrafficRuleOverride, len(keys))
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
		out[id] = TrafficRuleOverride{
			Enabled:  enabledPtr,
			Outbound: ob,
		}
	}
	if len(out) == 0 {
		return TrafficRoutingConfig{}
	}
	return TrafficRoutingConfig{Presets: out}
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
