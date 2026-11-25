// 文件职责：定义防 DNS 绕过分层拦截策略配置模型（L1~L4 层开关、L4 App 家族精细开关、横向源 IP 豁免校验与深拷贝）。
package config

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
)

// DNSBypassAppGroupDefault 定义 L4 大厂 App 自建 HTTPDNS 分组默认启用基线（单一权威归属）：
// 微信专有调度（wechat）高误伤默认关闭，其余主流 App 纯 HTTPDNS 默认开启。
var defaultDNSBypassAppGroupEnabled = map[string]bool{
	"bilibili":  true,
	"bytedance": true,
	"jd":        true,
	"netease":   true,
	"meituan":   true,
	"ctrip":     true,
	"oem":       true,
	"wechat":    false,
}

// IsKnownDNSBypassAppGroup 校验给定的 L4 App 家族 ID 是否在受管注册表中。
func IsKnownDNSBypassAppGroup(id string) bool {
	_, ok := defaultDNSBypassAppGroupEnabled[strings.ToLower(strings.TrimSpace(id))]
	return ok
}

// DNSBypassGuardLayers 控制 L1~L4 四个正交防绕过拦截层的独立开关（L1~L3 默认启用，L4 默认关闭按需开启）。
type DNSBypassGuardLayers struct {
	DoTDoQ     *bool `yaml:"dot_doq,omitempty" json:"dotDoq,omitempty"`
	PublicDoH  *bool `yaml:"public_doh,omitempty" json:"publicDoh,omitempty"`
	SDKHTTPDNS *bool `yaml:"sdk_httpdns,omitempty" json:"sdkHttpdns,omitempty"`
	AppHTTPDNS *bool `yaml:"app_httpdns,omitempty" json:"appHttpdns,omitempty"`
}

// DNSBypassGuardConfig 定义客户端网关 DNS 防绕过分层策略与横向免拦白名单。
type DNSBypassGuardConfig struct {
	Enabled         *bool                `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Layers          DNSBypassGuardLayers `yaml:"layers,omitempty" json:"layers,omitempty"`
	AppGroups       map[string]bool      `yaml:"app_groups,omitempty" json:"appGroups,omitempty"`
	ExemptSourceIPs []string             `yaml:"exempt_source_ips,omitempty" json:"exemptSourceIps,omitempty"`
}

func boolPtrDefaultTrue(p *bool) bool {
	return p == nil || *p
}

func boolPtrDefaultFalse(p *bool) bool {
	return p != nil && *p
}

// IsEnabled 返回防绕过分层引擎总开关（未配置时默认开启）。
func (g DNSBypassGuardConfig) IsEnabled() bool { return boolPtrDefaultTrue(g.Enabled) }

// LayerDoTDoQ 返回 L1（TCP/UDP 853 DoT/DoQ 端口层）是否启用（默认开启）。
func (g DNSBypassGuardConfig) LayerDoTDoQ() bool { return boolPtrDefaultTrue(g.Layers.DoTDoQ) }

// LayerPublicDoH 返回 L2（国内外公共 DoH IP/域名层）是否启用（默认开启）。
func (g DNSBypassGuardConfig) LayerPublicDoH() bool { return boolPtrDefaultTrue(g.Layers.PublicDoH) }

// LayerSDKHTTPDNS 返回 L3（国内云厂商通用 HTTPDNS SDK 80/443 层）是否启用（默认开启）。
func (g DNSBypassGuardConfig) LayerSDKHTTPDNS() bool { return boolPtrDefaultTrue(g.Layers.SDKHTTPDNS) }

// LayerAppHTTPDNS 返回 L4（主流大厂 App 自建 HTTPDNS 层）总开关是否启用（默认关闭，需用户按需开启）。
func (g DNSBypassGuardConfig) LayerAppHTTPDNS() bool { return boolPtrDefaultFalse(g.Layers.AppHTTPDNS) }

// IsAppGroupEnabled 返回指定 L4 App 家族的最终生效状态（显式配置优先，否则回退默认安全基线）。
func (g DNSBypassGuardConfig) IsAppGroupEnabled(id string) bool {
	key := strings.ToLower(strings.TrimSpace(id))
	if g.AppGroups != nil {
		if v, ok := g.AppGroups[key]; ok {
			return v
		}
	}
	return defaultDNSBypassAppGroupEnabled[key]
}

// Clone 返回 DNSBypassGuardConfig 的深拷贝，隔离全部指针、映射与切片。
func (g DNSBypassGuardConfig) Clone() DNSBypassGuardConfig {
	return DNSBypassGuardConfig{
		Enabled: cloneBoolPtr(g.Enabled),
		Layers: DNSBypassGuardLayers{
			DoTDoQ:     cloneBoolPtr(g.Layers.DoTDoQ),
			PublicDoH:  cloneBoolPtr(g.Layers.PublicDoH),
			SDKHTTPDNS: cloneBoolPtr(g.Layers.SDKHTTPDNS),
			AppHTTPDNS: cloneBoolPtr(g.Layers.AppHTTPDNS),
		},
		AppGroups:       maps.Clone(g.AppGroups),
		ExemptSourceIPs: slices.Clone(g.ExemptSourceIPs),
	}
}

// NormalizeExemptSourceIPs 严格校验并归一化横向免拦源设备 IP/CIDR 列表（阻断回环、全网 0.0.0.0/0、注入与畸形输入）。
func NormalizeExemptSourceIPs(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, entry := range raw {
		if strings.ContainsAny(entry, "\r\n\t\x00;'\"`\\") {
			return nil, fmt.Errorf("免拦源 IP %q 包含非法控制或注入字符", entry)
		}
		s := strings.TrimSpace(entry)
		if s == "" {
			continue
		}
		if strings.ContainsAny(s, " \t") {
			return nil, fmt.Errorf("免拦源 IP %q 不允许包含空白字符", s)
		}
		var prefix netip.Prefix
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("无效的免拦源 CIDR %q: %w", s, err)
			}
			prefix = p.Masked()
		} else {
			addr, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("无效的免拦源 IP %q: %w", s, err)
			}
			addr = addr.Unmap()
			prefix = netip.PrefixFrom(addr, addr.BitLen())
		}
		addr := prefix.Addr().Unmap()
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("免拦源网段 %q 禁止匹配全网 (/%d)，请使用总开关关闭或指定具体设备网段", s, prefix.Bits())
		}
		if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalMulticast() {
			return nil, fmt.Errorf("免拦源地址 %q 不允许使用回环、未指定或组播地址", s)
		}
		norm := prefix.String()
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil, nil
	}
	if len(out) > 64 {
		return nil, fmt.Errorf("免拦源设备数量超过上限（最多 64 条）")
	}
	return out, nil
}
