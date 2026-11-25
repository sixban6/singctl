// 文件职责：定义客户端本地域名与设备名册配置模型（HomeDomainConfig）、RFC 1123 域名/后缀校验、托管重写生成与设备昵称反查。
package config

import (
	"cmp"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

const DefaultHomeDomainSuffix = "home"

var (
	homeDomainLabelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	forbiddenHomeTLDs = map[string]bool{
		"local": true, "localhost": true, "invalid": true, "example": true, "test": true,
		"com": true, "net": true, "org": true, "cn": true, "io": true, "co": true,
		"gov": true, "edu": true, "mil": true, "int": true, "dev": true, "app": true,
		"ai": true, "me": true, "tv": true, "cc": true, "xyz": true, "top": true,
		"vip": true, "cloud": true, "google": true, "apple": true, "ms": true,
	}
	reservedDeviceAliases = map[string]bool{
		"localhost": true,
		"wpad":      true,
		"isatap":    true,
		"broadcasthost": true,
	}
)

// HomeDomainService 描述设备卡片上展示的一键直达服务快捷入口（如 WebUI :8090、NAS :5000、SSH）。
type HomeDomainService struct {
	Label  string `yaml:"label,omitempty" json:"label,omitempty"`
	Scheme string `yaml:"scheme,omitempty" json:"scheme,omitempty"` // "http" | "https" | "ssh"
	Port   int    `yaml:"port,omitempty" json:"port,omitempty"`
}

// HomeDomainDevice 描述一台已命名并绑定本地域名的局域网/Tailscale 设备。
type HomeDomainDevice struct {
	Alias       string              `yaml:"alias" json:"alias"`
	DisplayName string              `yaml:"display_name,omitempty" json:"displayName,omitempty"`
	IP          string              `yaml:"ip" json:"ip"`
	MAC         string              `yaml:"mac,omitempty" json:"mac,omitempty"`
	Source      string              `yaml:"source,omitempty" json:"source,omitempty"` // "self" | "lan" | "tailscale" | "manual"
	Wildcard    bool                `yaml:"wildcard,omitempty" json:"wildcard,omitempty"`
	Services    []HomeDomainService `yaml:"services,omitempty" json:"services,omitempty"`
	Note        string              `yaml:"note,omitempty" json:"note,omitempty"`
}

// HomeDomainConfig 定义客户端设备昵称与跨 Tailscale 本地域名解析配置。
type HomeDomainConfig struct {
	Enabled      *bool              `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Suffix       string             `yaml:"suffix,omitempty" json:"suffix,omitempty"`
	TailscaleDNS *bool              `yaml:"tailscale_dns,omitempty" json:"tailscaleDns,omitempty"`
	FollowDHCP   *bool              `yaml:"follow_dhcp,omitempty" json:"followDhcp,omitempty"`
	Devices      []HomeDomainDevice `yaml:"devices,omitempty" json:"devices,omitempty"`
}

// IsEnabled 返回本地域名功能是否处于启用状态（nil 或 true 视为启用）。
func (h HomeDomainConfig) IsEnabled() bool {
	return h.Enabled == nil || *h.Enabled
}

// IsEmpty 判断是否未显式设置任何本地域名配置字段。
func (h HomeDomainConfig) IsEmpty() bool {
	return h.Enabled == nil &&
		strings.TrimSpace(h.Suffix) == "" &&
		h.TailscaleDNS == nil &&
		h.FollowDHCP == nil &&
		len(h.Devices) == 0
}

// SetEnabled 显式设置本地域名启用状态。
func (h *HomeDomainConfig) SetEnabled(v bool) {
	if h == nil {
		return
	}
	h.Enabled = &v
}

// IsTailscaleDNSEnabled 返回是否启用内置 Tailscale 专属 Split-DNS 应答器（默认 true）。
func (h HomeDomainConfig) IsTailscaleDNSEnabled() bool {
	return h.TailscaleDNS == nil || *h.TailscaleDNS
}

// SetTailscaleDNSEnabled 设置内置 Tailscale Split-DNS 应答器开关。
func (h *HomeDomainConfig) SetTailscaleDNSEnabled(v bool) {
	if h == nil {
		return
	}
	h.TailscaleDNS = &v
}

// IsFollowDHCPEnabled 返回 MAC 绑定设备在 DHCP 换 IP 时是否自动跟随更新（默认 true）。
func (h HomeDomainConfig) IsFollowDHCPEnabled() bool {
	return h.FollowDHCP == nil || *h.FollowDHCP
}

// SetFollowDHCPEnabled 设置 DHCP 自动跟随更新开关。
func (h *HomeDomainConfig) SetFollowDHCPEnabled(v bool) {
	if h == nil {
		return
	}
	h.FollowDHCP = &v
}

// EffectiveSuffix 返回归一化后的安全内网域名后缀（默认 "home"）。
func (h HomeDomainConfig) EffectiveSuffix() string {
	if norm, err := NormalizeHomeDomainSuffix(h.Suffix); err == nil && norm != "" {
		return norm
	}
	return DefaultHomeDomainSuffix
}

// NormalizeHomeDomainSuffix 校验并归一化内网域名后缀（默认 home，允许 home.arpa/lan/internal 等 1~2 段私网后缀，拦截 .local 与公网 TLD）。
func NormalizeHomeDomainSuffix(raw string) (string, error) {
	s := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
	if s == "" {
		return DefaultHomeDomainSuffix, nil
	}
	if strings.ContainsAny(s, " \t\r\n/\\;:`'\"$()") {
		return "", fmt.Errorf("后缀包含非法字符: %q", raw)
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return "", fmt.Errorf("内网后缀最多支持 2 段标签（如 home 或 home.arpa），当前: %q", raw)
	}
	for _, label := range parts {
		if !homeDomainLabelRe.MatchString(label) {
			return "", fmt.Errorf("内网后缀标签不合法: %q", label)
		}
	}
	last := parts[len(parts)-1]
	if last == "local" {
		return "", fmt.Errorf("禁止使用 .local 后缀（会被 Apple Bonjour / mDNS 拦截导致解析冲突），推荐 home 或 home.arpa")
	}
	if last == "arpa" && s != "home.arpa" {
		return "", fmt.Errorf("arpa 后缀仅允许使用 RFC 8375 标准 home.arpa")
	}
	if forbiddenHomeTLDs[last] {
		return "", fmt.Errorf("禁止使用保留或公网顶级域 %q 作为内网后缀，防止覆盖公网站点", last)
	}
	return s, nil
}

// NormalizeDeviceAlias 校验并归一化 RFC 1123 单段英文短域名标签（如 ax3000t / nas / n60-pro）。
func NormalizeDeviceAlias(raw string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return "", fmt.Errorf("设备短域名不能为空")
	}
	if !homeDomainLabelRe.MatchString(s) {
		return "", fmt.Errorf("设备短域名 %q 仅允许小写英文字母、数字和连字符，且不能以连字符开头或结尾", raw)
	}
	if reservedDeviceAliases[s] {
		return "", fmt.Errorf("设备短域名 %q 为系统保留名称，请换一个别名", s)
	}
	return s, nil
}

// SanitizeSuggestedAlias 将原始主机名（如 Xiaomi_AX3000T、My NAS.local）自动清洗为可直接作为默认建议的合法短域名。
func SanitizeSuggestedAlias(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	// 去掉常见的 .local / .lan / .home / .home.arpa / tailnet 尾缀，取首段主机名
	if dot := strings.IndexByte(s, '.'); dot > 0 {
		s = s[:dot]
	}
	var b strings.Builder
	prevDash := false
	for i := range len(s) {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			b.WriteByte(ch)
			prevDash = false
		} else if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	if norm, err := NormalizeDeviceAlias(out); err == nil {
		return norm
	}
	return ""
}

// NormalizeMAC 将 MAC 地址归一化为小写冒号分隔格式（aa:bb:cc:dd:ee:ff）；非合法 6 字节 MAC 返回空串。
func NormalizeMAC(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "-", ":")
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return ""
	}
	for _, p := range parts {
		if len(p) != 2 {
			return ""
		}
		for i := range 2 {
			c := p[i]
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return ""
			}
		}
	}
	if s == "00:00:00:00:00:00" || s == "ff:ff:ff:ff:ff:ff" {
		return ""
	}
	return s
}

// Validate 全面校验本地域名配置（后缀合法性、设备别名唯一性、目标 IP 合法性与服务端口合法性）。
func (h HomeDomainConfig) Validate() error {
	if _, err := NormalizeHomeDomainSuffix(h.Suffix); err != nil {
		return err
	}
	seenAlias := make(map[string]struct{}, len(h.Devices))
	for _, d := range h.Devices {
		alias, err := NormalizeDeviceAlias(d.Alias)
		if err != nil {
			return err
		}
		if _, dup := seenAlias[alias]; dup {
			return fmt.Errorf("存在重复的设备短域名: %s", alias)
		}
		seenAlias[alias] = struct{}{}

		addr, parseErr := netip.ParseAddr(strings.TrimSpace(d.IP))
		if parseErr != nil || addr.IsUnspecified() || addr.IsMulticast() {
			return fmt.Errorf("设备 %s 的目标 IP %q 无效", alias, d.IP)
		}
		if strings.TrimSpace(d.MAC) != "" && NormalizeMAC(d.MAC) == "" {
			return fmt.Errorf("设备 %s 的 MAC 地址 %q 格式无效", alias, d.MAC)
		}
		for _, svc := range d.Services {
			scheme := strings.ToLower(strings.TrimSpace(svc.Scheme))
			if scheme != "" && scheme != "http" && scheme != "https" && scheme != "ssh" {
				return fmt.Errorf("设备 %s 的快捷服务协议 %q 不受支持（仅支持 http/https/ssh）", alias, svc.Scheme)
			}
			if svc.Port < 0 || svc.Port > 65535 {
				return fmt.Errorf("设备 %s 的快捷服务端口 %d 无效", alias, svc.Port)
			}
		}
	}
	return nil
}

// BuildManagedRewrites 将已启用且合法的命名设备编译为确定性排序的 DNS 重写规则列表（含可选 *.alias.<suffix> 通配记录）。
func (h HomeDomainConfig) BuildManagedRewrites() []DNSRewriteRule {
	if !h.IsEnabled() || len(h.Devices) == 0 {
		return nil
	}
	suffix := h.EffectiveSuffix()
	type deviceEntry struct {
		alias    string
		ip       string
		wildcard bool
	}
	entries := make([]deviceEntry, 0, len(h.Devices))
	seen := make(map[string]struct{}, len(h.Devices))
	for _, d := range h.Devices {
		alias, err := NormalizeDeviceAlias(d.Alias)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(d.IP))
		if err != nil || addr.IsUnspecified() || addr.IsMulticast() {
			continue
		}
		if _, dup := seen[alias]; dup {
			continue
		}
		seen[alias] = struct{}{}
		entries = append(entries, deviceEntry{
			alias:    alias,
			ip:       addr.Unmap().String(),
			wildcard: d.Wildcard,
		})
	}
	slices.SortFunc(entries, func(a, b deviceEntry) int {
		return cmp.Compare(a.alias, b.alias)
	})
	out := make([]DNSRewriteRule, 0, len(entries)*2)
	for _, e := range entries {
		fqdn := e.alias + "." + suffix
		out = append(out, DNSRewriteRule{Domain: fqdn, Answer: e.ip})
		if e.wildcard {
			out = append(out, DNSRewriteRule{Domain: "*." + fqdn, Answer: e.ip})
		}
	}
	return out
}

// ManagedDomainMap 返回全部托管域名（含 *. 通配键，小写）到对应设备的映射，供 DNS 面板徽章与防误删保护使用。
func (h HomeDomainConfig) ManagedDomainMap() map[string]HomeDomainDevice {
	if !h.IsEnabled() || len(h.Devices) == 0 {
		return nil
	}
	suffix := h.EffectiveSuffix()
	out := make(map[string]HomeDomainDevice, len(h.Devices)*2)
	for _, d := range h.Devices {
		alias, err := NormalizeDeviceAlias(d.Alias)
		if err != nil {
			continue
		}
		fqdn := alias + "." + suffix
		out[fqdn] = d
		if d.Wildcard {
			out["*."+fqdn] = d
		}
	}
	return out
}

// LookupFriendlyName 按 MAC 优先、IP 兜底反查已命名设备的友好备注与完整本地域名，供流量审计与防绕过界面联动展示。
func (h HomeDomainConfig) LookupFriendlyName(ipStr, macStr string) (displayName, fqdn string, ok bool) {
	if len(h.Devices) == 0 {
		return "", "", false
	}
	suffix := h.EffectiveSuffix()
	normMAC := NormalizeMAC(macStr)
	var canonIP string
	if addr, err := netip.ParseAddr(strings.TrimSpace(ipStr)); err == nil {
		canonIP = addr.Unmap().String()
	}

	if normMAC != "" {
		for _, d := range h.Devices {
			if NormalizeMAC(d.MAC) == normMAC {
				if alias, err := NormalizeDeviceAlias(d.Alias); err == nil {
					return cmp.Or(strings.TrimSpace(d.DisplayName), alias), alias + "." + suffix, true
				}
			}
		}
	}
	if canonIP != "" {
		for _, d := range h.Devices {
			if dAddr, err := netip.ParseAddr(strings.TrimSpace(d.IP)); err == nil && dAddr.Unmap().String() == canonIP {
				if alias, err := NormalizeDeviceAlias(d.Alias); err == nil {
					return cmp.Or(strings.TrimSpace(d.DisplayName), alias), alias + "." + suffix, true
				}
			}
		}
	}
	return "", "", false
}

// Clone 深拷贝 HomeDomainConfig 及其所有切片与指针字段。
func (h HomeDomainConfig) Clone() HomeDomainConfig {
	out := HomeDomainConfig{
		Enabled:      cloneBoolPtr(h.Enabled),
		Suffix:       h.Suffix,
		TailscaleDNS: cloneBoolPtr(h.TailscaleDNS),
		FollowDHCP:   cloneBoolPtr(h.FollowDHCP),
	}
	if h.Devices != nil {
		out.Devices = make([]HomeDomainDevice, len(h.Devices))
		for i, d := range h.Devices {
			out.Devices[i] = d
			out.Devices[i].Services = slices.Clone(d.Services)
		}
	}
	return out
}
