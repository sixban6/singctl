// 文件职责：负责「局域网单设备禁止/允许走外网代理」规则向 sing-box 配置树 (*sboption.Document) 的路由+DNS 双层锚点编译与原地热同步。
package singbox

import (
	"fmt"
	"slices"
	"strings"

	"singctl/internal/singbox/sboption"
)

// NormalizeDirectDeviceCIDRs 将局域网设备 IP 列表规范化为去重后的 /32 或 /128 CIDR 列表。
func NormalizeDirectDeviceCIDRs(rawIPs []string) []string {
	if len(rawIPs) == 0 {
		return nil
	}
	out := make([]string, 0, len(rawIPs))
	seen := make(map[string]struct{}, len(rawIPs))
	for _, raw := range rawIPs {
		cidr := NormalizeSourceIPCIDR(raw)
		if cidr == "" {
			continue
		}
		if _, dup := seen[cidr]; dup {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resolveDirectOutboundTagInDoc(doc *sboption.Document) string {
	if doc == nil {
		return "#DC"
	}
	for _, ob := range doc.Outbounds {
		if ob.Tag == "#DC" {
			return "#DC"
		}
	}
	for _, ob := range doc.Outbounds {
		if strings.EqualFold(strings.TrimSpace(ob.Type), "direct") && strings.TrimSpace(ob.Tag) != "" {
			return ob.Tag
		}
	}
	return "#DC"
}

func isManagedDirectDeviceRouteRule(r sboption.RouteRule) bool {
	act := strings.ToLower(strings.TrimSpace(r.Action))
	if act != "" && act != "route" {
		return false
	}
	if r.Outbound != "#DC" && !strings.EqualFold(strings.TrimSpace(r.Outbound), "direct") {
		return false
	}
	if r.SourceIPCIDR.IsEmpty() {
		return false
	}
	return len(r.Extra) == 0 &&
		r.Type == "" &&
		r.Mode == "" &&
		len(r.Rules) == 0 &&
		r.ClashMode == "" &&
		r.Invert == nil &&
		r.IPIsPrivate == nil &&
		r.Network.IsEmpty() &&
		r.Protocol.IsEmpty() &&
		r.Port.IsEmpty() &&
		r.PortRange.IsEmpty() &&
		r.RuleSet.IsEmpty() &&
		r.Domain.IsEmpty() &&
		r.DomainSuffix.IsEmpty() &&
		r.DomainKeyword.IsEmpty() &&
		r.DomainRegex.IsEmpty() &&
		r.IPCIDR.IsEmpty()
}

func isManagedDirectDeviceDNSRule(r sboption.DNSRule) bool {
	act := strings.ToLower(strings.TrimSpace(r.Action))
	if act != "" && act != "route" {
		return false
	}
	if r.Server != "dns_local" || r.SourceIPCIDR.IsEmpty() {
		return false
	}
	return len(r.Extra) == 0 &&
		r.Type == "" &&
		r.Mode == "" &&
		len(r.Rules) == 0 &&
		r.ClashMode == "" &&
		r.ClientSubnet == "" &&
		r.Rcode == "" &&
		r.Answer.IsEmpty() &&
		r.Strategy == "" &&
		r.Invert == nil &&
		r.DisableCache == nil &&
		r.RewriteTTL == nil &&
		r.RuleSet.IsEmpty() &&
		r.Domain.IsEmpty() &&
		r.DomainSuffix.IsEmpty() &&
		r.DomainKeyword.IsEmpty() &&
		r.DomainRegex.IsEmpty() &&
		r.QueryType.IsEmpty()
}

// ApplyDirectDevicesToDoc 在 sing-box 配置树中幂等同步受管「单设备全直连」路由与 DNS 规则。
// iOS 沙盒平台不注入局域网路由器 source_ip_cidr 规则。
func ApplyDirectDevicesToDoc(doc *sboption.Document, directDevices []string, platform string) bool {
	if doc == nil {
		return false
	}
	changed := false

	if doc.Route != nil && len(doc.Route.Rules) > 0 {
		kept := make([]sboption.RouteRule, 0, len(doc.Route.Rules))
		for _, r := range doc.Route.Rules {
			if isManagedDirectDeviceRouteRule(r) {
				changed = true
				continue
			}
			kept = append(kept, r)
		}
		doc.Route.Rules = kept
	}

	if doc.DNS != nil && len(doc.DNS.Rules) > 0 {
		kept := make([]sboption.DNSRule, 0, len(doc.DNS.Rules))
		for _, r := range doc.DNS.Rules {
			if isManagedDirectDeviceDNSRule(r) {
				changed = true
				continue
			}
			kept = append(kept, r)
		}
		doc.DNS.Rules = kept
	}

	if strings.EqualFold(strings.TrimSpace(platform), PlatformIOS) {
		return changed
	}
	cidrs := NormalizeDirectDeviceCIDRs(directDevices)
	if len(cidrs) == 0 {
		return changed
	}

	if doc.DNS != nil {
		dnsIdx := sboption.TrafficDNSInsertIndex(doc.DNS.Rules)
		dnsRule := sboption.DNSRule{
			Server:       "dns_local",
			SourceIPCIDR: sboption.ListOf(cidrs...),
		}
		doc.DNS.Rules = slices.Insert(doc.DNS.Rules, dnsIdx, dnsRule)
		changed = true
	}

	if doc.Route == nil {
		doc.Route = &sboption.RouteOptions{}
	}
	directTag := resolveDirectOutboundTagInDoc(doc)
	routeIdx := sboption.TrafficRouteInsertIndex(doc.Route.Rules)
	routeRule := sboption.RouteRule{
		Action:       "route",
		SourceIPCIDR: sboption.ListOf(cidrs...),
		Outbound:     directTag,
	}
	doc.Route.Rules = slices.Insert(doc.Route.Rules, routeIdx, routeRule)
	return true
}

// SyncDirectDevicesInConfigJSON 在不重新拉取远程订阅的前提下，对现有 sing-box config.json 原地幂等更新单设备直连规则。
func SyncDirectDevicesInConfigJSON(rawJSON string, directDevices []string) (string, error) {
	doc, err := sboption.ParseDocument([]byte(rawJSON))
	if err != nil {
		return "", fmt.Errorf("failed to parse config.json: %w", err)
	}
	ApplyDirectDevicesToDoc(doc, directDevices, "")
	return doc.MarshalPretty()
}
