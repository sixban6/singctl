// 文件职责：提供 VLAN 无线密钥按需安全读取、DHCP Option 6 DNS 解析校验与跨网段 DNS 防劫持联动编排。
package vlan

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

const maxDHCPDNSServers = 4

// WirelessSecret 按需读取指定 VLAN 分段在 OpenWrt 现网配置的 Wi-Fi 名称与预共享密钥（不在常规轮询 Overview 中返回）。
func (s *Service) WirelessSecret(ctx context.Context, segID string) (*WirelessSecret, error) {
	trimmed := strings.TrimSpace(segID)
	id := strings.ToLower(trimmed)
	if id == "" || hasControlOrInject(segID) || (id != "lan" && !validSegmentIDRe.MatchString(id)) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidSegmentID, segID)
	}

	netRaw, err := s.runUCI(ctx, "show", "network")
	if err != nil {
		return nil, fmt.Errorf("读取 OpenWrt network UCI 失败: %w", err)
	}
	netUCI := parseUCIShow("network", netRaw)
	sec := netUCI.ByName(id)
	if sec == nil || sec.Type != "interface" || sec.Opt("proto") != "static" || sec.Opt("ipaddr") == "" {
		return nil, fmt.Errorf("%w: %q", ErrSegmentNotFound, id)
	}

	wirelessRaw, _ := s.runUCI(ctx, "show", "wireless")
	wUCI := parseUCIShow("wireless", wirelessRaw)
	var chosen *UCISection
	if wUCI != nil {
		for _, iface := range wUCI.ByType("wifi-iface") {
			if iface.Opt("mode") != "" && iface.Opt("mode") != "ap" {
				continue
			}
			if iface.Opt("network") != id {
				continue
			}
			if chosen == nil || (chosen.Opt("disabled") == "1" && iface.Opt("disabled") != "1") {
				chosen = iface
			}
			if iface.Opt("disabled") != "1" {
				break
			}
		}
	}

	if chosen == nil {
		return &WirelessSecret{
			SegmentID:          id,
			PasswordConfigured: false,
		}, nil
	}
	key := chosen.Opt("key")
	return &WirelessSecret{
		SegmentID:          id,
		Section:            chosen.Name,
		SSID:               chosen.Opt("ssid"),
		PasswordConfigured: key != "",
		Password:           key,
	}, nil
}

func isValidDHCPDNSAddr(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return false
	}
	return addr != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func normalizeAndValidateDHCPDNS(raw []string) ([]string, []string) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(raw))
	valid := make([]string, 0, len(raw))
	var errs []string

	for _, entry := range raw {
		s := strings.TrimSpace(entry)
		if s == "" {
			continue
		}
		if hasControlOrInject(s) {
			errs = append(errs, fmt.Sprintf("自定义 DNS 地址 %q 包含非法控制字符或注入载荷", s))
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			errs = append(errs, fmt.Sprintf("自定义 DNS 地址 %q 不是有效的 IPv4 地址", s))
			continue
		}
		if !isValidDHCPDNSAddr(addr) {
			errs = append(errs, fmt.Sprintf("不允许将保留或特殊 IP (%s) 设为 DHCP 下发 DNS", s))
			continue
		}
		norm := addr.String()
		if !seen[norm] {
			seen[norm] = true
			valid = append(valid, norm)
		}
	}
	if len(valid) > maxDHCPDNSServers {
		errs = append(errs, fmt.Sprintf("单个子网最多允许指定 %d 个 DHCP 下发 DNS 服务器（当前 %d 个）", maxDHCPDNSServers, len(valid)))
	}
	return valid, errs
}

func effectiveCustomDNS(dnsList []string, selfGatewayIP string) []string {
	selfIP := strings.TrimSpace(selfGatewayIP)
	var out []string
	for _, raw := range dnsList {
		ip := strings.TrimSpace(raw)
		if ip == "" || ip == selfIP {
			continue
		}
		if !slices.Contains(out, ip) {
			out = append(out, ip)
		}
	}
	return out
}

func parseDHCPDNSOptions(sec *UCISection) []string {
	if sec == nil {
		return nil
	}
	var out []string
	for _, opt := range sec.List("dhcp_option") {
		items, isDNS := extractDHCPDNSOptionItems(opt)
		if !isDNS {
			continue
		}
		for _, item := range items {
			addr, err := netip.ParseAddr(strings.TrimSpace(item))
			if err != nil || !isValidDHCPDNSAddr(addr) {
				continue
			}
			s := addr.String()
			if !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

func extractDHCPDNSOptionItems(rawOpt string) ([]string, bool) {
	s := strings.TrimSpace(rawOpt)
	var rest string
	switch {
	case strings.HasPrefix(s, "6,"):
		rest = strings.TrimPrefix(s, "6,")
	case strings.HasPrefix(s, "option:dns-server,"):
		rest = strings.TrimPrefix(s, "option:dns-server,")
	default:
		return nil, false
	}
	parts := strings.Split(rest, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out, true
}

func filterNonDNSDHCPOptions(sec *UCISection) []string {
	if sec == nil {
		return nil
	}
	var kept []string
	for _, opt := range sec.List("dhcp_option") {
		if _, isDNS := extractDHCPDNSOptionItems(opt); isDNS {
			continue
		}
		if trimmed := strings.TrimSpace(opt); trimmed != "" {
			kept = append(kept, trimmed)
		}
	}
	return kept
}

func firewallZoneForSegment(fwUCI *UCIConfig, segID string) string {
	if fwUCI != nil {
		for _, z := range fwUCI.ByType("zone") {
			if z.Opt("name") == segID || slices.Contains(z.List("network"), segID) {
				if zName := z.Opt("name"); zName != "" {
					return zName
				}
				return segID
			}
		}
	}
	return segID
}

func buildCustomDNSFirewallRules(ov *Overview, fwUCI *UCIConfig, zoneName, segID, selfGatewayIP string, dnsIPs []string) ([]string, []string) {
	customDNS := effectiveCustomDNS(dnsIPs, selfGatewayIP)
	var createdRefs []string
	var cmds []string

	if len(customDNS) == 0 {
		return cmds, createdRefs
	}

	var wanPfx netip.Prefix
	hasWanPfx := false
	if ov != nil && ov.WANSubnet != "" {
		if p, err := netip.ParsePrefix(ov.WANSubnet); err == nil {
			wanPfx = p
			hasWanPfx = true
		}
	}

	ruleIdx := 0
	for _, dnsIP := range customDNS {
		addr, err := netip.ParseAddr(dnsIP)
		if err != nil {
			continue
		}
		destZone := ""
		if ov != nil {
			for _, seg := range ov.Segments {
				if seg.ID == segID || seg.CIDR == "" {
					continue
				}
				if segPfx, pErr := netip.ParsePrefix(seg.CIDR); pErr == nil && segPfx.Contains(addr) {
					destZone = firewallZoneForSegment(fwUCI, seg.ID)
					break
				}
			}
		}
		if destZone == "" && hasWanPfx && wanPfx.Contains(addr) {
			destZone = "wan"
		}
		if destZone == "" {
			continue
		}

		ref := fmt.Sprintf("singctl_allow_dns_%s_%d", segID, ruleIdx)
		ruleIdx++
		createdRefs = append(createdRefs, ref)
		cmds = append(cmds,
			fmt.Sprintf("set firewall.%s=rule", ref),
			fmt.Sprintf("set firewall.%s.name=%s", ref, quoteUCI(fmt.Sprintf("SingCtl-Allow-DNS-%s-%d", segID, ruleIdx))),
			fmt.Sprintf("set firewall.%s.src=%s", ref, quoteUCI(zoneName)),
			fmt.Sprintf("set firewall.%s.dest=%s", ref, quoteUCI(destZone)),
			fmt.Sprintf("set firewall.%s.dest_ip=%s", ref, quoteUCI(dnsIP)),
			fmt.Sprintf("set firewall.%s.proto='tcp udp'", ref),
			fmt.Sprintf("set firewall.%s.dest_port='53'", ref),
			fmt.Sprintf("set firewall.%s.target='ACCEPT'", ref),
		)
	}
	return cmds, createdRefs
}

func collectStaleCustomDNSRuleDeletes(fwUCI *UCIConfig, segID string, activeRefs []string) []string {
	if fwUCI == nil {
		return nil
	}
	pfx := "singctl_allow_dns_" + segID + "_"
	var deletes []string
	for _, sec := range fwUCI.Sections {
		if strings.HasPrefix(sec.Name, pfx) && !slices.Contains(activeRefs, sec.Name) {
			deletes = append(deletes, fmt.Sprintf("delete firewall.%s", sec.Name))
		}
	}
	return deletes
}
