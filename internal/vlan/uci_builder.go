// 文件职责：提供 OpenWrt VLAN 的 DHCP/无线/防火墙 UCI 指令构建、现网分段解析与跨网隔离关系徽标生成。
package vlan

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

func buildDHCPCommands(dUCI *UCIConfig, req SaveSegmentRequest) []string {
	cmds := []string{
		fmt.Sprintf("set dhcp.%s=dhcp", req.ID),
		fmt.Sprintf("set dhcp.%s.interface=%s", req.ID, quoteUCI(req.ID)),
		fmt.Sprintf("set dhcp.%s.start=%s", req.ID, quoteUCI(strconv.Itoa(req.DHCPStart))),
		fmt.Sprintf("set dhcp.%s.limit=%s", req.ID, quoteUCI(strconv.Itoa(req.DHCPLimit))),
		fmt.Sprintf("set dhcp.%s.leasetime=%s", req.ID, quoteUCI(req.LeaseTime)),
	}

	var curSec *UCISection
	if dUCI != nil {
		curSec = dUCI.ByName(req.ID)
		if curSec == nil {
			for _, cand := range dUCI.ByType("dhcp") {
				if cand.Opt("interface") == req.ID {
					curSec = cand
					break
				}
			}
		}
	}
	keptOpts := filterNonDNSDHCPOptions(curSec)
	customDNS := effectiveCustomDNS(req.DHCPDNS, req.IPAddr)
	if (curSec != nil && len(curSec.List("dhcp_option")) > 0) || len(keptOpts) > 0 || len(customDNS) > 0 {
		cmds = append(cmds, fmt.Sprintf("delete dhcp.%s.dhcp_option", req.ID))
		for _, opt := range keptOpts {
			cmds = append(cmds, fmt.Sprintf("add_list dhcp.%s.dhcp_option=%s", req.ID, quoteUCI(opt)))
		}
		if len(customDNS) > 0 {
			cmds = append(cmds, fmt.Sprintf("add_list dhcp.%s.dhcp_option=%s", req.ID, quoteUCI("6,"+strings.Join(customDNS, ","))))
		}
	}

	switch req.IPv6Mode {
	case IPv6Relay:
		cmds = append(cmds,
			fmt.Sprintf("set dhcp.%s.ra='relay'", req.ID),
			fmt.Sprintf("set dhcp.%s.dhcpv6='relay'", req.ID),
			fmt.Sprintf("set dhcp.%s.ndp='relay'", req.ID),
			fmt.Sprintf("set dhcp.%s.ra_dns='0'", req.ID),
			fmt.Sprintf("set dhcp.%s.dns_service='0'", req.ID),
		)
	case IPv6Server:
		cmds = append(cmds,
			fmt.Sprintf("set dhcp.%s.ra='server'", req.ID),
			fmt.Sprintf("set dhcp.%s.dhcpv6='server'", req.ID),
			fmt.Sprintf("set dhcp.%s.ra_slaac='1'", req.ID),
			fmt.Sprintf("set dhcp.%s.ra_dns='0'", req.ID),
			fmt.Sprintf("set dhcp.%s.dns_service='0'", req.ID),
		)
	default:
		cmds = append(cmds,
			fmt.Sprintf("delete dhcp.%s.ra", req.ID),
			fmt.Sprintf("delete dhcp.%s.dhcpv6", req.ID),
			fmt.Sprintf("delete dhcp.%s.ndp", req.ID),
		)
		if len(customDNS) > 0 {
			cmds = append(cmds,
				fmt.Sprintf("set dhcp.%s.ra_dns='0'", req.ID),
				fmt.Sprintf("set dhcp.%s.dns_service='0'", req.ID),
			)
		}
	}
	return cmds
}

func buildWirelessCommands(wUCI *UCIConfig, radios []RadioInfo, req SaveSegmentRequest, existing *Segment) []string {
	if req.Wireless == nil || len(radios) == 0 {
		return nil
	}
	secName := "singctl_vlan_" + req.ID
	if req.Wireless.Section != "" {
		secName = req.Wireless.Section
	} else if existing != nil && existing.Wireless != nil && existing.Wireless.Section != "" {
		secName = existing.Wireless.Section
	}

	var cur *UCISection
	if wUCI != nil {
		cur = wUCI.ByName(secName)
	}

	if !req.Wireless.Enabled {
		if cur != nil && cur.Opt("disabled") != "1" {
			return []string{fmt.Sprintf("set wireless.%s.disabled='1'", secName)}
		}
		return nil
	}

	radio := req.Wireless.Radio
	if radio == "" && len(radios) > 0 {
		radio = radios[0].Name
	}
	wantIsolate := "0"
	if req.Wireless.Isolate {
		wantIsolate = "1"
	}

	// 无线属性脏检测：未改任何无线字段且未传新密码（留空或等于现网原密码）时返回空切片，避免触发无意义的 uci commit wireless 与高危 wifi reload。
	if cur != nil && (req.Wireless.Password == "" || req.Wireless.Password == cur.Opt("key")) {
		curMode := cmp.Or(cur.Opt("mode"), "ap")
		curDisabled := cmp.Or(cur.Opt("disabled"), "0")
		curIsolate := cmp.Or(cur.Opt("isolate"), "0")
		if cur.Opt("device") == radio &&
			curMode == "ap" &&
			cur.Opt("network") == req.ID &&
			cur.Opt("ssid") == req.Wireless.SSID &&
			cur.Opt("encryption") == req.Wireless.Encryption &&
			curDisabled == "0" &&
			curIsolate == wantIsolate {
			return nil
		}
	}

	var cmds []string
	if !strings.HasPrefix(secName, "@") {
		cmds = append(cmds, fmt.Sprintf("set wireless.%s=wifi-iface", secName))
	}
	cmds = append(cmds,
		fmt.Sprintf("set wireless.%s.device=%s", secName, quoteUCI(radio)),
		fmt.Sprintf("set wireless.%s.mode='ap'", secName),
		fmt.Sprintf("set wireless.%s.network=%s", secName, quoteUCI(req.ID)),
		fmt.Sprintf("set wireless.%s.ssid=%s", secName, quoteUCI(req.Wireless.SSID)),
		fmt.Sprintf("set wireless.%s.encryption=%s", secName, quoteUCI(req.Wireless.Encryption)),
		fmt.Sprintf("set wireless.%s.disabled='0'", secName),
		fmt.Sprintf("set wireless.%s.isolate=%s", secName, quoteUCI(wantIsolate)),
	)
	if req.Wireless.Password != "" {
		cmds = append(cmds, fmt.Sprintf("set wireless.%s.key=%s", secName, quoteUCI(req.Wireless.Password)))
	}
	return cmds
}

func buildDeleteWirelessCommands(wUCI *UCIConfig, segID string) []string {
	if wUCI == nil {
		return nil
	}
	var cmds []string
	for _, sec := range wUCI.ByType("wifi-iface") {
		if sec.Opt("network") != segID {
			continue
		}
		if strings.HasPrefix(sec.Name, "singctl_vlan_") {
			cmds = append(cmds, fmt.Sprintf("delete wireless.%s", sec.Name))
		} else {
			cmds = append(cmds,
				fmt.Sprintf("set wireless.%s.network='lan'", sec.Name),
				fmt.Sprintf("set wireless.%s.disabled='1'", sec.Name),
			)
		}
	}
	return cmds
}

func buildFirewallCommands(ov *Overview, fwUCI *UCIConfig, wanSubnet string, req SaveSegmentRequest) []string {
	zoneName := req.ID
	zoneRef := "singctl_zone_" + req.ID
	if fwUCI != nil {
		for _, z := range fwUCI.ByType("zone") {
			if z.Opt("name") == zoneName || slices.Contains(z.List("network"), req.ID) {
				zoneRef = z.Name
				if z.Opt("name") != "" {
					zoneName = z.Opt("name")
				}
				break
			}
		}
	}

	var cmds []string
	if !strings.HasPrefix(zoneRef, "@") {
		cmds = append(cmds, fmt.Sprintf("set firewall.%s=zone", zoneRef))
	}
	cmds = append(cmds,
		fmt.Sprintf("set firewall.%s.name=%s", zoneRef, quoteUCI(zoneName)),
		fmt.Sprintf("set firewall.%s.network=%s", zoneRef, quoteUCI(req.ID)),
		fmt.Sprintf("set firewall.%s.input='ACCEPT'", zoneRef),
		fmt.Sprintf("set firewall.%s.output='ACCEPT'", zoneRef),
		fmt.Sprintf("set firewall.%s.forward='REJECT'", zoneRef),
		fmt.Sprintf("set firewall.%s.masq='1'", zoneRef),
	)

	// Allow outbound to WAN（优先复用现网已有匹配 forwarding 节并清理历史重复的 singctl_fwd_wan_<id>）.
	fwdWanRef := "singctl_fwd_wan_" + req.ID
	cmds = append(cmds, buildForwardingRuleCommands(fwUCI, fwdWanRef, zoneName, "wan", req.Policy.AllowWAN)...)

	// Allow one-way management/control from main LAN（优先复用现网已有匹配 forwarding 节并清理重复节）.
	fwdMainRef := "singctl_fwd_main_" + req.ID
	cmds = append(cmds, buildForwardingRuleCommands(fwUCI, fwdMainRef, "lan", zoneName, req.Policy.AllowFromMainLAN)...)

	// Custom one-way forwarding to other VLANs.
	for _, dst := range req.Policy.AllowForwardTo {
		dstClean := strings.ToLower(strings.TrimSpace(dst))
		if !validSegmentIDRe.MatchString(dstClean) || dstClean == req.ID {
			continue
		}
		ref := fmt.Sprintf("singctl_fwd_%s_%s", req.ID, dstClean)
		cmds = append(cmds,
			fmt.Sprintf("set firewall.%s=forwarding", ref),
			fmt.Sprintf("set firewall.%s.src=%s", ref, quoteUCI(zoneName)),
			fmt.Sprintf("set firewall.%s.dest=%s", ref, quoteUCI(dstClean)),
		)
	}

	// Block router management ports (SSH/Dropbear/LuCI/HTTPS/SingCtl WebUI).
	mgmtRef := "singctl_block_mgmt_" + req.ID
	if req.Policy.BlockRouterMgmt {
		cmds = append(cmds,
			fmt.Sprintf("set firewall.%s=rule", mgmtRef),
			fmt.Sprintf("set firewall.%s.name=%s", mgmtRef, quoteUCI("SingCtl-Block-Mgmt-"+req.ID)),
			fmt.Sprintf("set firewall.%s.src=%s", mgmtRef, quoteUCI(zoneName)),
			fmt.Sprintf("set firewall.%s.proto='tcp'", mgmtRef),
			fmt.Sprintf("set firewall.%s.dest_port='22 80 443 2222 8090'", mgmtRef),
			fmt.Sprintf("set firewall.%s.target='REJECT'", mgmtRef),
		)
	} else {
		cmds = append(cmds, fmt.Sprintf("delete firewall.%s", mgmtRef))
	}

	// Allow custom DHCP DNS cross-zone 53 pinholes BEFORE BlockUpstreamLAN rules so upstream/main-LAN DNS is not shadowed.
	dnsCmds, activeDNSRefs := buildCustomDNSFirewallRules(ov, fwUCI, zoneName, req.ID, req.IPAddr, req.DHCPDNS)
	cmds = append(cmds, collectStaleCustomDNSRuleDeletes(fwUCI, req.ID, activeDNSRefs)...)
	cmds = append(cmds, dnsCmds...)

	// Block access to upstream main LAN subnet (e.g. 192.168.1.0/24).
	upRef := "singctl_block_up_" + req.ID
	if req.Policy.BlockUpstreamLAN && wanSubnet != "" {
		cmds = append(cmds,
			fmt.Sprintf("set firewall.%s=rule", upRef),
			fmt.Sprintf("set firewall.%s.name=%s", upRef, quoteUCI("SingCtl-Block-Upstream-"+req.ID)),
			fmt.Sprintf("set firewall.%s.src=%s", upRef, quoteUCI(zoneName)),
			fmt.Sprintf("set firewall.%s.dest='wan'", upRef),
			fmt.Sprintf("set firewall.%s.dest_ip=%s", upRef, quoteUCI(wanSubnet)),
			fmt.Sprintf("set firewall.%s.proto='all'", upRef),
			fmt.Sprintf("set firewall.%s.target='REJECT'", upRef),
		)
	} else {
		cmds = append(cmds, fmt.Sprintf("delete firewall.%s", upRef))
	}

	// Trusted upstream source IPs (e.g. Home Assistant).
	for i, srcIP := range req.Policy.TrustedSourceIPs {
		s := strings.TrimSpace(srcIP)
		if s == "" {
			continue
		}
		ref := fmt.Sprintf("singctl_allow_trust_%s_%d", req.ID, i)
		cmds = append(cmds,
			fmt.Sprintf("set firewall.%s=rule", ref),
			fmt.Sprintf("set firewall.%s.name=%s", ref, quoteUCI(fmt.Sprintf("SingCtl-Allow-Trusted-%s-%d", req.ID, i))),
			fmt.Sprintf("set firewall.%s.src='wan'", ref),
			fmt.Sprintf("set firewall.%s.dest=%s", ref, quoteUCI(zoneName)),
			fmt.Sprintf("set firewall.%s.src_ip=%s", ref, quoteUCI(s)),
			fmt.Sprintf("set firewall.%s.proto='all'", ref),
			fmt.Sprintf("set firewall.%s.target='ACCEPT'", ref),
		)
	}

	// mDNS discovery (UDP 5353).
	mdnsRef := "singctl_allow_mdns_" + req.ID
	if req.Policy.AllowMDNS {
		cmds = append(cmds,
			fmt.Sprintf("set firewall.%s=rule", mdnsRef),
			fmt.Sprintf("set firewall.%s.name=%s", mdnsRef, quoteUCI("SingCtl-Allow-mDNS-"+req.ID)),
			fmt.Sprintf("set firewall.%s.src='wan'", mdnsRef),
			fmt.Sprintf("set firewall.%s.proto='udp'", mdnsRef),
			fmt.Sprintf("set firewall.%s.dest_port='5353'", mdnsRef),
			fmt.Sprintf("set firewall.%s.target='ACCEPT'", mdnsRef),
		)
	} else {
		cmds = append(cmds, fmt.Sprintf("delete firewall.%s", mdnsRef))
	}

	cmds = append(cmds, buildSideRouterFirewallCommands(fwUCI, zoneName, req.ID, req.ProxyMode == ProxyModeSideRouter && req.Policy.AllowWAN)...)

	return cmds
}

func buildForwardingRuleCommands(fwUCI *UCIConfig, managedRef, src, dest string, allow bool) []string {
	var existingOther []string
	hasManaged := false
	if fwUCI != nil {
		for _, f := range fwUCI.ByType("forwarding") {
			if f.Opt("src") == src && f.Opt("dest") == dest {
				if f.Name == managedRef {
					hasManaged = true
				} else {
					existingOther = append(existingOther, f.Name)
				}
			}
		}
		if !hasManaged && fwUCI.ByName(managedRef) != nil {
			hasManaged = true
		}
	}

	var cmds []string
	if allow {
		if len(existingOther) > 0 {
			// 复用现网已有匹配 forwarding（如匿名 @forwarding[N]），并自动清理冗余的 singctl_fwd_* 重复节
			if hasManaged {
				cmds = append(cmds, fmt.Sprintf("delete firewall.%s", managedRef))
			}
			return cmds
		}
		return []string{
			fmt.Sprintf("set firewall.%s=forwarding", managedRef),
			fmt.Sprintf("set firewall.%s.src=%s", managedRef, quoteUCI(src)),
			fmt.Sprintf("set firewall.%s.dest=%s", managedRef, quoteUCI(dest)),
		}
	}

	if hasManaged {
		cmds = append(cmds, fmt.Sprintf("delete firewall.%s", managedRef))
	}
	for _, ref := range existingOther {
		cmds = append(cmds, fmt.Sprintf("delete firewall.%s", ref))
	}
	if len(cmds) == 0 {
		cmds = append(cmds, fmt.Sprintf("delete firewall.%s", managedRef))
	}
	return cmds
}

func buildDeleteFirewallCommands(fwUCI *UCIConfig, segID string) []string {
	var cmds []string
	if fwUCI == nil {
		return cmds
	}
	managedPrefixes := []string{
		"singctl_zone_" + segID,
		"singctl_fwd_wan_" + segID,
		"singctl_fwd_main_" + segID,
		"singctl_fwd_" + segID + "_",
		"singctl_block_mgmt_" + segID,
		"singctl_block_up_" + segID,
		"singctl_allow_trust_" + segID + "_",
		"singctl_allow_dns_" + segID + "_",
		"singctl_allow_mdns_" + segID,
		"singctl_side_iso_" + segID,
		"singctl_side_fwd_" + segID,
	}
	for _, sec := range fwUCI.Sections {
		matched := false
		for _, pfx := range managedPrefixes {
			if sec.Name == pfx || strings.HasPrefix(sec.Name, pfx) {
				matched = true
				break
			}
		}
		if matched {
			cmds = append(cmds, fmt.Sprintf("delete firewall.%s", sec.Name))
			continue
		}
		if sec.Type == "zone" && (sec.Opt("name") == segID || slices.Contains(sec.List("network"), segID)) {
			cmds = append(cmds, fmt.Sprintf("delete firewall.%s", sec.Name))
		}
		if sec.Type == "forwarding" && (sec.Opt("src") == segID || sec.Opt("dest") == segID) {
			cmds = append(cmds, fmt.Sprintf("delete firewall.%s", sec.Name))
		}
	}
	return cmds
}

func parseWirelessTopology(wUCI *UCIConfig) ([]RadioInfo, []WirelessSSIDInfo) {
	if wUCI == nil {
		return []RadioInfo{}, []WirelessSSIDInfo{}
	}
	radios := make([]RadioInfo, 0)
	bandByRadio := make(map[string]string)
	for _, sec := range wUCI.ByType("wifi-device") {
		band := strings.ToLower(strings.TrimSpace(sec.Opt("band")))
		label := "2.4GHz"
		switch band {
		case "5g":
			label = "5GHz"
		case "6g":
			label = "6GHz"
		default:
			if band == "" {
				band = "2g"
			}
		}
		bandByRadio[sec.Name] = band
		radios = append(radios, RadioInfo{
			Name:       sec.Name,
			Band:       band,
			BandLabel:  label,
			Phy:        sec.Opt("phy"),
			DriverType: sec.Opt("type"),
		})
	}

	ssids := make([]WirelessSSIDInfo, 0)
	for _, sec := range wUCI.ByType("wifi-iface") {
		if sec.Opt("mode") != "" && sec.Opt("mode") != "ap" {
			continue
		}
		ssids = append(ssids, WirelessSSIDInfo{
			Section:            sec.Name,
			Device:             sec.Opt("device"),
			Band:               bandByRadio[sec.Opt("device")],
			SSID:               sec.Opt("ssid"),
			Network:            sec.Opt("network"),
			Encryption:         sec.Opt("encryption"),
			Isolate:            sec.Opt("isolate") == "1",
			Disabled:           sec.Opt("disabled") == "1",
			ManagedBySingCtl:   strings.HasPrefix(sec.Name, "singctl_vlan_"),
			PasswordConfigured: sec.Opt("key") != "",
		})
	}
	return radios, ssids
}

func buildSegments(
	state *parsedState,
	segPorts map[string]map[string]string,
	segVLANs map[string]int,
	ssids []WirelessSSIDInfo,
	bypassSet map[string]bool,
	sideRouteSet map[string]bool,
	callerAddr netip.Addr,
	callerAddrOK bool,
) []Segment {
	ssidByNet := make(map[string]WirelessSSIDInfo)
	for _, s := range ssids {
		if _, exists := ssidByNet[s.Network]; !exists || !s.Disabled {
			ssidByNet[s.Network] = s
		}
	}

	segments := make([]Segment, 0)
	for _, sec := range state.NetUCI.ByType("interface") {
		if sec.Name == "loopback" || sec.Name == "wan" || sec.Name == "wan6" || sec.Name == "Wan6" || sec.Name == "tailscale" {
			continue
		}
		if sec.Opt("proto") != "static" || sec.Opt("ipaddr") == "" {
			continue
		}
		netmask := cmp.Or(sec.Opt("netmask"), "255.255.255.0")
		cidrPfx, err := computeNetworkCIDR(sec.Opt("ipaddr"), netmask)
		cidrStr := ""
		isCallerMgmt := false
		if err == nil {
			cidrStr = cidrPfx.String()
			if callerAddrOK && cidrPfx.Contains(callerAddr) {
				isCallerMgmt = true
			}
		}

		dhcpStart, dhcpLimit, leaseTime, dhcpDNS, ipv6Mode := parseSegmentDHCP(state.DHCP, sec.Name)
		policy := parseSegmentFirewallPolicy(state.Firewall, sec.Name, state.WANSubnet)

		var wifiSpec *WirelessSpec
		if sw, ok := ssidByNet[sec.Name]; ok {
			wifiSpec = &WirelessSpec{
				Enabled:            !sw.Disabled,
				Section:            sw.Section,
				Radio:              sw.Device,
				Band:               sw.Band,
				SSID:               sw.SSID,
				PasswordConfigured: sw.PasswordConfigured,
				Encryption:         sw.Encryption,
				Isolate:            sw.Isolate,
			}
		}

		proxyMode := ProxyModeFollow
		if sideRouteSet[cidrStr] {
			proxyMode = ProxyModeSideRouter
		} else if bypassSet[cidrStr] {
			proxyMode = ProxyModeDirect
		}

		seg := Segment{
			ID:               sec.Name,
			DisplayName:      inferSegmentDisplayName(sec.Name),
			Preset:           inferSegmentPreset(sec.Name, policy, wifiSpec),
			VLANID:           segVLANs[sec.Name],
			Device:           sec.Opt("device"),
			IPAddr:           sec.Opt("ipaddr"),
			Netmask:          netmask,
			CIDR:             cidrStr,
			DHCPStart:        dhcpStart,
			DHCPLimit:        dhcpLimit,
			LeaseTime:        leaseTime,
			DHCPDNS:          dhcpDNS,
			IPv6Mode:         ipv6Mode,
			ProxyMode:        proxyMode,
			IsPrimaryLAN:     sec.Name == "lan",
			IsCallerMgmt:     isCallerMgmt,
			ManagedBySingCtl: isSegmentManagedBySingCtl(state, sec.Name),
			Ports:            segPorts[sec.Name],
			Wireless:         wifiSpec,
			Policy:           policy,
		}
		seg.Relations = buildRelationBadges(seg)
		segments = append(segments, seg)
	}

	// Keep primary LAN first, then sort by VLAN ID.
	slices.SortFunc(segments, func(a, b Segment) int {
		if a.IsPrimaryLAN != b.IsPrimaryLAN {
			if a.IsPrimaryLAN {
				return -1
			}
			return 1
		}
		if a.VLANID != b.VLANID {
			return a.VLANID - b.VLANID
		}
		return strings.Compare(a.ID, b.ID)
	})
	return segments
}

func parseSegmentDHCP(dUCI *UCIConfig, segID string) (start, limit int, lease string, dhcpDNS []string, ipv6Mode string) {
	start, limit, lease, ipv6Mode = 100, 150, "12h", IPv6Off
	if dUCI == nil {
		return
	}
	sec := dUCI.ByName(segID)
	if sec == nil {
		for _, cand := range dUCI.ByType("dhcp") {
			if cand.Opt("interface") == segID {
				sec = cand
				break
			}
		}
	}
	if sec == nil {
		return
	}
	if v, err := strconv.Atoi(sec.Opt("start")); err == nil && v > 0 {
		start = v
	}
	if v, err := strconv.Atoi(sec.Opt("limit")); err == nil && v > 0 {
		limit = v
	}
	if v := sec.Opt("leasetime"); v != "" {
		lease = v
	}
	dhcpDNS = parseDHCPDNSOptions(sec)
	switch sec.Opt("ra") {
	case "relay":
		ipv6Mode = IPv6Relay
	case "server":
		ipv6Mode = IPv6Server
	}
	return
}

func parseSegmentFirewallPolicy(fwUCI *UCIConfig, segID, wanSubnet string) SecurityPolicy {
	pol := SecurityPolicy{AllowWAN: segID == "lan"}
	if fwUCI == nil {
		return pol
	}
	zoneName := segID
	for _, z := range fwUCI.ByType("zone") {
		if z.Opt("name") == segID || slices.Contains(z.List("network"), segID) {
			if z.Opt("name") != "" {
				zoneName = z.Opt("name")
			}
			break
		}
	}

	for _, f := range fwUCI.ByType("forwarding") {
		src, dst := f.Opt("src"), f.Opt("dest")
		if src == zoneName && dst == "wan" {
			pol.AllowWAN = true
		} else if src == "lan" && dst == zoneName {
			pol.AllowFromMainLAN = true
		} else if src == zoneName && dst != "" && dst != "wan" && dst != "tailscale" {
			if !slices.Contains(pol.AllowForwardTo, dst) {
				pol.AllowForwardTo = append(pol.AllowForwardTo, dst)
			}
		}
	}

	for _, r := range fwUCI.ByType("rule") {
		src := r.Opt("src")
		dst := r.Opt("dest")
		target := strings.ToUpper(r.Opt("target"))
		destPort := r.Opt("dest_port")
		if src == zoneName && (target == "REJECT" || target == "DROP") {
			if dst == "" && (strings.Contains(destPort, "22") || strings.Contains(destPort, "80") || strings.Contains(destPort, "8090")) {
				pol.BlockRouterMgmt = true
			}
			if dst == "wan" && r.Opt("dest_ip") != "" && (wanSubnet == "" || r.Opt("dest_ip") == wanSubnet) {
				pol.BlockUpstreamLAN = true
			}
		}
		if src == "wan" && dst == zoneName && target == "ACCEPT" && r.Opt("src_ip") != "" {
			if !slices.Contains(pol.TrustedSourceIPs, r.Opt("src_ip")) {
				pol.TrustedSourceIPs = append(pol.TrustedSourceIPs, r.Opt("src_ip"))
			}
		}
		if src == "wan" && target == "ACCEPT" && strings.Contains(destPort, "5353") {
			pol.AllowMDNS = true
		}
	}
	return pol
}

func isSegmentManagedBySingCtl(state *parsedState, segID string) bool {
	if state.Firewall != nil && state.Firewall.ByName("singctl_zone_"+segID) != nil {
		return true
	}
	if state.NetUCI != nil && (state.NetUCI.ByName("singctl_bv_"+segID) != nil || state.NetUCI.ByName("singctl_sv_"+segID) != nil) {
		return true
	}
	return false
}

func inferSegmentDisplayName(id string) string {
	switch strings.ToLower(id) {
	case "lan":
		return "主管理网"
	case "wifi":
		return "主力无线网"
	case "iot":
		return "智能家居隔离网"
	case "guest":
		return "访客隔离网"
	default:
		return id
	}
}

func inferSegmentPreset(id string, pol SecurityPolicy, wifi *WirelessSpec) string {
	switch strings.ToLower(id) {
	case "iot":
		return PresetIoT
	case "guest":
		return PresetGuest
	case "wifi":
		return PresetWiFi
	}
	if pol.BlockRouterMgmt && pol.BlockUpstreamLAN {
		if wifi != nil && wifi.Enabled {
			if pol.AllowFromMainLAN {
				return PresetIoT
			}
			return PresetGuest
		}
		return PresetWired
	}
	return PresetWiFi
}

func buildRelationBadges(seg Segment) []RelationBadge {
	if seg.IsPrimaryLAN {
		return []RelationBadge{{Tone: "ok", Text: "默认管理主网"}}
	}
	var out []RelationBadge
	if seg.ProxyMode == ProxyModeSideRouter {
		out = append(out, RelationBadge{Tone: "accent", Text: "旁路由分流"})
	}
	if seg.Policy.BlockUpstreamLAN {
		out = append(out, RelationBadge{Tone: "danger", Text: "已隔离主网"})
	}
	if seg.Policy.BlockRouterMgmt {
		out = append(out, RelationBadge{Tone: "danger", Text: "禁止访问路由后台"})
	}
	if seg.Policy.AllowFromMainLAN || len(seg.Policy.TrustedSourceIPs) > 0 {
		out = append(out, RelationBadge{Tone: "ok", Text: "主网可单向控制"})
	}
	for _, dst := range seg.Policy.AllowForwardTo {
		out = append(out, RelationBadge{Tone: "accent", Text: "可单向访问 " + dst})
	}
	if seg.Policy.AllowMDNS {
		out = append(out, RelationBadge{Tone: "neutral", Text: "支持设备发现"})
	}
	return out
}

func extractHostIP(remoteAddr string) string {
	s := strings.TrimSpace(remoteAddr)
	if s == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}
