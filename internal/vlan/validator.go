// 文件职责：提供 VLAN 分段的强安全校验、CIDR 冲突与私网检查、管理口防锁死守卫及智能无冲突预设推荐。
package vlan

import (
	"cmp"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

var (
	validSegmentIDRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,15}$`)
	validLeaseTimeRe = regexp.MustCompile(`^[1-9][0-9]{0,3}[mhd]$`)
	reservedSegIDs   = map[string]bool{
		"lan":       true,
		"wan":       true,
		"wan6":      true,
		"loopback":  true,
		"globals":   true,
		"tailscale": true,
		"singbox":   true,
		"sing_box":  true,
	}
	tailscaleCGNAT = netip.MustParsePrefix("100.64.0.0/10")
)

func hasControlOrInject(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return strings.ContainsAny(s, ";`$|&<>")
}

func computeNetworkCIDR(ipStr, netmaskStr string) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("网关 IP %q 不是合法的 IPv4 地址", ipStr)
	}
	maskIP := net.ParseIP(cmp.Or(strings.TrimSpace(netmaskStr), "255.255.255.0")).To4()
	if maskIP == nil {
		return netip.Prefix{}, fmt.Errorf("子网掩码 %q 无效", netmaskStr)
	}
	ones, bits := net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3]).Size()
	if bits != 32 || ones < 16 || ones > 30 {
		return netip.Prefix{}, fmt.Errorf("子网掩码 %q 超出允许范围 (/16 ~ /30)", netmaskStr)
	}
	return netip.PrefixFrom(addr, ones).Masked(), nil
}

func isPrivateRFC1918(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] == 10 ||
		(b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
		(b[0] == 192 && b[1] == 168)
}

func normalizeSaveRequest(req SaveSegmentRequest) SaveSegmentRequest {
	req.ID = strings.ToLower(strings.TrimSpace(req.ID))
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	req.IPAddr = strings.TrimSpace(req.IPAddr)
	req.Netmask = cmp.Or(strings.TrimSpace(req.Netmask), "255.255.255.0")
	if req.DHCPStart <= 0 {
		req.DHCPStart = 100
	}
	if req.DHCPLimit <= 0 {
		req.DHCPLimit = 150
	}
	req.LeaseTime = cmp.Or(strings.TrimSpace(req.LeaseTime), "12h")
	switch strings.ToLower(strings.TrimSpace(req.IPv6Mode)) {
	case IPv6Relay:
		req.IPv6Mode = IPv6Relay
	case IPv6Server:
		req.IPv6Mode = IPv6Server
	default:
		req.IPv6Mode = IPv6Off
	}
	if strings.EqualFold(strings.TrimSpace(req.ProxyMode), ProxyModeDirect) {
		req.ProxyMode = ProxyModeDirect
	} else {
		req.ProxyMode = ProxyModeFollow
	}
	if req.Ports != nil {
		req.Ports = maps.Clone(req.Ports)
	}
	if req.Policy.TrustedSourceIPs != nil {
		req.Policy.TrustedSourceIPs = slices.Clone(req.Policy.TrustedSourceIPs)
	}
	if req.Policy.AllowForwardTo != nil {
		req.Policy.AllowForwardTo = slices.Clone(req.Policy.AllowForwardTo)
	}
	if req.Wireless != nil {
		w := *req.Wireless
		w.SSID = strings.TrimSpace(w.SSID)
		w.Radio = strings.TrimSpace(w.Radio)
		if w.Encryption != "psk2" && w.Encryption != "sae-mixed" {
			w.Encryption = "psk2"
		}
		req.Wireless = &w
	}
	return req
}

func validateSaveRequest(ov *Overview, req SaveSegmentRequest, existing *Segment) (errs []string, warns []string) {
	if req.ID == "" || hasControlOrInject(req.ID) || !validSegmentIDRe.MatchString(req.ID) {
		errs = append(errs, "网络标识须为 2~16 位小写字母/数字/下划线，且以字母开头（如 iot、guest、office）")
	} else if reservedSegIDs[req.ID] {
		errs = append(errs, fmt.Sprintf("网络标识 %q 为系统保留接口名，请更换其他名称", req.ID))
	}

	if existing != nil && existing.IsCallerMgmt && !req.AllowModifyMgmt {
		errs = append(errs, fmt.Sprintf("当前浏览器正通过 %q 网段管理路由器，已锁定防误改导致失联（如需调整请先勾选高级覆盖项）", existing.ID))
	}

	if req.VLANID < 2 || req.VLANID > 4094 {
		errs = append(errs, fmt.Sprintf("VLAN ID 必须在 2 ~ 4094 之间（当前: %d）", req.VLANID))
	} else {
		for _, seg := range ov.Segments {
			if seg.ID != req.ID && seg.VLANID == req.VLANID {
				errs = append(errs, fmt.Sprintf("VLAN ID %d 已被现有网段 %q 占用", req.VLANID, seg.ID))
			}
		}
	}

	cidr, cidrErr := computeNetworkCIDR(req.IPAddr, req.Netmask)
	if cidrErr != nil {
		errs = append(errs, cidrErr.Error())
	} else {
		gwAddr, _ := netip.ParseAddr(req.IPAddr)
		if !isPrivateRFC1918(gwAddr) {
			errs = append(errs, fmt.Sprintf("网关 IP %s 必须为私网地址（192.168.x.x / 10.x.x.x / 172.16-31.x.x）", req.IPAddr))
		}
		if cidr.Overlaps(tailscaleCGNAT) {
			errs = append(errs, fmt.Sprintf("网段 %s 与 Tailscale 内网网段 (100.64.0.0/10) 冲突", cidr.String()))
		}
		if ov.WANSubnet != "" {
			if wanPfx, err := netip.ParsePrefix(ov.WANSubnet); err == nil && cidr.Overlaps(wanPfx) {
				errs = append(errs, fmt.Sprintf("网段 %s 与当前上级 WAN 网段 (%s) 重叠", cidr.String(), ov.WANSubnet))
			}
		}
		for _, seg := range ov.Segments {
			if seg.ID == req.ID || seg.CIDR == "" {
				continue
			}
			if other, err := netip.ParsePrefix(seg.CIDR); err == nil && cidr.Overlaps(other) {
				errs = append(errs, fmt.Sprintf("网段 %s 与现有网段 %q (%s) 重叠", cidr.String(), seg.ID, seg.CIDR))
			}
		}
	}

	if req.DHCPStart < 2 || req.DHCPStart > 250 || req.DHCPLimit < 1 || req.DHCPStart+req.DHCPLimit > 254 {
		errs = append(errs, fmt.Sprintf("DHCP 地址池范围 (%d ~ %d) 越界", req.DHCPStart, req.DHCPStart+req.DHCPLimit))
	}
	if !validLeaseTimeRe.MatchString(req.LeaseTime) {
		errs = append(errs, fmt.Sprintf("DHCP 租期格式无效: %q（如 2h、12h、1d）", req.LeaseTime))
	}

	// Port checks: forbid WAN port, unknown port, or moving caller's active management port.
	portMap := make(map[string]PortInfo, len(ov.Ports))
	for _, p := range ov.Ports {
		portMap[p.Name] = p
	}
	for pName, mode := range req.Ports {
		if mode == "" || mode == PortModeOff {
			continue
		}
		if mode != PortModeAccess && mode != PortModeTrunk {
			errs = append(errs, fmt.Sprintf("网口 %q 的分配模式 %q 无效", pName, mode))
			continue
		}
		pi, ok := portMap[pName]
		if !ok {
			errs = append(errs, fmt.Sprintf("未找到物理网口 %q", pName))
			continue
		}
		if pi.IsWAN {
			errs = append(errs, fmt.Sprintf("禁止把上级 WAN 口 (%s) 划入子网分段", pi.Label))
		}
		if pi.IsMgmt && mode == PortModeAccess && !req.AllowModifyMgmt {
			errs = append(errs, fmt.Sprintf("网口 %s 是当前管理会话所在网口，已锁定防断联", pi.Label))
		}
		if mode == PortModeAccess && pi.UntaggedSegmentID != "" && pi.UntaggedSegmentID != req.ID && pi.UntaggedSegmentID != "lan" {
			errs = append(errs, fmt.Sprintf("网口 %s 已作为接入终端口分配给 %q，不能同时作为多个网段的独占接入口", pi.Label, pi.UntaggedSegmentID))
		}
	}

	if req.Wireless != nil && req.Wireless.Enabled {
		if len(ov.Radios) == 0 {
			errs = append(errs, "当前设备未检测到可用物理无线射频，无法启用专属 Wi-Fi")
		} else {
			if req.Wireless.SSID == "" || len(req.Wireless.SSID) > 32 || hasControlOrInject(req.Wireless.SSID) {
				errs = append(errs, "Wi-Fi 名称不能为空、不超过 32 字符且不能包含换行或特殊控制字符")
			}
			needPass := existing == nil || existing.Wireless == nil || !existing.Wireless.PasswordConfigured
			if req.Wireless.Password != "" {
				if len(req.Wireless.Password) < 8 || len(req.Wireless.Password) > 63 || hasControlOrInject(req.Wireless.Password) {
					errs = append(errs, "Wi-Fi 密码须为 8~63 位且不能包含换行或非法控制字符")
				}
			} else if needPass {
				errs = append(errs, "新建专属 Wi-Fi 必须设置 8~63 位连接密码")
			}
			if req.Wireless.Radio != "" {
				foundRadio := false
				for _, r := range ov.Radios {
					if r.Name == req.Wireless.Radio {
						foundRadio = true
						break
					}
				}
				if !foundRadio {
					errs = append(errs, fmt.Sprintf("无线射频 %q 不存在", req.Wireless.Radio))
				}
			}
		}
	}

	for _, rawIP := range req.Policy.TrustedSourceIPs {
		s := strings.TrimSpace(rawIP)
		if s == "" {
			continue
		}
		if _, pErr := netip.ParsePrefix(s); pErr != nil {
			if _, aErr := netip.ParseAddr(s); aErr != nil {
				errs = append(errs, fmt.Sprintf("受信任主控 IP/网段 %q 格式无效", s))
			}
		}
	}

	if req.ProxyMode == ProxyModeDirect && req.IPv6Mode != IPv6Off {
		warns = append(warns, "已开启「纯直连绕过代理」，建议同时关闭该网段 IPv6 以避免部分设备 IPv6 流量分流不一致")
	}
	return errs, warns
}

func validateDeleteRequest(ov *Overview, segID string) (existing *Segment, errs []string) {
	id := strings.ToLower(strings.TrimSpace(segID))
	if id == "" || reservedSegIDs[id] {
		return nil, []string{fmt.Sprintf("系统主网或保留接口 %q 不允许删除", segID)}
	}
	for i := range ov.Segments {
		if ov.Segments[i].ID == id {
			existing = &ov.Segments[i]
			break
		}
	}
	if existing == nil {
		return nil, []string{fmt.Sprintf("未找到待删除的网络分段 %q", id)}
	}
	if existing.IsPrimaryLAN {
		return existing, []string{"默认主管理网 (lan) 不允许删除"}
	}
	if existing.IsCallerMgmt {
		return existing, []string{fmt.Sprintf("你当前正通过 %q 网段访问管理页，已禁止删除该网段以防失联", existing.ID)}
	}
	return existing, nil
}

// buildPresets 根据当前已占用的 VLAN ID 与网段，动态计算 4 套零冲突的零术语场景模板。
func buildPresets(ov *Overview) []PresetTemplate {
	usedVID := make(map[int]bool)
	usedThirdOctet := make(map[int]bool)
	usedIDs := make(map[string]bool)

	markCIDR := func(raw string) {
		if pfx, err := netip.ParsePrefix(raw); err == nil && pfx.Addr().Is4() {
			b := pfx.Addr().As4()
			if b[0] == 192 && b[1] == 168 {
				usedThirdOctet[int(b[2])] = true
			}
		}
	}
	markCIDR(ov.WANSubnet)
	for _, seg := range ov.Segments {
		usedIDs[seg.ID] = true
		if seg.VLANID > 0 {
			usedVID[seg.VLANID] = true
		}
		markCIDR(seg.CIDR)
	}

	pickVIDAndIP := func(pref int) (int, string) {
		cand := pref
		for usedVID[cand] || usedThirdOctet[cand] || cand < 10 || cand > 240 {
			cand++
			if cand > 240 {
				cand = 10
			}
		}
		usedVID[cand] = true
		usedThirdOctet[cand] = true
		return cand, fmt.Sprintf("192.168.%d.1", cand)
	}
	pickID := func(base string) string {
		if !usedIDs[base] {
			usedIDs[base] = true
			return base
		}
		for i := 2; i <= 9; i++ {
			cand := fmt.Sprintf("%s%d", base, i)
			if !usedIDs[cand] {
				usedIDs[cand] = true
				return cand
			}
		}
		return base + "_net"
	}

	radio2g, radio5g := "", ""
	for _, r := range ov.Radios {
		if r.Band == "2g" && radio2g == "" {
			radio2g = r.Name
		}
		if r.Band == "5g" && radio5g == "" {
			radio5g = r.Name
		}
	}
	if radio2g == "" && len(ov.Radios) > 0 {
		radio2g = ov.Radios[0].Name
	}
	if radio5g == "" {
		radio5g = radio2g
	}

	iotVID, iotIP := pickVIDAndIP(28)
	guestVID, guestIP := pickVIDAndIP(30)
	wifiVID, wifiIP := pickVIDAndIP(27)
	wiredVID, wiredIP := pickVIDAndIP(40)

	return []PresetTemplate{
		{
			ID:              PresetIoT,
			Title:           "智能家居隔离网",
			Tagline:         "给扫地机、摄像头、智能插座用：互不可见、碰不到主网和路由后台、纯直连不走代理",
			RecommendedName: "智能家居隔离网",
			SuggestedID:     pickID("iot"),
			SuggestedVLANID: iotVID,
			SuggestedIPAddr: iotIP,
			DefaultIPv6Mode: IPv6Off,
			DefaultProxy:    ProxyModeDirect,
			DefaultWireless: WirelessSpec{
				Enabled:    radio2g != "",
				Radio:      radio2g,
				Band:       "2g",
				SSID:       "Home-IoT",
				Encryption: "psk2",
				Isolate:    true,
			},
			DefaultPolicy: SecurityPolicy{
				AllowWAN:         true,
				BlockRouterMgmt:  true,
				BlockUpstreamLAN: true,
				AllowFromMainLAN: true,
				AllowMDNS:        true,
			},
		},
		{
			ID:              PresetGuest,
			Title:           "访客隔离 Wi-Fi",
			Tagline:         "给亲友临时上网用：只能上外网，彻底看不到你家电脑、NAS 和路由器后台",
			RecommendedName: "访客隔离网",
			SuggestedID:     pickID("guest"),
			SuggestedVLANID: guestVID,
			SuggestedIPAddr: guestIP,
			DefaultIPv6Mode: IPv6Off,
			DefaultProxy:    ProxyModeDirect,
			DefaultWireless: WirelessSpec{
				Enabled:    radio2g != "",
				Radio:      radio2g,
				Band:       "2g",
				SSID:       "Home-Guest",
				Encryption: "sae-mixed",
				Isolate:    true,
			},
			DefaultPolicy: SecurityPolicy{
				AllowWAN:         true,
				BlockRouterMgmt:  true,
				BlockUpstreamLAN: true,
				AllowFromMainLAN: false,
				AllowMDNS:        false,
			},
		},
		{
			ID:              PresetWiFi,
			Title:           "主力高速 Wi-Fi 网",
			Tagline:         "给手机、笔记本单独划分高速无线子网，可单向控制智能家居设备",
			RecommendedName: "主力高速 Wi-Fi",
			SuggestedID:     pickID("wifi"),
			SuggestedVLANID: wifiVID,
			SuggestedIPAddr: wifiIP,
			DefaultIPv6Mode: IPv6Relay,
			DefaultProxy:    ProxyModeFollow,
			DefaultWireless: WirelessSpec{
				Enabled:    radio5g != "",
				Radio:      radio5g,
				Band:       "5g",
				SSID:       "Home-5G",
				Encryption: "sae-mixed",
				Isolate:    false,
			},
			DefaultPolicy: SecurityPolicy{
				AllowWAN:         true,
				BlockRouterMgmt:  false,
				BlockUpstreamLAN: false,
				AllowFromMainLAN: true,
				AllowMDNS:        true,
			},
		},
		{
			ID:              PresetWired,
			Title:           "独立有线隔离口",
			Tagline:         "把路由器背面指定网口单独划出来，插上网线自动进入隔离网段（适合盒子/测试机）",
			RecommendedName: "独立有线隔离网",
			SuggestedID:     pickID("lab_lan"),
			SuggestedVLANID: wiredVID,
			SuggestedIPAddr: wiredIP,
			DefaultIPv6Mode: IPv6Off,
			DefaultProxy:    ProxyModeDirect,
			DefaultWireless: WirelessSpec{
				Enabled: false,
			},
			DefaultPolicy: SecurityPolicy{
				AllowWAN:         true,
				BlockRouterMgmt:  true,
				BlockUpstreamLAN: true,
				AllowFromMainLAN: true,
				AllowMDNS:        false,
			},
		},
	}
}
