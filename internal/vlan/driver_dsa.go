// 文件职责：实现 OpenWrt DSA（bridge-vlan，适配 n60pro 等现代硬路由）与 x86 多网口软路由（适配 n4120）的 VLAN 驱动策略。
package vlan

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// DSADriver 适配现代 OpenWrt DSA 交换机架构（独立 lan1..lanN 网口 + br-lan bridge-vlan）。
type DSADriver struct{}

func (d *DSADriver) ID() string    { return DriverDSA }
func (d *DSADriver) Label() string { return "DSA 桥接 VLAN" }

func (d *DSADriver) Matches(netUCI *UCIConfig, _ *boardInfo, netDevs []string) bool {
	if netUCI == nil {
		return false
	}
	if len(netUCI.ByType("switch_vlan")) > 0 || len(netUCI.ByType("switch")) > 0 {
		return false
	}
	if len(netUCI.ByType("bridge-vlan")) > 0 {
		return true
	}
	for _, dev := range collectBridgePorts(netUCI, "br-lan") {
		if strings.HasPrefix(dev, "lan") {
			return true
		}
	}
	for _, dev := range netDevs {
		if strings.HasPrefix(dev, "lan") && len(dev) > 3 {
			return true
		}
	}
	return false
}

func (d *DSADriver) ParseTopology(state *parsedState, readLink func(dev string) (bool, int)) ([]PortInfo, map[string]map[string]string, map[string]int) {
	return parseBridgeVLANTopology(state, readLink)
}

func (d *DSADriver) BuildNetworkCommands(state *parsedState, req SaveSegmentRequest, existing *Segment) ([]string, string, error) {
	return buildBridgeVLANCommands(state, req, existing, false)
}

func (d *DSADriver) BuildDeleteNetworkCommands(state *parsedState, seg Segment) ([]string, error) {
	return buildDeleteBridgeVLANCommands(state, seg)
}

// SoftRouterDriver 适配无交换芯片的 x86 / ARM 多网口软路由（如 n4120，基于 br-lan 802.1Q bridge-vlan）。
type SoftRouterDriver struct{}

func (d *SoftRouterDriver) ID() string    { return DriverSoftRouter }
func (d *SoftRouterDriver) Label() string { return "多网口软路由 (802.1Q)" }

func (d *SoftRouterDriver) Matches(netUCI *UCIConfig, _ *boardInfo, _ []string) bool {
	if netUCI == nil {
		return false
	}
	if len(netUCI.ByType("switch_vlan")) > 0 || len(netUCI.ByType("switch")) > 0 {
		return false
	}
	return len(collectBridgePorts(netUCI, "br-lan")) > 0
}

func (d *SoftRouterDriver) ParseTopology(state *parsedState, readLink func(dev string) (bool, int)) ([]PortInfo, map[string]map[string]string, map[string]int) {
	return parseBridgeVLANTopology(state, readLink)
}

func (d *SoftRouterDriver) BuildNetworkCommands(state *parsedState, req SaveSegmentRequest, existing *Segment) ([]string, string, error) {
	return buildBridgeVLANCommands(state, req, existing, true)
}

func (d *SoftRouterDriver) BuildDeleteNetworkCommands(state *parsedState, seg Segment) ([]string, error) {
	return buildDeleteBridgeVLANCommands(state, seg)
}

func collectBridgePorts(netUCI *UCIConfig, bridgeName string) []string {
	if netUCI == nil {
		return nil
	}
	for _, sec := range netUCI.ByType("device") {
		if sec.Opt("name") == bridgeName && sec.Opt("type") == "bridge" {
			return sec.List("ports")
		}
	}
	return nil
}

func parseBridgePortToken(tok string) (portName, mode string) {
	name, flags, hasColon := strings.Cut(strings.TrimSpace(tok), ":")
	if !hasColon {
		return name, PortModeAccess
	}
	if strings.Contains(flags, "t") {
		return name, PortModeTrunk
	}
	return name, PortModeAccess
}

func parseBridgeVLANTopology(state *parsedState, readLink func(dev string) (bool, int)) ([]PortInfo, map[string]map[string]string, map[string]int) {
	state.LANBridge = "br-lan"
	netDevsSet := make(map[string]bool, len(state.NetDevs))
	for _, dev := range state.NetDevs {
		netDevsSet[dev] = true
	}

	ports := make([]PortInfo, 0)
	seenPorts := make(map[string]bool)
	addPort := func(name, label string, isWAN bool) {
		name = strings.TrimSpace(name)
		if name == "" || seenPorts[name] {
			return
		}
		if len(netDevsSet) > 0 && !netDevsSet[name] {
			return
		}
		seenPorts[name] = true
		up, spd := readLink(name)
		ports = append(ports, PortInfo{
			Name:      name,
			Label:     cmp.Or(label, strings.ToUpper(name)),
			IsWAN:     isWAN,
			LinkUp:    up,
			SpeedMbps: spd,
		})
	}

	if state.WANDevice != "" {
		addPort(state.WANDevice, "WAN ("+state.WANDevice+")", true)
	}

	bridgePorts := collectBridgePorts(state.NetUCI, "br-lan")
	if len(bridgePorts) > 0 {
		for _, p := range bridgePorts {
			if p == state.WANDevice {
				continue
			}
			addPort(p, strings.ToUpper(p), false)
		}
	} else if state.Board != nil {
		for _, p := range state.Board.Network.LAN.Ports {
			if p == state.WANDevice {
				continue
			}
			addPort(p, strings.ToUpper(p), false)
		}
	}

	// Map bridge-vlan entries by VLAN ID.
	vlanPortsByVID := make(map[int]map[string]string)
	for _, bv := range state.NetUCI.ByType("bridge-vlan") {
		if bv.Opt("device") != "" && bv.Opt("device") != "br-lan" {
			continue
		}
		vid, err := strconv.Atoi(strings.TrimSpace(bv.Opt("vlan")))
		if err != nil || vid <= 0 {
			continue
		}
		pm := make(map[string]string)
		for _, tok := range bv.List("ports") {
			pName, mode := parseBridgePortToken(tok)
			if pName != "" && seenPorts[pName] {
				pm[pName] = mode
			}
		}
		vlanPortsByVID[vid] = pm
	}

	// Count how many non-primary VLANs mark a port as untagged (bare legacy port lists on n60pro).
	untaggedCount := make(map[string]int)
	for vid, pm := range vlanPortsByVID {
		if vid == 1 {
			continue
		}
		for pName, mode := range pm {
			if mode == PortModeAccess {
				untaggedCount[pName]++
			}
		}
	}

	segPorts := make(map[string]map[string]string)
	segVLANs := make(map[string]int)

	for _, sec := range state.NetUCI.ByType("interface") {
		if sec.Name == "loopback" || sec.Name == "wan" || sec.Name == "wan6" || sec.Name == "Wan6" || sec.Name == "tailscale" {
			continue
		}
		if sec.Opt("proto") != "static" || sec.Opt("ipaddr") == "" {
			continue
		}
		dev := sec.Opt("device")
		vid := 1
		if _, after, ok := strings.Cut(dev, "."); ok {
			if parsedVID, err := strconv.Atoi(after); err == nil && parsedVID > 0 {
				vid = parsedVID
			}
		}
		segVLANs[sec.Name] = vid

		if pm, ok := vlanPortsByVID[vid]; ok {
			cleaned := make(map[string]string, len(pm))
			for pName, mode := range pm {
				// If a port was listed bare across multiple VLANs (legacy hand-edited config), treat as trunk to avoid false conflicts.
				if vid != 1 && mode == PortModeAccess && untaggedCount[pName] > 1 {
					cleaned[pName] = PortModeTrunk
				} else {
					cleaned[pName] = mode
				}
			}
			segPorts[sec.Name] = cleaned
		} else if sec.Name == "lan" {
			pm := make(map[string]string)
			for _, p := range ports {
				if !p.IsWAN {
					pm[p.Name] = PortModeAccess
				}
			}
			segPorts[sec.Name] = pm
		}
	}

	// Populate PortInfo Untagged/Tagged summary for UI port bar.
	portIdx := make(map[string]int, len(ports))
	for i := range ports {
		portIdx[ports[i].Name] = i
	}
	for segID, pm := range segPorts {
		for pName, mode := range pm {
			idx, ok := portIdx[pName]
			if !ok || ports[idx].IsWAN {
				continue
			}
			if mode == PortModeAccess {
				if segID != "lan" || ports[idx].UntaggedSegmentID == "" {
					ports[idx].UntaggedSegmentID = segID
				}
			} else if mode == PortModeTrunk {
				if !slices.Contains(ports[idx].TaggedSegmentIDs, segID) {
					ports[idx].TaggedSegmentIDs = append(ports[idx].TaggedSegmentIDs, segID)
				}
			}
		}
	}
	for i := range ports {
		slices.Sort(ports[i].TaggedSegmentIDs)
	}
	return ports, segPorts, segVLANs
}

func buildPrimaryLANBridgeVLANCommands(state *parsedState, occupiedAccess map[string]bool) []string {
	if state == nil || state.NetUCI == nil {
		return nil
	}
	lanSec := state.NetUCI.ByName("lan")
	if lanSec == nil {
		return nil
	}
	lanDev := lanSec.Opt("device")
	if lanDev != "br-lan" && lanDev != "br-lan.1" {
		return nil
	}

	lanBVRef := "singctl_bv_lan"
	for _, bv := range state.NetUCI.ByType("bridge-vlan") {
		if (bv.Opt("device") == "" || bv.Opt("device") == "br-lan") && bv.Opt("vlan") == "1" {
			lanBVRef = bv.Name
			break
		}
	}

	var cmds []string
	if !strings.HasPrefix(lanBVRef, "@") {
		cmds = append(cmds, fmt.Sprintf("set network.%s=bridge-vlan", lanBVRef))
	}
	cmds = append(cmds,
		fmt.Sprintf("set network.%s.device='br-lan'", lanBVRef),
		fmt.Sprintf("set network.%s.vlan='1'", lanBVRef),
		fmt.Sprintf("set network.%s.local='1'", lanBVRef),
		fmt.Sprintf("delete network.%s.ports", lanBVRef),
	)

	var remaining []string
	for _, p := range state.Ports {
		if p.IsWAN || occupiedAccess[p.Name] {
			continue
		}
		remaining = append(remaining, p.Name)
	}
	slices.Sort(remaining)
	for _, pName := range remaining {
		cmds = append(cmds, fmt.Sprintf("add_list network.%s.ports=%s", lanBVRef, quoteUCI(pName+":u*")))
	}
	cmds = append(cmds, "set network.lan.device='br-lan.1'")
	return cmds
}

func buildBridgeVLANCommands(state *parsedState, req SaveSegmentRequest, existing *Segment, enableFiltering bool) ([]string, string, error) {
	var cmds []string
	vid := req.VLANID
	l3Dev := fmt.Sprintf("br-lan.%d", vid)

	// Ensure br-lan device exists with vlan_filtering enabled if requested.
	if enableFiltering {
		for i, devSec := range state.NetUCI.ByType("device") {
			if devSec.Opt("name") == "br-lan" && devSec.Opt("type") == "bridge" {
				cmds = append(cmds, fmt.Sprintf("set network.@device[%d].vlan_filtering='1'", i))
				break
			}
		}
	}

	// Preserve primary LAN (VLAN 1) untagged membership on all remaining non-access ports so enabling
	// bridge vlan_filtering on OpenWrt DSA never drops L2 connectivity for LAN1 / admin management.
	occupiedAccess := make(map[string]bool)
	for _, seg := range state.Segments {
		if seg.IsPrimaryLAN || seg.ID == req.ID {
			continue
		}
		for pName, mode := range seg.Ports {
			if mode == PortModeAccess {
				occupiedAccess[pName] = true
			}
		}
	}
	for pName, mode := range req.Ports {
		if mode == PortModeAccess {
			occupiedAccess[pName] = true
		}
	}
	cmds = append(cmds, buildPrimaryLANBridgeVLANCommands(state, occupiedAccess)...)

	// Find existing bridge-vlan for this VID or allocate deterministic named section.
	bvRef := "singctl_bv_" + req.ID
	if existing != nil {
		for _, bv := range state.NetUCI.ByType("bridge-vlan") {
			if bv.Opt("vlan") == strconv.Itoa(existing.VLANID) {
				bvRef = bv.Name
				break
			}
		}
	}

	if !strings.HasPrefix(bvRef, "@") {
		cmds = append(cmds, fmt.Sprintf("set network.%s=bridge-vlan", bvRef))
	}
	cmds = append(cmds,
		fmt.Sprintf("set network.%s.device='br-lan'", bvRef),
		fmt.Sprintf("set network.%s.vlan=%s", bvRef, quoteUCI(strconv.Itoa(vid))),
		fmt.Sprintf("set network.%s.local='1'", bvRef),
		fmt.Sprintf("delete network.%s.ports", bvRef),
	)

	var portNames []string
	for pName := range req.Ports {
		portNames = append(portNames, pName)
	}
	slices.Sort(portNames)
	for _, pName := range portNames {
		mode := req.Ports[pName]
		switch mode {
		case PortModeAccess:
			cmds = append(cmds, fmt.Sprintf("add_list network.%s.ports=%s", bvRef, quoteUCI(pName+":u*")))
		case PortModeTrunk:
			cmds = append(cmds, fmt.Sprintf("add_list network.%s.ports=%s", bvRef, quoteUCI(pName+":t")))
		}
	}

	// Ensure interface section exists with exact L3 settings.
	netmask := cmp.Or(strings.TrimSpace(req.Netmask), "255.255.255.0")
	cmds = append(cmds,
		fmt.Sprintf("set network.%s=interface", req.ID),
		fmt.Sprintf("set network.%s.proto='static'", req.ID),
		fmt.Sprintf("set network.%s.device=%s", req.ID, quoteUCI(l3Dev)),
		fmt.Sprintf("set network.%s.ipaddr=%s", req.ID, quoteUCI(req.IPAddr)),
		fmt.Sprintf("set network.%s.netmask=%s", req.ID, quoteUCI(netmask)),
	)
	if req.Wireless != nil && req.Wireless.Enabled {
		cmds = append(cmds, fmt.Sprintf("set network.%s.type='bridge'", req.ID))
	}
	switch req.IPv6Mode {
	case IPv6Relay, IPv6Server:
		cmds = append(cmds,
			fmt.Sprintf("set network.%s.delegate='0'", req.ID),
			fmt.Sprintf("set network.%s.ip6assign='64'", req.ID),
		)
	default:
		cmds = append(cmds,
			fmt.Sprintf("set network.%s.delegate='0'", req.ID),
			fmt.Sprintf("delete network.%s.ip6assign", req.ID),
		)
	}

	return cmds, l3Dev, nil
}

func buildDeleteBridgeVLANCommands(state *parsedState, seg Segment) ([]string, error) {
	var cmds []string
	cmds = append(cmds, fmt.Sprintf("delete network.%s", seg.ID))
	for _, bv := range state.NetUCI.ByType("bridge-vlan") {
		if bv.Opt("vlan") == strconv.Itoa(seg.VLANID) || bv.Name == "singctl_bv_"+seg.ID {
			cmds = append(cmds, fmt.Sprintf("delete network.%s", bv.Name))
			break
		}
	}
	// Return any exclusive access ports freed by this deleted VLAN back to primary LAN (VLAN 1).
	if lanSec := state.NetUCI.ByName("lan"); lanSec != nil && lanSec.Opt("device") == "br-lan.1" {
		occupiedAccess := make(map[string]bool)
		for _, other := range state.Segments {
			if other.IsPrimaryLAN || other.ID == seg.ID {
				continue
			}
			for pName, mode := range other.Ports {
				if mode == PortModeAccess {
					occupiedAccess[pName] = true
				}
			}
		}
		cmds = append(cmds, buildPrimaryLANBridgeVLANCommands(state, occupiedAccess)...)
	}
	return cmds, nil
}
