// 文件职责：实现 OpenWrt swconfig（switch0 + switch_vlan + 独立网桥 br-v<id>，适配 ax3000t 等机型）的 VLAN 驱动策略。
package vlan

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// SwconfigDriver 适配传统 OpenWrt swconfig 交换芯片架构（如小米 AX3000T AN8855 / MT7981 21.02）。
type SwconfigDriver struct{}

func (d *SwconfigDriver) ID() string    { return DriverSwconfig }
func (d *SwconfigDriver) Label() string { return "swconfig 交换芯片" }

func (d *SwconfigDriver) Matches(netUCI *UCIConfig, _ *boardInfo, _ []string) bool {
	if netUCI == nil {
		return false
	}
	return len(netUCI.ByType("switch_vlan")) > 0 || len(netUCI.ByType("switch")) > 0
}

func (d *SwconfigDriver) ParseTopology(state *parsedState, _ func(dev string) (bool, int)) ([]PortInfo, map[string]map[string]string, map[string]int) {
	switchName := "switch0"
	if sws := state.NetUCI.ByType("switch"); len(sws) > 0 && sws[0].Opt("name") != "" {
		switchName = sws[0].Opt("name")
	}
	state.SwitchName = switchName

	// Detect CPU port (tagged across multiple switch_vlans, e.g. "5t") and collect all physical ports.
	svs := state.NetUCI.ByType("switch_vlan")
	taggedFreq := make(map[string]int)
	allPortNums := make(map[string]bool)
	svByVID := make(map[int][]string)

	for _, sv := range svs {
		vidStr := cmp.Or(sv.Opt("vid"), sv.Opt("vlan"))
		vid, err := strconv.Atoi(strings.TrimSpace(vidStr))
		if err != nil || vid <= 0 {
			continue
		}
		tokens := strings.Fields(sv.Opt("ports"))
		svByVID[vid] = tokens
		for _, tok := range tokens {
			if strings.HasSuffix(tok, "t") {
				taggedFreq[tok]++
			} else {
				allPortNums[tok] = true
			}
		}
	}

	cpuPort := "5t"
	bestFreq := 0
	for tok, freq := range taggedFreq {
		if freq > bestFreq {
			bestFreq = freq
			cpuPort = tok
		}
	}
	state.CPUPort = cpuPort
	cpuNum := strings.TrimSuffix(cpuPort, "t")

	// Detect WAN VID from wan interface device (e.g. "eth0.2" -> VID 2).
	wanVID := 2
	if wanSec := state.NetUCI.ByName("wan"); wanSec != nil {
		if _, after, ok := strings.Cut(wanSec.Opt("device"), "."); ok {
			if v, err := strconv.Atoi(after); err == nil && v > 0 {
				wanVID = v
			}
		}
	}
	wanPortNum := ""
	for _, tok := range svByVID[wanVID] {
		if !strings.HasSuffix(tok, "t") && tok != cpuNum {
			wanPortNum = tok
			break
		}
	}
	state.WANPortNum = wanPortNum

	// Build deterministic sorted port list: WAN first, then LAN1, LAN2, ...
	var portNums []int
	for numStr := range allPortNums {
		if numStr == cpuNum {
			continue
		}
		if n, err := strconv.Atoi(numStr); err == nil {
			portNums = append(portNums, n)
		}
	}
	slices.Sort(portNums)

	var ports []PortInfo
	portNumToName := make(map[string]string)
	if wanPortNum != "" {
		portNumToName[wanPortNum] = "wan"
		ports = append(ports, PortInfo{
			Name:       "wan",
			Label:      "WAN (Port " + wanPortNum + ")",
			SwitchPort: wanPortNum,
			IsWAN:      true,
			LinkUp:     state.WANIP != "",
		})
	}
	lanIdx := 1
	for _, n := range portNums {
		numStr := strconv.Itoa(n)
		if numStr == wanPortNum {
			continue
		}
		pName := fmt.Sprintf("lan%d", lanIdx)
		portNumToName[numStr] = pName
		ports = append(ports, PortInfo{
			Name:       pName,
			Label:      fmt.Sprintf("LAN%d (Port %s)", lanIdx, numStr),
			SwitchPort: numStr,
			IsWAN:      false,
			LinkUp:     true,
		})
		lanIdx++
	}

	// Map bridge name -> underlying eth0.<vid> VID.
	bridgeToVID := make(map[string]int)
	for _, devSec := range state.NetUCI.ByType("device") {
		if devSec.Opt("type") != "bridge" {
			continue
		}
		bName := devSec.Opt("name")
		for _, p := range devSec.List("ports") {
			if _, after, ok := strings.Cut(p, "."); ok {
				if v, err := strconv.Atoi(after); err == nil && v > 0 {
					bridgeToVID[bName] = v
					break
				}
			}
		}
	}

	segPorts := make(map[string]map[string]string)
	segVLANs := make(map[string]int)
	portIdx := make(map[string]int, len(ports))
	for i := range ports {
		portIdx[ports[i].Name] = i
	}

	for _, sec := range state.NetUCI.ByType("interface") {
		if sec.Name == "loopback" || sec.Name == "wan" || sec.Name == "wan6" || sec.Name == "Wan6" || sec.Name == "tailscale" {
			continue
		}
		if sec.Opt("proto") != "static" || sec.Opt("ipaddr") == "" {
			continue
		}
		dev := sec.Opt("device")
		vid := bridgeToVID[dev]
		if vid == 0 {
			if _, after, ok := strings.Cut(dev, "."); ok {
				if v, err := strconv.Atoi(after); err == nil && v > 0 {
					vid = v
				}
			}
		}
		if vid == 0 && sec.Name == "lan" {
			vid = 1
		}
		segVLANs[sec.Name] = vid

		pm := make(map[string]string)
		for _, tok := range svByVID[vid] {
			isTagged := strings.HasSuffix(tok, "t")
			num := strings.TrimSuffix(tok, "t")
			if num == cpuNum || num == wanPortNum {
				continue
			}
			pName, ok := portNumToName[num]
			if !ok {
				continue
			}
			if isTagged {
				pm[pName] = PortModeTrunk
				if idx, ok := portIdx[pName]; ok && !slices.Contains(ports[idx].TaggedSegmentIDs, sec.Name) {
					ports[idx].TaggedSegmentIDs = append(ports[idx].TaggedSegmentIDs, sec.Name)
				}
			} else {
				pm[pName] = PortModeAccess
				if idx, ok := portIdx[pName]; ok {
					ports[idx].UntaggedSegmentID = sec.Name
				}
			}
		}
		segPorts[sec.Name] = pm
	}

	return ports, segPorts, segVLANs
}

func (d *SwconfigDriver) BuildNetworkCommands(state *parsedState, req SaveSegmentRequest, existing *Segment) ([]string, string, error) {
	var cmds []string
	vid := req.VLANID
	switchName := cmp.Or(state.SwitchName, "switch0")
	cpuPort := cmp.Or(state.CPUPort, "5t")

	portNameToNum := make(map[string]string, len(state.Ports))
	for _, p := range state.Ports {
		if p.SwitchPort != "" {
			portNameToNum[p.Name] = p.SwitchPort
		}
	}

	// Build switch_vlan ports string: always preserve CPU tagged port first.
	portTokens := []string{cpuPort}
	movedAccessNums := make(map[string]bool)
	var portNames []string
	for pName := range req.Ports {
		portNames = append(portNames, pName)
	}
	slices.Sort(portNames)
	for _, pName := range portNames {
		num, ok := portNameToNum[pName]
		if !ok || num == "" {
			continue
		}
		switch req.Ports[pName] {
		case PortModeAccess:
			portTokens = append(portTokens, num)
			movedAccessNums[num] = true
		case PortModeTrunk:
			portTokens = append(portTokens, num+"t")
		}
	}

	svRef := "singctl_sv_" + req.ID
	if existing != nil {
		for _, sv := range state.NetUCI.ByType("switch_vlan") {
			if cmp.Or(sv.Opt("vid"), sv.Opt("vlan")) == strconv.Itoa(existing.VLANID) {
				svRef = sv.Name
				break
			}
		}
	}
	if !strings.HasPrefix(svRef, "@") {
		cmds = append(cmds, fmt.Sprintf("set network.%s=switch_vlan", svRef))
	}
	cmds = append(cmds,
		fmt.Sprintf("set network.%s.device=%s", svRef, quoteUCI(switchName)),
		fmt.Sprintf("set network.%s.vlan=%s", svRef, quoteUCI(strconv.Itoa(vid))),
		fmt.Sprintf("set network.%s.vid=%s", svRef, quoteUCI(strconv.Itoa(vid))),
		fmt.Sprintf("set network.%s.ports=%s", svRef, quoteUCI(strings.Join(portTokens, " "))),
	)

	// Remove newly claimed untagged access ports from lan's switch_vlan to avoid duplicate untagged assignment.
	if len(movedAccessNums) > 0 {
		for _, sv := range state.NetUCI.ByType("switch_vlan") {
			if cmp.Or(sv.Opt("vid"), sv.Opt("vlan")) == "1" {
				var kept []string
				for _, tok := range strings.Fields(sv.Opt("ports")) {
					if !strings.HasSuffix(tok, "t") && movedAccessNums[tok] {
						continue
					}
					kept = append(kept, tok)
				}
				cmds = append(cmds, fmt.Sprintf("set network.%s.ports=%s", sv.Name, quoteUCI(strings.Join(kept, " "))))
				break
			}
		}
	}

	// Independent bridge br-v<vid> wrapping eth0.<vid> (exact ax3000t pattern).
	bridgeName := fmt.Sprintf("br-v%d", vid)
	if existing != nil && existing.Device != "" && !strings.Contains(existing.Device, ".") {
		bridgeName = existing.Device
	}
	devRef := "singctl_br_" + req.ID
	cmds = append(cmds,
		fmt.Sprintf("set network.%s=device", devRef),
		fmt.Sprintf("set network.%s.type='bridge'", devRef),
		fmt.Sprintf("set network.%s.name=%s", devRef, quoteUCI(bridgeName)),
		fmt.Sprintf("delete network.%s.ports", devRef),
		fmt.Sprintf("add_list network.%s.ports=%s", devRef, quoteUCI(fmt.Sprintf("eth0.%d", vid))),
	)
	if req.IPv6Mode == IPv6Off || req.IPv6Mode == "" {
		cmds = append(cmds, fmt.Sprintf("set network.%s.ipv6='0'", devRef))
	}

	netmask := cmp.Or(strings.TrimSpace(req.Netmask), "255.255.255.0")
	cmds = append(cmds,
		fmt.Sprintf("set network.%s=interface", req.ID),
		fmt.Sprintf("set network.%s.proto='static'", req.ID),
		fmt.Sprintf("set network.%s.device=%s", req.ID, quoteUCI(bridgeName)),
		fmt.Sprintf("set network.%s.ipaddr=%s", req.ID, quoteUCI(req.IPAddr)),
		fmt.Sprintf("set network.%s.netmask=%s", req.ID, quoteUCI(netmask)),
		fmt.Sprintf("set network.%s.delegate='0'", req.ID),
	)
	return cmds, bridgeName, nil
}

func (d *SwconfigDriver) BuildDeleteNetworkCommands(state *parsedState, seg Segment) ([]string, error) {
	var cmds []string
	cmds = append(cmds,
		fmt.Sprintf("delete network.%s", seg.ID),
		fmt.Sprintf("delete network.singctl_br_%s", seg.ID),
	)
	for _, sv := range state.NetUCI.ByType("switch_vlan") {
		if cmp.Or(sv.Opt("vid"), sv.Opt("vlan")) == strconv.Itoa(seg.VLANID) || sv.Name == "singctl_sv_"+seg.ID {
			cmds = append(cmds, fmt.Sprintf("delete network.%s", sv.Name))
			break
		}
	}
	return cmds, nil
}
