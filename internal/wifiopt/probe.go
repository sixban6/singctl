// 文件职责：实现 OpenWrt 无线射频（兼容 MediaTek mtwifi 与通用 mac80211）、在线终端、网桥与错包率的毫秒级只读探测。
package wifiopt

import (
	"cmp"
	"context"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type iwinfoBlock struct {
	IfName      string
	ESSID       string
	Mode        string
	Channel     int
	FreqGHz     string
	TxPowerDBm  int
	BitRateMbps float64
	Encryption  string
	DriverType  string
	Hardware    string
}

type netDevStat struct {
	RxPackets uint64
	RxErrors  uint64
}

type dhcpLease struct {
	IP       string
	Hostname string
}

type probeState struct {
	Driver      string
	WirelessUCI *uciDoc
	NetworkUCI  *uciDoc
	Bridges     map[string][]string // bridgeName -> []ifname
	NetToBridge map[string]string   // uci network name -> bridge device
	Iwinfo      map[string]iwinfoBlock
	DevStats    map[string]netDevStat
	Leases      map[string]dhcpLease // lower mac -> lease
	IfaceBySec  map[string]*uciSection
	RadioByDev  map[string]*uciSection
	IfNameBySec map[string]string
}

var (
	reESSID     = regexp.MustCompile(`ESSID:\s*"([^"]*)"`)
	reModeCh    = regexp.MustCompile(`Mode:\s*(\S+)\s+Channel:\s*(\d+|unknown)(?:\s+\(([0-9.]+)\s*GHz\))?`)
	reTxPower   = regexp.MustCompile(`Tx-Power:\s*(\d+)\s*dBm`)
	reBitRate   = regexp.MustCompile(`Bit Rate:\s*([0-9.]+)\s*MBit/s`)
	reHardware  = regexp.MustCompile(`Hardware:\s*[^\[]*\[([^\]]+)\]`)
	reAssocHead = regexp.MustCompile(`^([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(-?\d+)\s*dBm`)
	reRateLine  = regexp.MustCompile(`(RX|TX):\s*([0-9.]+)\s*MBit/s.*?(?:(\d+)MHz)?`)
)

// Overview 毫秒级只读采集 Wi-Fi 射频、在线客户端、体检结论、自动优化计划与高并发底盘状态。
func (s *Service) Overview(ctx context.Context) (*Overview, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	chassis := s.InspectChassis(ctx)

	ov := &Overview{
		Radios:           []RadioInfo{},
		SSIDs:            []SSIDInfo{},
		Clients:          []ClientInfo{},
		Diagnostics:      []DiagnosisItem{},
		AutoOptimizePlan: []OptimizationStep{},
		Chassis:          chassis,
		SampledAt:        s.now().Unix(),
	}

	st, supported, hint, err := s.probe(ctx)
	if err != nil {
		return nil, err
	}
	if !supported {
		ov.Supported = false
		ov.UnsupportedHint = hint
		ov.HealthScore = 100
		ov.HealthLevel = "good"
		ov.HealthSummary = hint
		return ov, nil
	}

	ov.Supported = true
	ov.Driver = st.Driver

	// 1. 构建 SSID 与客户端视图
	ssidByBandName := make(map[string]map[string]bool)
	var apSections []*uciSection
	for _, sec := range st.WirelessUCI.byType("wifi-iface") {
		mode := strings.ToLower(cmp.Or(sec.opt("mode"), "ap"))
		if mode != "ap" {
			continue
		}
		apSections = append(apSections, sec)
		dev := st.RadioByDev[sec.opt("device")]
		if dev == nil {
			continue
		}
		band := normalizeBand(dev.opt("band"), dev.opt("htmode"), parseInt(dev.opt("channel")))
		if sec.opt("disabled") != "1" && dev.opt("disabled") != "1" && sec.opt("ssid") != "" {
			if ssidByBandName[band] == nil {
				ssidByBandName[band] = make(map[string]bool)
			}
			ssidByBandName[band][sec.opt("ssid")] = true
		}
	}

	has5GRadio := false
	for _, dev := range st.WirelessUCI.byType("wifi-device") {
		if normalizeBand(dev.opt("band"), dev.opt("htmode"), parseInt(dev.opt("channel"))) == "5g" {
			has5GRadio = true
			break
		}
	}

	radioIfaceCount := make(map[string]int)
	radioClients := make(map[string]int)
	radioRxPkts := make(map[string]uint64)
	radioRxErrs := make(map[string]uint64)
	radioIw := make(map[string]iwinfoBlock)

	for _, sec := range apSections {
		devName := sec.opt("device")
		dev := st.RadioByDev[devName]
		band := "2g"
		radioDisabled := false
		if dev != nil {
			band = normalizeBand(dev.opt("band"), dev.opt("htmode"), parseInt(dev.opt("channel")))
			radioDisabled = dev.opt("disabled") == "1"
		}
		ifName := st.IfNameBySec[sec.Name]
		iw := st.Iwinfo[ifName]
		if _, ok := radioIw[devName]; !ok && (iw.Channel > 0 || iw.Hardware != "" || iw.BitRateMbps > 0) {
			radioIw[devName] = iw
		}
		stat := st.DevStats[ifName]

		var clients []ClientInfo
		if ifName != "" && sec.opt("disabled") != "1" && !radioDisabled {
			clients = s.readAssocClients(ctx, ifName, sec.opt("ssid"), band, st.Leases)
		}
		ov.Clients = append(ov.Clients, clients...)

		radioIfaceCount[devName]++
		radioClients[devName] += len(clients)
		radioRxPkts[devName] += stat.RxPackets
		radioRxErrs[devName] += stat.RxErrors

		ssidName := sec.opt("ssid")
		dualPaired := false
		if ssidName != "" {
			if band == "2g" && ssidByBandName["5g"][ssidName] {
				dualPaired = true
			} else if band == "5g" && ssidByBandName["2g"][ssidName] {
				dualPaired = true
			}
		}

		// mtwifi 默认 RRMEnable=1，除非显式设为 0；mac80211 需显式 ieee80211k=1
		kEnabled := sec.opt("ieee80211k") == "1"
		if st.Driver == "mtwifi" && sec.opt("ieee80211k") == "" {
			kEnabled = false // 建议显式写入 UCI 以便持久可见
		}

		ov.SSIDs = append(ov.SSIDs, SSIDInfo{
			Section:            sec.Name,
			Device:             devName,
			Band:               band,
			IfName:             ifName,
			SSID:               ssidName,
			Network:            sec.opt("network"),
			Bridge:             st.NetToBridge[sec.opt("network")],
			Encryption:         cmp.Or(sec.opt("encryption"), iw.Encryption),
			PasswordConfigured: sec.opt("key") != "",
			Disabled:           sec.opt("disabled") == "1" || radioDisabled,
			Isolate:            sec.opt("isolate") == "1",
			IEEE80211k:         kEnabled,
			ClientCount:        len(clients),
			RxPackets:          stat.RxPackets,
			RxErrors:           stat.RxErrors,
			RxErrorRatePct:     calcErrRate(stat.RxPackets, stat.RxErrors),
			DualBandPaired:     dualPaired,
			CanUpgradeDualBand: band == "2g" && has5GRadio && !dualPaired && sec.opt("disabled") != "1" && ssidName != "" && sec.opt("isolate") != "1",
		})
	}

	// 2. 构建射频卡片视图
	for _, dev := range st.WirelessUCI.byType("wifi-device") {
		iw := radioIw[dev.Name]
		if iw.IfName == "" && dev.opt("phy") != "" {
			iw = st.Iwinfo[dev.opt("phy")]
		}
		uciCh := cmp.Or(dev.opt("channel"), "auto")
		curCh := iw.Channel
		if curCh == 0 {
			curCh = parseInt(uciCh)
		}
		band := normalizeBand(dev.opt("band"), dev.opt("htmode"), curCh)
		disabled := dev.opt("disabled") == "1"
		txPct := parseInt(dev.opt("txpower"))
		if txPct == 0 {
			txPct = 100
		}

		modes := []string{"HE20", "HE40"}
		recChs := []int{1, 6, 11}
		if band == "5g" {
			modes = []string{"HE20", "HE40", "HE80", "HE160"}
			recChs = []int{36, 40, 44, 48, 149, 153, 157, 161}
		}

		ov.Radios = append(ov.Radios, RadioInfo{
			Device:         dev.Name,
			Driver:         cmp.Or(dev.opt("type"), st.Driver),
			Phy:            dev.opt("phy"),
			Band:           band,
			Hardware:       iw.Hardware,
			Disabled:       disabled,
			Up:             !disabled && (iw.Channel > 0 || radioIfaceCount[dev.Name] > 0),
			Channel:        uciCh,
			CurrentChannel: curCh,
			FrequencyGHz:   iw.FreqGHz,
			HTMode:         cmp.Or(dev.opt("htmode"), defaultHTMode(band)),
			Country:        dev.opt("country"),
			TxPowerPct:     txPct,
			TxPowerDBm:     iw.TxPowerDBm,
			BitRateMbps:    iw.BitRateMbps,
			MuBeamformer:   dev.opt("mu_beamformer") == "1",
			WHNAT:          dev.opt("whnat") == "1",
			OverlappingCh:  band == "2g" && curCh > 0 && !isNonOverlapping2GChannel(curCh),
			DFSChannel:     band == "5g" && curCh > 0 && isDFSChannel(curCh),
			SupportedModes: modes,
			RecommendChs:   recChs,
			InterfaceCount: radioIfaceCount[dev.Name],
			ClientCount:    radioClients[dev.Name],
			RxPackets:      radioRxPkts[dev.Name],
			RxErrors:       radioRxErrs[dev.Name],
			RxErrorRatePct: calcErrRate(radioRxPkts[dev.Name], radioRxErrs[dev.Name]),
		})
	}

	// 3. 运行声明式体检引擎并生成一键优化计划
	runDiagnostics(ov, st)
	return ov, nil
}

func (s *Service) probe(ctx context.Context) (*probeState, bool, string, error) {
	if _, err := s.lookPath("uci"); err != nil {
		return nil, false, "当前设备未检测到 OpenWrt UCI 环境，Wi-Fi 调优仅适用于带无线射频的 OpenWrt 路由器。", nil
	}
	wRaw, err := s.runCmd(ctx, "uci", "show", "wireless")
	if err != nil || strings.TrimSpace(string(wRaw)) == "" {
		return nil, false, "当前设备未检测到 OpenWrt 无线射频配置（/etc/config/wireless 为空）。", nil
	}
	wDoc := parseUCIShow("wireless", string(wRaw))
	radios := wDoc.byType("wifi-device")
	if len(radios) == 0 {
		return nil, false, "未在 /etc/config/wireless 中发现可用无线射频设备。", nil
	}

	driver := "mac80211"
	radioByDev := make(map[string]*uciSection, len(radios))
	for _, r := range radios {
		radioByDev[r.Name] = r
		if strings.EqualFold(r.opt("type"), "mtwifi") {
			driver = "mtwifi"
		}
	}

	netRaw, _ := s.runCmd(ctx, "uci", "show", "network")
	netDoc := parseUCIShow("network", string(netRaw))
	netToBridge := make(map[string]string)
	for _, sec := range netDoc.byType("interface") {
		if dev := cmp.Or(sec.opt("device"), sec.opt("ifname")); dev != "" {
			netToBridge[sec.Name] = dev
		}
	}

	iwRaw, _ := s.runCmd(ctx, "iwinfo")
	iwMap := parseIwinfoOutput(string(iwRaw))

	brRaw, _ := s.runCmd(ctx, "brctl", "show")
	bridges := parseBrctlShow(string(brRaw))

	devRaw, _ := s.readFile("/proc/net/dev")
	devStats := parseProcNetDev(string(devRaw))

	leaseRaw, _ := s.readFile("/tmp/dhcp.leases")
	leases := parseDHCPLeases(string(leaseRaw))

	ifaceBySec := make(map[string]*uciSection)
	ifNameBySec := mapIfaceNames(wDoc, radioByDev, iwMap, driver)
	for _, sec := range wDoc.byType("wifi-iface") {
		ifaceBySec[sec.Name] = sec
	}

	return &probeState{
		Driver:      driver,
		WirelessUCI: wDoc,
		NetworkUCI:  netDoc,
		Bridges:     bridges,
		NetToBridge: netToBridge,
		Iwinfo:      iwMap,
		DevStats:    devStats,
		Leases:      leases,
		IfaceBySec:  ifaceBySec,
		RadioByDev:  radioByDev,
		IfNameBySec: ifNameBySec,
	}, true, "", nil
}

// mapIfaceNames 为 mtwifi（按 device 下 AP 顺序映射 ra0/ra1 或 rax0/rax1）和 mac80211 映射真实网卡接口名。
func mapIfaceNames(wDoc *uciDoc, radioByDev map[string]*uciSection, iwMap map[string]iwinfoBlock, driver string) map[string]string {
	out := make(map[string]string)
	perDevIdx := make(map[string]int)
	used := make(map[string]bool)

	for _, sec := range wDoc.byType("wifi-iface") {
		mode := strings.ToLower(cmp.Or(sec.opt("mode"), "ap"))
		if mode != "ap" {
			continue
		}
		if explicit := sec.opt("ifname"); explicit != "" {
			out[sec.Name] = explicit
			used[explicit] = true
			continue
		}
		devName := sec.opt("device")
		dev := radioByDev[devName]
		if driver == "mtwifi" && dev != nil {
			idx := perDevIdx[devName]
			perDevIdx[devName] = idx + 1
			prefix := strings.TrimRight(dev.opt("phy"), "0123456789")
			if prefix == "" {
				if normalizeBand(dev.opt("band"), dev.opt("htmode"), 0) == "5g" {
					prefix = "rax"
				} else {
					prefix = "ra"
				}
			}
			cand := fmt.Sprintf("%s%d", prefix, idx)
			out[sec.Name] = cand
			used[cand] = true
			continue
		}
		// mac80211：按 ESSID 精确匹配尚未占用的 iwinfo Master 接口
		ssid := sec.opt("ssid")
		var names []string
		for k := range iwMap {
			names = append(names, k)
		}
		slices.Sort(names)
		for _, k := range names {
			if used[k] {
				continue
			}
			blk := iwMap[k]
			if strings.EqualFold(blk.Mode, "Master") && ssid != "" && blk.ESSID == ssid {
				out[sec.Name] = k
				used[k] = true
				break
			}
		}
	}
	return out
}

func (s *Service) readAssocClients(ctx context.Context, ifName, ssid, band string, leases map[string]dhcpLease) []ClientInfo {
	raw, err := s.runCmd(ctx, "iwinfo", ifName, "assoclist")
	if err != nil || len(raw) == 0 {
		return nil
	}
	var clients []ClientInfo
	var cur *ClientInfo
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if m := reAssocHead.FindStringSubmatch(trimmed); len(m) == 3 {
			if cur != nil {
				clients = append(clients, *cur)
			}
			mac := strings.ToLower(m[1])
			sig := parseInt(m[2])
			lease := leases[mac]
			cur = &ClientInfo{
				MAC:        mac,
				Hostname:   lease.Hostname,
				IP:         lease.IP,
				IfName:     ifName,
				SSID:       ssid,
				Band:       band,
				SignalDBm:  sig,
				WeakSignal: sig != 0 && sig <= -82,
			}
			continue
		}
		if cur != nil {
			if m := reRateLine.FindStringSubmatch(trimmed); len(m) >= 3 {
				rate, _ := strconv.ParseFloat(m[2], 64)
				if m[1] == "RX" {
					cur.RxMbps = rate
				} else {
					cur.TxMbps = rate
				}
				if len(m) >= 4 && m[3] != "" {
					if bw := parseInt(m[3]); bw > cur.BandwidthMHz {
						cur.BandwidthMHz = bw
					}
				}
				if (cur.TxMbps > 0 && cur.TxMbps < 30) || (cur.RxMbps > 0 && cur.RxMbps < 30) {
					cur.WeakSignal = true
				}
			}
		}
	}
	if cur != nil {
		clients = append(clients, *cur)
	}
	return clients
}

func parseIwinfoOutput(raw string) map[string]iwinfoBlock {
	res := make(map[string]iwinfoBlock)
	var cur *iwinfoBlock
	flush := func() {
		if cur != nil && cur.IfName != "" {
			res[cur.IfName] = *cur
		}
	}
	for line := range strings.SplitSeq(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			fields := strings.Fields(line)
			if len(fields) == 0 {
				cur = nil
				continue
			}
			cur = &iwinfoBlock{IfName: fields[0]}
			if m := reESSID.FindStringSubmatch(line); len(m) == 2 {
				cur.ESSID = m[1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		if m := reModeCh.FindStringSubmatch(line); len(m) >= 3 {
			cur.Mode = m[1]
			cur.Channel = parseInt(m[2])
			if len(m) >= 4 {
				cur.FreqGHz = m[3]
			}
		}
		if m := reTxPower.FindStringSubmatch(line); len(m) == 2 {
			cur.TxPowerDBm = parseInt(m[1])
		}
		if m := reBitRate.FindStringSubmatch(line); len(m) == 2 {
			cur.BitRateMbps, _ = strconv.ParseFloat(m[1], 64)
		}
		if strings.Contains(line, "Encryption:") {
			if _, after, ok := strings.Cut(line, "Encryption:"); ok {
				cur.Encryption = strings.TrimSpace(after)
			}
		}
		if m := reHardware.FindStringSubmatch(line); len(m) == 2 {
			cur.Hardware = strings.TrimSpace(m[1])
		}
	}
	flush()
	return res
}

func parseBrctlShow(raw string) map[string][]string {
	out := make(map[string][]string)
	curBridge := ""
	for line := range strings.SplitSeq(raw, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "bridge name") {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				curBridge = fields[0]
				if len(fields) >= 4 {
					out[curBridge] = append(out[curBridge], fields[3])
				}
			}
		} else if curBridge != "" {
			iface := strings.TrimSpace(line)
			if iface != "" {
				out[curBridge] = append(out[curBridge], iface)
			}
		}
	}
	return out
}

func parseProcNetDev(raw string) map[string]netDevStat {
	out := make(map[string]netDevStat)
	for line := range strings.SplitSeq(raw, "\n") {
		iface, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) < 3 {
			continue
		}
		pkts, _ := strconv.ParseUint(fields[1], 10, 64)
		errs, _ := strconv.ParseUint(fields[2], 10, 64)
		out[strings.TrimSpace(iface)] = netDevStat{RxPackets: pkts, RxErrors: errs}
	}
	return out
}

func parseDHCPLeases(raw string) map[string]dhcpLease {
	out := make(map[string]dhcpLease)
	for line := range strings.SplitSeq(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mac := strings.ToLower(fields[1])
		host := fields[3]
		if host == "*" {
			host = ""
		}
		out[mac] = dhcpLease{IP: fields[2], Hostname: host}
	}
	return out
}

func calcErrRate(pkts, errs uint64) float64 {
	if pkts == 0 {
		return 0
	}
	return math.Round(float64(errs)*10000/float64(pkts)) / 100
}

func parseInt(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func defaultHTMode(band string) string {
	if band == "5g" {
		return "HE80"
	}
	return "HE20"
}
