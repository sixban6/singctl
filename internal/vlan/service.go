// 文件职责：编排 OpenWrt VLAN 硬件发现、四件套 UCI (network/dhcp/wireless/firewall) 编译、人话摘要生成与透明代理绕行联动。
package vlan

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Env 封装 VLAN 服务所需的全部可替换宿主机 I/O 依赖（nil 自动回退生产默认实现，严禁包级全局变量）。
type Env struct {
	IsOpenWrt             func() bool
	RunUCI                func(ctx context.Context, args ...string) (string, error)
	BatchUCI              func(ctx context.Context, commands []string) error
	ReloadNetwork         func(ctx context.Context) error
	ReloadNetworkWithOpts func(ctx context.Context, opts ReloadOptions) error
	PrepareDMAHeadroom    func()
	SyncProxyBypass       func(ctx context.Context, cidrs []string) error
	ReadFile              func(path string) ([]byte, error)
	ListNetDevs           func() ([]string, error)
	ReadIPv4Addrs         func() (map[string]string, error)
	ProxyBypassFile       string
	BoardJSONPath         string
	DHCPLeasesPath        string
}

// Service 提供 OpenWrt VLAN 分段的硬件探测、只读总览、Dry-Run 预览、原子应用与安全删除编排。
type Service struct {
	env      Env
	registry *DriverRegistry
}

// NewService 创建带显式依赖注入的 VLAN 管理服务。
func NewService(env Env) *Service {
	return &Service{
		env:      env,
		registry: NewDefaultRegistry(),
	}
}

func (s *Service) inspectState(ctx context.Context, callerIP string) (*Overview, *parsedState, error) {
	if !s.isOpenWrt() {
		return &Overview{
			Supported:         false,
			UnsupportedReason: "当前宿主机非 OpenWrt / ImmortalWrt 路由器环境（未检测到 UCI），VLAN 自动分段仅适用于 OpenWrt 网关",
			Driver:            DriverUnsupported,
			DriverLabel:       "仅支持 OpenWrt",
			Ports:             []PortInfo{},
			Radios:            []RadioInfo{},
			ExistingSSIDs:     []WirelessSSIDInfo{},
			Segments:          []Segment{},
			Presets:           []PresetTemplate{},
		}, nil, nil
	}

	netRaw, err := s.runUCI(ctx, "show", "network")
	if err != nil {
		return nil, nil, fmt.Errorf("读取 OpenWrt network UCI 失败: %w", err)
	}
	wirelessRaw, _ := s.runUCI(ctx, "show", "wireless")
	dhcpRaw, _ := s.runUCI(ctx, "show", "dhcp")
	fwRaw, _ := s.runUCI(ctx, "show", "firewall")

	boardRaw, _ := s.readFile(s.boardJSONPath())
	board := parseBoardJSON(boardRaw)
	netDevs := s.listNetDevs()
	ipv4Addrs := s.readIPv4Addrs()

	state := &parsedState{
		Board:       board,
		NetUCI:      parseUCIShow("network", netRaw),
		WirelessUCI: parseUCIShow("wireless", wirelessRaw),
		DHCP:        parseUCIShow("dhcp", dhcpRaw),
		Firewall:    parseUCIShow("firewall", fwRaw),
		NetDevs:     netDevs,
		IPv4Addrs:   ipv4Addrs,
	}

	if wanSec := state.NetUCI.ByName("wan"); wanSec != nil {
		state.WANDevice = wanSec.Opt("device")
	}
	if state.WANDevice == "" && board != nil {
		state.WANDevice = board.Network.WAN.Device
	}
	if state.WANDevice != "" {
		if cidrStr, ok := ipv4Addrs[state.WANDevice]; ok {
			if pfx, err := netip.ParsePrefix(cidrStr); err == nil && pfx.Addr().Is4() {
				state.WANIP = pfx.Addr().String()
				state.WANSubnet = pfx.Masked().String()
			}
		}
	}

	drv := s.registry.Detect(state.NetUCI, board, netDevs)
	if drv == nil {
		return &Overview{
			Supported:         false,
			UnsupportedReason: "未能识别当前路由器的交换机或网桥拓扑（未检测到 DSA/swconfig/br-lan）",
			Driver:            DriverUnsupported,
			DriverLabel:       "未识别拓扑",
			Ports:             []PortInfo{},
			Radios:            []RadioInfo{},
			ExistingSSIDs:     []WirelessSSIDInfo{},
			Segments:          []Segment{},
			Presets:           []PresetTemplate{},
		}, nil, nil
	}
	state.Driver = drv

	ports, segPorts, segVLANs := drv.ParseTopology(state, s.readPortLink)
	radios, ssids := parseWirelessTopology(state.WirelessUCI)
	bypassSet := make(map[string]bool)
	for _, c := range ReadProxyBypassList(s.proxyBypassFile()) {
		bypassSet[c] = true
	}

	cleanCallerIP := extractHostIP(callerIP)
	callerAddr, callerAddrErr := netip.ParseAddr(cleanCallerIP)

	segments := buildSegments(state, segPorts, segVLANs, ssids, bypassSet, callerAddr, callerAddrErr == nil)

	leasesRaw, _ := s.readFile(s.dhcpLeasesPath())
	leaseCounts := countDHCPLeasesByCIDR(leasesRaw, segments)
	callerSegID := ""
	for i := range segments {
		segments[i].OnlineClients = leaseCounts[segments[i].ID]
		if segments[i].IsCallerMgmt {
			callerSegID = segments[i].ID
		}
	}

	// Protect the caller's active management port without locking every LAN port on a fresh router.
	callerPort := ""
	if callerSegID != "" {
		var segPortIdxs []int
		var upSegPortIdxs []int
		for i := range ports {
			if ports[i].UntaggedSegmentID == callerSegID {
				segPortIdxs = append(segPortIdxs, i)
				if ports[i].LinkUp {
					upSegPortIdxs = append(upSegPortIdxs, i)
				}
			}
		}
		switch {
		case len(segPortIdxs) == 1:
			idx := segPortIdxs[0]
			ports[idx].IsMgmt = true
			callerPort = ports[idx].Name
		case len(upSegPortIdxs) == 1:
			idx := upSegPortIdxs[0]
			ports[idx].IsMgmt = true
			callerPort = ports[idx].Name
		case len(segPortIdxs) > 1:
			// Preserve the first port (typically LAN1) as a safe management fallback; other LAN ports stay assignable.
			idx := segPortIdxs[0]
			ports[idx].IsMgmt = true
			callerPort = ports[idx].Name
		}
	}
	state.Ports = ports
	state.Segments = segments

	boardModel := ""
	if board != nil {
		boardModel = board.Model.Name
	}

	ov := &Overview{
		Supported:       true,
		Driver:          drv.ID(),
		DriverLabel:     drv.Label(),
		BoardModel:      boardModel,
		WANDevice:       state.WANDevice,
		WANIP:           state.WANIP,
		WANSubnet:       state.WANSubnet,
		CallerIP:        cleanCallerIP,
		CallerSegmentID: callerSegID,
		CallerPort:      callerPort,
		Ports:           ports,
		Radios:          radios,
		ExistingSSIDs:   ssids,
		Segments:        segments,
	}
	ov.Presets = buildPresets(ov)
	return ov, state, nil
}

// Overview 返回宿主机 VLAN 硬件拓扑、物理口状态、无线射频、现网分段与零术语推荐预设。
func (s *Service) Overview(ctx context.Context, callerIP string) (*Overview, error) {
	ov, _, err := s.inspectState(ctx, callerIP)
	return ov, err
}

// PreviewSave 执行完整校验与 Dry-Run，生成面向普通用户的人话变更摘要与面向专家的底层 UCI 指令预览。
func (s *Service) PreviewSave(ctx context.Context, callerIP string, rawReq SaveSegmentRequest) (*PreviewResult, error) {
	ov, state, err := s.inspectState(ctx, callerIP)
	if err != nil {
		return nil, err
	}
	if !ov.Supported || state == nil {
		return &PreviewResult{Valid: false, Errors: []string{cmp.Or(ov.UnsupportedReason, "当前环境不支持 VLAN 自动配置")}}, nil
	}

	req := normalizeSaveRequest(rawReq)
	var existing *Segment
	for i := range ov.Segments {
		if ov.Segments[i].ID == req.ID {
			existing = &ov.Segments[i]
			break
		}
	}

	errs, warns := validateSaveRequest(ov, req, existing)
	if len(errs) > 0 {
		return &PreviewResult{Valid: false, Errors: errs, Warnings: warns}, nil
	}

	cmds, plain, bypassCIDRs, routeHint, err := s.compileSavePlan(ov, state, req, existing)
	if err != nil {
		return &PreviewResult{Valid: false, Errors: []string{err.Error()}, Warnings: warns}, nil
	}

	return &PreviewResult{
		Valid:             true,
		Warnings:          warns,
		PlainSummary:      plain,
		UCICommands:       cmds,
		ProxyBypassCIDRs:  bypassCIDRs,
		UpstreamRouteHint: routeHint,
	}, nil
}

// CommitSave 执行第一阶段：校验、原子写入 UCI 变更与透明代理绕行清单（不阻塞等待网络/无线重载）。
func (s *Service) CommitSave(ctx context.Context, callerIP string, rawReq SaveSegmentRequest) (*ApplyResult, error) {
	prev, err := s.PreviewSave(ctx, callerIP, rawReq)
	if err != nil {
		return nil, err
	}
	if !prev.Valid {
		return nil, fmt.Errorf("%s", strings.Join(prev.Errors, "；"))
	}

	if err := s.batchUCI(ctx, prev.UCICommands); err != nil {
		return nil, err
	}
	if err := s.syncProxyBypass(ctx, prev.ProxyBypassCIDRs); err != nil {
		return nil, fmt.Errorf("同步透明代理绕行规则失败: %w", err)
	}

	req := normalizeSaveRequest(rawReq)
	return &ApplyResult{
		OK:                true,
		SegmentID:         req.ID,
		PlainSummary:      prev.PlainSummary,
		UCICommands:       prev.UCICommands,
		Warnings:          prev.Warnings,
		UpstreamRouteHint: prev.UpstreamRouteHint,
		ReloadOpts: ReloadOptions{
			WirelessChanged: slices.Contains(DirtyUCIPackages(prev.UCICommands), "wireless"),
		},
	}, nil
}

// ApplySave 校验并原子提交 VLAN 变更至 OpenWrt UCI、同步透明代理绕行清单并热重载网络服务。
func (s *Service) ApplySave(ctx context.Context, callerIP string, rawReq SaveSegmentRequest) (*ApplyResult, error) {
	res, err := s.CommitSave(ctx, callerIP, rawReq)
	if err != nil {
		return nil, err
	}
	if err := s.ReloadWithOptions(ctx, res.ReloadOpts); err != nil {
		return nil, fmt.Errorf("重载 OpenWrt 网络服务失败: %w", err)
	}
	return res, nil
}

// PreviewDelete 校验删除指定 VLAN 分段的安全性并返回变更摘要与底层清理指令。
func (s *Service) PreviewDelete(ctx context.Context, callerIP, segID string) (*PreviewResult, error) {
	ov, state, err := s.inspectState(ctx, callerIP)
	if err != nil {
		return nil, err
	}
	if !ov.Supported || state == nil {
		return &PreviewResult{Valid: false, Errors: []string{cmp.Or(ov.UnsupportedReason, "当前环境不支持 VLAN 自动配置")}}, nil
	}
	existing, errs := validateDeleteRequest(ov, segID)
	if len(errs) > 0 {
		return &PreviewResult{Valid: false, Errors: errs}, nil
	}

	netCmds, err := state.Driver.BuildDeleteNetworkCommands(state, *existing)
	if err != nil {
		return nil, err
	}
	cmds := append([]string{}, netCmds...)
	cmds = append(cmds, fmt.Sprintf("delete dhcp.%s", existing.ID))
	cmds = append(cmds, buildDeleteWirelessCommands(state.WirelessUCI, existing.ID)...)
	cmds = append(cmds, buildDeleteFirewallCommands(state.Firewall, existing.ID)...)

	var nextBypass []string
	for _, seg := range ov.Segments {
		if seg.ID != existing.ID && seg.ProxyMode == ProxyModeDirect && seg.CIDR != "" {
			nextBypass = append(nextBypass, seg.CIDR)
		}
	}

	plain := []string{
		fmt.Sprintf("移除子网分段「%s」(%s)", cmp.Or(existing.DisplayName, existing.ID), existing.CIDR),
		"自动清理关联 DHCP 池、防火墙区域与隔离规则，并安全解绑关联的无线网络",
	}
	if existing.ProxyMode == ProxyModeDirect {
		plain = append(plain, "同步移除该网段的透明代理纯直连绕行规则")
	}

	return &PreviewResult{
		Valid:            true,
		PlainSummary:     plain,
		UCICommands:      cmds,
		ProxyBypassCIDRs: nextBypass,
	}, nil
}

// CommitDelete 执行第一阶段：校验删除安全性、原子写入 UCI 清理指令并同步代理绕行清单（不阻塞等待网络重载）。
func (s *Service) CommitDelete(ctx context.Context, callerIP, segID string) (*ApplyResult, error) {
	prev, err := s.PreviewDelete(ctx, callerIP, segID)
	if err != nil {
		return nil, err
	}
	if !prev.Valid {
		return nil, fmt.Errorf("%s", strings.Join(prev.Errors, "；"))
	}
	if err := s.batchUCI(ctx, prev.UCICommands); err != nil {
		return nil, err
	}
	if err := s.syncProxyBypass(ctx, prev.ProxyBypassCIDRs); err != nil {
		return nil, fmt.Errorf("同步透明代理绕行规则失败: %w", err)
	}
	return &ApplyResult{
		OK:           true,
		SegmentID:    strings.ToLower(strings.TrimSpace(segID)),
		PlainSummary: prev.PlainSummary,
		UCICommands:  prev.UCICommands,
		ReloadOpts: ReloadOptions{
			WirelessChanged: slices.Contains(DirtyUCIPackages(prev.UCICommands), "wireless"),
		},
	}, nil
}

// ApplyDelete 执行受保护的 VLAN 分段卸载、同步绕行清单并热重载网络服务。
func (s *Service) ApplyDelete(ctx context.Context, callerIP, segID string) (*ApplyResult, error) {
	res, err := s.CommitDelete(ctx, callerIP, segID)
	if err != nil {
		return nil, err
	}
	if err := s.ReloadWithOptions(ctx, res.ReloadOpts); err != nil {
		return nil, fmt.Errorf("重载 OpenWrt 网络服务失败: %w", err)
	}
	return res, nil
}

func (s *Service) syncProxyBypass(ctx context.Context, cidrs []string) error {
	if s.env.SyncProxyBypass != nil {
		return s.env.SyncProxyBypass(ctx, cidrs)
	}
	return SyncRuntimeProxyBypass(ctx, s.proxyBypassFile(), cidrs)
}

func (s *Service) compileSavePlan(ov *Overview, state *parsedState, req SaveSegmentRequest, existing *Segment) ([]string, []string, []string, string, error) {
	cidr, err := computeNetworkCIDR(req.IPAddr, req.Netmask)
	if err != nil {
		return nil, nil, nil, "", err
	}
	netCmds, l3Dev, err := state.Driver.BuildNetworkCommands(state, req, existing)
	if err != nil {
		return nil, nil, nil, "", err
	}

	var cmds []string
	cmds = append(cmds, netCmds...)
	cmds = append(cmds, buildDHCPCommands(req)...)
	cmds = append(cmds, buildWirelessCommands(state.WirelessUCI, ov.Radios, req, existing)...)
	cmds = append(cmds, buildFirewallCommands(state.Firewall, ov.WANSubnet, req)...)

	// Compute resulting proxy bypass CIDR list across all segments.
	var bypassCIDRs []string
	for _, seg := range ov.Segments {
		if seg.ID == req.ID {
			continue
		}
		if seg.ProxyMode == ProxyModeDirect && seg.CIDR != "" {
			bypassCIDRs = append(bypassCIDRs, seg.CIDR)
		}
	}
	if req.ProxyMode == ProxyModeDirect {
		bypassCIDRs = append(bypassCIDRs, cidr.String())
	}
	bypassCIDRs, _ = NormalizeBypassCIDRs(bypassCIDRs)

	// Plain-Chinese human summary (zero jargon for default mode!).
	title := cmp.Or(req.DisplayName, req.ID)
	verb := "新建"
	if existing != nil {
		verb = "更新"
	}
	plain := []string{
		fmt.Sprintf("%s独立子网「%s」（网段 %s，网关 %s，底层接口 %s）", verb, title, cidr.String(), req.IPAddr, l3Dev),
		fmt.Sprintf("自动分配地址池 .%d ~ .%d（租期 %s）", req.DHCPStart, req.DHCPStart+req.DHCPLimit, req.LeaseTime),
	}
	if req.Wireless != nil && req.Wireless.Enabled && req.Wireless.SSID != "" {
		isoText := ""
		if req.Wireless.Isolate {
			isoText = "，已开启设备间互不可见"
		}
		plain = append(plain, fmt.Sprintf("开启专属 Wi-Fi「%s」%s", req.Wireless.SSID, isoText))
	}
	var accessPorts, trunkPorts []string
	for pName, mode := range req.Ports {
		if mode == PortModeAccess {
			accessPorts = append(accessPorts, strings.ToUpper(pName))
		} else if mode == PortModeTrunk {
			trunkPorts = append(trunkPorts, strings.ToUpper(pName))
		}
	}
	slices.Sort(accessPorts)
	slices.Sort(trunkPorts)
	if len(accessPorts) > 0 {
		plain = append(plain, fmt.Sprintf("物理网口 %s 划入该网段（插上网线即自动入网）", strings.Join(accessPorts, " / ")))
	}
	if len(trunkPorts) > 0 {
		plain = append(plain, fmt.Sprintf("物理网口 %s 开启多网一线透传（下联专业 AP / 交换机）", strings.Join(trunkPorts, " / ")))
	}
	if req.ProxyMode == ProxyModeDirect {
		plain = append(plain, "上网方式：纯直连绕过透明代理（不消耗代理流量，不误伤国内智能家居）")
	} else {
		plain = append(plain, "上网方式：跟随网关全局透明代理分流")
	}
	var secNotes []string
	if req.Policy.BlockRouterMgmt {
		secNotes = append(secNotes, "禁止访问路由器后台")
	}
	if req.Policy.BlockUpstreamLAN && ov.WANSubnet != "" {
		secNotes = append(secNotes, "禁止访问上级主网")
	}
	if req.Policy.AllowFromMainLAN {
		secNotes = append(secNotes, "允许主网单向控制")
	}
	if len(secNotes) > 0 {
		plain = append(plain, "安全隔离："+strings.Join(secNotes, " · "))
	}

	routeHint := ""
	if ov.WANIP != "" {
		routeHint = fmt.Sprintf("ip route replace %s via %s", cidr.String(), ov.WANIP)
	}
	return cmds, plain, bypassCIDRs, routeHint, nil
}
