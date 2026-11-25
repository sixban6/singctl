// 文件职责：编排 OpenWrt VLAN 硬件发现、四件套 UCI (network/dhcp/wireless/firewall) 编译、人话摘要生成与透明代理绕行联动。
package vlan

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

var (
	// ErrInvalidSegmentID 表示传入的分段标识包含非法字符或格式不符合 UCI 接口规范。
	ErrInvalidSegmentID = errors.New("invalid segment id")
	// ErrSegmentNotFound 表示指定的 VLAN 分段在现网 UCI 中不存在。
	ErrSegmentNotFound = errors.New("segment not found")
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
	SyncDNSBypass         func(ctx context.Context, rules []VLANDNSBypassRule) error
	SyncSideRoutes        func(ctx context.Context, spec VLANSideRouteSpec) error
	ReadFile              func(path string) ([]byte, error)
	ListNetDevs           func() ([]string, error)
	ReadIPv4Addrs         func() (map[string]string, error)
	SideRouterIP          string
	ProxyBypassFile       string
	DNSBypassFile         string
	SideRoutesFile        string
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

	radios, ssids := parseWirelessTopology(state.WirelessUCI)
	bypassSet := make(map[string]bool)
	for _, c := range ReadProxyBypassList(s.proxyBypassFile()) {
		bypassSet[c] = true
	}
	sideSpec := ReadSideRouteSpec(s.sideRoutesFile())
	sideRouteSet := make(map[string]bool, len(sideSpec.CIDRs))
	for _, c := range sideSpec.CIDRs {
		sideRouteSet[c] = true
	}
	resolvedSideIP := cmp.Or(strings.TrimSpace(s.env.SideRouterIP), sideSpec.SideRouterIP)
	cleanCallerIP := extractHostIP(callerIP)
	callerAddr, callerAddrErr := netip.ParseAddr(cleanCallerIP)
	boardModel := ""
	if board != nil {
		boardModel = board.Model.Name
	}

	drv := s.registry.Detect(state.NetUCI, board, netDevs)
	if drv == nil {
		roSegments := buildSegments(state, map[string]map[string]string{}, map[string]int{}, ssids, bypassSet, sideRouteSet, callerAddr, callerAddrErr == nil)
		lanSec := state.NetUCI.ByName("lan")
		lanDev := ""
		if lanSec != nil {
			lanDev = lanSec.Opt("device")
		}
		isSingleNICSideRouter := lanSec != nil &&
			len(radios) == 0 &&
			len(collectBridgePorts(state.NetUCI, "br-lan")) == 0 &&
			len(state.NetUCI.ByType("switch")) == 0 &&
			len(state.NetUCI.ByType("switch_vlan")) == 0
		if isSingleNICSideRouter {
			return &Overview{
				Supported:         false,
				UnsupportedReason: fmt.Sprintf("检测到当前设备（%s）为单网口（%s）无网桥且未启用无线 AP 的旁路由拓扑，本机无独立交换网口可划分；请在主路由 / AP 上配置物理网口与访客/IoT 隔离 Wi-Fi（隔离网网关指向主路由即可直连绕过旁路由代理）。", cmp.Or(boardModel, "OpenWrt"), cmp.Or(lanDev, "eth0")),
				Driver:            DriverUnsupported,
				DriverLabel:       "单网口旁路由",
				BoardModel:        boardModel,
				Ports:             []PortInfo{},
				Radios:            radios,
				ExistingSSIDs:     ssids,
				Segments:          roSegments,
				Presets:           []PresetTemplate{},
			}, nil, nil
		}
		return &Overview{
			Supported:         false,
			UnsupportedReason: "未能识别当前路由器的交换机或网桥拓扑（未检测到 DSA/swconfig/br-lan）",
			Driver:            DriverUnsupported,
			DriverLabel:       "未识别拓扑",
			BoardModel:        boardModel,
			Ports:             []PortInfo{},
			Radios:            radios,
			ExistingSSIDs:     ssids,
			Segments:          roSegments,
			Presets:           []PresetTemplate{},
		}, nil, nil
	}
	state.Driver = drv

	ports, segPorts, segVLANs := drv.ParseTopology(state, s.readPortLink)
	segments := buildSegments(state, segPorts, segVLANs, ssids, bypassSet, sideRouteSet, callerAddr, callerAddrErr == nil)

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

	if ports == nil {
		ports = []PortInfo{}
	}
	if radios == nil {
		radios = []RadioInfo{}
	}
	if ssids == nil {
		ssids = []WirelessSSIDInfo{}
	}
	if segments == nil {
		segments = []Segment{}
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
		SideRouterIP:    resolvedSideIP,
		Ports:           ports,
		Radios:          radios,
		ExistingSSIDs:   ssids,
		Segments:        segments,
	}
	ov.Presets = buildPresets(ov)
	if ov.Presets == nil {
		ov.Presets = []PresetTemplate{}
	}
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
	if validDNS, _ := normalizeAndValidateDHCPDNS(req.DHCPDNS); len(validDNS) > 0 {
		req.DHCPDNS = validDNS
	}
	ensureSideRouterEffectiveDNS(ov, &req)

	prev, err := s.compileSavePlan(ov, state, req, existing)
	if err != nil {
		return &PreviewResult{Valid: false, Errors: []string{err.Error()}, Warnings: warns}, nil
	}
	prev.Warnings = warns
	return prev, nil
}

// CommitSave 执行第一阶段：校验、原子写入 UCI 变更与透明代理/自定义 DNS 免劫持规则（不阻塞等待网络/无线重载）。
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
	if err := s.syncDNSBypass(ctx, prev.DNSBypassRules); err != nil {
		return nil, fmt.Errorf("同步自定义 DNS 免劫持规则失败: %w", err)
	}
	if err := s.syncSideRoutes(ctx, prev.SideRouteSpec); err != nil {
		return nil, fmt.Errorf("同步旁路由策略路由规则失败: %w", err)
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

	nextBypass, nextSide := collectSegmentProxyAndSideCIDRs(ov.Segments, existing.ID, SaveSegmentRequest{}, "")
	var nextDNSBypass []VLANDNSBypassRule
	for _, seg := range ov.Segments {
		if seg.ID == existing.ID || seg.CIDR == "" {
			continue
		}
		if customDNS := effectiveCustomDNS(seg.DHCPDNS, seg.IPAddr); len(customDNS) > 0 {
			nextDNSBypass = append(nextDNSBypass, VLANDNSBypassRule{
				CIDR:   seg.CIDR,
				DNSIPs: customDNS,
			})
		}
	}

	plain := []string{
		fmt.Sprintf("移除子网分段「%s」(%s)", cmp.Or(existing.DisplayName, existing.ID), existing.CIDR),
		"自动清理关联 DHCP 池、防火墙区域与隔离规则，并安全解绑关联的无线网络",
	}
	if existing.ProxyMode == ProxyModeDirect || existing.ProxyMode == ProxyModeSideRouter {
		plain = append(plain, "同步移除该网段的透明代理绕行与策略路由规则")
	}

	return &PreviewResult{
		Valid:            true,
		PlainSummary:     plain,
		UCICommands:      cmds,
		ProxyBypassCIDRs: nextBypass,
		DNSBypassRules:   nextDNSBypass,
		SideRouteSpec:    VLANSideRouteSpec{SideRouterIP: ov.SideRouterIP, CIDRs: nextSide},
	}, nil
}

// CommitDelete 执行第一阶段：校验删除安全性、原子写入 UCI 清理指令并同步代理/DNS 绕行清单（不阻塞等待网络重载）。
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
	if err := s.syncDNSBypass(ctx, prev.DNSBypassRules); err != nil {
		return nil, fmt.Errorf("同步自定义 DNS 免劫持规则失败: %w", err)
	}
	if err := s.syncSideRoutes(ctx, prev.SideRouteSpec); err != nil {
		return nil, fmt.Errorf("同步旁路由策略路由规则失败: %w", err)
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

func (s *Service) syncDNSBypass(ctx context.Context, rules []VLANDNSBypassRule) error {
	if s.env.SyncDNSBypass != nil {
		return s.env.SyncDNSBypass(ctx, rules)
	}
	return SyncRuntimeDNSBypass(ctx, s.dnsBypassFile(), rules)
}

func (s *Service) compileSavePlan(ov *Overview, state *parsedState, req SaveSegmentRequest, existing *Segment) (*PreviewResult, error) {
	cidr, err := computeNetworkCIDR(req.IPAddr, req.Netmask)
	if err != nil {
		return nil, err
	}
	netCmds, l3Dev, err := state.Driver.BuildNetworkCommands(state, req, existing)
	if err != nil {
		return nil, err
	}

	var cmds []string
	cmds = append(cmds, netCmds...)
	cmds = append(cmds, buildDHCPCommands(state.DHCP, req)...)
	cmds = append(cmds, buildWirelessCommands(state.WirelessUCI, ov.Radios, req, existing)...)
	cmds = append(cmds, buildFirewallCommands(ov, state.Firewall, ov.WANSubnet, req)...)

	// Compute resulting proxy bypass CIDR list, side-router PBR CIDRs, and custom DNS bypass rules across all segments.
	bypassCIDRs, sideCIDRs := collectSegmentProxyAndSideCIDRs(ov.Segments, req.ID, req, cidr.String())
	var dnsBypassRules []VLANDNSBypassRule
	for _, seg := range ov.Segments {
		if seg.ID == req.ID || seg.CIDR == "" {
			continue
		}
		if customDNS := effectiveCustomDNS(seg.DHCPDNS, seg.IPAddr); len(customDNS) > 0 {
			dnsBypassRules = append(dnsBypassRules, VLANDNSBypassRule{
				CIDR:   seg.CIDR,
				DNSIPs: customDNS,
			})
		}
	}
	customDNS := effectiveCustomDNS(req.DHCPDNS, req.IPAddr)
	if len(customDNS) > 0 {
		dnsBypassRules = append(dnsBypassRules, VLANDNSBypassRule{
			CIDR:   cidr.String(),
			DNSIPs: customDNS,
		})
	}
	dnsBypassRules, _ = NormalizeDNSBypassRules(dnsBypassRules)

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
	if len(customDNS) > 0 {
		plain = append(plain, fmt.Sprintf("DHCP 下发指定 DNS：%s（已自动放行跨网段 53 端口并豁免本机 DNS 劫持）", strings.Join(customDNS, ", ")))
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
	switch req.ProxyMode {
	case ProxyModeSideRouter:
		plain = append(plain, fmt.Sprintf("上网方式：交由旁路由 (%s) 透明分流与 DNS 解析（内网设备保持隔离，旁路由离线自动回退主路由直连）", ov.SideRouterIP))
	case ProxyModeDirect:
		plain = append(plain, "上网方式：纯直连绕过透明代理（不消耗代理流量，不误伤国内智能家居）")
	default:
		plain = append(plain, "上网方式：跟随主路由工作模式转发")
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
	return &PreviewResult{
		Valid:             true,
		PlainSummary:      plain,
		UCICommands:       cmds,
		ProxyBypassCIDRs:  bypassCIDRs,
		DNSBypassRules:    dnsBypassRules,
		SideRouteSpec:     VLANSideRouteSpec{SideRouterIP: ov.SideRouterIP, CIDRs: sideCIDRs},
		UpstreamRouteHint: routeHint,
	}, nil
}
