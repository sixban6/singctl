// 文件职责：负责上游光猫与 WAN 接入形态探测、厂商被动指纹识别及 OpenWrt PPPoE 桥接光猫免插线辅助接口托管。
package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
	"singctl/internal/platform/servicemgr"
)

const (
	// DefaultModemConsolePort 为按需启动的上游光猫反向代理控制台默认端口。
	DefaultModemConsolePort = 8091
	// ModemBridgeUCISection 为 OpenWrt PPPoE 桥接访问光猫独立静态接口 UCI 名称。
	ModemBridgeUCISection = "singctl_modem"

	ModemAccessRouterNAT   = "router_nat"
	ModemAccessPPPoEBridge = "pppoe_bridge"
	ModemAccessSideViaMain = "side_via_main"
	ModemAccessUnknown     = "unknown"

	WANExitPublic  = "public"
	WANExitCGNAT   = "cgnat"
	WANExitPrivate = "private"
	WANExitUnknown = "unknown"

	DeviceKindModem   = "modem"
	DeviceKindRouter  = "router"
	DeviceKindUnknown = "unknown"
)

var (
	cgnatIPv4Prefix      = netip.MustParsePrefix("100.64.0.0/10")
	defaultModemIPOrder  = []string{"192.168.1.1", "192.168.100.1", "192.168.3.1", "192.168.2.1", "192.168.0.1"}
	defaultModemHTTPList = []struct {
		scheme string
		port   int
	}{
		{"http", 80},
		{"https", 443},
		{"http", 8080},
	}
)

// ModemDeps 显式注入光猫探测与桥接接口托管依赖（nil 自动回退生产实现）。
type ModemDeps struct {
	IsOpenWrt    func() bool
	HasCommand   func(string) bool
	RunCmd       func(ctx context.Context, name string, args ...string) ([]byte, error)
	LocalSubnets func() []netip.Prefix
	TraceHops    func(ctx context.Context) []string
	HTTPProbe    func(ctx context.Context, scheme, ip string, port int) (statusCode int, headers http.Header, bodySnippet string, latencyMs int, err error)
	ServiceMgr   servicemgr.Manager
}

// ModemHopInfo 描述探测到的单跳上游私网网关设备。
type ModemHopInfo struct {
	Hop        int    `json:"hop"`
	IP         string `json:"ip"`
	DeviceKind string `json:"deviceKind"`
	VendorHint string `json:"vendorHint,omitempty"`
	Online     bool   `json:"online"`
}

// ModemStatus 描述上游光猫与宽带 WAN 接入探测结果。
type ModemStatus struct {
	Supported           bool           `json:"supported"`
	IsOpenWrt           bool           `json:"isOpenWrt"`
	GatewayRole         string         `json:"gatewayRole"`
	AccessMode          string         `json:"accessMode"`
	WANProto            string         `json:"wanProto,omitempty"`
	WANIface            string         `json:"wanIface,omitempty"`
	WANPhysDevice       string         `json:"wanPhysDevice,omitempty"`
	WANIP               string         `json:"wanIp,omitempty"`
	WANExitType         string         `json:"wanExitType"`
	ConfiguredModemIP   string         `json:"configuredModemIp,omitempty"`
	DetectedModemIP     string         `json:"detectedModemIp,omitempty"`
	EffectiveModemIP    string         `json:"effectiveModemIp,omitempty"`
	CandidateIPs        []string       `json:"candidateIps,omitempty"`
	Online              bool           `json:"online"`
	Scheme              string         `json:"scheme,omitempty"`
	Port                int            `json:"port,omitempty"`
	AdminPort           int            `json:"adminPort,omitempty"`
	LatencyMs           int            `json:"latencyMs,omitempty"`
	DeviceKind          string         `json:"deviceKind,omitempty"`
	VendorHint          string         `json:"vendorHint,omitempty"`
	NATLayers           int            `json:"natLayers,omitempty"`
	UpstreamHops        []ModemHopInfo `json:"upstreamHops,omitempty"`
	BridgeHelperCapable bool           `json:"bridgeHelperCapable"`
	BridgeHelperEnabled bool           `json:"bridgeHelperEnabled"`
	BridgeHelperIP      string         `json:"bridgeHelperIp,omitempty"`
	SubnetConflict      string         `json:"subnetConflict,omitempty"`
	DoubleNATHint       string         `json:"doubleNatHint,omitempty"`
}

type resolvedModemDeps struct {
	isOpenWrt    func() bool
	hasCommand   func(string) bool
	runCmd       func(ctx context.Context, name string, args ...string) ([]byte, error)
	localSubnets func() []netip.Prefix
	traceHops    func(ctx context.Context) []string
	httpProbe    func(ctx context.Context, scheme, ip string, port int) (int, http.Header, string, int, error)
	serviceMgr   servicemgr.Manager
}

func (d ModemDeps) resolve() resolvedModemDeps {
	isOW := d.IsOpenWrt
	if isOW == nil {
		isOW = isOpenWrtSystem
	}
	hasCmd := d.HasCommand
	if hasCmd == nil {
		if d.RunCmd != nil {
			hasCmd = func(string) bool { return true }
		} else {
			hasCmd = func(name string) bool {
				_, err := exec.LookPath(name)
				return err == nil
			}
		}
	}
	runCmd := d.RunCmd
	if runCmd == nil {
		runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	localSubnets := d.LocalSubnets
	if localSubnets == nil {
		localSubnets = defaultLocalLANSubnets
	}
	httpProbe := d.HTTPProbe
	if httpProbe == nil {
		httpProbe = defaultModemHTTPProbe
	}
	mgr := d.ServiceMgr
	if mgr == nil {
		if d.RunCmd == nil && runtime.GOOS == "linux" {
			mgr = servicemgr.Detect(nil)
		} else {
			mgr = servicemgr.NewNoop()
		}
	}
	traceHops := d.TraceHops
	if traceHops == nil {
		traceHops = func(c context.Context) []string {
			return defaultTracePrivateHops(c, hasCmd, runCmd)
		}
	}
	return resolvedModemDeps{
		isOpenWrt:    isOW,
		hasCommand:   hasCmd,
		runCmd:       runCmd,
		localSubnets: localSubnets,
		traceHops:    traceHops,
		httpProbe:    httpProbe,
		serviceMgr:   mgr,
	}
}

// ValidateModemIP 校验自定义上游光猫 IPv4 地址（留空表示自动探测；仅允许 RFC1918 私网单播 IP 且禁止本机/冲突地址）。
func ValidateModemIP(rawIP string, disallowIPs ...string) (string, error) {
	trimmed := strings.TrimSpace(rawIP)
	if trimmed == "" {
		return "", nil
	}
	for i := range len(trimmed) {
		c := trimmed[i]
		if c < 0x20 || c == 0x7f {
			return "", errors.New("光猫 IP 地址包含非法控制字符")
		}
	}
	if strings.ContainsAny(trimmed, ";`$|&<> \t") {
		return "", fmt.Errorf("光猫 IP 地址 %q 包含非法字符", trimmed)
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("光猫 IP %q 格式无效（必须为合法的 IPv4 地址）", trimmed)
	}
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.String() == "255.255.255.255" {
		return "", fmt.Errorf("光猫 IP %q 不能为回环、组播或广播地址", trimmed)
	}
	if cgnatIPv4Prefix.Contains(addr) || !isRFC1918Private(addr) {
		return "", fmt.Errorf("光猫 IP %q 必须为局域网私网 IPv4 地址（192.168.x.x / 10.x.x.x / 172.16-31.x.x）", trimmed)
	}
	for _, dis := range disallowIPs {
		if d := strings.TrimSpace(dis); d != "" && d == addr.String() {
			return "", fmt.Errorf("光猫 IP 不能等于本机或主/旁路由网关地址 (%s)", d)
		}
	}
	return addr.String(), nil
}

type wanProbeSummary struct {
	up         bool
	proto      string
	iface      string
	physDevice string
	ip         string
	gatewayIP  string
}

func inspectWAN(ctx context.Context, d resolvedModemDeps) wanProbeSummary {
	var res wanProbeSummary
	if d.hasCommand("ifstatus") {
		if out, err := d.runCmd(ctx, "ifstatus", "wan"); err == nil && len(out) > 0 {
			var parsed struct {
				Up          bool   `json:"up"`
				Proto       string `json:"proto"`
				Device      string `json:"device"`
				L3Device    string `json:"l3_device"`
				IPv4Address []struct {
					Address string `json:"address"`
				} `json:"ipv4-address"`
				Route []struct {
					Target  string `json:"target"`
					Mask    int    `json:"mask"`
					Nexthop string `json:"nexthop"`
				} `json:"route"`
			}
			if jErr := json.Unmarshal(out, &parsed); jErr == nil {
				res.up = parsed.Up
				res.proto = strings.ToLower(strings.TrimSpace(parsed.Proto))
				res.physDevice = strings.TrimSpace(parsed.Device)
				res.iface = cmp.Or(strings.TrimSpace(parsed.L3Device), res.physDevice)
				if len(parsed.IPv4Address) > 0 {
					res.ip = strings.TrimSpace(parsed.IPv4Address[0].Address)
				}
				for _, rt := range parsed.Route {
					if rt.Target == "0.0.0.0" && rt.Mask == 0 && rt.Nexthop != "" {
						res.gatewayIP = strings.TrimSpace(rt.Nexthop)
						break
					}
				}
			}
		}
	}
	if d.hasCommand("uci") && d.isOpenWrt() {
		if res.proto == "" {
			if p, ok := uciGetTrimmed(ctx, d.runCmd, "network.wan.proto"); ok {
				res.proto = strings.ToLower(p)
			}
		}
		if res.physDevice == "" {
			if dev, ok := uciGetTrimmed(ctx, d.runCmd, "network.wan.device"); ok && dev != "" {
				res.physDevice = dev
			} else if ifn, ok := uciGetTrimmed(ctx, d.runCmd, "network.wan.ifname"); ok && ifn != "" {
				res.physDevice = ifn
			}
		}
		if res.iface == "" {
			if res.proto == "pppoe" {
				res.iface = "pppoe-wan"
			} else {
				res.iface = res.physDevice
			}
		}
	}
	return res
}

func classifyWANExit(ipStr string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil || !addr.Is4() {
		return WANExitUnknown
	}
	if isRFC1918Private(addr) {
		return WANExitPrivate
	}
	if cgnatIPv4Prefix.Contains(addr) {
		return WANExitCGNAT
	}
	return WANExitPublic
}

func defaultLocalLANSubnets() []netip.Prefix {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		lower := strings.ToLower(ifi.Name)
		if isVirtualTunnelIface(ifi.Name) || strings.Contains(lower, "pppoe") || lower == "eth0.2" {
			continue
		}
		addrs, aErr := ifi.Addrs()
		if aErr != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet == nil {
				continue
			}
			v4 := ipNet.IP.To4()
			if v4 == nil {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones <= 0 {
				continue
			}
			addr, pErr := netip.ParseAddr(v4.String())
			if pErr != nil || !isRFC1918Private(addr) {
				continue
			}
			out = append(out, netip.PrefixFrom(addr, ones).Masked())
		}
	}
	return out
}

type probeEndpointResult struct {
	ip         string
	scheme     string
	port       int
	adminPort  int
	latencyMs  int
	deviceKind string
	vendorHint string
	online     bool
}

func probeSingleModemIP(ctx context.Context, ip string, probe func(context.Context, string, string, int) (int, http.Header, string, int, error)) probeEndpointResult {
	for _, ep := range defaultModemHTTPList {
		code, hdrs, body, ms, err := probe(ctx, ep.scheme, ip, ep.port)
		if err != nil || code <= 0 {
			continue
		}
		kind, hint := ClassifyGatewayEndpoint(hdrs, body)
		res := probeEndpointResult{
			ip:         ip,
			scheme:     ep.scheme,
			port:       ep.port,
			latencyMs:  ms,
			deviceKind: kind,
			vendorHint: hint,
			online:     true,
		}
		if ep.port != 8080 {
			adminCtx, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
			aCode, aHdrs, aBody, _, aErr := probe(adminCtx, "http", ip, 8080)
			cancel()
			if aErr == nil && aCode > 0 {
				res.adminPort = 8080
				aKind, aHint := ClassifyGatewayEndpoint(aHdrs, aBody)
				if res.deviceKind != DeviceKindModem && aKind == DeviceKindModem {
					res.deviceKind = aKind
					res.vendorHint = aHint
				}
			}
		}
		return res
	}
	return probeEndpointResult{ip: ip, deviceKind: DeviceKindUnknown}
}

func findSubnetConflictMessage(modemIP string, subnets []netip.Prefix) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(modemIP))
	if err != nil || !addr.Is4() {
		return ""
	}
	for _, pfx := range subnets {
		if pfx.Addr().Is4() && pfx.Contains(addr) {
			return fmt.Sprintf("光猫地址 %s 与本机局域网网段 %s 冲突；如需桥接免插线访问，请先修改光猫或本机 LAN 网段避免重叠", addr.String(), pfx.String())
		}
	}
	return ""
}

// ProbeModemStatus 按需探测宽带 WAN 接入方式、多跳上级链路、真光猫指纹及 PPPoE 桥接可打通状态。
func ProbeModemStatus(ctx context.Context, gwCfg config.GatewayConfig, topo TopologyInfo, deps ModemDeps) ModemStatus {
	if ctx == nil {
		ctx = context.Background()
	}
	d := deps.resolve()
	role := gwCfg.EffectiveMode()
	configured := strings.TrimSpace(gwCfg.ModemIP)
	isOW := d.isOpenWrt()

	st := ModemStatus{
		Supported:         isOW || d.hasCommand("ip") || runtime.GOOS == "linux",
		IsOpenWrt:         isOW,
		GatewayRole:       role,
		AccessMode:        ModemAccessUnknown,
		WANExitType:       WANExitUnknown,
		ConfiguredModemIP: configured,
		DeviceKind:        DeviceKindUnknown,
	}

	var wan wanProbeSummary
	if role == ModeMain {
		wan = inspectWAN(ctx, d)
		st.WANProto = wan.proto
		st.WANIface = wan.iface
		st.WANPhysDevice = wan.physDevice
		st.WANIP = wan.ip
		st.WANExitType = classifyWANExit(wan.ip)
	}

	// 识别接入拓扑形态
	firstHopGW := ""
	switch {
	case role == ModeSide:
		st.AccessMode = ModemAccessSideViaMain
	case wan.proto == "pppoe":
		st.AccessMode = ModemAccessPPPoEBridge
		st.NATLayers = 1
		st.BridgeHelperCapable = isOW && d.hasCommand("uci") && wan.physDevice != ""
	case wan.gatewayIP != "" && isRFC1918AddrStr(wan.gatewayIP) && wan.gatewayIP != topo.LANIP:
		st.AccessMode = ModemAccessRouterNAT
		firstHopGW = wan.gatewayIP
	case topo.CurrentGatewayIP != "" && isRFC1918AddrStr(topo.CurrentGatewayIP) && topo.CurrentGatewayIP != topo.LANIP:
		st.AccessMode = ModemAccessRouterNAT
		firstHopGW = topo.CurrentGatewayIP
	}

	// 读取桥接免插线接口状态
	if isOW && d.hasCommand("uci") {
		if helperIP, ok := uciGetTrimmed(ctx, d.runCmd, "network."+ModemBridgeUCISection+".ipaddr"); ok && helperIP != "" {
			st.BridgeHelperEnabled = true
			st.BridgeHelperIP = helperIP
		}
	}

	// 追踪进入公网前的多跳私网网关链（PPPoE 桥接模式无私网中间跳，跳过 traceroute 耗时）
	var tracedHops []string
	if wan.proto != "pppoe" {
		for _, ip := range d.traceHops(ctx) {
			if ip == topo.LANIP || ip == strings.TrimSpace(gwCfg.MainRouterIP) || ip == strings.TrimSpace(gwCfg.SideRouterIP) {
				continue
			}
			if !slices.Contains(tracedHops, ip) {
				tracedHops = append(tracedHops, ip)
			}
		}
	}
	if len(tracedHops) == 0 && firstHopGW != "" {
		tracedHops = []string{firstHopGW}
	}

	// 构建候选光猫 IP 列表（先排除本机 LAN / 主旁路由自身 IP）
	lanPrefix, _ := netip.ParsePrefix(strings.TrimSpace(topo.LANCIDR))
	var candidates []string
	addCand := func(raw string, checkLANOverlap bool) {
		s := strings.TrimSpace(raw)
		if s == "" || slices.Contains(candidates, s) {
			return
		}
		if s == topo.LANIP || s == strings.TrimSpace(gwCfg.MainRouterIP) || s == strings.TrimSpace(gwCfg.SideRouterIP) {
			return
		}
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() || !isRFC1918Private(addr) {
			return
		}
		if checkLANOverlap && lanPrefix.IsValid() && lanPrefix.Contains(addr) {
			return
		}
		candidates = append(candidates, s)
	}

	addCand(configured, false)
	for _, h := range tracedHops {
		addCand(h, false)
	}
	addCand(firstHopGW, false)
	for _, def := range defaultModemIPOrder {
		addCand(def, true)
	}
	st.CandidateIPs = candidates

	// 选择并发探测列表：有明确私网跳时同时探测所有跳数（用于构建路由链 + 识别真光猫）；无私网跳且手动配置时优先只探配置项
	probeTargets := candidates
	if len(tracedHops) == 0 && configured != "" {
		probeTargets = []string{configured}
	} else if st.AccessMode == ModemAccessPPPoEBridge && configured != "" {
		probeTargets = []string{configured}
	}

	resultByIP := make(map[string]probeEndpointResult, len(probeTargets))
	if len(probeTargets) > 0 {
		results := make([]probeEndpointResult, len(probeTargets))
		var wg sync.WaitGroup
		for i, ip := range probeTargets {
			wg.Go(func() {
				pCtx, cancel := context.WithTimeout(ctx, 1800*time.Millisecond)
				defer cancel()
				results[i] = probeSingleModemIP(pCtx, ip, d.httpProbe)
			})
		}
		wg.Wait()

		for _, r := range results {
			resultByIP[r.ip] = r
		}
	}

	for i, hopIP := range tracedHops {
		r := resultByIP[hopIP]
		kind := cmp.Or(r.deviceKind, DeviceKindUnknown)
		st.UpstreamHops = append(st.UpstreamHops, ModemHopInfo{
			Hop:        i + 1,
			IP:         hopIP,
			DeviceKind: kind,
			VendorHint: r.vendorHint,
			Online:     r.online,
		})
	}
	if st.AccessMode == ModemAccessRouterNAT {
		st.NATLayers = 1 + max(1, len(st.UpstreamHops))
	}

	// 选择最优光猫 IP（优先识别确认的真光猫且优先外层跳，自动越过中间家用路由器）
	detected := selectBestModemIP(tracedHops, candidates, resultByIP, firstHopGW)
	st.DetectedModemIP = detected
	st.EffectiveModemIP = cmp.Or(configured, detected)

	if effRes, ok := resultByIP[st.EffectiveModemIP]; ok && effRes.online {
		st.Online = true
		st.Scheme = effRes.scheme
		st.Port = effRes.port
		st.AdminPort = effRes.adminPort
		st.LatencyMs = effRes.latencyMs
		st.DeviceKind = effRes.deviceKind
		st.VendorHint = effRes.vendorHint
	}

	if st.AccessMode == ModemAccessRouterNAT {
		st.DoubleNATHint = buildMultiNATHint(st.NATLayers, st.UpstreamHops, st.EffectiveModemIP, resultByIP)
	}

	if st.EffectiveModemIP != "" && (st.AccessMode == ModemAccessPPPoEBridge || st.BridgeHelperEnabled) {
		subnets := d.localSubnets()
		if len(subnets) == 0 && lanPrefix.IsValid() {
			subnets = []netip.Prefix{lanPrefix.Masked()}
		}
		st.SubnetConflict = findSubnetConflictMessage(st.EffectiveModemIP, subnets)
	}

	return st
}

func selectBestModemIP(tracedHops, candidates []string, resMap map[string]probeEndpointResult, fallbackGW string) string {
	// 外层跳优先序（倒序 traceroute 私网跳） + 其余候选 IP
	ordered := make([]string, 0, len(candidates))
	for i := len(tracedHops) - 1; i >= 0; i-- {
		if !slices.Contains(ordered, tracedHops[i]) {
			ordered = append(ordered, tracedHops[i])
		}
	}
	for _, c := range candidates {
		if !slices.Contains(ordered, c) {
			ordered = append(ordered, c)
		}
	}

	for _, ip := range ordered {
		if r, ok := resMap[ip]; ok && r.online && r.deviceKind == DeviceKindModem {
			return ip
		}
	}
	for i := len(tracedHops) - 1; i >= 0; i-- {
		ip := tracedHops[i]
		if r, ok := resMap[ip]; ok && r.online && r.deviceKind != DeviceKindRouter {
			return ip
		}
	}
	for _, ip := range ordered {
		if r, ok := resMap[ip]; ok && r.online && r.deviceKind != DeviceKindRouter {
			return ip
		}
	}
	for _, ip := range ordered {
		if r, ok := resMap[ip]; ok && r.online {
			return ip
		}
	}
	if len(tracedHops) > 0 {
		return tracedHops[len(tracedHops)-1]
	}
	return fallbackGW
}

func buildMultiNATHint(natLayers int, hops []ModemHopInfo, effectiveIP string, resMap map[string]probeEndpointResult) string {
	if natLayers >= 3 && len(hops) >= 2 {
		parts := make([]string, 0, len(hops))
		for _, h := range hops {
			desc := h.IP
			if h.VendorHint != "" {
				desc += " (" + h.VendorHint + ")"
			}
			parts = append(parts, desc)
		}
		effRes := resMap[effectiveIP]
		if effRes.deviceKind == DeviceKindModem {
			return fmt.Sprintf("检测到三层 NAT 串联（本机 → %s），已自动跳过中间路由器并直连最外层真光猫 %s；多层 NAT 会降低 Tailscale P2P 打洞率并阻断 IPv6-PD，建议精简中间路由或将光猫改为桥接。", strings.Join(parts, " → "), effectiveIP)
		}
		return fmt.Sprintf("检测到三层 NAT 串联（本机 → %s），当前外层网关为 %s；多层 NAT 可能影响 Tailscale P2P 与 IPv6-PD。", strings.Join(parts, " → "), effectiveIP)
	}
	if effRes, ok := resMap[effectiveIP]; ok && effRes.deviceKind == DeviceKindRouter {
		return fmt.Sprintf("当前第 1 跳网关 %s 识别为「%s」（双层 NAT），暂未发现更外层路由跳数；如果上方还有真实光猫（例如 192.168.1.1），可手动填写其 IP 直连。", effectiveIP, cmp.Or(effRes.vendorHint, "上级路由器"))
	}
	return "当前由上游光猫进行路由拨号（双层 NAT），可能影响 Tailscale P2P 打洞与 IPv6-PD 前缀下发；可在下方直接登录光猫改为桥接或开启 DMZ。"
}

func isRFC1918AddrStr(raw string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	return err == nil && addr.Is4() && isRFC1918Private(addr)
}

func deriveHelperIPForModem(modemAddr netip.Addr) string {
	o := modemAddr.As4()
	hostOctet := byte(254)
	if o[3] == 254 {
		hostOctet = 253
	}
	return netip.AddrFrom4([4]byte{o[0], o[1], o[2], hostOctet}).String()
}

// ApplyModemBridgeHelper 在 OpenWrt 主路由 PPPoE 桥接模式下安全挂载或移除 WAN 物理口旁路管理接口（defaultroute=0）。
func ApplyModemBridgeHelper(ctx context.Context, enable bool, modemIP string, topo TopologyInfo, deps ModemDeps) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	d := deps.resolve()
	if !d.isOpenWrt() || !d.hasCommand("uci") {
		return "", errors.New("仅支持 OpenWrt / ImmortalWrt 宿主机自动挂载桥接光猫访问接口")
	}

	if !enable {
		if d.hasCommand("ifdown") {
			_, _ = d.runCmd(ctx, "ifdown", ModemBridgeUCISection)
		}
		_, _ = d.runCmd(ctx, "uci", "-q", "delete", "network."+ModemBridgeUCISection)
		_ = runUCICommand(ctx, d.runCmd, "commit", "network")
		if wanZone, ok := findFirewallZoneSection(ctx, d.runCmd, "wan"); ok {
			_, _ = d.runCmd(ctx, "uci", "-q", "del_list", fmt.Sprintf("firewall.%s.network=%s", wanZone, ModemBridgeUCISection))
			_ = runUCICommand(ctx, d.runCmd, "commit", "firewall")
		}
		if _, rErr := reloadFirewallModemSoftly(ctx, d); rErr != nil {
			return "", rErr
		}
		return "已移除 PPPoE 桥接光猫直通接口并恢复原状（WAN 拨号零中断）", nil
	}

	validModem, err := ValidateModemIP(modemIP, topo.LANIP)
	if err != nil {
		return "", err
	}
	if validModem == "" {
		return "", errors.New("请先指定要访问的桥接光猫 IPv4 地址（例如 192.168.1.1 或 192.168.100.1）")
	}

	wan := inspectWAN(ctx, d)
	if wan.proto != "pppoe" {
		return "", fmt.Errorf("当前 WAN 口协议为 %q（非 PPPoE 桥接拨号），无需配置桥接访问辅助接口", cmp.Or(wan.proto, "未知"))
	}
	if wan.physDevice == "" {
		return "", errors.New("未探测到 WAN 物理网卡名，无法挂载桥接光猫访问接口")
	}

	subnets := d.localSubnets()
	if len(subnets) == 0 {
		if pfx, pErr := netip.ParsePrefix(strings.TrimSpace(topo.LANCIDR)); pErr == nil {
			subnets = []netip.Prefix{pfx.Masked()}
		}
	}
	if conflict := findSubnetConflictMessage(validModem, subnets); conflict != "" {
		return "", errors.New(conflict)
	}

	modemAddr := netip.MustParseAddr(validModem)
	helperIP := deriveHelperIPForModem(modemAddr)

	uciSteps := [][]string{
		{"set", "network." + ModemBridgeUCISection + "=interface"},
		{"set", "network." + ModemBridgeUCISection + ".proto=static"},
		{"set", "network." + ModemBridgeUCISection + ".device=" + wan.physDevice},
		{"set", "network." + ModemBridgeUCISection + ".ipaddr=" + helperIP},
		{"set", "network." + ModemBridgeUCISection + ".netmask=255.255.255.0"},
		{"set", "network." + ModemBridgeUCISection + ".defaultroute=0"},
		{"set", "network." + ModemBridgeUCISection + ".peerdns=0"},
		{"commit", "network"},
	}
	for _, args := range uciSteps {
		if uErr := runUCICommand(ctx, d.runCmd, args...); uErr != nil {
			return "", uErr
		}
	}

	if wanZone, ok := findFirewallZoneSection(ctx, d.runCmd, "wan"); ok {
		netList, _ := uciGetTrimmed(ctx, d.runCmd, fmt.Sprintf("firewall.%s.network", wanZone))
		if !slices.Contains(strings.Fields(netList), ModemBridgeUCISection) {
			if aErr := runUCICommand(ctx, d.runCmd, "add_list", fmt.Sprintf("firewall.%s.network=%s", wanZone, ModemBridgeUCISection)); aErr != nil {
				return "", aErr
			}
			if cErr := runUCICommand(ctx, d.runCmd, "commit", "firewall"); cErr != nil {
				return "", cErr
			}
		}
	}

	if d.hasCommand("ifup") {
		_, _ = d.runCmd(ctx, "ifup", ModemBridgeUCISection)
	}
	if _, rErr := reloadFirewallModemSoftly(ctx, d); rErr != nil {
		return "", rErr
	}

	return fmt.Sprintf("已挂载桥接光猫直通接口 (%s @ %s -> %s，defaultroute=0 不干扰宽带拨号)", wan.physDevice, helperIP, validModem), nil
}

func findFirewallZoneSection(ctx context.Context, runCmd func(context.Context, string, ...string) ([]byte, error), targetName string) (string, bool) {
	for i := range 8 {
		sec := fmt.Sprintf("@zone[%d]", i)
		val, ok := uciGetTrimmed(ctx, runCmd, "firewall."+sec+".name")
		if ok && strings.EqualFold(val, targetName) {
			return sec, true
		}
	}
	return "", false
}

func reloadFirewallModemSoftly(ctx context.Context, d resolvedModemDeps) (string, error) {
	if d.hasCommand("fw4") {
		if out, err := d.runCmd(ctx, "fw4", "reload"); err != nil {
			return "", fmt.Errorf("fw4 reload 失败: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return "fw4 reload", nil
	}
	if err := d.serviceMgr.Reload(ctx, "firewall"); err != nil {
		return "", fmt.Errorf("重载 firewall 服务失败: %w", err)
	}
	return "firewall reload", nil
}
