package gateway

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"singctl/internal/config"
)

const (
	ModeMain = "main"
	ModeSide = "side"
)

var validIfaceNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,32}$`)

// TopologyInfo 描述本机探测到的局域网接口、地址与上级网关状态。
type TopologyInfo struct {
	LANIP                 string `json:"lanIP"`
	LANCIDR               string `json:"lanCIDR"`
	HostPrefix            string `json:"hostPrefix,omitempty"`
	LANIface              string `json:"lanIface"`
	CurrentGatewayIP      string `json:"currentGatewayIP"`
	SuggestedMainRouterIP string `json:"suggestedMainRouterIP"`
	SelfLooped            bool   `json:"selfLooped"`
	HasLocalDNSListener   bool   `json:"hasLocalDNSListener,omitempty"`
}

// ResolvedPlan 表示校验通过后的网关执行计划。
type ResolvedPlan struct {
	Mode              string
	MainRouterIP      string
	LANIP             string
	LANCIDR           string
	LANIface          string
	InterceptLocalDNS bool
}

// SysctlKV 表示单条内核运行参数键值。
type SysctlKV struct {
	Key   string
	Value string
}

// ResolveAndValidate 校验客户端网关配置并结合探测拓扑补全执行参数。
// 仅允许 "main"（默认）与 "side" 两种显式模式，拒绝隐式 "auto" 或非法注入参数。
func ResolveAndValidate(cfg config.GatewayConfig, topo TopologyInfo) (ResolvedPlan, error) {
	rawMode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch rawMode {
	case "", ModeMain:
		return ResolvedPlan{Mode: ModeMain}, nil
	case ModeSide:
	default:
		return ResolvedPlan{}, fmt.Errorf("无效的 gateway.mode %q（仅支持 \"main\" 或 \"side\"）", cfg.Mode)
	}

	gwRaw := strings.TrimSpace(cfg.MainRouterIP)
	if gwRaw == "" {
		return ResolvedPlan{}, errors.New("旁路由模式必须指定上级主路由(网关) IP (gateway.main_router_ip)")
	}

	gwAddr, err := netip.ParseAddr(gwRaw)
	if err != nil || !gwAddr.Is4() {
		return ResolvedPlan{}, fmt.Errorf("上级主路由 IP %q 格式无效（必须为合法 IPv4 单播地址）", gwRaw)
	}
	if gwAddr.IsLoopback() || gwAddr.IsMulticast() || gwAddr.IsUnspecified() || gwAddr.String() == "255.255.255.255" {
		return ResolvedPlan{}, fmt.Errorf("上级主路由 IP %q 不能为回环、组播或广播地址", gwRaw)
	}

	lanIP := strings.TrimSpace(topo.LANIP)
	if lanIP != "" && gwAddr.String() == lanIP {
		return ResolvedPlan{}, fmt.Errorf("上级主路由 IP 不能等于旁路由本机 IP (%s)，否则会导致路由死循环", lanIP)
	}

	iface := cmp.Or(strings.TrimSpace(cfg.LANIface), strings.TrimSpace(topo.LANIface))
	if iface != "" && !validIfaceNameRe.MatchString(iface) {
		return ResolvedPlan{}, fmt.Errorf("非法的局域网网卡名称 %q", iface)
	}

	lanCIDR := strings.TrimSpace(topo.LANCIDR)
	if lanCIDR != "" {
		pfx, pErr := netip.ParsePrefix(lanCIDR)
		if pErr != nil || !pfx.Addr().Is4() {
			return ResolvedPlan{}, fmt.Errorf("非法的局域网网段 %q", lanCIDR)
		}
		lanCIDR = pfx.Masked().String()
	} else {
		lanCIDR = netip.PrefixFrom(gwAddr, 24).Masked().String()
	}

	return ResolvedPlan{
		Mode:              ModeSide,
		MainRouterIP:      gwAddr.String(),
		LANIP:             lanIP,
		LANCIDR:           lanCIDR,
		LANIface:          iface,
		InterceptLocalDNS: !topo.HasLocalDNSListener,
	}, nil
}
