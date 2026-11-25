// 文件职责：定义零外部依赖 AF_NETLINK/NETLINK_ROUTE 契约接口、跨平台数据类型、标准前缀常量与纯二进制 RTNETLINK 报文解析器。
package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// ErrUnsupportedPlatform 在非 Linux 平台调用生产 Netlink 客户端时返回。
var ErrUnsupportedPlatform = errors.New("rtnl: AF_NETLINK is only supported on Linux")

// Linux RTNETLINK Wire ABI 常量（跨平台共享解析逻辑，避免非 Linux 编译受限于 unix.* 条件常量）。
const (
	afUnspec = 0
	afInet   = 2
	afInet6  = 10

	nlmsgNoop  = 1
	nlmsgError = 2
	nlmsgDone  = 3

	nlmFMulti = 0x2

	rtmNewLink  = 16
	rtmNewAddr  = 20
	rtmNewRoute = 24
	rtmNewNeigh = 28
	rtmNewRule  = 32

	iffUp       = 0x1
	iffLoopback = 0x8

	iflaIfname = 3

	ifaAddress = 1
	ifaLocal   = 2
	ifaFlags   = 8

	ifaFDeprecated = 0x20
	ifaFDadFailed  = 0x8
	ifaFTentative  = 0x40
	ifaFTemporary  = 0x1

	nudIncomplete = 0x01
	nudFailed     = 0x20
	nudNoarp      = 0x40

	ndaDst    = 1
	ndaLladdr = 2

	rtaDst      = 1
	rtaOif      = 4
	rtaGateway  = 5
	rtaPriority = 6
	rtaTable    = 15

	fraIifname  = 3
	fraPriority = 6
	fraFwmark   = 10
	fraTable    = 15
	fraFwmask   = 16

	rtTableMain = 254

	rtnUnicast = 1
	rtnLocal   = 2
	rtnThrow   = 9
)

// NeighborEntry 表示内核邻居表（ARP / NDP）中的单条 IP -> MAC 映射。
type NeighborEntry struct {
	IP      netip.Addr
	MAC     string
	IfIndex int
	State   uint16
}

// LinkInfo 描述内核网络接口基础状态与索引映射。
type LinkInfo struct {
	Index  int
	Name   string
	IsUp   bool
	IsLoop bool
}

// InterfaceAddr 表示网卡绑定的单条单播地址与接口状态。
type InterfaceAddr struct {
	IfIndex int
	IfName  string
	IsUp    bool
	IsLoop  bool
	Flags   uint32
	Scope   uint8
	Prefix  netip.Prefix
}

// DefaultRoute 表示主路由表中的默认网关信息。
type DefaultRoute struct {
	Family   int // 4 或 6
	Gateway  netip.Addr
	IfIndex  int
	IfName   string
	Priority uint32
}

// RuleSpec 表示内核策略路由（FIB Rule）关键字段。
type RuleSpec struct {
	Family   int // 4 或 6
	Priority uint32
	Mark     uint32
	Mask     uint32
	IifName  string
	Table    int
}

// TProxyRouteSpec 声明透明代理所需的双栈策略路由表与逃生网段规格。
type TProxyRouteSpec struct {
	ForwardFwMark   uint32         // 默认 0x1
	ForwardTable    int            // 默认 100
	LocalFwMark     uint32         // 默认 0x2
	LocalTable      int            // 默认 101
	EnableIPv6      bool
	ThrowV4Prefixes []netip.Prefix
	ThrowV6Prefixes []netip.Prefix
}

// Client 定义零子进程的内核路由、地址与邻居表操作契约。
type Client interface {
	ListAddresses() ([]InterfaceAddr, error)
	ListNeighbors(family int) ([]NeighborEntry, error)
	GetDefaultRoute(family int) (DefaultRoute, bool, error)
	ReplaceDefaultRoute(family int, gw netip.Addr, ifName string) error
	HasRouteTableLocal(family int, table int) (bool, error)
	EnsureThrowRoutes(family int, table int, prefixes []netip.Prefix) error
	ReconcileTProxyRoutes(spec TProxyRouteSpec) error
	CleanupTProxyRoutes(tables ...int) error
}

// Default 返回当前操作系统的默认 rtnl.Client 实现。
func Default() Client {
	return newDefaultClient()
}

var (
	defaultThrowV4Strings = []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	defaultThrowV6Strings = []string{
		"::1/128",
		"fc00::/7",
		"fe80::/10",
		"fd7a:115c:a1e0::/48",
		"ff00::/8",
	}
)

// DefaultThrowV4Prefixes 返回避免 TProxy 表 100 触发 src_valid_mark=1 martian 丢包的 IPv4 逃生前缀副本。
func DefaultThrowV4Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(defaultThrowV4Strings))
	for _, s := range defaultThrowV4Strings {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// DefaultThrowV6Prefixes 返回透明代理 IPv6 表 100 默认直连逃生前缀副本。
func DefaultThrowV6Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(defaultThrowV6Strings))
	for _, s := range defaultThrowV6Strings {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func align4(n int) int {
	return (n + 3) &^ 3
}

type rawNLMsg struct {
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
	Body  []byte
}

func splitNLMsgs(raw []byte) ([]rawNLMsg, error) {
	var msgs []rawNLMsg
	off := 0
	for off+16 <= len(raw) {
		msgLen := int(binary.NativeEndian.Uint32(raw[off : off+4]))
		if msgLen < 16 || off+msgLen > len(raw) {
			break
		}
		typ := binary.NativeEndian.Uint16(raw[off+4 : off+6])
		flags := binary.NativeEndian.Uint16(raw[off+6 : off+8])
		seq := binary.NativeEndian.Uint32(raw[off+8 : off+12])
		pid := binary.NativeEndian.Uint32(raw[off+12 : off+16])
		if typ == nlmsgDone {
			break
		}
		if typ == nlmsgNoop {
			off += align4(msgLen)
			continue
		}
		if typ == nlmsgError {
			if msgLen >= 20 {
				errno := int32(binary.NativeEndian.Uint32(raw[off+16 : off+20]))
				if errno != 0 {
					return nil, fmt.Errorf("netlink error: errno %d", -errno)
				}
			}
			off += align4(msgLen)
			continue
		}
		msgs = append(msgs, rawNLMsg{
			Type:  typ,
			Flags: flags,
			Seq:   seq,
			Pid:   pid,
			Body:  raw[off+16 : off+msgLen],
		})
		off += align4(msgLen)
	}
	_ = nlmFMulti
	return msgs, nil
}

type rawAttr struct {
	Type uint16
	Data []byte
}

func parseAttrs(b []byte) []rawAttr {
	var attrs []rawAttr
	off := 0
	for off+4 <= len(b) {
		rtaLen := int(binary.NativeEndian.Uint16(b[off : off+2]))
		rtaType := binary.NativeEndian.Uint16(b[off+2 : off+4])
		if rtaLen < 4 || off+rtaLen > len(b) {
			break
		}
		attrs = append(attrs, rawAttr{
			Type: rtaType & 0x7fff, // strip NLA_F_NESTED / NLA_F_NET_BYTEORDER bits
			Data: b[off+4 : off+rtaLen],
		})
		off += align4(rtaLen)
	}
	return attrs
}

// ParseIfInfoMessages 解析 RTM_NEWLINK 原始二进制流，返回 ifIndex -> LinkInfo 映射。
func ParseIfInfoMessages(raw []byte) (map[int]LinkInfo, error) {
	msgs, err := splitNLMsgs(raw)
	if err != nil {
		return nil, err
	}
	out := make(map[int]LinkInfo)
	for _, m := range msgs {
		if m.Type != rtmNewLink || len(m.Body) < 16 {
			continue
		}
		idx := int(int32(binary.NativeEndian.Uint32(m.Body[4:8])))
		flags := binary.NativeEndian.Uint32(m.Body[8:12])
		var name string
		for _, a := range parseAttrs(m.Body[16:]) {
			if a.Type == iflaIfname {
				name = strings.TrimRight(string(a.Data), "\x00")
				break
			}
		}
		if idx > 0 {
			out[idx] = LinkInfo{
				Index:  idx,
				Name:   name,
				IsUp:   flags&iffUp != 0,
				IsLoop: flags&iffLoopback != 0,
			}
		}
	}
	return out, nil
}

// ParseNewNeighMessages 解析 RTM_NEWNEIGH 二进制报文，过滤无效状态后返回指定协议族（4/6/0=全部）邻居列表。
func ParseNewNeighMessages(raw []byte, family int) ([]NeighborEntry, error) {
	msgs, err := splitNLMsgs(raw)
	if err != nil {
		return nil, err
	}
	wantAF := uint8(afUnspec)
	switch family {
	case 4:
		wantAF = afInet
	case 6:
		wantAF = afInet6
	}
	var out []NeighborEntry
	for _, m := range msgs {
		if m.Type != rtmNewNeigh || len(m.Body) < 12 {
			continue
		}
		af := m.Body[0]
		if wantAF != afUnspec && af != wantAF {
			continue
		}
		ifIdx := int(int32(binary.NativeEndian.Uint32(m.Body[4:8])))
		state := binary.NativeEndian.Uint16(m.Body[8:10])
		if state == 0 || state&(nudFailed|nudIncomplete|nudNoarp) != 0 {
			continue
		}
		var dst netip.Addr
		var mac string
		for _, a := range parseAttrs(m.Body[12:]) {
			switch a.Type {
			case ndaDst:
				if parsed, ok := netip.AddrFromSlice(a.Data); ok {
					dst = parsed.Unmap()
				}
			case ndaLladdr:
				if len(a.Data) == 6 && !isZeroMAC(a.Data) {
					mac = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
						a.Data[0], a.Data[1], a.Data[2], a.Data[3], a.Data[4], a.Data[5])
				}
			}
		}
		if !dst.IsValid() || mac == "" {
			continue
		}
		out = append(out, NeighborEntry{
			IP:      dst,
			MAC:     mac,
			IfIndex: ifIdx,
			State:   state,
		})
	}
	return out, nil
}

func isZeroMAC(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ParseNewAddrMessages 解析 RTM_NEWADDR 二进制流并结合接口表映射为 InterfaceAddr 切片。
func ParseNewAddrMessages(raw []byte, links map[int]LinkInfo) ([]InterfaceAddr, error) {
	msgs, err := splitNLMsgs(raw)
	if err != nil {
		return nil, err
	}
	var out []InterfaceAddr
	for _, m := range msgs {
		if m.Type != rtmNewAddr || len(m.Body) < 8 {
			continue
		}
		af := m.Body[0]
		prefixLen := int(m.Body[1])
		flags := uint32(m.Body[2])
		scope := m.Body[3]
		ifIdx := int(binary.NativeEndian.Uint32(m.Body[4:8]))

		var addrLocal, addrPeer netip.Addr
		for _, a := range parseAttrs(m.Body[8:]) {
			switch a.Type {
			case ifaLocal:
				if ip, ok := netip.AddrFromSlice(a.Data); ok {
					addrLocal = ip.Unmap()
				}
			case ifaAddress:
				if ip, ok := netip.AddrFromSlice(a.Data); ok {
					addrPeer = ip.Unmap()
				}
			case ifaFlags:
				if len(a.Data) >= 4 {
					flags = binary.NativeEndian.Uint32(a.Data[:4])
				}
			}
		}
		ip := addrLocal
		if !ip.IsValid() {
			ip = addrPeer
		}
		if !ip.IsValid() {
			continue
		}
		if af == afInet && prefixLen == 0 {
			prefixLen = 32
		}
		pfx := netip.PrefixFrom(ip, prefixLen)
		if !pfx.IsValid() {
			continue
		}
		li := links[ifIdx]
		out = append(out, InterfaceAddr{
			IfIndex: ifIdx,
			IfName:  li.Name,
			IsUp:    li.IsUp,
			IsLoop:  li.IsLoop,
			Flags:   flags,
			Scope:   scope,
			Prefix:  pfx,
		})
	}
	return out, nil
}

// ExtractLANIPv6Prefixes 从网卡地址列表提取活跃 LAN 接口上的公网 GUA / ULA IPv6 `/64` 前缀，排除临时、废弃、回环与链路本地地址。
func ExtractLANIPv6Prefixes(addrs []InterfaceAddr, lanIface string) []netip.Prefix {
	var out []netip.Prefix
	tailscaleNet := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	for _, a := range addrs {
		if !a.IsUp || a.IsLoop {
			continue
		}
		if lanIface != "" && !strings.EqualFold(a.IfName, lanIface) {
			continue
		}
		lowerName := strings.ToLower(a.IfName)
		if strings.HasPrefix(lowerName, "tailscale") ||
			strings.HasPrefix(lowerName, "wg") ||
			strings.HasPrefix(lowerName, "tun") ||
			(lanIface == "" && strings.HasPrefix(lowerName, "pppoe")) {
			continue
		}
		if a.Flags&(ifaFDeprecated|ifaFDadFailed|ifaFTentative) != 0 {
			continue
		}
		addr := a.Prefix.Addr().Unmap()
		if !addr.Is6() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || tailscaleNet.Contains(addr) {
			continue
		}
		bits := a.Prefix.Bits()
		if bits <= 0 || bits > 64 {
			bits = 64
		}
		norm := netip.PrefixFrom(addr, bits).Masked()
		if !slices.Contains(out, norm) {
			out = append(out, norm)
		}
	}
	return out
}

// SelectDefaultRouteFromMessages 从 RTM_NEWROUTE 二进制流筛选 RT_TABLE_MAIN 主表中优先级最高的默认路由。
func SelectDefaultRouteFromMessages(raw []byte, family int, links map[int]LinkInfo) (DefaultRoute, bool, error) {
	msgs, err := splitNLMsgs(raw)
	if err != nil {
		return DefaultRoute{}, false, err
	}
	wantAF := uint8(afInet)
	if family == 6 {
		wantAF = afInet6
	}
	var best DefaultRoute
	found := false
	for _, m := range msgs {
		if m.Type != rtmNewRoute || len(m.Body) < 12 {
			continue
		}
		af := m.Body[0]
		dstLen := m.Body[1]
		table := uint32(m.Body[4])
		rtType := m.Body[7]
		if af != wantAF || dstLen != 0 || rtType != rtnUnicast {
			continue
		}
		var gw netip.Addr
		var oif int
		var prio uint32
		hasDstAttr := false
		for _, a := range parseAttrs(m.Body[12:]) {
			switch a.Type {
			case rtaTable:
				if len(a.Data) >= 4 {
					table = binary.NativeEndian.Uint32(a.Data[:4])
				}
			case rtaGateway:
				if ip, ok := netip.AddrFromSlice(a.Data); ok {
					gw = ip.Unmap()
				}
			case rtaOif:
				if len(a.Data) >= 4 {
					oif = int(binary.NativeEndian.Uint32(a.Data[:4]))
				}
			case rtaPriority:
				if len(a.Data) >= 4 {
					prio = binary.NativeEndian.Uint32(a.Data[:4])
				}
			case rtaDst:
				hasDstAttr = true
			}
		}
		if hasDstAttr || table != rtTableMain {
			continue
		}
		cand := DefaultRoute{
			Family:   family,
			Gateway:  gw,
			IfIndex:  oif,
			IfName:   links[oif].Name,
			Priority: prio,
		}
		if !found || cand.Priority < best.Priority {
			best = cand
			found = true
		}
	}
	return best, found, nil
}

// HasTableLocalRouteInMessages 检查 RTM_NEWROUTE 响应中指定协议族与路由表是否存在 RTN_LOCAL 路由。
func HasTableLocalRouteInMessages(raw []byte, family int, targetTable int) bool {
	msgs, err := splitNLMsgs(raw)
	if err != nil {
		return false
	}
	wantAF := uint8(afInet)
	if family == 6 {
		wantAF = afInet6
	}
	for _, m := range msgs {
		if m.Type != rtmNewRoute || len(m.Body) < 12 {
			continue
		}
		if m.Body[0] != wantAF || m.Body[7] != rtnLocal {
			continue
		}
		table := int(m.Body[4])
		for _, a := range parseAttrs(m.Body[12:]) {
			if a.Type == rtaTable && len(a.Data) >= 4 {
				table = int(binary.NativeEndian.Uint32(a.Data[:4]))
			}
		}
		if table == targetTable {
			return true
		}
	}
	return false
}

// ParseRuleMessages 解析 RTM_NEWRULE 二进制流并返回策略路由规则切片。
func ParseRuleMessages(raw []byte, family int) ([]RuleSpec, error) {
	msgs, err := splitNLMsgs(raw)
	if err != nil {
		return nil, err
	}
	var out []RuleSpec
	for _, m := range msgs {
		if m.Type != rtmNewRule || len(m.Body) < 12 {
			continue
		}
		af := m.Body[0]
		fam := 4
		if af == afInet6 {
			fam = 6
		} else if af != afInet {
			continue
		}
		if family != 0 && fam != family {
			continue
		}
		spec := RuleSpec{
			Family: fam,
			Table:  int(m.Body[4]),
			Mask:   0xffffffff,
		}
		for _, a := range parseAttrs(m.Body[12:]) {
			switch a.Type {
			case fraTable:
				if len(a.Data) >= 4 {
					spec.Table = int(binary.NativeEndian.Uint32(a.Data[:4]))
				}
			case fraPriority:
				if len(a.Data) >= 4 {
					spec.Priority = binary.NativeEndian.Uint32(a.Data[:4])
				}
			case fraFwmark:
				if len(a.Data) >= 4 {
					spec.Mark = binary.NativeEndian.Uint32(a.Data[:4])
				}
			case fraFwmask:
				if len(a.Data) >= 4 {
					spec.Mask = binary.NativeEndian.Uint32(a.Data[:4])
				}
			case fraIifname:
				spec.IifName = strings.TrimRight(string(a.Data), "\x00")
			}
		}
		out = append(out, spec)
	}
	return out, nil
}
