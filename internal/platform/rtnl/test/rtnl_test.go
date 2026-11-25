package rtnl_test

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"singctl/internal/platform/rtnl"
)

func align4(n int) int {
	return (n + 3) &^ 3
}

func buildRtAttr(typ uint16, payload []byte) []byte {
	total := align4(4 + len(payload))
	buf := make([]byte, total)
	binary.NativeEndian.PutUint16(buf[0:2], uint16(4+len(payload)))
	binary.NativeEndian.PutUint16(buf[2:4], typ)
	copy(buf[4:], payload)
	return buf
}

func buildNLMsg(typ, flags uint16, seq, pid uint32, body []byte) []byte {
	total := align4(16 + len(body))
	buf := make([]byte, total)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(total))
	binary.NativeEndian.PutUint16(buf[4:6], typ)
	binary.NativeEndian.PutUint16(buf[6:8], flags)
	binary.NativeEndian.PutUint32(buf[8:12], seq)
	binary.NativeEndian.PutUint32(buf[12:16], pid)
	copy(buf[16:], body)
	return buf
}

func buildNLMsgDone(seq uint32) []byte {
	return buildNLMsg(3 /* NLMSG_DONE */, 0x2, seq, 0, []byte{0, 0, 0, 0})
}

func u32Bytes(v uint32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return b[:]
}

func TestParseNewNeighMessages_IPv6AndIPv4AndEdgeCases(t *testing.T) {
	// NdMsg layout: Family(1), Pad1(1), Pad2(2), Ifindex(4), State(2), Flags(1), Type(1)
	makeNeigh := func(family uint8, ifIdx int32, state uint16, dst []byte, mac []byte) []byte {
		hdr := make([]byte, 12)
		hdr[0] = family
		binary.NativeEndian.PutUint32(hdr[4:8], uint32(ifIdx))
		binary.NativeEndian.PutUint16(hdr[8:10], state)
		body := append([]byte{}, hdr...)
		if dst != nil {
			body = append(body, buildRtAttr(1 /* NDA_DST */, dst)...)
		}
		if mac != nil {
			body = append(body, buildRtAttr(2 /* NDA_LLADDR */, mac)...)
		}
		return buildNLMsg(28 /* RTM_NEWNEIGH */, 0x2, 1, 100, body)
	}

	v6Valid := netip.MustParseAddr("2001:db8:1::10").As16()
	v6Stale := netip.MustParseAddr("fe80::20").As16()
	v6Failed := netip.MustParseAddr("2001:db8:1::99").As16()
	v6Noarp := netip.MustParseAddr("2001:db8:1::88").As16()
	v6ZeroMAC := netip.MustParseAddr("2001:db8:1::77").As16()

	macA := []byte{0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03}
	macB := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	zeroMAC := []byte{0, 0, 0, 0, 0, 0}

	var stream []byte
	stream = append(stream, makeNeigh(10 /* AF_INET6 */, 3, 0x02 /* NUD_REACHABLE */, v6Valid[:], macA)...)
	stream = append(stream, makeNeigh(10 /* AF_INET6 */, 3, 0x04 /* NUD_STALE */, v6Stale[:], macB)...)
	stream = append(stream, makeNeigh(10 /* AF_INET6 */, 3, 0x20 /* NUD_FAILED */, v6Failed[:], macA)...)
	stream = append(stream, makeNeigh(10 /* AF_INET6 */, 3, 0x40 /* NUD_NOARP */, v6Noarp[:], macA)...)
	stream = append(stream, makeNeigh(10 /* AF_INET6 */, 3, 0x02 /* NUD_REACHABLE */, v6ZeroMAC[:], zeroMAC)...)
	// Cross-family entry when filtering family=10 should be ignored
	v4 := netip.MustParseAddr("192.0.2.50").As4()
	stream = append(stream, makeNeigh(2 /* AF_INET */, 3, 0x02, v4[:], macA)...)
	stream = append(stream, buildNLMsgDone(1)...)

	got, err := rtnl.ParseNewNeighMessages(stream, 6)
	if err != nil {
		t.Fatalf("ParseNewNeighMessages failed: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 valid IPv6 neighbors, got %d (%+v)", len(got), got)
	}
	if got[0].IP.String() != "2001:db8:1::10" || got[0].MAC != "aa:bb:cc:01:02:03" || got[0].IfIndex != 3 {
		t.Fatalf("unexpected first neighbor: %+v", got[0])
	}
	if got[1].IP.String() != "fe80::20" || got[1].MAC != "11:22:33:44:55:66" {
		t.Fatalf("unexpected second neighbor: %+v", got[1])
	}

	// Malformed / truncated frames must never panic and return gracefully.
	for _, malformed := range [][]byte{
		nil,
		{},
		{0x04, 0x00, 0x00, 0x00},
		{0xff, 0xff, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	} {
		entries, parseErr := rtnl.ParseNewNeighMessages(malformed, 6)
		if parseErr != nil && len(entries) != 0 {
			t.Fatalf("expected empty entries on malformed payload")
		}
	}
}

func TestParseIfInfoAndAddrAndExtractLANIPv6(t *testing.T) {
	// IfInfomsg: Family(1), Pad(1), Type(2), Index(4), Flags(4), Change(4) = 16B
	makeLink := func(idx int32, flags uint32, name string) []byte {
		hdr := make([]byte, 16)
		binary.NativeEndian.PutUint32(hdr[4:8], uint32(idx))
		binary.NativeEndian.PutUint32(hdr[8:12], flags)
		attr := buildRtAttr(3 /* IFLA_IFNAME */, append([]byte(name), 0))
		return buildNLMsg(16 /* RTM_NEWLINK */, 0x2, 1, 100, append(hdr, attr...))
	}

	// IfAddrmsg: Family(1), Prefixlen(1), Flags(1), Scope(1), Index(4) = 8B
	makeAddr := func(family, prefixLen, scope uint8, idx uint32, ip []byte, extFlags uint32) []byte {
		hdr := make([]byte, 8)
		hdr[0] = family
		hdr[1] = prefixLen
		hdr[3] = scope
		binary.NativeEndian.PutUint32(hdr[4:8], idx)
		body := append(hdr, buildRtAttr(1 /* IFA_ADDRESS */, ip)...)
		if extFlags != 0 {
			body = append(body, buildRtAttr(8 /* IFA_FLAGS */, u32Bytes(extFlags))...)
		}
		return buildNLMsg(20 /* RTM_NEWADDR */, 0x2, 2, 100, body)
	}

	var linksStream []byte
	linksStream = append(linksStream, makeLink(1, 0x1|0x8 /* IFF_UP|IFF_LOOPBACK */, "lo")...)
	linksStream = append(linksStream, makeLink(2, 0x1 /* IFF_UP */, "br-lan")...)
	linksStream = append(linksStream, makeLink(3, 0x1 /* IFF_UP */, "tailscale0")...)
	linksStream = append(linksStream, makeLink(4, 0x0 /* down */, "eth2")...)
	linksStream = append(linksStream, buildNLMsgDone(1)...)

	links, err := rtnl.ParseIfInfoMessages(linksStream)
	if err != nil {
		t.Fatalf("ParseIfInfoMessages failed: %v", err)
	}
	if links[2].Name != "br-lan" || !links[2].IsUp || links[2].IsLoop {
		t.Fatalf("unexpected br-lan link info: %+v", links[2])
	}
	if !links[1].IsLoop || links[4].IsUp {
		t.Fatalf("unexpected loopback/down link info: %+v", links)
	}

	gua1 := netip.MustParseAddr("2001:db8:abcd:1::1").As16()
	ula1 := netip.MustParseAddr("fd12:3456:789a::1").As16()
	ll1 := netip.MustParseAddr("fe80::1").As16()
	tempGUA := netip.MustParseAddr("2001:db8:dead:beef::99").As16()
	tsAddr := netip.MustParseAddr("fd7a:115c:a1e0::1234").As16()
	v4Lan := netip.MustParseAddr("192.0.2.1").As4()

	var addrStream []byte
	addrStream = append(addrStream, makeAddr(10, 64, 0, 2, gua1[:], 0x80 /* IFA_F_PERMANENT */)...)
	addrStream = append(addrStream, makeAddr(10, 64, 0, 2, ula1[:], 0x80)...)
	addrStream = append(addrStream, makeAddr(10, 64, 0xfd, 2, ll1[:], 0x80)...)
	addrStream = append(addrStream, makeAddr(10, 64, 0, 2, tempGUA[:], 0x20 /* IFA_F_DEPRECATED */)...)
	addrStream = append(addrStream, makeAddr(10, 48, 0, 3, tsAddr[:], 0x80)...)
	addrStream = append(addrStream, makeAddr(2, 24, 0, 2, v4Lan[:], 0x80)...)
	addrStream = append(addrStream, buildNLMsgDone(2)...)

	addrs, err := rtnl.ParseNewAddrMessages(addrStream, links)
	if err != nil {
		t.Fatalf("ParseNewAddrMessages failed: %v", err)
	}
	if len(addrs) != 6 {
		t.Fatalf("expected 6 parsed addrs, got %d", len(addrs))
	}

	lanV6 := rtnl.ExtractLANIPv6Prefixes(addrs, "br-lan")
	if len(lanV6) != 2 {
		t.Fatalf("expected 2 non-deprecated global/ULA LAN prefixes on br-lan, got %v", lanV6)
	}
	if lanV6[0].String() != "2001:db8:abcd:1::/64" || lanV6[1].String() != "fd12:3456:789a::/64" {
		t.Fatalf("unexpected normalized LAN IPv6 prefixes: %v", lanV6)
	}
}

func TestParseNewRouteMessages_DefaultRouteAndTableSelection(t *testing.T) {
	// RtMsg: Family(1), DstLen(1), SrcLen(1), Tos(1), Table(1), Protocol(1), Scope(1), Type(1), Flags(4) = 12B
	makeRoute := func(family, dstLen, tableSmall uint8, typ uint8, table32 uint32, gw []byte, oif uint32, priority uint32) []byte {
		hdr := make([]byte, 12)
		hdr[0] = family
		hdr[1] = dstLen
		hdr[4] = tableSmall
		hdr[7] = typ
		body := hdr
		if gw != nil {
			body = append(body, buildRtAttr(5 /* RTA_GATEWAY */, gw)...)
		}
		if oif != 0 {
			body = append(body, buildRtAttr(4 /* RTA_OIF */, u32Bytes(oif))...)
		}
		if table32 != 0 {
			body = append(body, buildRtAttr(15 /* RTA_TABLE */, u32Bytes(table32))...)
		}
		if priority != 0 {
			body = append(body, buildRtAttr(6 /* RTA_PRIORITY */, u32Bytes(priority))...)
		}
		return buildNLMsg(24 /* RTM_NEWROUTE */, 0x2, 3, 100, body)
	}

	links := map[int]rtnl.LinkInfo{
		1: {Index: 1, Name: "lo", IsUp: true, IsLoop: true},
		5: {Index: 5, Name: "eth0", IsUp: true},
	}

	gw4 := netip.MustParseAddr("198.51.100.1").As4()
	gwLocal := netip.MustParseAddr("203.0.113.1").As4()

	var routeStream []byte
	// Table 100 local route must be ignored for main default lookup
	routeStream = append(routeStream, makeRoute(2, 0, 100, 2 /* RTN_LOCAL */, 100, gwLocal[:], 1, 1)...)
	// Main table lower priority (higher metric) vs preferred metric
	routeStream = append(routeStream, makeRoute(2, 0, 254, 1 /* RTN_UNICAST */, 254, gwLocal[:], 5, 200)...)
	routeStream = append(routeStream, makeRoute(2, 0, 254, 1 /* RTN_UNICAST */, 254, gw4[:], 5, 50)...)
	routeStream = append(routeStream, buildNLMsgDone(3)...)

	def, found, err := rtnl.SelectDefaultRouteFromMessages(routeStream, 4, links)
	if err != nil {
		t.Fatalf("SelectDefaultRouteFromMessages failed: %v", err)
	}
	if !found {
		t.Fatalf("expected default route found")
	}
	if def.Gateway.String() != "198.51.100.1" || def.IfName != "eth0" || def.IfIndex != 5 {
		t.Fatalf("unexpected selected default route: %+v", def)
	}

	if !rtnl.HasTableLocalRouteInMessages(routeStream, 4, 100) {
		t.Fatalf("expected table 100 RTN_LOCAL route detected")
	}
	if rtnl.HasTableLocalRouteInMessages(routeStream, 4, 101) {
		t.Fatalf("did not expect table 101 RTN_LOCAL route detected")
	}
}

func TestParseRuleMessages(t *testing.T) {
	makeRule := func(family uint8, tableSmall uint8, prio, mark, mask, table32 uint32, iif string) []byte {
		hdr := make([]byte, 12)
		hdr[0] = family
		hdr[4] = tableSmall
		hdr[7] = 1 // FR_ACT_TO_TBL
		body := hdr
		if prio != 0 {
			body = append(body, buildRtAttr(6 /* FRA_PRIORITY */, u32Bytes(prio))...)
		}
		if mark != 0 {
			body = append(body, buildRtAttr(10 /* FRA_FWMARK */, u32Bytes(mark))...)
		}
		if mask != 0 {
			body = append(body, buildRtAttr(16 /* FRA_FWMASK */, u32Bytes(mask))...)
		}
		if table32 != 0 {
			body = append(body, buildRtAttr(15 /* FRA_TABLE */, u32Bytes(table32))...)
		}
		if iif != "" {
			body = append(body, buildRtAttr(3 /* FRA_IIFNAME */, append([]byte(iif), 0))...)
		}
		return buildNLMsg(32 /* RTM_NEWRULE */, 0x2, 4, 100, body)
	}

	var stream []byte
	stream = append(stream, makeRule(2, 100, 32764, 0x1, 0xffffffff, 100, "")...)
	stream = append(stream, makeRule(10, 101, 32765, 0x2, 0xffffffff, 101, "lo")...)
	stream = append(stream, buildNLMsgDone(4)...)

	v4Rules, err := rtnl.ParseRuleMessages(stream, 4)
	if err != nil || len(v4Rules) != 1 || v4Rules[0].Mark != 0x1 || v4Rules[0].Table != 100 || v4Rules[0].Priority != 32764 {
		t.Fatalf("unexpected v4 rules: %+v err=%v", v4Rules, err)
	}
	v6Rules, err := rtnl.ParseRuleMessages(stream, 6)
	if err != nil || len(v6Rules) != 1 || v6Rules[0].Mark != 0x2 || v6Rules[0].Table != 101 || v6Rules[0].IifName != "lo" {
		t.Fatalf("unexpected v6 rules: %+v err=%v", v6Rules, err)
	}
}

func TestThrowDefaultsAndMockClientConcurrency(t *testing.T) {
	v4 := rtnl.DefaultThrowV4Prefixes()
	v6 := rtnl.DefaultThrowV6Prefixes()
	if len(v4) < 7 || len(v6) < 4 {
		t.Fatalf("unexpected default throw prefix counts: v4=%d v6=%d", len(v4), len(v6))
	}

	mock := rtnl.NewMockClient()
	mock.DefaultRoutes[4] = rtnl.DefaultRoute{
		Family:  4,
		Gateway: netip.MustParseAddr("192.0.2.1"),
		IfIndex: 2,
		IfName:  "br-lan",
	}
	mock.Neighbors[6] = []rtnl.NeighborEntry{
		{IP: netip.MustParseAddr("2001:db8::5"), MAC: "aa:bb:cc:dd:ee:05", IfIndex: 2, State: 0x02},
	}

	spec := rtnl.TProxyRouteSpec{
		ForwardFwMark:   0x1,
		ForwardTable:    100,
		LocalFwMark:     0x2,
		LocalTable:      101,
		EnableIPv6:      true,
		ThrowV4Prefixes: v4,
		ThrowV6Prefixes: v6,
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			_, _, _ = mock.GetDefaultRoute(4)
			_, _ = mock.ListNeighbors(6)
			_ = mock.ReconcileTProxyRoutes(spec)
			_ = mock.CleanupTProxyRoutes(100, 101)
		})
	}
	wg.Wait()

	if len(mock.ReconciledSpecs()) != 8 || len(mock.CleanedTables()) != 8 {
		t.Fatalf("unexpected mock call counts: reconcile=%d cleanup=%d", len(mock.ReconciledSpecs()), len(mock.CleanedTables()))
	}
}
