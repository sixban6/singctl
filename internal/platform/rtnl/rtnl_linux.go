// 文件职责：提供 Linux 平台基于 AF_NETLINK / NETLINK_ROUTE 的纯 Go 零子进程内核路由与邻居表客户端实现。
//go:build linux

package rtnl

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

type linuxClient struct{}

func newDefaultClient() Client {
	return &linuxClient{}
}

var nlSeqCounter atomic.Uint32

func openNetlinkSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	tv := unix.Timeval{Sec: 2, Usec: 0}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func appendNLAttr(buf []byte, typ uint16, data []byte) []byte {
	attrLen := 4 + len(data)
	padded := align4(attrLen)
	start := len(buf)
	buf = append(buf, make([]byte, padded)...)
	binary.NativeEndian.PutUint16(buf[start:start+2], uint16(attrLen))
	binary.NativeEndian.PutUint16(buf[start+2:start+4], typ)
	copy(buf[start+4:], data)
	return buf
}

func u32AttrBytes(v uint32) []byte {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return b[:]
}

func buildRequestPacket(typ, flags uint16, seq uint32, body []byte) []byte {
	total := align4(16 + len(body))
	pkt := make([]byte, total)
	binary.NativeEndian.PutUint32(pkt[0:4], uint32(total))
	binary.NativeEndian.PutUint16(pkt[4:6], typ)
	binary.NativeEndian.PutUint16(pkt[6:8], flags)
	binary.NativeEndian.PutUint32(pkt[8:12], seq)
	copy(pkt[16:], body)
	return pkt
}

func queryNetlinkDump(msgType uint16, body []byte) ([]byte, error) {
	fd, err := openNetlinkSocket()
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	seq := nlSeqCounter.Add(1)
	req := buildRequestPacket(msgType, unix.NLM_F_REQUEST|unix.NLM_F_DUMP, seq, body)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}

	var out []byte
	recvBuf := make([]byte, 32768)
	for {
		n, _, rErr := unix.Recvfrom(fd, recvBuf, 0)
		if rErr != nil {
			if errors.Is(rErr, unix.EINTR) {
				continue
			}
			return nil, rErr
		}
		if n < 16 {
			break
		}
		chunk := recvBuf[:n]
		out = append(out, chunk...)

		done := false
		off := 0
		for off+16 <= len(chunk) {
			msgLen := int(binary.NativeEndian.Uint32(chunk[off : off+4]))
			if msgLen < 16 || off+msgLen > len(chunk) {
				done = true
				break
			}
			typ := binary.NativeEndian.Uint16(chunk[off+4 : off+6])
			flags := binary.NativeEndian.Uint16(chunk[off+6 : off+8])
			msgSeq := binary.NativeEndian.Uint32(chunk[off+8 : off+12])
			if msgSeq == seq {
				if typ == unix.NLMSG_DONE {
					done = true
					break
				}
				if typ == unix.NLMSG_ERROR && msgLen >= 20 {
					errno := int32(binary.NativeEndian.Uint32(chunk[off+16 : off+20]))
					if errno != 0 {
						return nil, unix.Errno(-errno)
					}
					done = true
					break
				}
				if flags&unix.NLM_F_MULTI == 0 {
					done = true
				}
			}
			off += align4(msgLen)
		}
		if done {
			break
		}
	}
	return out, nil
}

func execNetlinkAck(msgType, flags uint16, body []byte) error {
	fd, err := openNetlinkSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	seq := nlSeqCounter.Add(1)
	req := buildRequestPacket(msgType, flags|unix.NLM_F_REQUEST|unix.NLM_F_ACK, seq, body)
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}

	recvBuf := make([]byte, 8192)
	for {
		n, _, rErr := unix.Recvfrom(fd, recvBuf, 0)
		if rErr != nil {
			if errors.Is(rErr, unix.EINTR) {
				continue
			}
			return rErr
		}
		if n < 16 {
			return fmt.Errorf("short netlink ack (%d bytes)", n)
		}
		chunk := recvBuf[:n]
		off := 0
		for off+16 <= len(chunk) {
			msgLen := int(binary.NativeEndian.Uint32(chunk[off : off+4]))
			if msgLen < 16 || off+msgLen > len(chunk) {
				break
			}
			typ := binary.NativeEndian.Uint16(chunk[off+4 : off+6])
			msgSeq := binary.NativeEndian.Uint32(chunk[off+8 : off+12])
			if msgSeq == seq && typ == unix.NLMSG_ERROR && msgLen >= 20 {
				errno := int32(binary.NativeEndian.Uint32(chunk[off+16 : off+20]))
				if errno != 0 {
					return unix.Errno(-errno)
				}
				return nil
			}
			off += align4(msgLen)
		}
	}
}

func toUnixAF(family int) uint8 {
	switch family {
	case 4:
		return unix.AF_INET
	case 6:
		return unix.AF_INET6
	default:
		return unix.AF_UNSPEC
	}
}

func (c *linuxClient) dumpLinks() (map[int]LinkInfo, error) {
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	raw, err := queryNetlinkDump(unix.RTM_GETLINK, body)
	if err != nil {
		return nil, err
	}
	return ParseIfInfoMessages(raw)
}

func (c *linuxClient) ListAddresses() ([]InterfaceAddr, error) {
	links, err := c.dumpLinks()
	if err != nil {
		return nil, err
	}
	body := make([]byte, unix.SizeofIfAddrmsg)
	body[0] = unix.AF_UNSPEC
	raw, err := queryNetlinkDump(unix.RTM_GETADDR, body)
	if err != nil {
		return nil, err
	}
	return ParseNewAddrMessages(raw, links)
}

func (c *linuxClient) ListNeighbors(family int) ([]NeighborEntry, error) {
	body := make([]byte, unix.SizeofNdMsg)
	body[0] = toUnixAF(family)
	raw, err := queryNetlinkDump(unix.RTM_GETNEIGH, body)
	if err != nil {
		return nil, err
	}
	return ParseNewNeighMessages(raw, family)
}

func (c *linuxClient) GetDefaultRoute(family int) (DefaultRoute, bool, error) {
	links, err := c.dumpLinks()
	if err != nil {
		return DefaultRoute{}, false, err
	}
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = toUnixAF(family)
	raw, err := queryNetlinkDump(unix.RTM_GETROUTE, body)
	if err != nil {
		return DefaultRoute{}, false, err
	}
	return SelectDefaultRouteFromMessages(raw, family, links)
}

func (c *linuxClient) ReplaceDefaultRoute(family int, gw netip.Addr, ifName string) error {
	gw = gw.Unmap()
	if !gw.IsValid() {
		return fmt.Errorf("invalid gateway IP")
	}
	af := toUnixAF(family)
	if gw.Is4() {
		af = unix.AF_INET
	} else if gw.Is6() {
		af = unix.AF_INET6
	}

	body := make([]byte, unix.SizeofRtMsg)
	body[0] = af
	body[4] = unix.RT_TABLE_MAIN
	body[5] = unix.RTPROT_BOOT
	body[6] = unix.RT_SCOPE_UNIVERSE
	body[7] = unix.RTN_UNICAST

	body = appendNLAttr(body, unix.RTA_GATEWAY, gw.AsSlice())
	if ifName != "" {
		ifi, err := net.InterfaceByName(ifName)
		if err != nil {
			return fmt.Errorf("lookup interface %s: %w", ifName, err)
		}
		body = appendNLAttr(body, unix.RTA_OIF, u32AttrBytes(uint32(ifi.Index)))
	}
	return execNetlinkAck(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}

func buildUnicastRouteBody(spec UnicastRouteSpec, forDelete bool) ([]byte, error) {
	if !spec.Dst.IsValid() {
		return nil, fmt.Errorf("invalid destination prefix %v", spec.Dst)
	}
	if !spec.Gateway.IsValid() {
		return nil, fmt.Errorf("invalid gateway address %v", spec.Gateway)
	}
	dst := spec.Dst.Masked()
	dstAddr := dst.Addr().Unmap()
	gwAddr := spec.Gateway.Unmap()
	if dstAddr.Is4() != gwAddr.Is4() {
		return nil, fmt.Errorf("address family mismatch between dst %s and gateway %s", dst, gwAddr)
	}

	af := uint8(unix.AF_INET)
	if dstAddr.Is6() {
		af = unix.AF_INET6
	}
	tbl := cmp.Or(spec.Table, int(unix.RT_TABLE_MAIN))

	body := make([]byte, unix.SizeofRtMsg)
	body[0] = af
	body[1] = uint8(dst.Bits())
	if tbl > 0 && tbl < 256 {
		body[4] = uint8(tbl)
	} else {
		body[4] = unix.RT_TABLE_UNSPEC
	}
	if forDelete {
		body[5] = unix.RTPROT_UNSPEC
		body[6] = unix.RT_SCOPE_NOWHERE
		body[7] = unix.RTN_UNSPEC
	} else {
		body[5] = unix.RTPROT_BOOT
		body[6] = unix.RT_SCOPE_UNIVERSE
		body[7] = unix.RTN_UNICAST
	}

	if dst.Bits() > 0 {
		body = appendNLAttr(body, unix.RTA_DST, dstAddr.AsSlice())
	}
	body = appendNLAttr(body, unix.RTA_GATEWAY, gwAddr.AsSlice())
	if spec.IfName != "" {
		ifi, err := net.InterfaceByName(spec.IfName)
		if err != nil {
			return nil, fmt.Errorf("lookup interface %s: %w", spec.IfName, err)
		}
		body = appendNLAttr(body, unix.RTA_OIF, u32AttrBytes(uint32(ifi.Index)))
	}
	if spec.Priority > 0 {
		body = appendNLAttr(body, unix.RTA_PRIORITY, u32AttrBytes(spec.Priority))
	}
	if tbl >= 256 {
		body = appendNLAttr(body, unix.RTA_TABLE, u32AttrBytes(uint32(tbl)))
	}
	return body, nil
}

func (c *linuxClient) ReplaceUnicastRoute(spec UnicastRouteSpec) error {
	body, err := buildUnicastRouteBody(spec, false)
	if err != nil {
		return err
	}
	return execNetlinkAck(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}

func (c *linuxClient) DeleteUnicastRoute(spec UnicastRouteSpec) error {
	body, err := buildUnicastRouteBody(spec, true)
	if err != nil {
		return err
	}
	err = execNetlinkAck(unix.RTM_DELROUTE, 0, body)
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func (c *linuxClient) HasRouteTableLocal(family int, table int) (bool, error) {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = toUnixAF(family)
	raw, err := queryNetlinkDump(unix.RTM_GETROUTE, body)
	if err != nil {
		return false, err
	}
	return HasTableLocalRouteInMessages(raw, family, table), nil
}

func addLocalLoopbackRoute(af uint8, loIndex int, table int) error {
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = af
	body[4] = unix.RT_TABLE_UNSPEC
	body[5] = unix.RTPROT_BOOT
	body[6] = unix.RT_SCOPE_HOST
	body[7] = unix.RTN_LOCAL
	body = appendNLAttr(body, unix.RTA_OIF, u32AttrBytes(uint32(loIndex)))
	body = appendNLAttr(body, unix.RTA_TABLE, u32AttrBytes(uint32(table)))
	return execNetlinkAck(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}

func addThrowPrefixRoute(pfx netip.Prefix, table int) error {
	if !pfx.IsValid() {
		return nil
	}
	addr := pfx.Masked().Addr().Unmap()
	af := uint8(unix.AF_INET)
	if addr.Is6() {
		af = unix.AF_INET6
	}
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = af
	body[1] = uint8(pfx.Bits())
	body[4] = unix.RT_TABLE_UNSPEC
	body[5] = unix.RTPROT_BOOT
	body[6] = unix.RT_SCOPE_UNIVERSE
	body[7] = unix.RTN_THROW
	if pfx.Bits() > 0 {
		body = appendNLAttr(body, unix.RTA_DST, addr.AsSlice())
	}
	body = appendNLAttr(body, unix.RTA_TABLE, u32AttrBytes(uint32(table)))
	return execNetlinkAck(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_REPLACE, body)
}

func ensureMarkRule(af uint8, mark uint32, table int) error {
	famInt := 4
	if af == unix.AF_INET6 {
		famInt = 6
	}
	ruleBody := make([]byte, unix.SizeofRtMsg)
	ruleBody[0] = af
	raw, err := queryNetlinkDump(unix.RTM_GETRULE, ruleBody)
	if err == nil {
		if existing, pErr := ParseRuleMessages(raw, famInt); pErr == nil {
			for _, r := range existing {
				if r.Mark == mark && r.Table == table {
					return nil
				}
			}
		}
	}

	req := make([]byte, unix.SizeofRtMsg)
	req[0] = af
	req[4] = unix.RT_TABLE_UNSPEC
	req[7] = unix.FR_ACT_TO_TBL
	req = appendNLAttr(req, unix.FRA_FWMARK, u32AttrBytes(mark))
	req = appendNLAttr(req, unix.FRA_FWMASK, u32AttrBytes(0xffffffff))
	req = appendNLAttr(req, unix.FRA_TABLE, u32AttrBytes(uint32(table)))
	err = execNetlinkAck(unix.RTM_NEWRULE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, req)
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	return err
}

func (c *linuxClient) EnsureThrowRoutes(family int, table int, prefixes []netip.Prefix) error {
	for _, pfx := range prefixes {
		addr := pfx.Addr().Unmap()
		if (family == 4 && !addr.Is4()) || (family == 6 && !addr.Is6()) {
			continue
		}
		if err := addThrowPrefixRoute(pfx, table); err != nil {
			return err
		}
	}
	return nil
}

func (c *linuxClient) ReconcileTProxyRoutes(spec TProxyRouteSpec) error {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("lookup lo interface: %w", err)
	}
	fwdMark := cmp.Or(spec.ForwardFwMark, uint32(0x1))
	fwdTable := cmp.Or(spec.ForwardTable, 100)
	localMark := cmp.Or(spec.LocalFwMark, uint32(0x2))
	localTable := cmp.Or(spec.LocalTable, 101)

	v4Throws := spec.ThrowV4Prefixes
	if len(v4Throws) == 0 {
		v4Throws = DefaultThrowV4Prefixes()
	}

	// IPv4 forward (table 100) + local (table 101)
	if err := ensureMarkRule(unix.AF_INET, fwdMark, fwdTable); err != nil {
		return err
	}
	if err := addLocalLoopbackRoute(unix.AF_INET, lo.Index, fwdTable); err != nil {
		return err
	}
	if err := c.EnsureThrowRoutes(4, fwdTable, v4Throws); err != nil {
		return err
	}
	if err := ensureMarkRule(unix.AF_INET, localMark, localTable); err != nil {
		return err
	}
	if err := addLocalLoopbackRoute(unix.AF_INET, lo.Index, localTable); err != nil {
		return err
	}

	if !spec.EnableIPv6 {
		return nil
	}

	v6Throws := spec.ThrowV6Prefixes
	if len(v6Throws) == 0 {
		v6Throws = DefaultThrowV6Prefixes()
	}
	if err := ensureMarkRule(unix.AF_INET6, fwdMark, fwdTable); err != nil {
		return err
	}
	if err := addLocalLoopbackRoute(unix.AF_INET6, lo.Index, fwdTable); err != nil {
		return err
	}
	if err := c.EnsureThrowRoutes(6, fwdTable, v6Throws); err != nil {
		return err
	}
	if err := ensureMarkRule(unix.AF_INET6, localMark, localTable); err != nil {
		return err
	}
	return addLocalLoopbackRoute(unix.AF_INET6, lo.Index, localTable)
}

func (c *linuxClient) CleanupTProxyRoutes(tables ...int) error {
	if len(tables) == 0 {
		return nil
	}
	for _, af := range []uint8{unix.AF_INET, unix.AF_INET6} {
		// 1. 删除匹配目标路由表号的 FIB Rules
		ruleReq := make([]byte, unix.SizeofRtMsg)
		ruleReq[0] = af
		if rawRules, err := queryNetlinkDump(unix.RTM_GETRULE, ruleReq); err == nil {
			if msgs, mErr := splitNLMsgs(rawRules); mErr == nil {
				for _, m := range msgs {
					if m.Type != unix.RTM_NEWRULE || len(m.Body) < unix.SizeofRtMsg {
						continue
					}
					tbl := int(m.Body[4])
					for _, a := range parseAttrs(m.Body[unix.SizeofRtMsg:]) {
						if a.Type == unix.FRA_TABLE && len(a.Data) >= 4 {
							tbl = int(binary.NativeEndian.Uint32(a.Data[:4]))
						}
					}
					if slices.Contains(tables, tbl) {
						delErr := execNetlinkAck(unix.RTM_DELRULE, 0, m.Body)
						if delErr != nil && !errors.Is(delErr, unix.ENOENT) && !errors.Is(delErr, unix.ESRCH) {
							return delErr
						}
					}
				}
			}
		}

		// 2. 清空目标路由表中的全部路由项
		routeReq := make([]byte, unix.SizeofRtMsg)
		routeReq[0] = af
		if rawRoutes, err := queryNetlinkDump(unix.RTM_GETROUTE, routeReq); err == nil {
			if msgs, mErr := splitNLMsgs(rawRoutes); mErr == nil {
				for _, m := range msgs {
					if m.Type != unix.RTM_NEWROUTE || len(m.Body) < unix.SizeofRtMsg {
						continue
					}
					tbl := int(m.Body[4])
					for _, a := range parseAttrs(m.Body[unix.SizeofRtMsg:]) {
						if a.Type == unix.RTA_TABLE && len(a.Data) >= 4 {
							tbl = int(binary.NativeEndian.Uint32(a.Data[:4]))
						}
					}
					if slices.Contains(tables, tbl) {
						delErr := execNetlinkAck(unix.RTM_DELROUTE, 0, m.Body)
						if delErr != nil && !errors.Is(delErr, unix.ESRCH) && !errors.Is(delErr, unix.ENOENT) {
							return delErr
						}
					}
				}
			}
		}
	}
	return nil
}
