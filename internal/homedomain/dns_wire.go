// 文件职责：提供零外部依赖的纯 Go RFC 1035 本地域名 DNS 报文解析、索引匹配（精确/通配/NODATA/NXDOMAIN/REFUSED）与轻量 UDP 探针。
package homedomain

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"singctl/internal/config"
)

const (
	TypeA     uint16 = 1
	TypeAAAA  uint16 = 28
	TypeANY   uint16 = 255
	ClassIN   uint16 = 1
	defaultTT        = 60 // 60 秒短 TTL：局域网/DHCP 切换或改名后快速刷新，且不给客户端造成查询压力

	RcodeNoError  uint8 = 0
	RcodeFormErr  uint8 = 1
	RcodeNXDomain uint8 = 3
	RcodeRefused  uint8 = 5
)

type hostAddrs struct {
	v4 []netip.Addr
	v6 []netip.Addr
}

// RecordIndex 为只读不可变内存域名索引（热重载时通过 atomic.Pointer 整体原子切换）。
type RecordIndex struct {
	suffix   string
	exact    map[string]hostAddrs
	wildcard map[string]hostAddrs // key 为不含 "*." 的基域名，如 "nas.home"
	count    int
}

// NewRecordIndex 根据规范化后缀与受管重写列表构建不可变内存 DNS 索引。
func NewRecordIndex(suffix string, rules []config.DNSRewriteRule) *RecordIndex {
	normSfx, err := config.NormalizeHomeDomainSuffix(suffix)
	if err != nil || normSfx == "" {
		normSfx = config.DefaultHomeDomainSuffix
	}
	idx := &RecordIndex{
		suffix:   normSfx,
		exact:    make(map[string]hostAddrs, len(rules)),
		wildcard: make(map[string]hostAddrs),
	}
	for _, r := range rules {
		dom := strings.ToLower(strings.Trim(strings.TrimSpace(r.Domain), "."))
		addr, aErr := netip.ParseAddr(strings.TrimSpace(r.Answer))
		if dom == "" || aErr != nil {
			continue
		}
		addr = addr.Unmap()
		isWild := strings.HasPrefix(dom, "*.")
		if isWild {
			base := strings.TrimPrefix(dom, "*.")
			if base == "" {
				continue
			}
			cur := idx.wildcard[base]
			if addr.Is4() {
				cur.v4 = append(cur.v4, addr)
			} else if addr.Is6() {
				cur.v6 = append(cur.v6, addr)
			}
			idx.wildcard[base] = cur
			idx.count++
			continue
		}
		cur := idx.exact[dom]
		if addr.Is4() {
			cur.v4 = append(cur.v4, addr)
		} else if addr.Is6() {
			cur.v6 = append(cur.v6, addr)
		}
		idx.exact[dom] = cur
		idx.count++
	}
	return idx
}

// Suffix 返回当前索引托管的内网后缀。
func (idx *RecordIndex) Suffix() string {
	if idx == nil {
		return config.DefaultHomeDomainSuffix
	}
	return idx.suffix
}

// Count 返回索引中生效的重写记录总数。
func (idx *RecordIndex) Count() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func (idx *RecordIndex) inScope(qname string) bool {
	if idx == nil || idx.suffix == "" {
		return false
	}
	return qname == idx.suffix || strings.HasSuffix(qname, "."+idx.suffix)
}

func (idx *RecordIndex) lookup(qname string) (hostAddrs, bool) {
	if idx == nil {
		return hostAddrs{}, false
	}
	if a, ok := idx.exact[qname]; ok {
		return a, true
	}
	// 自底向上匹配通配父域（如 a.b.nas.home -> *.nas.home）
	cur := qname
	for {
		dot := strings.IndexByte(cur, '.')
		if dot < 0 || dot+1 >= len(cur) {
			break
		}
		parent := cur[dot+1:]
		if a, ok := idx.wildcard[parent]; ok {
			return a, true
		}
		cur = parent
	}
	return hostAddrs{}, false
}

// parseDNSName 安全解析 DNS 报文中指定偏移处的 QNAME，内置压缩指针防死循环与越界保护。
func parseDNSName(msg []byte, offset int) (string, int, bool) {
	if offset < 0 || offset >= len(msg) {
		return "", 0, false
	}
	var labels []string
	cur := offset
	nextAfter := -1
	jumps := 0
	for {
		if cur >= len(msg) {
			return "", 0, false
		}
		length := int(msg[cur])
		if length == 0 {
			if nextAfter < 0 {
				nextAfter = cur + 1
			}
			break
		}
		// RFC 1035 压缩指针（高两位为 11）
		if length&0xc0 == 0xc0 {
			if cur+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[cur:cur+2]) & 0x3fff)
			if ptr >= len(msg) || ptr == cur {
				return "", 0, false
			}
			jumps++
			if jumps > 16 {
				return "", 0, false
			}
			if nextAfter < 0 {
				nextAfter = cur + 2
			}
			cur = ptr
			continue
		}
		if length&0xc0 != 0 || length > 63 {
			return "", 0, false
		}
		cur++
		if cur+length > len(msg) {
			return "", 0, false
		}
		labels = append(labels, strings.ToLower(string(msg[cur:cur+length])))
		cur += length
		if len(labels) > 128 {
			return "", 0, false
		}
	}
	return strings.Join(labels, "."), nextAfter, true
}

// AppendDNSNameForTest 将域名按 RFC 1035 标签序列追加至缓冲区（同时供内部探针与黑盒测试使用）。
func AppendDNSNameForTest(dst []byte, name string) []byte {
	trimmed := strings.Trim(strings.TrimSpace(name), ".")
	if trimmed != "" {
		for label := range strings.SplitSeq(trimmed, ".") {
			if len(label) == 0 || len(label) > 63 {
				continue
			}
			dst = append(dst, byte(len(label)))
			dst = append(dst, label...)
		}
	}
	return append(dst, 0)
}

// AnswerPacket 解析单条 RFC 1035 查询并构建应答报文：
//   - 非法/截断/非查询报文返回 ok=false（静默丢弃）
//   - 非受管后缀域名返回 REFUSED（严禁成为开放递归解析器）
//   - 受管后缀内未命中主机返回 NXDOMAIN
//   - 命中主机但请求的记录类型不存在（如仅 IPv4 主机查 AAAA）返回 NOERROR + 0 条记录（NODATA）
func (idx *RecordIndex) AnswerPacket(req []byte) ([]byte, bool) {
	if len(req) < 12 {
		return nil, false
	}
	flags := binary.BigEndian.Uint16(req[2:4])
	if flags&0x8000 != 0 {
		// QR=1 表示这是响应包而非查询包
		return nil, false
	}
	qdCount := binary.BigEndian.Uint16(req[4:6])
	if qdCount == 0 {
		return nil, false
	}

	qname, nextOff, ok := parseDNSName(req, 12)
	if !ok || nextOff+4 > len(req) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(req[nextOff : nextOff+2])
	qclass := binary.BigEndian.Uint16(req[nextOff+2 : nextOff+4])
	questionEnd := nextOff + 4

	var (
		rcode   uint8 = RcodeNoError
		answers []netip.Addr
	)
	if !idx.inScope(qname) {
		rcode = RcodeRefused
	} else if qclass != ClassIN && qclass != TypeANY {
		rcode = RcodeRefused
	} else if addrs, found := idx.lookup(qname); !found {
		rcode = RcodeNXDomain
	} else {
		switch qtype {
		case TypeA:
			answers = addrs.v4
		case TypeAAAA:
			answers = addrs.v6
		case TypeANY:
			answers = append(append([]netip.Addr(nil), addrs.v4...), addrs.v6...)
		default:
			// 其它记录类型（如 HTTPS / SVCB / TXT / MX）返回 NODATA (NOERROR, ancount=0)
			answers = nil
		}
	}

	// 构造标准响应头：QR=1, AA=1, 保留客户端 RD 位，RA=0（纯权威应答，不做递归）
	respFlags := uint16(0x8400) | (flags & 0x0100) | uint16(rcode&0x0f)
	resp := make([]byte, 0, questionEnd+len(answers)*28)
	resp = append(resp, req[:12]...)
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	// 复制首条 Question 段，后续 Answer 统一使用 0xc00c 压缩指针指向 QNAME
	resp = append(resp, req[12:questionEnd]...)

	for _, ip := range answers {
		resp = append(resp, 0xc0, 0x0c) // 指向偏移 12 的 QNAME
		if ip.Is4() {
			raw4 := ip.As4()
			resp = binary.BigEndian.AppendUint16(resp, TypeA)
			resp = binary.BigEndian.AppendUint16(resp, ClassIN)
			resp = binary.BigEndian.AppendUint32(resp, defaultTT)
			resp = binary.BigEndian.AppendUint16(resp, 4)
			resp = append(resp, raw4[:]...)
		} else {
			raw6 := ip.As16()
			resp = binary.BigEndian.AppendUint16(resp, TypeAAAA)
			resp = binary.BigEndian.AppendUint16(resp, ClassIN)
			resp = binary.BigEndian.AppendUint32(resp, defaultTT)
			resp = binary.BigEndian.AppendUint16(resp, 16)
			resp = append(resp, raw6[:]...)
		}
	}
	return resp, true
}

// ProbeDNSRecord 向指定 UDP DNS 服务器（host:port）发送 A 记录查询，返回解析出的 IPv4 列表与往返耗时。
func ProbeDNSRecord(ctx context.Context, serverAddr, domain string, timeout time.Duration) ([]string, time.Duration, error) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", serverAddr)
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	var txid [2]byte
	_, _ = rand.Read(txid[:])

	pkt := make([]byte, 12)
	pkt[0], pkt[1] = txid[0], txid[1]
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT=1
	pkt = AppendDNSNameForTest(pkt, domain)
	pkt = binary.BigEndian.AppendUint16(pkt, TypeA)
	pkt = binary.BigEndian.AppendUint16(pkt, ClassIN)

	start := time.Now()
	if _, err := conn.Write(pkt); err != nil {
		return nil, time.Since(start), err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, err
	}
	if n < 12 || buf[0] != txid[0] || buf[1] != txid[1] || buf[2]&0x80 == 0 {
		return nil, rtt, errors.New("invalid DNS response header")
	}
	rcode := buf[3] & 0x0f
	if rcode != RcodeNoError {
		return nil, rtt, fmt.Errorf("DNS rcode=%d", rcode)
	}

	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	off := 12
	for range qd {
		_, next, ok := parseDNSName(buf[:n], off)
		if !ok || next+4 > n {
			return nil, rtt, errors.New("malformed DNS response question")
		}
		off = next + 4
	}
	var ips []string
	for range an {
		_, next, ok := parseDNSName(buf[:n], off)
		if !ok || next+10 > n {
			break
		}
		rtype := binary.BigEndian.Uint16(buf[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(buf[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdlen > n {
			break
		}
		if rtype == TypeA && rdlen == 4 {
			if ip, ok := netip.AddrFromSlice(buf[rdataStart : rdataStart+4]); ok {
				ips = append(ips, ip.String())
			}
		} else if rtype == TypeAAAA && rdlen == 16 {
			if ip, ok := netip.AddrFromSlice(buf[rdataStart : rdataStart+16]); ok {
				ips = append(ips, ip.String())
			}
		}
		off = rdataStart + rdlen
	}
	return ips, rtt, nil
}
