// 文件职责：测试纯 Go RFC 1035 本地域名 DNS 报文解析、A/AAAA/NODATA/NXDOMAIN/REFUSED 应答与通配子域匹配安全边界。
package homedomain_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"singctl/internal/config"
	"singctl/internal/homedomain"
)

func buildTestDNSQuery(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], id)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT=1
	pkt = homedomain.AppendDNSNameForTest(pkt, name)
	pkt = binary.BigEndian.AppendUint16(pkt, qtype)
	pkt = binary.BigEndian.AppendUint16(pkt, 1) // IN
	return pkt
}

func TestDNSWire_LookupAndWireReply(t *testing.T) {
	idx := homedomain.NewRecordIndex("home", []config.DNSRewriteRule{
		{Domain: "nas.home", Answer: "192.0.2.10"},
		{Domain: "*.nas.home", Answer: "192.0.2.10"},
		{Domain: "ax3000t.home", Answer: "100.64.0.22"},
		{Domain: "v6box.home", Answer: "2001:db8::10"},
	})

	// 1. Exact A query (case-insensitive)
	q := buildTestDNSQuery(t, 0x1234, "AX3000T.HOME", homedomain.TypeA)
	resp, ok := idx.AnswerPacket(q)
	if !ok || len(resp) < 16 {
		t.Fatalf("expected valid A response, ok=%v len=%d", ok, len(resp))
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatalf("txid mismatch")
	}
	if rcode := resp[3] & 0x0f; rcode != homedomain.RcodeNoError {
		t.Fatalf("expected NOERROR, got rcode=%d", rcode)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
		t.Fatalf("expected 1 A answer, got %d", ancount)
	}
	gotIP, _ := netip.AddrFromSlice(resp[len(resp)-4:])
	if gotIP.String() != "100.64.0.22" {
		t.Fatalf("expected 100.64.0.22, got %s", gotIP)
	}

	// 2. Wildcard subdomain match (*.nas.home)
	qWild := buildTestDNSQuery(t, 0x2222, "jellyfin.nas.home", homedomain.TypeA)
	respWild, ok := idx.AnswerPacket(qWild)
	if !ok || (respWild[3]&0x0f) != homedomain.RcodeNoError || binary.BigEndian.Uint16(respWild[6:8]) != 1 {
		t.Fatalf("expected wildcard A answer for jellyfin.nas.home")
	}
	gotWildIP, _ := netip.AddrFromSlice(respWild[len(respWild)-4:])
	if gotWildIP.String() != "192.0.2.10" {
		t.Fatalf("expected 192.0.2.10, got %s", gotWildIP)
	}

	// 3. AAAA for IPv4-only host MUST return NOERROR with 0 answers (NODATA, not NXDOMAIN!)
	qNoData := buildTestDNSQuery(t, 0x3333, "nas.home", homedomain.TypeAAAA)
	respNoData, ok := idx.AnswerPacket(qNoData)
	if !ok || (respNoData[3]&0x0f) != homedomain.RcodeNoError || binary.BigEndian.Uint16(respNoData[6:8]) != 0 {
		t.Fatalf("expected NODATA (NOERROR, ancount=0) for IPv4-only AAAA query, got rcode=%d an=%d",
			respNoData[3]&0x0f, binary.BigEndian.Uint16(respNoData[6:8]))
	}

	// 4. Exact AAAA query
	qV6 := buildTestDNSQuery(t, 0x4444, "v6box.home", homedomain.TypeAAAA)
	respV6, ok := idx.AnswerPacket(qV6)
	if !ok || (respV6[3]&0x0f) != homedomain.RcodeNoError || binary.BigEndian.Uint16(respV6[6:8]) != 1 {
		t.Fatalf("expected AAAA answer for v6box.home")
	}
	gotV6, _ := netip.AddrFromSlice(respV6[len(respV6)-16:])
	if gotV6.String() != "2001:db8::10" {
		t.Fatalf("expected 2001:db8::10, got %s", gotV6)
	}

	// 5. Unknown name under managed suffix -> NXDOMAIN
	qNX := buildTestDNSQuery(t, 0x5555, "unknown.home", homedomain.TypeA)
	respNX, ok := idx.AnswerPacket(qNX)
	if !ok || (respNX[3]&0x0f) != homedomain.RcodeNXDomain {
		t.Fatalf("expected NXDOMAIN for unknown.home, got rcode=%d", respNX[3]&0x0f)
	}

	// 6. Out-of-scope public domain -> REFUSED (never act as open resolver!)
	qExt := buildTestDNSQuery(t, 0x6666, "example.com", homedomain.TypeA)
	respExt, ok := idx.AnswerPacket(qExt)
	if !ok || (respExt[3]&0x0f) != homedomain.RcodeRefused {
		t.Fatalf("expected REFUSED for example.com, got rcode=%d", respExt[3]&0x0f)
	}

	// 7. Malformed / truncated / pointer-loop packets must fail safely without panic
	badPackets := [][]byte{
		nil,
		{},
		{0x01, 0x02, 0x03},
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}, // compression pointer loop
		{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 63, 'a', 'b'},           // truncated label
	}
	for i, bp := range badPackets {
		if _, ok := idx.AnswerPacket(bp); ok {
			t.Fatalf("malformed packet #%d unexpectedly answered", i)
		}
	}
}
