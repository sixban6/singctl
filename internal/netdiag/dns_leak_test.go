package netdiag

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"

	"singctl/internal/gateway"
)

func startMockUDPServer(t *testing.T, handler func(qname string, qtype uint16) ([]net.IP, []string)) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := pc.ReadFrom(buf)
			if rErr != nil {
				return
			}
			if n < 17 {
				continue
			}
			pkt := buf[:n]
			qname, qend := decodeMockQName(pkt, 12)
			if qend+4 > len(pkt) {
				continue
			}
			qtype := binary.BigEndian.Uint16(pkt[qend : qend+2])
			ips, txts := handler(qname, qtype)

			var resp []byte
			resp = append(resp, pkt[0], pkt[1], 0x81, 0x80, 0x00, 0x01)
			ansCount := uint16(len(ips) + len(txts))
			resp = binary.BigEndian.AppendUint16(resp, ansCount)
			resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NS=0, AR=0
			resp = append(resp, pkt[12:qend+4]...)

			for _, ip := range ips {
				resp = append(resp, 0xC0, 0x0C) // pointer to question QNAME
				if qtype == dnsTypeAAAA && ip.To16() != nil && ip.To4() == nil {
					resp = binary.BigEndian.AppendUint16(resp, dnsTypeAAAA)
					resp = binary.BigEndian.AppendUint16(resp, 1)
					resp = binary.BigEndian.AppendUint32(resp, 60)
					resp = binary.BigEndian.AppendUint16(resp, 16)
					resp = append(resp, ip.To16()...)
				} else if ip4 := ip.To4(); ip4 != nil {
					resp = binary.BigEndian.AppendUint16(resp, dnsTypeA)
					resp = binary.BigEndian.AppendUint16(resp, 1)
					resp = binary.BigEndian.AppendUint32(resp, 60)
					resp = binary.BigEndian.AppendUint16(resp, 4)
					resp = append(resp, ip4...)
				}
			}
			for _, txt := range txts {
				resp = append(resp, 0xC0, 0x0C)
				if qtype == dnsTypeHTTPS {
					resp = binary.BigEndian.AppendUint16(resp, dnsTypeHTTPS)
					resp = binary.BigEndian.AppendUint16(resp, 1)
					resp = binary.BigEndian.AppendUint32(resp, 60)
					resp = binary.BigEndian.AppendUint16(resp, 3)
					resp = append(resp, 0x00, 0x01, 0x00) // SvcPriority=1, TargetName="."
					_ = txt
					continue
				}
				resp = binary.BigEndian.AppendUint16(resp, dnsTypeTXT)
				resp = binary.BigEndian.AppendUint16(resp, 1)
				resp = binary.BigEndian.AppendUint32(resp, 60)
				resp = binary.BigEndian.AppendUint16(resp, uint16(1+len(txt)))
				resp = append(resp, byte(len(txt)))
				resp = append(resp, []byte(txt)...)
			}
			_, _ = pc.WriteTo(resp, addr)
		}
	}()

	return pc.LocalAddr().String()
}

func decodeMockQName(msg []byte, offset int) (string, int) {
	var parts []string
	cur := offset
	for cur < len(msg) {
		l := int(msg[cur])
		cur++
		if l == 0 {
			break
		}
		if cur+l > len(msg) {
			break
		}
		parts = append(parts, string(msg[cur:cur+l]))
		cur += l
	}
	return strings.Join(parts, "."), cur
}

func TestRunDNSLeakTest_SafeCNOnlyAndLeakedDetection(t *testing.T) {
	mockSafeDNS := startMockUDPServer(t, func(qname string, qtype uint16) ([]net.IP, []string) {
		switch {
		case qtype == dnsTypeTXT && qname == "o-o.myaddr.l.google.com":
			return nil, []string{"203.0.113.53", "edns0-client-subnet 198.51.100.0/24"}
		case qtype == dnsTypeA && (qname == "www.google.com" || qname == "github.com"):
			return []net.IP{net.ParseIP("203.0.113.80")}, nil
		case qtype == dnsTypeAAAA && qname == "www.bilibili.com":
			return []net.IP{netip.MustParseAddr("2001:db8:1::10").AsSlice()}, nil
		case qtype == dnsTypeAAAA && qname == "www.google.com":
			return nil, nil // suppressed by predefined NOERROR
		default:
			return nil, nil
		}
	})

	lookupOverseas := func(_ context.Context, ip string) (*ISPInfo, error) {
		switch ip {
		case "203.0.113.53", "198.51.100.0":
			return &ISPInfo{IP: ip, Country: "United States", CountryCode: "US", ISP: "Google LLC"}, nil
		case "192.0.2.99":
			return &ISPInfo{IP: ip, Country: "China", CountryCode: "CN", ISP: "China Telecom"}, nil
		default:
			return &ISPInfo{IP: ip, Country: "United States", CountryCode: "US", ISP: "Example ISP"}, nil
		}
	}
	lookupHome := func(_ context.Context) (*ISPInfo, error) {
		return &ISPInfo{IP: "192.0.2.88", Country: "China", CountryCode: "CN", ISP: "China Telecom"}, nil
	}

	// 1. Safe cn_only scenario
	rep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
		IPv6Mode:          "cn_only",
		GatewayMode:       "main",
		SingBoxRunning:    true,
		AdGuardHealthy:    true,
		PrimaryDNS:        mockSafeDNS,
		PlaintextProbeDNS: mockSafeDNS,
		SkipTCP6Dial:      true,
		LookupISP:         lookupOverseas,
		LookupHomeISP:     lookupHome,
		IPv6Status: gateway.IPv6StatusInfo{
			IsOpenWrt:         true,
			DnsmasqFilterAAAA: "0",
			DnsmasqForwardMax: "1024",
			LANPrefixes:       []string{"2001:db8:1::/64"},
			RADNSAnnounce:     false,
		},
	})
	if rep.Verdict != "safe" {
		t.Fatalf("expected verdict=safe in clean cn_only setup, got %q (%+v)", rep.Verdict, rep.Checks)
	}
	if rep.OverseasResolver == nil || rep.OverseasResolver.IP != "203.0.113.53" || rep.OverseasResolver.CountryCode != "US" {
		t.Fatalf("unexpected resolver profile: %+v", rep.OverseasResolver)
	}

	// 2. Leaked scenario (overseas resolver returns CN IP + overseas AAAA leaked under cn_only)
	mockLeakedDNS := startMockUDPServer(t, func(qname string, qtype uint16) ([]net.IP, []string) {
		switch {
		case qtype == dnsTypeTXT && qname == "o-o.myaddr.l.google.com":
			return nil, []string{"192.0.2.99", "edns0-client-subnet 192.0.2.0/24"}
		case qtype == dnsTypeA:
			return []net.IP{net.ParseIP("203.0.113.80")}, nil
		case qtype == dnsTypeAAAA && qname == "www.google.com":
			return []net.IP{netip.MustParseAddr("2001:db8:2::44").AsSlice()}, nil
		default:
			return nil, nil
		}
	})

	leakedRep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
		IPv6Mode:          "cn_only",
		GatewayMode:       "main",
		SingBoxRunning:    true,
		AdGuardHealthy:    true,
		PrimaryDNS:        mockLeakedDNS,
		PlaintextProbeDNS: mockLeakedDNS,
		SkipTCP6Dial:      true,
		LookupISP:         lookupOverseas,
		LookupHomeISP:     lookupHome,
	})
	if leakedRep.Verdict != "leaked" {
		t.Fatalf("expected verdict=leaked when CN resolver and overseas AAAA leak occur, got %q (%+v)", leakedRep.Verdict, leakedRep.Checks)
	}

	// 3. Warn when OpenWrt still announces IPv6 RDNSS or keeps low dnsforwardmax
	for _, tc := range []struct {
		name string
		st   gateway.IPv6StatusInfo
	}{
		{
			name: "ra_dns_enabled",
			st: gateway.IPv6StatusInfo{
				IsOpenWrt:         true,
				DnsmasqFilterAAAA: "0",
				DnsmasqForwardMax: "1024",
				LANPrefixes:       []string{"2001:db8:1::/64"},
				RADNSAnnounce:     true,
			},
		},
		{
			name: "dnsforwardmax_missing",
			st: gateway.IPv6StatusInfo{
				IsOpenWrt:         true,
				DnsmasqFilterAAAA: "0",
				LANPrefixes:       []string{"2001:db8:1::/64"},
				RADNSAnnounce:     false,
			},
		},
		{
			name: "dnsforwardmax_150",
			st: gateway.IPv6StatusInfo{
				IsOpenWrt:         true,
				DnsmasqFilterAAAA: "0",
				DnsmasqForwardMax: "150",
				LANPrefixes:       []string{"2001:db8:1::/64"},
				RADNSAnnounce:     false,
			},
		},
	} {
		warnRep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
			IPv6Mode:          "cn_only",
			GatewayMode:       "main",
			SingBoxRunning:    true,
			AdGuardHealthy:    true,
			PrimaryDNS:        mockSafeDNS,
			PlaintextProbeDNS: mockSafeDNS,
			SkipTCP6Dial:      true,
			SkipMultiProbe:    true,
			LookupISP:         lookupOverseas,
			LookupHomeISP:     lookupHome,
			IPv6Status:        tc.st,
		})
		if warnRep.Verdict != "warning" {
			t.Fatalf("%s: expected verdict=warning, got %q (%+v)", tc.name, warnRep.Verdict, warnRep.Checks)
		}
	}

	// 4. Catch overseas HTTPS (Type 65) leak even when AAAA is suppressed under cn_only
	mockHTTPSLeakDNS := startMockUDPServer(t, func(qname string, qtype uint16) ([]net.IP, []string) {
		switch {
		case qtype == dnsTypeTXT && qname == "o-o.myaddr.l.google.com":
			return nil, []string{"203.0.113.53", "edns0-client-subnet 198.51.100.0/24"}
		case qtype == dnsTypeA && (qname == "www.google.com" || qname == "github.com"):
			return []net.IP{net.ParseIP("203.0.113.80")}, nil
		case qtype == dnsTypeAAAA && qname == "www.bilibili.com":
			return []net.IP{netip.MustParseAddr("2001:db8:1::10").AsSlice()}, nil
		case qtype == dnsTypeHTTPS && qname == "www.google.com":
			return nil, []string{"https-rr"}
		default:
			return nil, nil
		}
	})
	httpsLeakRep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
		IPv6Mode:          "cn_only",
		GatewayMode:       "main",
		SingBoxRunning:    true,
		AdGuardHealthy:    true,
		PrimaryDNS:        mockHTTPSLeakDNS,
		PlaintextProbeDNS: mockHTTPSLeakDNS,
		SkipTCP6Dial:      true,
		SkipMultiProbe:    true,
		LookupISP:         lookupOverseas,
		LookupHomeISP:     lookupHome,
	})
	if httpsLeakRep.Verdict != "leaked" {
		t.Fatalf("expected verdict=leaked when overseas HTTPS Type 65 leaks under cn_only, got %q (%+v)", httpsLeakRep.Verdict, httpsLeakRep.Checks)
	}
}

func TestParseEDNSGeoAndSameIPv6Prefix48(t *testing.T) {
	c, cc, isp := parseEDNSGeo("United States - Google LLC")
	if c != "United States" || cc != "US" || isp != "Google LLC" {
		t.Fatalf("unexpected parseEDNSGeo US output: c=%q cc=%q isp=%q", c, cc, isp)
	}
	_, cnCC, cnISP := parseEDNSGeo("China - China Telecom")
	if cnCC != "CN" || cnISP != "China Telecom" {
		t.Fatalf("unexpected parseEDNSGeo CN output: cc=%q isp=%q", cnCC, cnISP)
	}

	if !sameIPv6Prefix48("2001:db8:abcd:1::10", "2001:db8:abcd:ff::99") {
		t.Fatal("expected addresses sharing /48 prefix to match")
	}
	if sameIPv6Prefix48("2001:db8:abcd:1::10", "2001:db8:9999:1::10") {
		t.Fatal("expected addresses with different /48 prefix not to match")
	}
}

func TestRunDNSLeakTest_MultiRoundAggregationAndMixedLeak(t *testing.T) {
	mockSafeDNS := startMockUDPServer(t, func(qname string, qtype uint16) ([]net.IP, []string) {
		switch {
		case qtype == dnsTypeTXT && qname == "o-o.myaddr.l.google.com":
			return nil, []string{"203.0.113.53", "edns0-client-subnet 198.51.100.0/24"}
		case qtype == dnsTypeA && (qname == "www.google.com" || qname == "github.com"):
			return []net.IP{net.ParseIP("203.0.113.80")}, nil
		case qtype == dnsTypeAAAA && qname == "www.bilibili.com":
			return []net.IP{netip.MustParseAddr("2001:db8:1::10").AsSlice()}, nil
		default:
			return nil, nil
		}
	})
	lookupOverseas := func(_ context.Context, ip string) (*ISPInfo, error) {
		switch ip {
		case "192.0.2.55":
			return &ISPInfo{IP: ip, Country: "China", CountryCode: "CN", ISP: "China Telecom"}, nil
		default:
			return &ISPInfo{IP: ip, Country: "United States", CountryCode: "US", ISP: "Google LLC"}, nil
		}
	}

	// 1. Clean 4-round aggregation across multiple US/JP resolvers
	rep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
		IPv6Mode:          "cn_only",
		GatewayMode:       "main",
		SingBoxRunning:    true,
		AdGuardHealthy:    true,
		PrimaryDNS:        mockSafeDNS,
		PlaintextProbeDNS: mockSafeDNS,
		SkipTCP6Dial:      true,
		GatewayRounds:     4,
		LookupISP:         lookupOverseas,
		EgressProber: func(context.Context) *EgressMatrix {
			return &EgressMatrix{
				DomesticIPv4: &EgressEndpoint{IP: "192.0.2.88", Country: "中国", CountryCode: "CN", ISP: "电信", Reachable: true},
				DomesticIPv6: &EgressEndpoint{IP: "2001:db8:1111:1::2", Country: "中国", CountryCode: "CN", ISP: "电信", Reachable: true},
				OverseasIPv4: &EgressEndpoint{IP: "198.51.100.44", Country: "United States", CountryCode: "US", ISP: "Example Transit", Reachable: true},
				OverseasIPv6: &EgressEndpoint{Reachable: false, Error: "AAAA blocked"},
			}
		},
		MultiProbeFetcher: func(_ context.Context, round int) (*EDNSProbeResult, error) {
			if round%2 == 0 {
				return &EDNSProbeResult{DNSIP: "203.0.113.53", DNSGeo: "United States - Google LLC", EDNSIP: "198.51.100.0"}, nil
			}
			return &EDNSProbeResult{DNSIP: "203.0.113.54", DNSGeo: "Japan - Cloudflare, Inc."}, nil
		},
	})
	if rep.Verdict != "safe" {
		t.Fatalf("expected verdict=safe, got %q (%+v)", rep.Verdict, rep.Checks)
	}
	if rep.GatewayRounds != 4 {
		t.Fatalf("expected GatewayRounds=4, got %d", rep.GatewayRounds)
	}
	if len(rep.DNSServers) != 2 {
		t.Fatalf("expected 2 aggregated DNS servers, got %+v", rep.DNSServers)
	}
	if rep.DNSServers[0].IP != "203.0.113.53" || rep.DNSServers[0].Hits != 3 { // 2 from EDNS rounds + 1 from TXT probe
		t.Fatalf("expected 203.0.113.53 hits=3, got %+v", rep.DNSServers[0])
	}
	if rep.DNSServers[1].IP != "203.0.113.54" || rep.DNSServers[1].CountryCode != "JP" || rep.DNSServers[1].Hits != 2 {
		t.Fatalf("expected 203.0.113.54 JP hits=2, got %+v", rep.DNSServers[1])
	}

	// 2. Catch 1 leaked CN resolver hidden among 3 clean US rounds
	mixedRep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
		IPv6Mode:          "cn_only",
		GatewayMode:       "main",
		SingBoxRunning:    true,
		AdGuardHealthy:    true,
		PrimaryDNS:        mockSafeDNS,
		PlaintextProbeDNS: mockSafeDNS,
		SkipTCP6Dial:      true,
		GatewayRounds:     4,
		LookupISP:         lookupOverseas,
		EgressProber: func(context.Context) *EgressMatrix {
			return &EgressMatrix{
				DomesticIPv4: &EgressEndpoint{IP: "192.0.2.88", CountryCode: "CN", Reachable: true},
				OverseasIPv6: &EgressEndpoint{Reachable: false},
			}
		},
		MultiProbeFetcher: func(_ context.Context, round int) (*EDNSProbeResult, error) {
			if round == 2 {
				return &EDNSProbeResult{DNSIP: "192.0.2.55", DNSGeo: "China - China Telecom"}, nil
			}
			return &EDNSProbeResult{DNSIP: "203.0.113.53", DNSGeo: "United States - Google LLC"}, nil
		},
	})
	if mixedRep.Verdict != "leaked" {
		t.Fatalf("expected verdict=leaked when 1 of 4 rounds leaks to CN DNS, got %q", mixedRep.Verdict)
	}
	if len(mixedRep.DNSServers) == 0 || !mixedRep.DNSServers[0].Leaked || mixedRep.DNSServers[0].IP != "192.0.2.55" {
		t.Fatalf("expected leaked CN resolver sorted first, got %+v", mixedRep.DNSServers)
	}

	// 3. Catch IPv6 home /48 egress leak even if DNS mock omitted overseas AAAA
	v6LeakRep := RunDNSLeakTest(t.Context(), DNSLeakTestOptions{
		IPv6Mode:          "cn_only",
		GatewayMode:       "main",
		SingBoxRunning:    true,
		AdGuardHealthy:    true,
		PrimaryDNS:        mockSafeDNS,
		PlaintextProbeDNS: mockSafeDNS,
		SkipTCP6Dial:      true,
		SkipMultiProbe:    true,
		LookupISP:         lookupOverseas,
		EgressProber: func(context.Context) *EgressMatrix {
			return &EgressMatrix{
				DomesticIPv4: &EgressEndpoint{IP: "192.0.2.88", CountryCode: "CN", Reachable: true},
				DomesticIPv6: &EgressEndpoint{IP: "2001:db8:abcd:1::2", CountryCode: "CN", Reachable: true},
				OverseasIPv6: &EgressEndpoint{IP: "2001:db8:abcd:2::99", CountryCode: "CN", Reachable: true},
			}
		},
	})
	if v6LeakRep.Verdict != "leaked" {
		t.Fatalf("expected verdict=leaked when overseas IPv6 shares home /48 prefix under cn_only, got %q", v6LeakRep.Verdict)
	}
}
