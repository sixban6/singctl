// 文件职责：提供底层 UDP/DNS 探测报文编解码原语、网关 DNS 回退查询与目标 IP ISP 归属探测。
package netdiag

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
)

func probeDNSEgressResolver(ctx context.Context, primaryDNS string) (resolverIP, ecsCIDR, viaAddr string, err error) {
	cands := candidateGatewayDNSServers(primaryDNS)
	var lastErr error
	for _, srv := range cands {
		if ans, qErr := queryDNSUDP(ctx, srv, "o-o.myaddr.l.google.com", DNSTypeTXT); qErr == nil {
			ip, ecs := parseResolverTXT(ans.TXTs)
			if ip != "" {
				return ip, ecs, srv, nil
			}
		} else {
			lastErr = qErr
		}
		if ans2, qErr2 := queryDNSUDP(ctx, srv, "whoami.ds.akahelp.net", DNSTypeTXT); qErr2 == nil {
			ip, ecs := parseResolverTXT(ans2.TXTs)
			if ip != "" {
				return ip, ecs, srv, nil
			}
		} else if lastErr == nil {
			lastErr = qErr2
		}
	}
	if lastErr == nil {
		lastErr = errors.New("未收到有效的 DNS TXT 溯源响应")
	}
	return "", "", "", lastErr
}

func parseResolverTXT(txts []string) (resolverIP, ecsCIDR string) {
	for _, raw := range txts {
		s := strings.Trim(strings.TrimSpace(raw), `"`)
		if s == "" {
			continue
		}
		if addr, err := netip.ParseAddr(s); err == nil {
			if resolverIP == "" {
				resolverIP = addr.Unmap().String()
			}
			continue
		}
		lower := strings.ToLower(s)
		if rest, ok := strings.CutPrefix(lower, "edns0-client-subnet "); ok {
			cand := strings.TrimSpace(rest)
			if pfx, err := netip.ParsePrefix(cand); err == nil {
				ecsCIDR = pfx.String()
			} else if addr, err := netip.ParseAddr(cand); err == nil {
				ecsCIDR = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String()
			}
			continue
		}
		fields := strings.Fields(s)
		if len(fields) == 2 {
			switch strings.ToLower(fields[0]) {
			case "ns", "ip":
				if resolverIP == "" {
					if addr, err := netip.ParseAddr(fields[1]); err == nil {
						resolverIP = addr.Unmap().String()
					}
				}
			case "ecs":
				if ecsCIDR == "" {
					if pfx, err := netip.ParsePrefix(fields[1]); err == nil {
						ecsCIDR = pfx.String()
					} else if addr, err := netip.ParseAddr(fields[1]); err == nil {
						ecsCIDR = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()).String()
					}
				}
			}
		}
	}
	return resolverIP, ecsCIDR
}

func formatResolverProfileLine(p *DNSResolverProfile) string {
	if p == nil {
		return ""
	}
	parts := []string{"解析器=" + cmp.Or(p.IP, "unknown")}
	if p.CountryCode != "" {
		parts = append(parts, "归属="+p.CountryCode)
	}
	if p.ISP != "" {
		parts = append(parts, "ISP="+p.ISP)
	}
	if p.ECS != "" {
		ecsStr := "ECS=" + p.ECS
		if p.ECSCountryCode != "" {
			ecsStr += " (" + p.ECSCountryCode + ")"
		}
		parts = append(parts, ecsStr)
	}
	return strings.Join(parts, " · ")
}

func candidateGatewayDNSServers(primaryDNS string) []string {
	if trimmed := strings.TrimSpace(primaryDNS); trimmed != "" {
		return []string{ensureDNSPort(trimmed)}
	}
	return []string{"127.0.0.1:53", "8.8.8.8:53"}
}

func ensureDNSPort(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return net.JoinHostPort(strings.Trim(addr, "[]"), "53")
}

func queryGatewayDNS(ctx context.Context, primaryDNS, domain string, qType uint16) (dnsAnswerSet, error) {
	return queryDNSWithFallback(ctx, candidateGatewayDNSServers(primaryDNS), domain, qType)
}

func queryDNSWithFallback(ctx context.Context, servers []string, domain string, qType uint16) (dnsAnswerSet, error) {
	var lastErr error
	for _, srv := range servers {
		ans, err := queryDNSUDP(ctx, srv, domain, qType)
		if err == nil {
			return ans, nil
		}
		lastErr = err
	}
	return dnsAnswerSet{}, lastErr
}

func queryDNSUDP(ctx context.Context, serverAddr, domain string, qType uint16) (dnsAnswerSet, error) {
	pkt, txid, err := buildDNSLeakQueryPacket(domain, qType)
	if err != nil {
		return dnsAnswerSet{}, err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "udp", ensureDNSPort(serverAddr))
	if err != nil {
		return dnsAnswerSet{}, err
	}
	defer conn.Close()

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(pkt); err != nil {
		return dnsAnswerSet{}, err
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return dnsAnswerSet{}, err
	}
	return parseDNSAnswerPacket(resp[:n], txid)
}

func buildDNSLeakQueryPacket(domain string, qType uint16) ([]byte, [2]byte, error) {
	var txid [2]byte
	_, _ = rand.Read(txid[:])

	clean := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if clean == "" {
		return nil, txid, errors.New("DNS 探测域名不能为空")
	}

	var buf bytes.Buffer
	buf.Write(txid[:])
	buf.Write([]byte{
		0x01, 0x00, // RD=1
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	})
	for label := range strings.SplitSeq(clean, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, txid, fmt.Errorf("invalid domain label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)
	var qt [4]byte
	binary.BigEndian.PutUint16(qt[0:2], qType)
	binary.BigEndian.PutUint16(qt[2:4], 1) // QCLASS=IN
	buf.Write(qt[:])
	return buf.Bytes(), txid, nil
}

func parseDNSAnswerPacket(msg []byte, expectedTxID [2]byte) (dnsAnswerSet, error) {
	var out dnsAnswerSet
	if len(msg) < 12 {
		return out, errors.New("DNS 响应报文过短")
	}
	if msg[0] != expectedTxID[0] || msg[1] != expectedTxID[1] {
		return out, errors.New("DNS 事务 ID 不匹配")
	}
	out.RCode = msg[3] & 0x0F
	if out.RCode != 0 {
		return out, fmt.Errorf("DNS RCODE=%d", out.RCode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	offset := 12
	for range qdCount {
		next, err := skipDNSLeakName(msg, offset)
		if err != nil {
			return out, err
		}
		if next+4 > len(msg) {
			return out, errors.New("DNS Question 截断")
		}
		offset = next + 4
	}

	for range anCount {
		next, err := skipDNSLeakName(msg, offset)
		if err != nil {
			return out, err
		}
		if next+10 > len(msg) {
			return out, errors.New("DNS Answer 头部截断")
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(msg) {
			return out, errors.New("DNS Answer 数据截断")
		}
		rdata := msg[rdataStart : rdataStart+rdLen]
		switch rrType {
		case DNSTypeA:
			if rdLen == 4 {
				ip := netip.AddrFrom4([4]byte(rdata)).String()
				if !slices.Contains(out.As, ip) {
					out.As = append(out.As, ip)
				}
			}
		case DNSTypeAAAA:
			if rdLen == 16 {
				ip := netip.AddrFrom16([16]byte(rdata)).Unmap().String()
				if !slices.Contains(out.AAAAs, ip) {
					out.AAAAs = append(out.AAAAs, ip)
				}
			}
		case DNSTypeTXT:
			var txtBuilder strings.Builder
			pos := 0
			for pos < len(rdata) {
				segLen := int(rdata[pos])
				pos++
				if pos+segLen > len(rdata) {
					break
				}
				txtBuilder.Write(rdata[pos : pos+segLen])
				pos += segLen
			}
			if txtVal := strings.TrimSpace(txtBuilder.String()); txtVal != "" {
				out.TXTs = append(out.TXTs, txtVal)
			}
		case DNSTypeHTTPS:
			out.HTTPSCount++
		}
		offset = rdataStart + rdLen
	}
	return out, nil
}

func skipDNSLeakName(msg []byte, offset int) (int, error) {
	cur := offset
	for range 128 {
		if cur >= len(msg) {
			return 0, errors.New("DNS 域名越界")
		}
		b := msg[cur]
		if b == 0 {
			return cur + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if cur+1 >= len(msg) {
				return 0, errors.New("DNS 压缩指针截断")
			}
			return cur + 2, nil
		}
		cur += 1 + int(b)
	}
	return 0, errors.New("DNS 域名层级过深")
}

func lookupTargetISPWithFallback(ctx context.Context, ip string) (*ISPInfo, error) {
	if info, err := GetTargetISP(ctx, ip); err == nil && info != nil {
		return info, nil
	}
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ip.sb/geoip/"+ip, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (singctl netdiag)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, err
	}
	var data ipSBResponse
	if err := json.Unmarshal(body, &data); err != nil || data.IP == "" {
		return nil, fmt.Errorf("ip.sb lookup failed for %s", ip)
	}
	asnStr := ""
	if data.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d %s", data.ASN, data.ASNOrg)
	}
	info := &ISPInfo{
		IP:          data.IP,
		Country:     data.Country,
		CountryCode: data.CountryCode,
		Region:      data.Region,
		City:        data.City,
		ISP:         data.ISP,
		Org:         data.ASNOrg,
		ASN:         asnStr,
	}
	info.Type = CategorizeISP(info.ISP, info.Org, info.ASN, info.CountryCode)
	return info, nil
}
