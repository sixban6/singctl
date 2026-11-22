// 文件职责：负责 AdGuard Home 加密上游 DNS 的 RFC 1035/7858 Wireformat 并发竞速探测与透明代理运行时直连豁免。
package adguard

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProbeAllUpstreams 并发实测本地防劫持引擎端到端延迟及每条已配置加密上游的独立响应耗时，自动标记最快上游。
func (m *Manager) ProbeAllUpstreams(ctx context.Context, domain string) *ProbeReport {
	targetDomain := cmp.Or(strings.TrimSpace(domain), "qq.com")
	dnsAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(m.cfg.DNS.GetDNSPort()))
	upstreams, mode := m.GetConfiguredUpstreams(ctx)

	report := &ProbeReport{
		DNSAddr:           dnsAddr,
		Domain:            targetDomain,
		UpstreamMode:      mode,
		UpstreamModeLabel: UpstreamModeDescription(mode),
		Upstreams:         []UpstreamProbeItem{},
	}

	var (
		wg        sync.WaitGroup
		localErr  error
		localIPs  []string
		localCost time.Duration
		items     []UpstreamProbeItem
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := ProbeDNS(dnsAddr, 1200*time.Millisecond); err != nil {
			localErr = fmt.Errorf("本地引擎 %s 未响应: %v", dnsAddr, err)
			return
		}
		localIPs, localCost, localErr = ProbeUpstreamResolution(dnsAddr, targetDomain, 3500*time.Millisecond)
	}()

	go func() {
		defer wg.Done()
		items = ProbeUpstreamList(ctx, upstreams, targetDomain, 3200*time.Millisecond)
	}()
	wg.Wait()

	bestIdx := -1
	for i := range items {
		if !items[i].Healthy {
			continue
		}
		if bestIdx == -1 || items[i].LatencyMs < items[bestIdx].LatencyMs {
			bestIdx = i
		}
	}
	if bestIdx >= 0 {
		items[bestIdx].Fastest = true
		report.FastestUpstream = items[bestIdx].Address
		report.FastestName = items[bestIdx].Name
		report.FastestLatencyMs = items[bestIdx].LatencyMs
	}
	report.Upstreams = items

	if localErr != nil || len(localIPs) == 0 {
		report.Healthy = false
		if localErr != nil {
			report.Error = localErr.Error()
		} else {
			report.Error = "本地引擎未返回有效解析记录"
		}
		return report
	}

	report.Healthy = true
	report.Resolved = localIPs[0]
	report.LatencyMs = max(int64(1), localCost.Milliseconds())
	return report
}

// ProbeUpstreamList 并发直连实测一组 DoH / DoT 上游服务器的真实加密解析 RTT（绕过本地缓存）。
func ProbeUpstreamList(ctx context.Context, upstreams []string, domain string, timeout time.Duration) []UpstreamProbeItem {
	if len(upstreams) == 0 {
		return []UpstreamProbeItem{}
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	out := make([]UpstreamProbeItem, len(upstreams))
	var wg sync.WaitGroup
	for i, raw := range upstreams {
		wg.Add(1)
		go func(idx int, addr string) {
			defer wg.Done()
			out[idx] = ProbeSingleUpstream(ctx, addr, domain, timeout)
		}(i, raw)
	}
	wg.Wait()
	return out
}

// ProbeSingleUpstream 对单条加密上游 (https:// DoH 或 tls:// DoT) 执行标准 RFC 1035 Wireformat 查询并精确计时。
func ProbeSingleUpstream(ctx context.Context, upstream, domain string, timeout time.Duration) UpstreamProbeItem {
	meta := DescribeUpstream(upstream)
	item := UpstreamProbeItem{
		Address:  meta.Address,
		Name:     meta.Name,
		Protocol: meta.Protocol,
	}

	queryWire, txid, err := BuildDNSQueryPacket(domain)
	if err != nil {
		item.Error = err.Error()
		return item
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u, parseErr := url.Parse(strings.TrimSpace(upstream))
	if parseErr != nil || u.Host == "" {
		item.Error = "无效的上游 URL"
		return item
	}

	start := time.Now()
	var respWire []byte

	switch strings.ToLower(u.Scheme) {
	case "https":
		respWire, err = queryDoHWireformat(probeCtx, strings.TrimSpace(upstream), queryWire, timeout)
	case "tls":
		respWire, err = queryDoTWireformat(probeCtx, u, queryWire, timeout)
	default:
		err = fmt.Errorf("暂不支持直接探测协议 %s", u.Scheme)
	}
	elapsed := time.Since(start)

	if err != nil {
		item.Error = simplifyProbeError(err)
		return item
	}

	resolvedIP, parseRespErr := ParseDNSFirstARecord(respWire, txid)
	if parseRespErr != nil {
		item.Error = parseRespErr.Error()
		return item
	}

	item.Healthy = true
	item.LatencyMs = max(int64(1), elapsed.Milliseconds())
	item.Resolved = resolvedIP
	return item
}

func queryDoHWireformat(ctx context.Context, endpoint string, query []byte, timeout time.Duration) ([]byte, error) {
	tr := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func queryDoTWireformat(ctx context.Context, u *url.URL, query []byte, timeout time.Duration) ([]byte, error) {
	host := u.Hostname()
	port := cmp.Or(u.Port(), "853")
	addr := net.JoinHostPort(host, port)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(query)))
	copy(frame[2:], query)

	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen < 12 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DoT response length %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// BuildDNSQueryPacket 构造标准 RFC 1035 IPv4 A 记录查询报文并返回随机事务 ID。
func BuildDNSQueryPacket(domain string) ([]byte, [2]byte, error) {
	var txid [2]byte
	_, _ = rand.Read(txid[:])

	clean := strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if clean == "" {
		return nil, txid, errors.New("探测域名不能为空")
	}

	var buf bytes.Buffer
	buf.Write(txid[:])
	buf.Write([]byte{
		0x01, 0x00, // Standard query, RD=1
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
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // QTYPE=A, QCLASS=IN
	return buf.Bytes(), txid, nil
}

// ParseDNSFirstARecord 解析 DNS 响应报文中的首条 IPv4 A 记录（兼容 CNAME 与压缩指针）。
func ParseDNSFirstARecord(msg []byte, expectedTxID [2]byte) (string, error) {
	if len(msg) < 12 {
		return "", errors.New("DNS 响应报文过短")
	}
	if msg[0] != expectedTxID[0] || msg[1] != expectedTxID[1] {
		return "", errors.New("DNS 事务 ID 不匹配")
	}
	rcode := msg[3] & 0x0F
	if rcode != 0 {
		return "", fmt.Errorf("DNS 响应错误码 RCODE=%d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	if anCount == 0 {
		return "", errors.New("未返回任何解析记录")
	}

	offset := 12
	for range qdCount {
		next, err := skipDNSName(msg, offset)
		if err != nil {
			return "", err
		}
		if next+4 > len(msg) {
			return "", errors.New("DNS Question 字段截断")
		}
		offset = next + 4
	}

	var firstCNAME bool
	for range anCount {
		next, err := skipDNSName(msg, offset)
		if err != nil {
			return "", err
		}
		if next+10 > len(msg) {
			return "", errors.New("DNS Answer 头部截断")
		}
		rrType := binary.BigEndian.Uint16(msg[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataStart := next + 10
		if rdataStart+rdLen > len(msg) {
			return "", errors.New("DNS Answer 数据截断")
		}
		if rrType == 1 && rdLen == 4 {
			ip := net.IPv4(msg[rdataStart], msg[rdataStart+1], msg[rdataStart+2], msg[rdataStart+3])
			return ip.String(), nil
		}
		if rrType == 5 {
			firstCNAME = true
		}
		offset = rdataStart + rdLen
	}
	if firstCNAME {
		return "CNAME", nil
	}
	return "", errors.New("响应中未包含 IPv4 A 记录")
}

func skipDNSName(msg []byte, offset int) (int, error) {
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

func simplifyProbeError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "i/o timeout"):
		return "连接超时"
	case strings.Contains(s, "x509:"):
		return "TLS 证书不含该纯 IP 签名"
	case strings.Contains(s, "connection refused"):
		return "目标端口拒绝连接"
	default:
		return s
	}
}

func ensureRuntimeFirewallBypass(ips []string) {
	if runtime.GOOS != "linux" {
		return
	}
	var customIPv4s []string
	for _, raw := range ips {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil || ip.To4() == nil {
			continue
		}
		v4 := ip.To4().String()
		if !validIPv4LiteralRe.MatchString(v4) {
			continue
		}
		if _, builtin := builtinBypassIPv4Set[v4]; builtin {
			continue
		}
		if !slices.Contains(customIPv4s, v4) {
			customIPv4s = append(customIPv4s, v4)
		}
	}
	if len(customIPv4s) == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if nftPath, err := exec.LookPath("nft"); err == nil {
		out, listErr := exec.CommandContext(ctx, nftPath, "list", "chain", "inet", "sing-box", "output").Output()
		if listErr == nil {
			existingRules := string(out)
			for _, v4 := range customIPv4s {
				if strings.Contains(existingRules, v4) {
					continue
				}
				_ = exec.CommandContext(ctx, nftPath, "insert", "rule", "inet", "sing-box", "output",
					"ip", "daddr", v4, "tcp", "dport", "{", "443,", "853", "}", "accept").Run()
			}
			return
		}
	}

	if iptPath, err := exec.LookPath("iptables"); err == nil {
		targetChain := ""
		if exec.CommandContext(ctx, iptPath, "-t", "mangle", "-L", "SINGBOX_OUTPUT", "-n").Run() == nil {
			targetChain = "SINGBOX_OUTPUT"
		} else if exec.CommandContext(ctx, iptPath, "-t", "mangle", "-L", "SING_BOX", "-n").Run() == nil {
			targetChain = "OUTPUT"
		}
		if targetChain != "" {
			for _, v4 := range customIPv4s {
				for _, port := range []string{"443", "853"} {
					if exec.CommandContext(ctx, iptPath, "-t", "mangle", "-C", targetChain, "-d", v4, "-p", "tcp", "--dport", port, "-j", "RETURN").Run() != nil {
						_ = exec.CommandContext(ctx, iptPath, "-t", "mangle", "-I", targetChain, "1", "-d", v4, "-p", "tcp", "--dport", port, "-j", "RETURN").Run()
					}
				}
			}
		}
	}
}
