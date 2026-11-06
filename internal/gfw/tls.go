package gfw

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// probeTLS 探测 TLS 与 Reality 伪装测试（满分 35 分）
func probeTLS(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "TLS 与 Reality 伪装主动探测",
		MaxScore: 35,
		Items:    make([]CheckItem, 0, 5),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	httpsPort := opts.GetHTTPSPort()
	targetSNI := opts.SNI
	if targetSNI == "" && opts.Domain != "" {
		targetSNI = opts.Domain
	}

	var (
		itemRandomSNI        CheckItem
		itemTargetSNI        CheckItem
		itemRealityDowngrade CheckItem
		itemALPN             CheckItem
		itemAlert            CheckItem
		wg                   sync.WaitGroup
	)

	wg.Add(5)

	// 1. 随机伪造 SNI 握手与动态签发神谕探测（并发）
	go func() {
		defer wg.Done()
		randomDomain := generateRandomDomain()
		it := CheckItem{
			Name:        "随机 SNI 握手与证书泄露探测",
			Description: fmt.Sprintf("使用伪造的随机域名 (%s) 发送 TLS ClientHello，检测证书泄露与动态自签神谕", randomDomain),
			MaxScore:    10,
		}

		randomCerts, randomErr := probeTLSCertificate(ctx, opts.IP, httpsPort, randomDomain, timeout)
		if randomErr != nil {
			errStr := randomErr.Error()
			if strings.Contains(errStr, "unrecognized name") || strings.Contains(errStr, "handshake failure") || strings.Contains(errStr, "internal error") {
				it.Score = 0
				it.Passed = true
				it.Details = "服务端对未识别的随机 SNI 正确发送了标准 TLS Alert，符合主流 Web 网关规范。"
			} else if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "EOF") {
				it.Score = 5
				it.Passed = false
				it.Details = fmt.Sprintf("服务端对随机 SNI 直接断开连接 (RST/EOF) 未发送标准 TLS Alert: %v", randomErr)
				it.Mitigation = "优化 TLS 握手层配置，对未授权 SNI 优先返回标准 TLS Alert 或有效公网 IP 默认证书。"
			} else {
				it.Score = 3
				it.Passed = false
				it.Details = fmt.Sprintf("探测随机 SNI 遇到异常: %v", randomErr)
			}
		} else if len(randomCerts) > 0 {
			cert := randomCerts[0]
			dnsNames := cert.DNSNames
			commonName := cert.Subject.CommonName
			issuerName := certIssuerDisplay(cert)
			allNames := append([]string{}, dnsNames...)
			if commonName != "" {
				allNames = append(allNames, commonName)
			}

			leakedTargetSNI := false
			matchedRandomSNI := false
			for _, name := range allNames {
				if opts.SNI != "" && strings.EqualFold(name, opts.SNI) {
					leakedTargetSNI = true
				}
				if strings.EqualFold(name, randomDomain) {
					matchedRandomSNI = true
				}
			}

			mintedOnTheFly := time.Since(cert.NotBefore) >= -1*time.Minute && time.Since(cert.NotBefore) < 5*time.Minute && isSelfSignedOrInternalCA(cert)

			switch {
			case leakedTargetSNI:
				it.Score = 10
				it.Passed = false
				it.Details = fmt.Sprintf("服务端对随机 SNI 探测直接暴露了 Reality 偷取的证书域名 (%s)！这是确凿的代理特征！", opts.SNI)
				it.Mitigation = "检查 L4 SNI 分流与 Reality 配置，严禁将未知随机 SNI 转发至 Reality 入站。"
			case matchedRandomSNI || mintedOnTheFly:
				it.Score = 10
				it.Passed = false
				it.Details = fmt.Sprintf("服务端针对随机伪造域名 (%s) 现场动态签发了同名自签证书 (Issuer: %s)！暴露了 tls internal on_demand 动态签发神谕指纹！",
					randomDomain, issuerName)
				it.Mitigation = "在 Caddy 配置中设置 server_ip 启用 Let's Encrypt shortlived 公网 IP 证书，关闭 :9445 的 tls internal on_demand。"
			case isSelfSignedOrInternalCA(cert):
				it.Score = 6
				it.Passed = false
				it.Details = fmt.Sprintf("服务端对随机 SNI 返回了带内部 CA 指纹的自签证书 (Issuer: %s, CN: %s)", issuerName, commonName)
				it.Mitigation = "建议使用 Let's Encrypt shortlived 公网 IP 证书替代内部自签证书，或在未命中 SNI 时返回 TLS Alert。"
			default:
				it.Score = 0
				it.Passed = true
				it.Details = fmt.Sprintf("服务端返回了受信任的默认回落证书 (Issuer: %s, SANs: %v)，表现正常。", issuerName, dnsNames)
			}
		}
		itemRandomSNI = it
	}()

	// 2. 目标 SNI 伪装度、CA 签名链、源站 Ground-Truth 差分与握手后 L7 穿透检验（并发）
	go func() {
		defer wg.Done()
		it := CheckItem{
			Name:        "目标 SNI 伪装度与证书签名链检测",
			Description: "验证伪装 SNI 的 CA 证书链真伪、真实源站镜像一致性、L7 穿透性与跨层 RTT 阶跃",
			MaxScore:    10,
		}

		if targetSNI != "" {
			probeRes, targetErr := probeTargetSNIDeep(ctx, opts.IP, httpsPort, targetSNI, timeout)
			if targetErr != nil {
				it.Score = 5
				it.Passed = false
				it.Details = fmt.Sprintf("使用目标 SNI (%s) 握手失败: %v", targetSNI, targetErr)
				it.Mitigation = "检查 Caddy L4 路由与后端 TLS/Reality 服务是否正常监听。"
			} else if len(probeRes.certs) > 0 {
				cert := probeRes.certs[0]
				issuerName := certIssuerDisplay(cert)

				caValid, caReason := verifyCertificateChain(probeRes.certs, targetSNI)

				var originMismatch bool
				var originReason string
				if opts.SNI != "" && strings.EqualFold(targetSNI, opts.SNI) {
					originMismatch, originReason = compareWithRealOrigin(ctx, opts.IP, targetSNI, probeRes, timeout)
				}

				var isRTTSuspect bool
				var rttReason string
				tcpRTT, tlsRTT := probeRes.tcpRTT, probeRes.tlsRTT
				if probeRes.tlsVersion == tls.VersionTLS13 {
					if tcpRTT > 0 && tlsRTT > 25*tcpRTT/10 && (tlsRTT-tcpRTT) > 250*time.Millisecond {
						isRTTSuspect = true
						rttReason = fmt.Sprintf("TLS 1.3 握手时延异常偏高 (TCP: %v, TLS: %v, 达 %.1fx TCP RTT, 跨层差值: %v)",
							tcpRTT.Round(time.Millisecond), tlsRTT.Round(time.Millisecond), float64(tlsRTT)/float64(tcpRTT), (tlsRTT - tcpRTT).Round(time.Millisecond))
					}
				} else {
					if tcpRTT > 0 && tlsRTT > 38*tcpRTT/10 && (tlsRTT-2*tcpRTT) > 350*time.Millisecond {
						isRTTSuspect = true
						rttReason = fmt.Sprintf("TLS 1.2 握手时延异常偏高 (TCP: %v, TLS: %v, 达 %.1fx TCP RTT, 跨层差值: %v)",
							tcpRTT.Round(time.Millisecond), tlsRTT.Round(time.Millisecond), float64(tlsRTT)/float64(tcpRTT), (tlsRTT - 2*tcpRTT).Round(time.Millisecond))
					}
				}

				switch {
				case !caValid:
					it.Score = 10
					it.Passed = false
					it.Details = fmt.Sprintf("目标 SNI (%s) 证书未通过公共 CA 信任链校验 (%s, Issuer: %s)！疑似 L4 分流失效回落到了本地自签假证书！",
						targetSNI, caReason, issuerName)
					it.Mitigation = "检查 Caddy layer4 的 @vless_reality / @http_domains 匹配规则，确保目标 SNI 正确路由而非落入 9445 自签兜底。"
				case originMismatch:
					it.Score = 10
					it.Passed = false
					it.Details = fmt.Sprintf("目标 SNI (%s) 与真实源站 Ground-Truth 比对不一致: %s", targetSNI, originReason)
					it.Mitigation = "确保 Reality handshake.server 指向真实的源站域名，且未被本地 Web 服务器截获。"
				case !probeRes.l7Alive:
					it.Score = 8
					it.Passed = false
					it.Details = fmt.Sprintf("目标 SNI (%s) 完成 TLS 握手后，在同一连接发起 L7 请求立即异常中断 (%s)，暴露出仅转发握手层的伪装破绽！",
						targetSNI, probeRes.l7Note)
					it.Mitigation = "确保未认证连接在 TLS 握手后能完整透明转发应用层流量至目标站点。"
				case isRTTSuspect:
					it.Score = 8
					it.Passed = false
					it.Details = fmt.Sprintf("证书链有效 (CN: %s, Issuer: %s)，但 %s，存在 Reality 跨地域远程偷取时延阶跃特征！",
						cert.Subject.CommonName, issuerName, rttReason)
					it.Mitigation = "挑选与当前 VPS 同机房或同城市、RTT < 10ms 的伪装域名，消除跨地域 TLS 梯级时延差。"
				default:
					it.Score = 0
					it.Passed = true
					it.Details = fmt.Sprintf("CA 信任链与源站特征校验通过 (CN: %s, Issuer: %s, ALPN: %s, L7: %s, TCP: %v, TLS: %v)",
						cert.Subject.CommonName, issuerName, probeRes.alpn, probeRes.l7Note, tcpRTT.Round(time.Millisecond), tlsRTT.Round(time.Millisecond))
				}
			}
		} else {
			it.Score = 0
			it.Passed = true
			it.Details = "未指定 --sni 或 --domain 参数，跳过针对性源站差分比对（建议指定伪装域名进行深度审讯）。"
		}
		itemTargetSNI = it
	}()

	// 3. Reality 专项深度探测：TLS 1.2 强制降级与目标回落行为一致性（并发）
	go func() {
		defer wg.Done()
		it := CheckItem{
			Name:        "Reality TLS 1.2 强制降级探测",
			Description: "主动探测器强制以 TLS 1.2 ClientHello 发起握手，检验服务端回落与证书连贯性",
			MaxScore:    8,
		}
		if targetSNI != "" {
			downgradePass, downgradeScore, downgradeDetails, downgradeMitigation := testRealityTLS12Downgrade(ctx, opts.IP, httpsPort, targetSNI, timeout)
			it.Passed = downgradePass
			it.Score = downgradeScore
			it.Details = downgradeDetails
			it.Mitigation = downgradeMitigation
		} else {
			it.Passed = true
			it.Score = 0
			it.Details = "未指定伪装 SNI 或域名，跳过 TLS 1.2 强制降级测试。"
		}
		itemRealityDowngrade = it
	}()

	// 4. ALPN 协商与 HTTP/2 协议栈一致性（并发）
	go func() {
		defer wg.Done()
		it := CheckItem{
			Name:        "ALPN 协商与 HTTP/2 协议栈一致性",
			Description: "声明 h2/http1.1 协商 ALPN，并在协商成功后验证真实 HTTP/2 SETTINGS 交互",
			MaxScore:    5,
		}
		alpnPass, alpnScore, alpnDetails, alpnMitigation := testALPNAndHTTP2(ctx, opts.IP, httpsPort, targetSNI, timeout)
		it.Passed = alpnPass
		it.Score = alpnScore
		it.Details = alpnDetails
		it.Mitigation = alpnMitigation
		itemALPN = it
	}()

	// 5. TLS Alert 规范响应测试（并发）
	go func() {
		defer wg.Done()
		it := CheckItem{
			Name:        "TLS 告警报文 (TLS Alert) RFC 规范性",
			Description: "发送损坏的 TLS 记录层报文，检验是否返回合规的 TLS Alert (0x15)",
			MaxScore:    7,
		}
		alertPassed, alertMsg := testTLSAlertResponse(ctx, opts.IP, httpsPort, timeout)
		if !alertPassed {
			it.Score = 7
			it.Passed = false
			it.Details = alertMsg
			it.Mitigation = "使用遵循 RFC 5246/8446 的完整 TLS 引擎（如 Caddy/Go tls），避免自制裁剪版协议解析器引发 Alert 缺失。"
		} else {
			it.Score = 0
			it.Passed = true
			it.Details = alertMsg
		}
		itemAlert = it
	}()

	wg.Wait()
	cat.Items = append(cat.Items, itemRandomSNI, itemTargetSNI, itemRealityDowngrade, itemALPN, itemAlert)

	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

type targetSNIProbeResult struct {
	certs       []*x509.Certificate
	tcpRTT      time.Duration
	tlsRTT      time.Duration
	tlsVersion  uint16
	cipherSuite uint16
	alpn        string
	leafSHA256  [32]byte
	l7Alive     bool
	l7Status    string
	l7ServerHdr string
	l7Note      string
}

func probeTargetSNIDeep(ctx context.Context, host string, port int, serverName string, timeout time.Duration) (*targetSNIProbeResult, error) {
	tcpStart := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	tcpRTT := time.Since(tcpStart)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	tlsStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	tlsRTT := time.Since(tlsStart)

	state := tlsConn.ConnectionState()
	res := &targetSNIProbeResult{
		certs:       state.PeerCertificates,
		tcpRTT:      tcpRTT,
		tlsRTT:      tlsRTT,
		tlsVersion:  state.Version,
		cipherSuite: state.CipherSuite,
		alpn:        state.NegotiatedProtocol,
		l7Alive:     true,
		l7Note:      "OK",
	}
	if len(state.PeerCertificates) > 0 {
		res.leafSHA256 = sha256.Sum256(state.PeerCertificates[0].Raw)
	}

	// 在同一条已完成握手的 TLS 连接上验证 L7 应用层可穿透性
	_ = tlsConn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if state.NegotiatedProtocol == "h2" {
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
		if _, wErr := tlsConn.Write(preface); wErr != nil {
			res.l7Alive = false
			res.l7Note = fmt.Sprintf("H2 Preface 写入失败: %v", wErr)
		} else {
			buf := make([]byte, 256)
			n, rErr := tlsConn.Read(buf)
			if rErr != nil || n < 9 {
				res.l7Alive = false
				res.l7Note = fmt.Sprintf("H2 握手帧读取中断: %v", rErr)
			} else if buf[3] == 0x04 {
				res.l7Note = "H2 SETTINGS 正常"
			}
		}
	} else {
		reqStr := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", serverName)
		if _, wErr := tlsConn.Write([]byte(reqStr)); wErr != nil {
			res.l7Alive = false
			res.l7Note = fmt.Sprintf("HTTP HEAD 写入失败: %v", wErr)
		} else {
			rd := bufio.NewReader(tlsConn)
			line, rErr := rd.ReadString('\n')
			if rErr != nil {
				res.l7Alive = false
				res.l7Note = fmt.Sprintf("HTTP HEAD 无响应断开: %v", rErr)
			} else {
				res.l7Status = strings.TrimSpace(line)
				res.l7Note = res.l7Status
				for range 20 {
					hdrLine, hErr := rd.ReadString('\n')
					if hErr != nil || strings.TrimSpace(hdrLine) == "" {
						break
					}
					if strings.HasPrefix(strings.ToLower(hdrLine), "server:") {
						res.l7ServerHdr = strings.TrimSpace(hdrLine[7:])
					}
				}
			}
		}
	}

	return res, nil
}

// verifyCertificateChain 验证证书是否非自签、未过期、域名匹配且通过系统根 CA 校验
func verifyCertificateChain(certs []*x509.Certificate, dnsName string) (bool, string) {
	if len(certs) == 0 {
		return false, "未返回任何证书"
	}
	leaf := certs[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return false, "证书尚未生效"
	}
	if now.After(leaf.NotAfter) {
		return false, fmt.Sprintf("证书已于 %s 过期", leaf.NotAfter.Format("2006-01-02"))
	}
	if isSelfSignedOrInternalCA(leaf) {
		return false, "自签名或内部非公共 CA 签发"
	}
	if dnsName != "" && net.ParseIP(dnsName) == nil {
		if err := leaf.VerifyHostname(dnsName); err != nil {
			return false, fmt.Sprintf("证书域名不匹配 (%v)", err)
		}
	}
	interPool := x509.NewCertPool()
	for _, ic := range certs[1:] {
		interPool.AddCert(ic)
	}
	verifyOpts := x509.VerifyOptions{
		DNSName:       dnsName,
		Intermediates: interPool,
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		return false, fmt.Sprintf("系统根证书链校验未通过 (%v)", err)
	}
	return true, "OK"
}

// compareWithRealOrigin 直连真实的 targetSNI:443 源站，比对证书签发机构、ALPN 与 TLS 版本是否一致
func compareWithRealOrigin(ctx context.Context, targetIP, targetSNI string, nodeRes *targetSNIProbeResult, timeout time.Duration) (bool, string) {
	if net.ParseIP(targetSNI) != nil {
		return false, ""
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, targetSNI)
	if err != nil || len(ips) == 0 {
		return false, ""
	}
	for _, resolvedIP := range ips {
		if resolvedIP == targetIP {
			// 目标域名本身就解析到当前被测 VPS IP（说明是节点自有域名而非偷取他站域名）
			return false, ""
		}
	}

	originCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	originRes, err := probeTargetSNIDeep(originCtx, targetSNI, 443, targetSNI, timeout)
	if err != nil || len(originRes.certs) == 0 {
		// 若本地环境无法直连源站，不误报
		return false, ""
	}

	nodeLeaf := nodeRes.certs[0]
	originLeaf := originRes.certs[0]

	// 比对证书 Issuer Organization / CommonName（考虑多 CDN 轮询可能证书序列号不同，但签发 CA 组织或 Subject 必然匹配）
	if !strings.EqualFold(nodeLeaf.Issuer.CommonName, originLeaf.Issuer.CommonName) &&
		strings.Join(nodeLeaf.Issuer.Organization, ",") != strings.Join(originLeaf.Issuer.Organization, ",") {
		return true, fmt.Sprintf("证书签发机构不一致 (节点返回: %s, 真实源站: %s)",
			certIssuerDisplay(nodeLeaf), certIssuerDisplay(originLeaf))
	}

	if nodeRes.alpn != originRes.alpn {
		return true, fmt.Sprintf("ALPN 协商不一致 (节点返回: %q, 真实源站: %q)", nodeRes.alpn, originRes.alpn)
	}

	if nodeRes.tlsVersion != originRes.tlsVersion {
		return true, fmt.Sprintf("TLS 协议版本不一致 (节点返回: 0x%04x, 真实源站: 0x%04x)", nodeRes.tlsVersion, originRes.tlsVersion)
	}

	if !strings.EqualFold(nodeRes.l7ServerHdr, originRes.l7ServerHdr) && (nodeRes.l7ServerHdr != "" || originRes.l7ServerHdr != "") {
		return true, fmt.Sprintf("HTTP Server 响应头不一致 (节点返回: %q, 真实源站: %q)", nodeRes.l7ServerHdr, originRes.l7ServerHdr)
	}

	return false, ""
}

func isSelfSignedOrInternalCA(cert *x509.Certificate) bool {
	if cert == nil {
		return true
	}
	if cert.Issuer.String() == cert.Subject.String() {
		return true
	}
	combined := strings.ToLower(cert.Issuer.CommonName + " " + strings.Join(cert.Issuer.Organization, " ") + " " + cert.Subject.CommonName)
	internalKeywords := []string{
		"caddy local",
		"traefik default",
		"ingress controller fake",
		"acme co",
		"localhost",
		"self-signed",
	}
	for _, kw := range internalKeywords {
		if strings.Contains(combined, kw) {
			return true
		}
	}
	return false
}

func certIssuerDisplay(cert *x509.Certificate) string {
	if cert == nil {
		return "unknown"
	}
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		return strings.Join(cert.Issuer.Organization, "/")
	}
	return cert.Issuer.String()
}

func generateRandomDomain() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("rnd-%s.org", hex.EncodeToString(b))
}

func probeTLSCertificate(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) ([]*x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	return certs, nil
}

// testRealityTLS12Downgrade 强制发送仅支持 TLS 1.2 的握手报文，检验 Reality 回落特征
func testRealityTLS12Downgrade(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) (bool, int, string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return true, 0, "连接端口失败，跳过 TLS 1.2 降级探测", ""
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "protocol version") || strings.Contains(errStr, "handshake failure") {
			return true, 0, "服务端合规拒绝了 TLS 1.2 降级并返回标准 Alert", ""
		}
		if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "EOF") {
			return false, 6, fmt.Sprintf("强制 TLS 1.2 握手被直接断开 (RST/EOF): %v，与主流真实商业站点的行为不符！", err),
				"检查 Reality 目标站点 (dest) 是否支持 TLS 1.2，或确保回落转发逻辑稳定。"
		}
		return true, 0, fmt.Sprintf("TLS 1.2 握手受限: %v", err), ""
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) > 0 && isSelfSignedOrInternalCA(state.PeerCertificates[0]) {
		return false, 8, fmt.Sprintf("强制 TLS 1.2 降级握手返回了内部自签证书 (Issuer: %s)，暴露了 TLS 1.2 与 1.3 分流不一致破绽！",
			certIssuerDisplay(state.PeerCertificates[0])), "确保 TLS 1.2 与 TLS 1.3 流量均路由至同一套有效证书或真实源站。"
	}
	return true, 0, fmt.Sprintf("TLS 1.2 降级握手成功 (CipherSuite: 0x%04x)，证书主体: %s，回落机制表现平滑。",
		state.CipherSuite, state.PeerCertificates[0].Subject.CommonName), ""
}

// testALPNAndHTTP2 验证 ALPN 协商与 HTTP/2 协议栈一致性
func testALPNAndHTTP2(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) (bool, int, string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return true, 0, "连接失败，跳过 ALPN 探测", ""
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return true, 0, fmt.Sprintf("ALPN 握手未完成: %v", err), ""
	}

	negotiated := tlsConn.ConnectionState().NegotiatedProtocol
	if negotiated == "h2" {
		preface := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
		if _, err := tlsConn.Write(preface); err != nil {
			return false, 5, fmt.Sprintf("协商 h2 成功但发送客户端 Preface 失败: %v", err), "检查反向代理对 HTTP/2 的支持完整性"
		}

		respBuf := make([]byte, 1024)
		n, err := tlsConn.Read(respBuf)
		if err != nil {
			return false, 5, fmt.Sprintf("服务端协商了 h2，但接收 HTTP/2 Preface 后异常断开: %v (ALPN 虚假协商特征)", err),
				"确保底层 Web 服务器原生支持 HTTP/2，避免外层 TLS 虚标 h2 但后端无法处理引发协议栈穿帮。"
		}

		if n >= 9 && respBuf[3] == 0x04 {
			return true, 0, "ALPN 成功协商 h2，并正确完成 HTTP/2 SETTINGS 握手帧交互，表现真实合规。", ""
		}

		if strings.Contains(string(respBuf[:n]), "400 Bad Request") {
			return false, 5, "服务端协商了 h2，但随后返回了 HTTP/1.1 400 Bad Request！这是典型的代理反代 ALPN 错配特征！",
				"统一前后端协议版本，确保前端 ALPN 与后端实际协议完全匹配。"
		}

		return true, 0, fmt.Sprintf("ALPN 协商 h2 响应正常 (%d 字节)", n), ""
	}

	return true, 0, fmt.Sprintf("ALPN 协商协议: %q (未启用 h2 或回退至 http/1.1)", negotiated), ""
}

// testTLSAlertResponse 发送非法 TLS 报文检测 Alert
func testTLSAlertResponse(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return true, fmt.Sprintf("无法连接 %d 端口，跳过 Alert 测试", port)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	malformedTLS := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, err := conn.Write(malformedTLS); err != nil {
		return false, fmt.Sprintf("写入探测包失败: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, fmt.Sprintf("未返回标准 TLS Alert，直接断开连接: %v", err)
	}

	if n >= 7 && buf[0] == 0x15 {
		alertLevel := "Warning (0x01)"
		if buf[5] == 0x02 {
			alertLevel = "Fatal (0x02)"
		}
		return true, fmt.Sprintf("服务端符合 RFC 规范，返回了标准 TLS Alert (Type: 0x15, Level: %s, Description: 0x%02x)", alertLevel, buf[6])
	}

	if n >= 2 && buf[0] == 0x15 {
		return true, fmt.Sprintf("服务端返回了 TLS Alert (Type: 0x15, 长度: %d 字节)", n)
	}

	if strings.Contains(string(buf[:n]), "400 Bad Request") {
		return true, "服务端作为 Web 服务器解析失败并正确返回了 HTTP 400"
	}

	return false, fmt.Sprintf("服务端返回了非标准的未定义响应 (首字节: 0x%02x, 长度: %d 字节)", buf[0], n)
}
