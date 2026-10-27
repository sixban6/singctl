package gfw

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// probeTLS 探测 TLS 与 Reality 伪装测试（满分 35 分）
func probeTLS(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "TLS 与 Reality 伪装主动探测",
		MaxScore: 35,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	httpsPort := opts.GetHTTPSPort()

	// 1. 随机伪造 SNI 握手探测（GFW Active Probing 核心手段）
	randomDomain := generateRandomDomain()
	itemRandomSNI := CheckItem{
		Name:        "随机 SNI 握手与证书泄露探测",
		Description: fmt.Sprintf("使用伪造的随机域名 (%s) 发送 TLS ClientHello", randomDomain),
		MaxScore:    10,
	}

	randomCerts, randomErr := probeTLSCertificate(ctx, opts.IP, httpsPort, randomDomain, timeout)
	if randomErr != nil {
		// 握手失败：分析失败类型
		errStr := randomErr.Error()
		if strings.Contains(errStr, "unrecognized name") || strings.Contains(errStr, "handshake failure") {
			itemRandomSNI.Score = 0
			itemRandomSNI.Passed = true
			itemRandomSNI.Details = "服务端对未识别的随机 SNI 正确发送了 TLS Alert (unrecognized_name)，符合标准 Web 规范。"
		} else if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "EOF") {
			itemRandomSNI.Score = 5
			itemRandomSNI.Passed = false
			itemRandomSNI.Details = fmt.Sprintf("服务端对随机 SNI 直接断开连接 (RST/EOF) 未发送标准 TLS Alert: %v", randomErr)
			itemRandomSNI.Mitigation = "优化 TLS 握手层配置，对未授权 SNI 优先返回标准 TLS Alert 或默认自签回落证书。"
		} else {
			itemRandomSNI.Score = 3
			itemRandomSNI.Passed = false
			itemRandomSNI.Details = fmt.Sprintf("探测随机 SNI 遇到异常: %v", randomErr)
		}
	} else if len(randomCerts) > 0 {
		// 握手成功，检查返回的证书
		cert := randomCerts[0]
		dnsNames := cert.DNSNames
		commonName := cert.Subject.CommonName
		allNames := append(dnsNames, commonName)

		// 检查证书是否包含明显代理关键词或 Reality 偷取的目标域名
		leaked := false
		if opts.SNI != "" {
			for _, name := range allNames {
				if strings.EqualFold(name, opts.SNI) {
					leaked = true
					break
				}
			}
		}

		if leaked {
			itemRandomSNI.Score = 10
			itemRandomSNI.Passed = false
			itemRandomSNI.Details = fmt.Sprintf("服务端对随机 SNI 探测直接暴露了 Reality 偷取的证书域名 (%s)！这是确凿的代理特征！", opts.SNI)
			itemRandomSNI.Mitigation = "检查 Reality 配置，在面对未知的随机 SNI 探测时，确保真实目标回落或正确丢弃。"
		} else {
			itemRandomSNI.Score = 0
			itemRandomSNI.Passed = true
			itemRandomSNI.Details = fmt.Sprintf("服务端返回了默认回落证书 (CN: %s, SANs: %v)，表现正常。", commonName, dnsNames)
		}
	}
	cat.Items = append(cat.Items, itemRandomSNI)

	// 2. 目标 SNI 伪装度与 RTT 时延比对探测
	targetSNI := opts.SNI
	if targetSNI == "" && opts.Domain != "" {
		targetSNI = opts.Domain
	}

	itemTargetSNI := CheckItem{
		Name:        "目标 SNI 伪装度与证书签名链检测",
		Description: "检测配置的伪装 SNI 证书与真实网络拓扑的一致性",
		MaxScore:    10,
	}

	var tls13Succeeded bool
	if targetSNI != "" {
		targetCerts, tcpRTT, tlsRTT, tlsVersion, targetErr := probeTLSCertWithRTT(ctx, opts.IP, httpsPort, targetSNI, timeout)
		if targetErr != nil {
			itemTargetSNI.Score = 5
			itemTargetSNI.Passed = false
			itemTargetSNI.Details = fmt.Sprintf("使用目标 SNI (%s) 握手失败: %v", targetSNI, targetErr)
		} else if len(targetCerts) > 0 {
			tls13Succeeded = true
			cert := targetCerts[0]

			// 比对真实目标 IP 的延迟 vs 当前 VPS 延迟（Reality 典型特征：TLS 握手需中继真实服务器，时延会产生梯级）
			// 区分 TLS 1.2 (2-RTT) 与 TLS 1.3 (1-RTT) 基准时延比率，杜绝高延迟线路误报
			var isSuspect bool
			var rttReason string
			if tlsVersion == tls.VersionTLS13 {
				if tcpRTT > 0 && tlsRTT > 25*tcpRTT/10 && (tlsRTT-tcpRTT) > 250*time.Millisecond {
					isSuspect = true
					rttReason = fmt.Sprintf("TLS 1.3 握手时延异常偏高 (TCP: %v, TLS: %v, 达到 %.1fx TCP RTT, 差值: %v)",
						tcpRTT, tlsRTT, float64(tlsRTT)/float64(tcpRTT), tlsRTT-tcpRTT)
				}
			} else {
				if tcpRTT > 0 && tlsRTT > 38*tcpRTT/10 && (tlsRTT-2*tcpRTT) > 350*time.Millisecond {
					isSuspect = true
					rttReason = fmt.Sprintf("TLS 1.2 握手时延异常偏高 (TCP: %v, TLS: %v, 达到 %.1fx TCP RTT, 差值: %v)",
						tcpRTT, tlsRTT, float64(tlsRTT)/float64(tcpRTT), tlsRTT-2*tcpRTT)
				}
			}

			if isSuspect {
				itemTargetSNI.Score = 8
				itemTargetSNI.Passed = false
				itemTargetSNI.Details = fmt.Sprintf("证书主体有效 (CN: %s)，但 %s，存在 Reality 跨地域远程偷取特征！",
					cert.Subject.CommonName, rttReason)
				itemTargetSNI.Mitigation = "挑选与 VPS 地理位置更近、时延极低的伪装域名，消除跨地域 TLS 梯级时延偏差。"
			} else {
				itemTargetSNI.Score = 0
				itemTargetSNI.Passed = true
				itemTargetSNI.Details = fmt.Sprintf("SNI 握手顺畅，证书主体 (CN: %s), 机构: %s, 延迟比率合理 (TCP: %v, TLS: %v, 协议版本: 0x%04x)",
					cert.Subject.CommonName, cert.Issuer.CommonName, tcpRTT, tlsRTT, tlsVersion)
			}
		}
	} else {
		itemTargetSNI.Score = 0
		itemTargetSNI.Passed = true
		itemTargetSNI.Details = "未指定 --sni 参数，跳过针对性 Reality 比对测试（建议通过 --sni 指定伪装域名进行深度测试）。"
	}
	cat.Items = append(cat.Items, itemTargetSNI)

	// 3. Reality 专项深度探测：TLS 1.2 强制降级与目标回落行为一致性
	itemRealityDowngrade := CheckItem{
		Name:        "Reality TLS 1.2 强制降级探测",
		Description: "主动探测器强制以 TLS 1.2 ClientHello 发起握手，检验服务端回落与证书连贯性",
		MaxScore:    8,
	}

	if targetSNI != "" && tls13Succeeded {
		downgradePass, downgradeScore, downgradeDetails, downgradeMitigation := testRealityTLS12Downgrade(ctx, opts.IP, httpsPort, targetSNI, timeout)
		itemRealityDowngrade.Passed = downgradePass
		itemRealityDowngrade.Score = downgradeScore
		itemRealityDowngrade.Details = downgradeDetails
		itemRealityDowngrade.Mitigation = downgradeMitigation
	} else {
		itemRealityDowngrade.Passed = true
		itemRealityDowngrade.Score = 0
		itemRealityDowngrade.Details = "未指定伪装 SNI 或 TLS 握手不可达，跳过 TLS 1.2 强制降级测试。"
	}
	cat.Items = append(cat.Items, itemRealityDowngrade)

	// 4. ALPN 协商与 HTTP/2 协议栈一致性
	itemALPN := CheckItem{
		Name:        "ALPN 协商与 HTTP/2 协议栈一致性",
		Description: "声明 h2/http1.1 协商 ALPN，并在协商成功后验证真实 HTTP/2 SETTINGS 交互",
		MaxScore:    5,
	}

	alpnPass, alpnScore, alpnDetails, alpnMitigation := testALPNAndHTTP2(ctx, opts.IP, httpsPort, targetSNI, timeout)
	itemALPN.Passed = alpnPass
	itemALPN.Score = alpnScore
	itemALPN.Details = alpnDetails
	itemALPN.Mitigation = alpnMitigation
	cat.Items = append(cat.Items, itemALPN)

	// 5. TLS Alert 规范响应测试
	itemAlert := CheckItem{
		Name:        "TLS 告警报文 (TLS Alert) RFC 规范性",
		Description: "发送损坏的 TLS 记录层报文，检验是否返回合规的 TLS Alert (0x15)",
		MaxScore:    7,
	}

	alertPassed, alertMsg := testTLSAlertResponse(ctx, opts.IP, httpsPort, timeout)
	if !alertPassed {
		itemAlert.Score = 7
		itemAlert.Passed = false
		itemAlert.Details = alertMsg
		itemAlert.Mitigation = "使用遵循 RFC 5246/8446 的完整 TLS 引擎（如 Caddy/Go tls），避免自制裁剪版协议解析器引发 Alert 缺失。"
	} else {
		itemAlert.Score = 0
		itemAlert.Passed = true
		itemAlert.Details = alertMsg
	}
	cat.Items = append(cat.Items, itemAlert)

	// 统计当前分类总分
	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
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

func probeTLSCertWithRTT(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) ([]*x509.Certificate, time.Duration, time.Duration, uint16, error) {
	tcpStart := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer conn.Close()
	tcpRTT := time.Since(tcpStart)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	tlsStart := time.Now()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, tcpRTT, 0, 0, err
	}
	tlsRTT := time.Since(tlsStart)

	state := tlsConn.ConnectionState()
	return state.PeerCertificates, tcpRTT, tlsRTT, state.Version, nil
}

// testRealityTLS12Downgrade 强制发送仅支持 TLS 1.2 的握手报文，检验 Reality 回落特征
func testRealityTLS12Downgrade(ctx context.Context, ip string, port int, serverName string, timeout time.Duration) (bool, int, string, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return true, 0, "连接端口失败，跳过 TLS 1.2 降级探测", ""
	}
	defer conn.Close()

	// 强制最高版本为 TLS 1.2
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
		// 如果服务端在 TLS 1.3 成功，但 TLS 1.2 握手时直接 RST/EOF 中断
		if strings.Contains(errStr, "connection reset") || strings.Contains(errStr, "EOF") {
			return false, 6, fmt.Sprintf("强制 TLS 1.2 握手被直接断开 (RST/EOF): %v，与主流真实商业站点的行为不符！", err),
				"检查 Reality 目标站点 (dest) 是否支持 TLS 1.2，或确保回落转发逻辑稳定。"
		}
		return true, 0, fmt.Sprintf("TLS 1.2 握手受限: %v", err), ""
	}

	state := tlsConn.ConnectionState()
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
		// 协商为 HTTP/2，发送标准 HTTP/2 Client Preface 与空 SETTINGS 帧验证
		// RFC 7540: Preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24 bytes)
		// SETTINGS Frame: Type 0x04, Length 0 (9 bytes: \x00\x00\x00\x04\x00\x00\x00\x00\x00)
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

		// 检查 HTTP/2 Frame Type 是否为 SETTINGS (0x04)
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
// RFC 5246 / RFC 8446 规定 TLS 记录层头部 5 字节，AlertLevel 在第 6 字节 (buf[5])，AlertDescription 在第 7 字节 (buf[6])
func testTLSAlertResponse(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return true, fmt.Sprintf("无法连接 %d 端口，跳过 Alert 测试", port)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 构造一个畸形的 TLS 记录头 (ContentType: Handshake=0x16, Version: TLS 1.0, Length: 5, Payload: 非法字节)
	malformedTLS := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, err := conn.Write(malformedTLS); err != nil {
		return false, fmt.Sprintf("写入探测包失败: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return false, fmt.Sprintf("未返回标准 TLS Alert，直接断开连接: %v", err)
	}

	// 检查首字节是否为 0x15 (TLS Alert)
	// 根据 TLS Record 规范：buf[0]=ContentType(0x15), buf[1..2]=Version, buf[3..4]=Length, buf[5]=AlertLevel, buf[6]=AlertDesc
	if n >= 7 && buf[0] == 0x15 {
		alertLevel := "Warning (0x01)"
		if buf[5] == 0x02 {
			alertLevel = "Fatal (0x02)"
		}
		return true, fmt.Sprintf("服务端符合 RFC 规范，返回了标准 TLS Alert (Type: 0x15, Level: %s, Description: 0x%02x)", alertLevel, buf[6])
	}

	// 兼顾短报文 Alert 容错（部分实现截断）
	if n >= 2 && buf[0] == 0x15 {
		return true, fmt.Sprintf("服务端返回了 TLS Alert (Type: 0x15, 长度: %d 字节)", n)
	}

	// 如果返回了 HTTP 400 也是合规 Web 服务器（如 Nginx/Caddy 对明文解析失败直接回退 400）
	if strings.Contains(string(buf[:n]), "400 Bad Request") {
		return true, "服务端作为 Web 服务器解析失败并正确返回了 HTTP 400"
	}

	return false, fmt.Sprintf("服务端返回了非标准的未定义响应 (首字节: 0x%02x, 长度: %d 字节)", buf[0], n)
}
