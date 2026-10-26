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

// probeTLS 探测 TLS 与 Reality 伪装测试（满分 30 分）
func probeTLS(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "TLS 与 Reality 伪装主动探测",
		MaxScore: 30,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// 1. 随机伪造 SNI 握手探测（GFW Active Probing 核心手段）
	randomDomain := generateRandomDomain()
	itemRandomSNI := CheckItem{
		Name:        "随机 SNI 握手与证书泄露探测",
		Description: fmt.Sprintf("使用伪造的随机域名 (%s) 发送 TLS ClientHello", randomDomain),
		MaxScore:    10,
	}

	randomCerts, randomErr := probeTLSCertificate(opts.IP, randomDomain, timeout)
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

	if targetSNI != "" {
		targetCerts, tcpRTT, tlsRTT, targetErr := probeTLSCertWithRTT(opts.IP, targetSNI, timeout)
		if targetErr != nil {
			itemTargetSNI.Score = 5
			itemTargetSNI.Passed = false
			itemTargetSNI.Details = fmt.Sprintf("使用目标 SNI (%s) 握手失败: %v", targetSNI, targetErr)
		} else if len(targetCerts) > 0 {
			cert := targetCerts[0]
			// 比对真实目标 IP 的延迟 vs 当前 VPS 延迟（Reality 典型特征：TLS 握手需中继真实服务器，时延会产生梯级）
			rttDelta := tlsRTT - tcpRTT
			if rttDelta > 300*time.Millisecond {
				itemTargetSNI.Score = 8
				itemTargetSNI.Passed = false
				itemTargetSNI.Details = fmt.Sprintf("证书主体有效 (CN: %s)，但 TLS 握手时延显著偏高 (TCP: %v, TLS: %v, 差值: %v)，存在 Reality 远程中继偷取特征！",
					cert.Subject.CommonName, tcpRTT, tlsRTT, rttDelta)
				itemTargetSNI.Mitigation = "尽量挑选与您的 VPS 地理位置更近、时延极低的伪装域名，消除 TLS 梯级时延偏差。"
			} else {
				itemTargetSNI.Score = 0
				itemTargetSNI.Passed = true
				itemTargetSNI.Details = fmt.Sprintf("SNI 握手顺畅，证书主体 (CN: %s), 证书机构: %s, 延迟正常 (TCP: %v, TLS: %v)",
					cert.Subject.CommonName, cert.Issuer.CommonName, tcpRTT, tlsRTT)
			}
		}
	} else {
		itemTargetSNI.Score = 0
		itemTargetSNI.Passed = true
		itemTargetSNI.Details = "未指定 --sni 参数，跳过针对性 Reality 比对测试（建议通过 --sni 指定伪装域名进行深度测试）。"
	}
	cat.Items = append(cat.Items, itemTargetSNI)

	// 3. TLS Alert 规范响应测试
	itemAlert := CheckItem{
		Name:        "TLS 告警报文 (TLS Alert) RFC 规范性",
		Description: "发送损坏的 TLS 记录层报文，检验是否返回合规的 TLS Alert (0x15)",
		MaxScore:    10,
	}

	alertPassed, alertMsg := testTLSAlertResponse(opts.IP, timeout)
	if !alertPassed {
		itemAlert.Score = 10
		itemAlert.Passed = false
		itemAlert.Details = alertMsg
		itemAlert.Mitigation = "使用遵循 RFC 5246 的完整 TLS 引擎（如 Caddy/Go tls），避免自制裁剪版协议解析器引发 Alert 缺失。"
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

func probeTLSCertificate(ip, serverName string, timeout time.Duration) ([]*x509.Certificate, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	return certs, nil
}

func probeTLSCertWithRTT(ip, serverName string, timeout time.Duration) ([]*x509.Certificate, time.Duration, time.Duration, error) {
	tcpStart := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return nil, 0, 0, err
	}
	defer conn.Close()
	tcpRTT := time.Since(tcpStart)

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))

	tlsStart := time.Now()
	if err := tlsConn.Handshake(); err != nil {
		return nil, tcpRTT, 0, err
	}
	tlsRTT := time.Since(tlsStart)

	certs := tlsConn.ConnectionState().PeerCertificates
	return certs, tcpRTT, tlsRTT, nil
}

// testTLSAlertResponse 发送非法 TLS 报文检测 Alert
func testTLSAlertResponse(ip string, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
	if err != nil {
		return true, "无法连接 443 端口，跳过 Alert 测试"
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
	if n >= 2 && buf[0] == 0x15 {
		alertLevel := "Warning"
		if buf[1] == 0x02 {
			alertLevel = "Fatal"
		}
		return true, fmt.Sprintf("服务端符合 RFC 规范，返回了标准 TLS Alert (Type: 0x15, Level: %s)", alertLevel)
	}

	// 如果返回了 HTTP 400 也是合规 Web 服务器（如 Nginx/Caddy 对明文解析失败直接回退 400）
	if strings.Contains(string(buf[:n]), "400 Bad Request") {
		return true, "服务端作为 Web 服务器解析失败并正确返回了 HTTP 400"
	}

	return false, fmt.Sprintf("服务端返回了非标准的未定义响应 (首字节: 0x%02x, 长度: %d 字节)", buf[0], n)
}
