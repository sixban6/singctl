package gfw

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// probeQUIC 探测 UDP / QUIC 协议画像（满分 15 分 - 针对 Hysteria2）
func probeQUIC(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "UDP / QUIC (Hysteria2) 协议探测",
		MaxScore: 15,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	httpsPort := opts.GetHTTPSPort()

	// 1. 畸形 QUIC 数据包探测与 Version Negotiation
	itemQUIC := CheckItem{
		Name:        fmt.Sprintf("UDP %d 畸形 QUIC 数据包与版本协商探测", httpsPort),
		Description: fmt.Sprintf("向 UDP %d 发送保留版本号为 0x1a2a3a4a 的 QUIC 报文，检验是否回复标准版本协商包", httpsPort),
		MaxScore:    8,
	}

	quicResponsive, isAbnormal, details := testQUICInitialPacket(ctx, opts.IP, httpsPort, timeout)
	if !quicResponsive {
		// 未开启 HTTP/3 或未开启 UDP 属于主流公网 Web 服务器常规策略，不增加风险分
		itemQUIC.Score = 0
		itemQUIC.Passed = true
		itemQUIC.Details = details
	} else if isAbnormal {
		itemQUIC.Score = 8
		itemQUIC.Passed = false
		itemQUIC.Details = details
		itemQUIC.Mitigation = "检查 UDP/QUIC 端口暴露情况，若使用 Hysteria 2，请确保采用标准的 QUIC 协议栈实现以防止非标特征泄露。"
	} else {
		itemQUIC.Score = 0
		itemQUIC.Passed = true
		itemQUIC.Details = details
	}
	cat.Items = append(cat.Items, itemQUIC)

	// 2. UDP 端口高熵探测
	itemUDPEntropy := CheckItem{
		Name:        fmt.Sprintf("UDP %d 随机高熵数据吞吐测试", httpsPort),
		Description: fmt.Sprintf("探测 UDP %d 对随机未格式化 UDP 报文的处理（防黑洞/反射分析）", httpsPort),
		MaxScore:    7,
	}

	udpResponsive, udpMsg := testUDPEntropy(ctx, opts.IP, httpsPort, timeout)
	if !udpResponsive {
		itemUDPEntropy.Score = 0
		itemUDPEntropy.Passed = true // 静默丢弃随机未格式化 UDP 报文是防御反射放大 DDoS 的标准最佳实践
		itemUDPEntropy.Details = udpMsg
	} else {
		itemUDPEntropy.Score = 0
		itemUDPEntropy.Passed = true
		itemUDPEntropy.Details = udpMsg
	}
	cat.Items = append(cat.Items, itemUDPEntropy)

	// 统计当前分类总分
	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

// testQUICInitialPacket 构造并发送测试 QUIC Initial 数据包
func testQUICInitialPacket(ctx context.Context, ip string, port int, timeout time.Duration) (bool, bool, string) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, false, fmt.Sprintf("解析 UDP 地址失败: %v", err)
	}

	var d net.Dialer
	connRaw, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return false, false, fmt.Sprintf("创建 UDP Socket 失败: %v", err)
	}
	defer connRaw.Close()

	conn, ok := connRaw.(*net.UDPConn)
	if !ok {
		return false, false, "非 UDP 套接字"
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 构造伪造的 QUIC Initial 头部 (Header form: Long header 0xc0, Version: 0x1a2a3a4a 触发版本协商)
	// RFC 9000: Sending an unsupported version like 0x1a2a3a4a SHOULD trigger Version Negotiation.
	quicProbe := []byte{
		0xc0,                   // Long Header (Initial)
		0x1a, 0x2a, 0x3a, 0x4a, // Unsupported reserved version for negotiation testing
		0x08,                   // DCID Length: 8
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // DCID
		0x08,                                           // SCID Length: 8
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // SCID
	}
	// 填充随机有效载荷满足最小包长 1200 字节（RFC 9000 规范要求 Initial 包必须 >= 1200 字节，否则服务器防放大直接丢弃）
	padding := make([]byte, 1200-len(quicProbe))
	_, _ = rand.Read(padding)
	packet := append(quicProbe, padding...)

	if _, err := conn.Write(packet); err != nil {
		return false, false, fmt.Sprintf("发送 QUIC 探测包失败: %v", err)
	}

	recvBuf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(recvBuf)
	if err != nil {
		return false, false, fmt.Sprintf("UDP %d 未响应 QUIC 报文 (目标未开启 HTTP/3 或防火墙过滤了 UDP，未暴露特征)", port)
	}

	if n > 0 {
		// RFC 9000: Version Negotiation Packet 的 Version 字段固定为 0x00000000 (bytes 1..4)
		if n >= 5 && recvBuf[1] == 0x00 && recvBuf[2] == 0x00 && recvBuf[3] == 0x00 && recvBuf[4] == 0x00 {
			return true, false, fmt.Sprintf("UDP %d 响应正常，返回了标准 RFC 9000 QUIC 版本协商报文 (%d 字节)", port, n)
		}
		// 返回了非标准响应
		return true, true, fmt.Sprintf("UDP %d 响应了非标准数据包 (%d 字节，首字节: 0x%02x)，可能存在非标 QUIC 代理特征！", port, n, recvBuf[0])
	}

	return false, false, "未收到响应"
}

func testUDPEntropy(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return false, "UDP 地址解析失败"
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", raddr.String())
	if err != nil {
		return false, "UDP 连接失败"
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	_, _ = conn.Write(buf)

	recv := make([]byte, 512)
	n, err := conn.Read(recv)
	if err != nil {
		return false, fmt.Sprintf("UDP %d 静默丢弃随机高熵包（符合标准安全防护策略，防止 UDP 反射攻击）", port)
	}

	return true, fmt.Sprintf("UDP %d 对随机未识别包返回了数据响应 (%d 字节)", port, n)
}
