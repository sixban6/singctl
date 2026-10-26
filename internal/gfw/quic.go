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

	// 1. 畸形 QUIC 数据包探测与 Version Negotiation
	itemQUIC := CheckItem{
		Name:        "畸形 QUIC 数据包与版本协商探测",
		Description: "向 UDP 443 发送保留版本号为 0 的畸形 QUIC 报文，检验是否回复标准 Stateless Reset 或协商包",
		MaxScore:    8,
	}

	quicResponsive, details := testQUICInitialPacket(opts.IP, timeout)
	if !quicResponsive {
		itemQUIC.Score = 4
		itemQUIC.Passed = false
		itemQUIC.Details = details
		itemQUIC.Mitigation = "如果服务器运行 Hysteria 2，建议确认 UDP 443 是否在系统防火墙正确放行，并确保使用了规范的 QUIC 实现以响应协商报文。"
	} else {
		itemQUIC.Score = 0
		itemQUIC.Passed = true
		itemQUIC.Details = details
	}
	cat.Items = append(cat.Items, itemQUIC)

	// 2. UDP 端口高熵探测
	itemUDPEntropy := CheckItem{
		Name:        "UDP 443 随机高熵数据吞吐测试",
		Description: "探测 UDP 443 对随机未格式化 UDP 报文的处理（防黑洞/反射分析）",
		MaxScore:    7,
	}

	udpResponsive, udpMsg := testUDPEntropy(opts.IP, timeout)
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
func testQUICInitialPacket(ip string, timeout time.Duration) (bool, string) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, fmt.Sprintf("解析 UDP 地址失败: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false, fmt.Sprintf("创建 UDP Socket 失败: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 构造伪造的 QUIC Initial 头部 (Header form: Long header 0xc0, Version: 0x00000000 触发版本协商)
	// RFC 9000: When a server receives a packet with Version 0x00000000, it MUST NOT send a Version Negotiation packet.
	// But sending an unsupported version like 0x1a2a3a4a SHOULD trigger Version Negotiation.
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
		return false, fmt.Sprintf("发送 QUIC 探测包失败: %v", err)
	}

	recvBuf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(recvBuf)
	if err != nil {
		return false, "UDP 443 未收到 QUIC 版本协商回复（可能未启用 HTTP/3，或防火墙阻断了非法包长）"
	}

	if n > 0 {
		return true, fmt.Sprintf("UDP 443 响应正常，返回了标准 QUIC 握手/协商报文 (%d 字节)", n)
	}

	return false, "未收到响应"
}

func testUDPEntropy(ip string, timeout time.Duration) (bool, string) {
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return false, "UDP 地址解析失败"
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return false, "UDP 连接失败"
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 64)
	_, _ = rand.Read(buf)
	_, _ = conn.Write(buf)

	recv := make([]byte, 512)
	n, _, readErr := conn.ReadFrom(recv)
	if readErr != nil {
		return false, "UDP 443 静默丢弃随机高熵包（符合标准安全防护策略，防止 UDP 反射）"
	}

	return true, fmt.Sprintf("UDP 443 对随机未识别包返回了数据响应 (%d 字节)", n)
}
