package gfw

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// probeEntropy 执行高熵与边界畸形数据包主动探测（满分 20 分 - 基于 IMC 2020 与 USENIX Security '23 研究）
func probeEntropy(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "高熵随机垃圾数据探测 (Active Probing)",
		MaxScore: 20,
		Items:    make([]CheckItem, 0, 2),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 4 * time.Second
	}

	httpsPort := opts.GetHTTPSPort()

	// 并发执行 4 组特征载荷探测：
	// 1. 13B 短高熵包 (小于 AEAD 16/32B Salt 阈值)
	// 2. 64B 标准高熵包 (大于 AEAD 头部阈值)
	// 3. 9B 截断 TLS ClientHello 包 (测试 L4 SNI 预读器挂起侧信道)
	// 4. 64B ExEntropy Rule-2 ASCII 前缀非 HTTP 边界包
	type probeResult struct {
		duration time.Duration
		resp     []byte
		err      error
	}

	var (
		res13B   probeResult
		res64B   probeResult
		resTrunc probeResult
		resASCII probeResult
		wg       sync.WaitGroup
	)

	wg.Add(4)
	go func() {
		defer wg.Done()
		d, b, err := testEntropyPayload(ctx, opts.IP, httpsPort, 13, timeout)
		res13B = probeResult{d, b, err}
	}()
	go func() {
		defer wg.Done()
		d, b, err := testEntropyPayload(ctx, opts.IP, httpsPort, 64, timeout)
		res64B = probeResult{d, b, err}
	}()
	go func() {
		defer wg.Done()
		// 构造外层声明 512 字节但实际仅发送 9 字节的截断 TLS ClientHello
		truncTLS := []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc}
		d, b, err := testCustomPayload(ctx, opts.IP, httpsPort, truncTLS, timeout)
		resTrunc = probeResult{d, b, err}
	}()
	go func() {
		defer wg.Done()
		// USENIX Security '23 ExEntropy Rule 2: 前 6+ 字节为可打印 ASCII 但非合法 HTTP Method
		asciiPrefix := make([]byte, 64)
		copy(asciiPrefix, []byte("PROBETST"))
		_, _ = rand.Read(asciiPrefix[8:])
		d, b, err := testCustomPayload(ctx, opts.IP, httpsPort, asciiPrefix, timeout)
		resASCII = probeResult{d, b, err}
	}()
	wg.Wait()

	// ── 检查项 1: IMC 2020 多阶段变长高熵探针与时延差侧信道 (MaxScore: 12) ──
	itemVarLen := CheckItem{
		Name:        fmt.Sprintf("端口 %d 多阶段变长高熵数据包注入测试", httpsPort),
		Description: "基于 IMC 2020 研究并发注入 13B/64B 变长随机密文，观测绝对挂起时长与长度-断开时延差 (Δt)",
		MaxScore:    12,
	}

	isTimeout64 := res64B.err != nil && strings.Contains(res64B.err.Error(), "i/o timeout")
	isTimeout13 := res13B.err != nil && strings.Contains(res13B.err.Error(), "i/o timeout")
	diff := res13B.duration - res64B.duration
	if diff < 0 {
		diff = -diff
	}

	switch {
	case isTimeout64 || isTimeout13:
		itemVarLen.Score = 12
		itemVarLen.Passed = false
		itemVarLen.Details = fmt.Sprintf("服务端在接收变长高熵数据包后处于挂起等待状态 (13B: %v, 64B: %v)！这是私有加密协议等待凑齐认证头部的典型特征！",
			res13B.duration.Round(time.Millisecond), res64B.duration.Round(time.Millisecond))
		itemVarLen.Mitigation = "配置前端网关在收到非 TLS/HTTP 握手数据时立即关闭连接 (ReadTimeout < 1s) 或快速返回错误。"
	case diff > 1200*time.Millisecond && (res13B.duration > 1500*time.Millisecond || res64B.duration > 1500*time.Millisecond):
		itemVarLen.Score = 10
		itemVarLen.Passed = false
		itemVarLen.Details = fmt.Sprintf("检测到短包 (13B: %v) 与长包 (64B: %v) 断开时延差达 %v，暴露了定长头部缓冲等待侧信道 (IMC 2020 特征)！",
			res13B.duration.Round(time.Millisecond), res64B.duration.Round(time.Millisecond), diff.Round(time.Millisecond))
		itemVarLen.Mitigation = "消除前置代理对特定字节数 (如 16/32B Salt) 的阻塞读取，统一异常流超时时间。"
	case res64B.duration > 2*time.Second || res13B.duration > 2*time.Second:
		itemVarLen.Score = 8
		itemVarLen.Passed = false
		itemVarLen.Details = fmt.Sprintf("服务端对高熵探针挂起较久后断开 (13B: %v, 64B: %v)，存在可疑等待行为。",
			res13B.duration.Round(time.Millisecond), res64B.duration.Round(time.Millisecond))
		itemVarLen.Mitigation = "缩短网关握手读取超时 (ReadHeaderTimeout)，防止主动探测器对连接存活时长画像。"
	case res64B.err == nil && len(res64B.resp) > 0 && !isStandardRejectPayload(res64B.resp):
		itemVarLen.Score = 8
		itemVarLen.Passed = false
		itemVarLen.Details = fmt.Sprintf("服务端对高熵随机包返回了非标准回声数据 (首字节: 0x%02x, 长度: %d 字节)", res64B.resp[0], len(res64B.resp))
		itemVarLen.Mitigation = "检查端口转发逻辑，禁止将未知二进制流直接透传给会产生非标响应的代理后端。"
	default:
		itemVarLen.Score = 0
		itemVarLen.Passed = true
		itemVarLen.Details = fmt.Sprintf("13B/64B 变长高熵探针均在极短时间内被拒绝 (13B: %v, 64B: %v, Δt: %v)，无定长等待侧信道。",
			res13B.duration.Round(time.Millisecond), res64B.duration.Round(time.Millisecond), diff.Round(time.Millisecond))
	}
	cat.Items = append(cat.Items, itemVarLen)

	// ── 检查项 2: USENIX Security '23 豁免边界与 L4 SNI 预读器截断探测 (MaxScore: 8) ──
	itemBoundary := CheckItem{
		Name:        "L4 SNI 预读截断与 ExEntropy 豁免边界探测",
		Description: "发送 9B 截断 TLS ClientHello 与 ASCII 前缀混合流，检测前置 L4 分流器是否存在挂起或脑裂特征",
		MaxScore:    8,
	}

	truncTimeout := resTrunc.err != nil && strings.Contains(resTrunc.err.Error(), "i/o timeout")
	asciiTimeout := resASCII.err != nil && strings.Contains(resASCII.err.Error(), "i/o timeout")
	truncStallDelta := resTrunc.duration - res64B.duration

	switch {
	case asciiTimeout || (resASCII.err == nil && len(resASCII.resp) > 0 && !isStandardRejectPayload(resASCII.resp)):
		itemBoundary.Score = 8
		itemBoundary.Passed = false
		itemBoundary.Details = fmt.Sprintf("ExEntropy ASCII 前缀边界探针触发异常挂起或非标响应 (耗时: %v)，协议嗅探器存在分流破绽！",
			resASCII.duration.Round(time.Millisecond))
		itemBoundary.Mitigation = "避免使用仅靠首字节判断协议的简陋分流器，确保非标准 ASCII 前缀流交由标准 Web 引擎快速返回 400 或 RST。"
	case (truncTimeout || resTrunc.duration > 2500*time.Millisecond) && res64B.duration < 600*time.Millisecond && truncStallDelta > 1800*time.Millisecond:
		itemBoundary.Score = 5
		itemBoundary.Passed = false
		itemBoundary.Details = fmt.Sprintf("截断 TLS ClientHello (声明 512B 仅发 9B) 导致服务端挂起 %v（普通乱码仅 %v），暴露前置 L4 SNI 预读器等待侧信道。",
			resTrunc.duration.Round(time.Millisecond), res64B.duration.Round(time.Millisecond))
		itemBoundary.Mitigation = "在 Caddy layer4 或 Nginx ssl_preread 中缩短 TLS 握手预读超时时间，防止半截握手包长期占用连接。"
	default:
		itemBoundary.Score = 0
		itemBoundary.Passed = true
		itemBoundary.Details = fmt.Sprintf("截断 TLS 头 (%v) 与 ASCII 边界探针 (%v) 均得到一致快速处置，未见 L4 嗅探器脑裂。",
			resTrunc.duration.Round(time.Millisecond), resASCII.duration.Round(time.Millisecond))
	}
	cat.Items = append(cat.Items, itemBoundary)

	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

func isStandardRejectPayload(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	// TLS Alert record (ContentType == 0x15)
	if len(b) >= 2 && b[0] == 0x15 {
		return true
	}
	s := string(b)
	return strings.Contains(s, "400") || strings.Contains(s, "Bad Request") || strings.Contains(s, "HTTP/")
}

func testEntropyPayload(ctx context.Context, ip string, port int, payloadLen int, timeout time.Duration) (time.Duration, []byte, error) {
	payload := make([]byte, payloadLen)
	_, _ = rand.Read(payload)
	// 确保首字节不误撞 TLS Handshake (0x16) 或可打印 ASCII HTTP 方法，保证纯正高熵特征
	if len(payload) > 0 && (payload[0] == 0x16 || (payload[0] >= 0x20 && payload[0] <= 0x7e)) {
		payload[0] = 0x8f
	}
	return testCustomPayload(ctx, ip, port, payload, timeout)
}

func testCustomPayload(ctx context.Context, ip string, port int, payload []byte, timeout time.Duration) (time.Duration, []byte, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	if err != nil {
		return 0, nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		return time.Since(start), nil, err
	}

	buf := make([]byte, 1024)
	n, readErr := conn.Read(buf)
	duration := time.Since(start)

	if readErr != nil {
		return duration, buf[:n], readErr
	}

	return duration, buf[:n], nil
}
