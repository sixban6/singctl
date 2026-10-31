package netdiag

import (
	"context"
	"crypto/rand"
	"math"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PingOptions 探测配置参数
type PingOptions struct {
	Host      string
	Port      int           // 默认 443
	Count     int           // 默认 10 轮
	Timeout   time.Duration // 单次超时，默认 1200ms
	Interval  time.Duration // 发包间隔，默认 120ms
	ForceTCP  bool
	ForceUDP  bool
	ForceICMP bool
}

func normalizePingOptions(opts *PingOptions) {
	if opts.Count <= 0 {
		opts.Count = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1200 * time.Millisecond
	}
	if opts.Interval <= 0 {
		opts.Interval = 120 * time.Millisecond
	}
	if opts.Port <= 0 {
		opts.Port = 443
	}
}

// ResolveTargetIP 解析目标域名为真实 IPv4 地址（优先 IPv4，并自动穿透 Fake-IP 198.18.0.0/15 虚拟网段）
func ResolveTargetIP(ctx context.Context, target string) string {
	target = strings.TrimSpace(target)
	if parsed := net.ParseIP(target); parsed != nil {
		return parsed.String()
	}

	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", target); err == nil {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil && !isFakeIP(ip4) {
				return ip4.String()
			}
		}
	}

	// 若默认 DNS 返回了 Fake-IP (198.18.0.0/15) 或解析失败，直连国内/公共 DNS 获取真实节点 IP
	for _, dnsServer := range []string{"223.5.5.5:53", "119.29.29.29:53", "1.1.1.1:53"} {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1500 * time.Millisecond}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
		if ips, err := r.LookupIP(ctx, "ip4", target); err == nil {
			for _, ip := range ips {
				if ip4 := ip.To4(); ip4 != nil && !isFakeIP(ip4) {
					return ip4.String()
				}
			}
		}
	}

	if ips, err := net.LookupIP(target); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String()
			}
		}
		return ips[0].String()
	}
	return target
}

func isFakeIP(ip4 net.IP) bool {
	return len(ip4) == 4 && ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

// RunPing 执行多维并发探测 (TCP + UDP/QUIC + ICMP)，精准捕捉真实丢包率（含 SYN 重传、UDP 1200B 大包拥塞及 ICMP 丢包）
func RunPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	normalizePingOptions(&opts)

	if opts.ForceICMP {
		return RunICMPPing(ctx, opts)
	}
	if opts.ForceUDP {
		return RunUDPPing(ctx, opts)
	}
	if opts.ForceTCP {
		return RunTCPPing(ctx, opts)
	}

	var (
		tcpRes  *PingResult
		udpRes  *PingResult
		icmpRes *PingResult
		tcpErr  error
		wg      sync.WaitGroup
	)

	wg.Add(3)
	go func() {
		defer wg.Done()
		tcpRes, tcpErr = RunTCPPing(ctx, opts)
	}()
	go func() {
		defer wg.Done()
		udpRes, _ = RunUDPPing(ctx, opts)
	}()
	go func() {
		defer wg.Done()
		icmpRes, _ = RunICMPPing(ctx, opts)
	}()
	wg.Wait()

	if tcpRes == nil && udpRes == nil && icmpRes == nil {
		return nil, tcpErr
	}

	return mergeMultiPingResults(opts, tcpRes, udpRes, icmpRes), nil
}

// mergeMultiPingResults 聚合 TCP、UDP (QUIC 1200B) 与 ICMP 三维探测结果，取真实有效最大丢包率作为综合评估指标
func mergeMultiPingResults(opts PingOptions, tcpRes, udpRes, icmpRes *PingResult) *PingResult {
	combined := &PingResult{
		Target:   opts.Host,
		Port:     opts.Port,
		IsTCP:    true,
		Protocol: "MULTI",
		Sent:     opts.Count,
		TCP:      tcpRes,
		UDP:      udpRes,
		ICMP:     icmpRes,
	}

	// 检测本地 TUN / 透明代理是否劫持了 TCP 握手：
	// 若 UDP 或 ICMP 真实物理往返延迟 > 50ms，而 TCP 握手延迟 < 25ms (且不到物理延迟的 1/3)，说明本机 TUN 虚拟网卡在本地秒回了 SYN-ACK
	realPhysicalRTT := time.Duration(0)
	if udpRes != nil && udpRes.Received > 0 && udpRes.MinRTT > realPhysicalRTT {
		realPhysicalRTT = udpRes.MinRTT
	}
	if icmpRes != nil && icmpRes.Received > 0 && icmpRes.MinRTT > realPhysicalRTT {
		realPhysicalRTT = icmpRes.MinRTT
	}
	if tcpRes != nil && len(tcpRes.RTTs) > 0 && realPhysicalRTT >= 50*time.Millisecond && tcpRes.MinRTT < 25*time.Millisecond && tcpRes.MinRTT*3 < realPhysicalRTT {
		tcpRes.LocalProxied = true
	}

	// 1. 选定主延迟基准 (若 TCP 未被本地 TUN 劫持则优先 TCP，否则优先 UDP/ICMP 真实物理链路)
	var base *PingResult
	switch {
	case tcpRes != nil && tcpRes.Received > 0 && !tcpRes.LocalProxied:
		base = tcpRes
	case udpRes != nil && udpRes.Received > 0:
		base = udpRes
		combined.IsTCP = false
		combined.IsUDP = true
	case icmpRes != nil && icmpRes.Received > 0:
		base = icmpRes
		combined.IsTCP = false
	case tcpRes != nil && len(tcpRes.RTTs) > 0:
		base = tcpRes
	case tcpRes != nil:
		base = tcpRes
	case icmpRes != nil:
		base = icmpRes
	default:
		base = udpRes
	}

	if base != nil {
		combined.MinRTT = base.MinRTT
		combined.AvgRTT = base.AvgRTT
		combined.MaxRTT = base.MaxRTT
		combined.Jitter = base.Jitter
		combined.RTTs = base.RTTs
		combined.Received = base.Received
		combined.LossCount = base.LossCount
		combined.RetransCount = base.RetransCount
		combined.LossRate = base.LossRate
	}

	// 2. 综合计算真实丢包率与最大抖动
	// なぜ: TCP 60B 小包握手往往受内核 SYN 重传掩护且不易触发队列尾丢弃；
	// 只要 ICMP 或 UDP (QUIC 1200B) 有回包 (Received > 0，排除防火墙 100% 静态拦截情况)，其丢包即为真实的跨境链路拥塞丢包！
	anyResponded := false
	maxLossRate := 0.0
	maxLossCount := 0
	maxSent := opts.Count
	maxJitter := combined.Jitter

	candidates := []*PingResult{tcpRes, udpRes, icmpRes}
	for _, c := range candidates {
		if c == nil {
			continue
		}
		if c.Received > 0 {
			anyResponded = true
			if c.LossRate > maxLossRate {
				maxLossRate = c.LossRate
				maxLossCount = c.LossCount
				maxSent = c.Sent
			}
			if c.Jitter > maxJitter {
				maxJitter = c.Jitter
			}
		}
	}

	if !anyResponded {
		combined.LossRate = 100.0
		combined.LossCount = combined.Sent
		combined.Received = 0
	} else {
		combined.LossRate = maxLossRate
		combined.LossCount = maxLossCount
		combined.Sent = maxSent
		combined.Received = maxSent - maxLossCount
		combined.Jitter = maxJitter
	}

	combined.QualityLevel = EvaluateQuality(combined.LossRate, combined.Jitter)
	return combined
}

// RunTCPPing 执行多轮免 Root 的 TCP Ping，并识别内核 SYN 重传导致的隐性丢包
func RunTCPPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	normalizePingOptions(&opts)
	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))
	result := &PingResult{
		Target:   opts.Host,
		Port:     opts.Port,
		IsTCP:    true,
		Protocol: "TCP",
		Sent:     opts.Count,
	}

	type probeOutcome struct {
		ok      bool
		elapsed time.Duration
	}
	outcomes := make([]probeOutcome, opts.Count)
	var wg sync.WaitGroup

	for i := 0; i < opts.Count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.Interval):
			}
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := time.Now()
			d := net.Dialer{Timeout: opts.Timeout}
			conn, err := d.DialContext(ctx, "tcp", addr)
			elapsed := time.Since(start)
			if err == nil {
				_ = conn.Close()
				outcomes[idx] = probeOutcome{ok: true, elapsed: elapsed}
			}
		}(i)
	}
	wg.Wait()

	var rtts []time.Duration
	for _, o := range outcomes {
		if o.ok {
			rtts = append(rtts, o.elapsed)
		}
	}

	computeRTTStats(result, rtts, true)
	result.QualityLevel = EvaluateQuality(result.LossRate, result.Jitter)
	return result, nil
}

// RunUDPPing 发送 1200 字节 RFC 9000 QUIC Initial 探测包，测试 UDP/Hysteria2 端口真实丢包与抖动（0 内核重传、真实 MTU 负载）
func RunUDPPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	normalizePingOptions(&opts)
	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))
	result := &PingResult{
		Target:   opts.Host,
		Port:     opts.Port,
		IsTCP:    false,
		IsUDP:    true,
		Protocol: "UDP",
		Sent:     opts.Count,
	}

	type udpOutcome struct {
		ok      bool
		refused bool
		elapsed time.Duration
	}
	outcomes := make([]udpOutcome, opts.Count)
	var wg sync.WaitGroup

	for i := 0; i < opts.Count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.Interval):
			}
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ok, refused, elapsed := sendSingleQUICProbe(ctx, addr, opts.Timeout)
			outcomes[idx] = udpOutcome{ok: ok, refused: refused, elapsed: elapsed}
		}(i)
	}
	wg.Wait()

	var rtts []time.Duration
	refusedCount := 0
	for _, o := range outcomes {
		if o.ok {
			rtts = append(rtts, o.elapsed)
		} else if o.refused {
			refusedCount++
		}
	}

	if len(rtts) == 0 && refusedCount > 0 {
		result.PortClosed = true
	}

	computeRTTStats(result, rtts, false)
	result.QualityLevel = EvaluateQuality(result.LossRate, result.Jitter)
	return result, nil
}

// sendSingleQUICProbe 向目标 UDP 端口发送单次 1200B QUIC Initial (0x1a2a3a4a) 触发无状态 Version Negotiation 回复
func sendSingleQUICProbe(ctx context.Context, addr string, timeout time.Duration) (ok bool, refused bool, elapsed time.Duration) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return false, false, 0
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// RFC 9000 Section 6: 1200 字节 Initial 包 + 保留版本号 0x1a2a3a4a 强制触发服务端无状态回复 Version Negotiation
	packet := make([]byte, 1200)
	_, _ = rand.Read(packet)
	packet[0] = 0xc0 // Long Header (Initial)
	packet[1] = 0x1a
	packet[2] = 0x2a
	packet[3] = 0x3a
	packet[4] = 0x4a // Reserved version for Version Negotiation
	packet[5] = 0x08 // DCID len = 8 (bytes 6..13 random)
	packet[14] = 0x08 // SCID len = 8 (bytes 15..22 random)

	start := time.Now()
	if _, err := conn.Write(packet); err != nil {
		return false, false, 0
	}

	recvBuf := make([]byte, 1500)
	n, err := conn.Read(recvBuf)
	elapsed = time.Since(start)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
			return false, true, elapsed
		}
		return false, false, 0
	}
	if n > 0 {
		return true, false, elapsed
	}
	return false, false, 0
}

// RunICMPPing 执行多轮并发交错的系统单包 ICMP 探测，兼容 OpenWrt BusyBox / Linux / macOS / Windows
func RunICMPPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	normalizePingOptions(&opts)
	result := &PingResult{
		Target:   opts.Host,
		Port:     0,
		IsTCP:    false,
		Protocol: "ICMP",
		Sent:     opts.Count,
	}

	// 检查系统 ping 命令是否存在
	if _, err := exec.LookPath("ping"); err != nil {
		return RunTCPPing(ctx, opts)
	}

	type icmpOutcome struct {
		ok      bool
		elapsed time.Duration
	}
	outcomes := make([]icmpOutcome, opts.Count)
	var wg sync.WaitGroup

	timeoutMs := int(opts.Timeout.Milliseconds())
	if timeoutMs < 500 {
		timeoutMs = 1000
	}
	timeoutSec := int(math.Ceil(opts.Timeout.Seconds()))
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	for i := 0; i < opts.Count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(opts.Interval):
			}
		}

		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var cmd *exec.Cmd
			switch runtime.GOOS {
			case "windows":
				cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.Itoa(timeoutMs), opts.Host)
			case "darwin":
				cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(timeoutMs), opts.Host)
			default: // Linux / OpenWrt
				cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(timeoutSec), opts.Host)
			}

			start := time.Now()
			out, err := cmd.CombinedOutput()
			elapsed := time.Since(start)
			if err == nil {
				if rtt, ok := extractSinglePingRTT(string(out)); ok {
					outcomes[idx] = icmpOutcome{ok: true, elapsed: rtt}
					return
				}
				outcomes[idx] = icmpOutcome{ok: true, elapsed: elapsed}
			}
		}(i)
	}
	wg.Wait()

	var rtts []time.Duration
	for _, o := range outcomes {
		if o.ok {
			rtts = append(rtts, o.elapsed)
		}
	}

	computeRTTStats(result, rtts, false)
	result.QualityLevel = EvaluateQuality(result.LossRate, result.Jitter)
	return result, nil
}

// computeRTTStats 统计 RTT 指标；若 detectSYNRetrans 为 true，则自动识别因丢包触发内核 TCP SYN 重传的异常高延迟轮次
func computeRTTStats(result *PingResult, rtts []time.Duration, detectSYNRetrans bool) {
	result.RTTs = rtts
	if len(rtts) == 0 {
		result.Received = 0
		result.LossCount = result.Sent
		if result.Sent > 0 {
			result.LossRate = 100.0
		}
		return
	}

	minRTT := rtts[0]
	maxRTT := rtts[0]
	var totalRTT time.Duration
	for _, rtt := range rtts {
		totalRTT += rtt
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}

	result.MinRTT = minRTT
	result.MaxRTT = maxRTT
	result.AvgRTT = time.Duration(int64(totalRTT) / int64(len(rtts)))

	var varianceSum float64
	avgNano := float64(result.AvgRTT.Nanoseconds())
	for _, rtt := range rtts {
		diff := float64(rtt.Nanoseconds()) - avgNano
		varianceSum += diff * diff
	}
	stdDevNano := math.Sqrt(varianceSum / float64(len(rtts)))
	result.Jitter = time.Duration(int64(stdDevNano))

	// 识别 TCP SYN 丢包重传：
	// 当操作系统内核发起 TCP 握手丢包时，Linux 默认 1000ms (macOS 200ms~500ms) 后自动重传 SYN。
	// 若单次握手耗时超过基准 MinRTT 的 2.0 倍且绝对增量 >= 220ms (如 Min 144ms 而某轮高达 1154ms)，说明该轮首包已丢失！
	retransCount := 0
	if detectSYNRetrans && minRTT > 0 {
		for _, rtt := range rtts {
			if rtt > minRTT*2 && (rtt-minRTT) >= 220*time.Millisecond {
				retransCount++
			}
		}
	}

	timeoutLoss := result.Sent - len(rtts)
	result.RetransCount = retransCount
	result.LossCount = timeoutLoss + retransCount
	if result.LossCount > result.Sent {
		result.LossCount = result.Sent
	}
	result.Received = result.Sent - result.LossCount
	if result.Sent > 0 {
		result.LossRate = (float64(result.LossCount) / float64(result.Sent)) * 100.0
	}
}

func extractSinglePingRTT(output string) (time.Duration, bool) {
	lower := strings.ToLower(output)
	for _, marker := range []string{"time=", "time<"} {
		if idx := strings.Index(lower, marker); idx != -1 {
			rest := strings.TrimSpace(lower[idx+len(marker):])
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				numStr := strings.TrimSuffix(fields[0], "ms")
				if val, err := strconv.ParseFloat(numStr, 64); err == nil && val > 0 {
					return time.Duration(val * float64(time.Millisecond)), true
				}
			}
		}
	}
	return 0, false
}

// EvaluateQuality 综合丢包率与抖动给出评级
func EvaluateQuality(lossRate float64, jitter time.Duration) RouteQuality {
	if lossRate == 0 && jitter < 15*time.Millisecond {
		return QualityExcellent
	}
	if lossRate <= 2.0 && jitter < 40*time.Millisecond {
		return QualityGood
	}
	if lossRate <= 15.0 {
		return QualityCongested
	}
	return QualitySevere
}

func parseSystemPingOutput(output string, res *PingResult) {
	lines := strings.Split(output, "\n")
	var rtts []time.Duration
	for _, line := range lines {
		lower := strings.ToLower(line)
		if rtt, ok := extractSinglePingRTT(line); ok {
			rtts = append(rtts, rtt)
		}
		// 解析丢包率 (e.g. 0% packet loss 或 0.0% loss)
		if strings.Contains(lower, "packet loss") || strings.Contains(lower, "loss") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasSuffix(p, "%") {
					valStr := strings.TrimSuffix(p, "%")
					if val, err := strconv.ParseFloat(valStr, 64); err == nil {
						res.LossRate = val
						res.LossCount = int(math.Round(float64(res.Sent) * (val / 100.0)))
						res.Received = res.Sent - res.LossCount
					}
					break
				}
			}
		}
		// 解析平均延迟 (e.g. min/avg/max/stddev = 145.2/150.1/160.3/4.2 ms)
		if strings.Contains(lower, "min/avg/max") || strings.Contains(lower, "round-trip") || strings.Contains(lower, "rtt") {
			if idx := strings.Index(line, "="); idx != -1 {
				vals := strings.TrimSpace(line[idx+1:])
				parts := strings.Split(vals, "/")
				if len(parts) >= 3 {
					if avg, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
						res.AvgRTT = time.Duration(avg * float64(time.Millisecond))
					}
					if min, err := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64); err == nil {
						res.MinRTT = time.Duration(min * float64(time.Millisecond))
					}
					if maxPart := strings.Fields(parts[2]); len(maxPart) > 0 {
						if max, err := strconv.ParseFloat(maxPart[0], 64); err == nil {
							res.MaxRTT = time.Duration(max * float64(time.Millisecond))
						}
					}
					if len(parts) >= 4 {
						if stdPart := strings.Fields(parts[3]); len(stdPart) > 0 {
							if std, err := strconv.ParseFloat(stdPart[0], 64); err == nil {
								res.Jitter = time.Duration(std * float64(time.Millisecond))
							}
						}
					}
				}
			}
		}
	}
	if len(rtts) > 0 {
		res.RTTs = rtts
		if res.Jitter == 0 && res.AvgRTT > 0 {
			var varianceSum float64
			avgNano := float64(res.AvgRTT.Nanoseconds())
			for _, rtt := range rtts {
				diff := float64(rtt.Nanoseconds()) - avgNano
				varianceSum += diff * diff
			}
			res.Jitter = time.Duration(int64(math.Sqrt(varianceSum / float64(len(rtts)))))
		}
	}
}
