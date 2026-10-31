package netdiag

import (
	"context"
	"math"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// PingOptions 探测配置参数
type PingOptions struct {
	Host     string
	Port     int           // 默认 443
	Count    int           // 默认 10 轮
	Timeout  time.Duration // 单次超时，默认 1500ms
	Interval time.Duration // 间隔，默认 150ms
	ForceTCP bool
	ForceICMP bool
}

// RunPing 执行 Ping 探测，优先推荐 TCP Ping（免 root、抗机房 ICMP 阻断、贴合代理端口真实表现）
// 若 TCP 探测遭遇全量丢包 (可能为端口未开放或宿主机防火墙拦截)，将自动回退至 ICMP 探测。
func RunPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	if opts.Count <= 0 {
		opts.Count = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1500 * time.Millisecond
	}
	if opts.Interval <= 0 {
		opts.Interval = 100 * time.Millisecond
	}
	if opts.Port <= 0 {
		opts.Port = 443
	}

	if opts.ForceICMP {
		return RunICMPPing(ctx, opts)
	}

	// 1. 优先尝试 TCP Ping
	tcpRes, err := RunTCPPing(ctx, opts)
	if err == nil && tcpRes != nil && tcpRes.Received > 0 {
		return tcpRes, nil
	}

	// 2. 如果强制 TCP 则不回退
	if opts.ForceTCP {
		return tcpRes, err
	}

	// 3. 自动回退至系统 ICMP Ping
	icmpRes, icmpErr := RunICMPPing(ctx, opts)
	if icmpErr == nil && icmpRes != nil && icmpRes.Received > 0 {
		return icmpRes, nil
	}

	// 如果两者均无返回或均失败，优先返回初始 TCP 结果（若有）
	if tcpRes != nil {
		return tcpRes, nil
	}
	if icmpRes != nil {
		return icmpRes, nil
	}
	return nil, err
}

// RunTCPPing 执行多轮免 Root 的 TCP Ping
func RunTCPPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	addr := net.JoinHostPort(opts.Host, strconv.Itoa(opts.Port))
	result := &PingResult{
		Target: opts.Host,
		Port:   opts.Port,
		IsTCP:  true,
		Sent:   opts.Count,
	}

	var rtts []time.Duration
	var minRTT, maxRTT time.Duration
	var totalRTT time.Duration

	for i := 0; i < opts.Count; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := time.Now()
		d := net.Dialer{Timeout: opts.Timeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		elapsed := time.Since(start)

		if err == nil {
			_ = conn.Close()
			rtts = append(rtts, elapsed)
			totalRTT += elapsed
			if len(rtts) == 1 || elapsed < minRTT {
				minRTT = elapsed
			}
			if elapsed > maxRTT {
				maxRTT = elapsed
			}
		}

		if i < opts.Count-1 {
			time.Sleep(opts.Interval)
		}
	}

	result.Received = len(rtts)
	result.LossCount = result.Sent - result.Received
	if result.Sent > 0 {
		result.LossRate = (float64(result.LossCount) / float64(result.Sent)) * 100
	}
	result.RTTs = rtts

	if len(rtts) > 0 {
		result.MinRTT = minRTT
		result.MaxRTT = maxRTT
		result.AvgRTT = time.Duration(int64(totalRTT) / int64(len(rtts)))

		// 计算抖动 Jitter (RTT 标准差)
		var varianceSum float64
		avgNano := float64(result.AvgRTT.Nanoseconds())
		for _, rtt := range rtts {
			diff := float64(rtt.Nanoseconds()) - avgNano
			varianceSum += diff * diff
		}
		stdDevNano := math.Sqrt(varianceSum / float64(len(rtts)))
		result.Jitter = time.Duration(int64(stdDevNano))
	}

	result.QualityLevel = EvaluateQuality(result.LossRate, result.Jitter)
	return result, nil
}

// RunICMPPing 调用系统 ping 进行 ICMP 探测回退
func RunICMPPing(ctx context.Context, opts PingOptions) (*PingResult, error) {
	result := &PingResult{
		Target: opts.Host,
		Port:   0,
		IsTCP:  false,
		Sent:   opts.Count,
	}

	var cmd *exec.Cmd
	timeoutSec := int(opts.Timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	switch runtime.GOOS {
	case "windows":
		cmd = exec.CommandContext(ctx, "ping", "-n", strconv.Itoa(opts.Count), "-w", strconv.Itoa(int(opts.Timeout.Milliseconds())), opts.Host)
	case "darwin":
		cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(opts.Count), "-W", strconv.Itoa(int(opts.Timeout.Milliseconds())), opts.Host)
	default: // Linux / OpenWrt
		cmd = exec.CommandContext(ctx, "ping", "-c", strconv.Itoa(opts.Count), "-W", strconv.Itoa(timeoutSec), opts.Host)
	}

	out, err := cmd.CombinedOutput()
	output := string(out)

	if err != nil && len(output) == 0 {
		// ping 命令不可用时，优雅回退到 TCP Ping
		return RunTCPPing(ctx, opts)
	}

	// 解析系统 Ping 输出
	parseSystemPingOutput(output, result)
	result.QualityLevel = EvaluateQuality(result.LossRate, result.Jitter)
	return result, nil
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
	for _, line := range lines {
		lower := strings.ToLower(line)
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
}
