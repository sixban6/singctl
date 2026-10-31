package netdiag

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// PrintDiagReport 格式化输出综合诊断报告
func PrintDiagReport(w io.Writer, r *DiagReport, verbose bool) error {
	divider := strings.Repeat("=", 64)
	subDivider := strings.Repeat("-", 64)

	fmt.Fprintln(w, "\n"+divider)
	fmt.Fprintf(w, "🌐  SingCtl 网络链路画像与选型诊断报告\n")
	fmt.Fprintf(w, "🎯 目标节点: %s", r.Target)
	if r.TargetIP != "" && r.TargetIP != r.Target {
		fmt.Fprintf(w, " (%s)", r.TargetIP)
	}
	if r.TargetPort > 0 {
		fmt.Fprintf(w, " : 端口 %d", r.TargetPort)
	}

	if r.LocalISP != nil {
		fmt.Fprintf(w, "\n🏠 本地网络: %s | %s %s | IP: %s", r.LocalISP.Type, r.LocalISP.Country, r.LocalISP.City, r.LocalISP.IP)
	}
	peakStr := ""
	if r.IsPeakHour {
		peakStr = " ⚠️ [晚高峰时段 20:00-24:00]"
	}
	fmt.Fprintf(w, "\n⏱️  检测时间: %s%s\n", r.ScanTime.Format("2006-01-02 15:04:05"), peakStr)
	fmt.Fprintln(w, subDivider)

	// [1/3] 延迟、抖动与丢包
	if r.Ping != nil {
		statusEmoji := qualityEmoji(r.Ping.QualityLevel)
		if r.Ping.TCP != nil || r.Ping.UDP != nil || r.Ping.ICMP != nil {
			fmt.Fprintf(w, "\n[1/3] 📡 连通性与丢包波动测试 (%d 轮 TCP + UDP/QUIC + ICMP 并发探测)\n", r.Ping.Sent)
			if r.Ping.TCP != nil {
				fmt.Fprintf(w, "      ├─ TCP 握手  : %s\n", formatSubPingLine(r.Ping.TCP, "TCP"))
			}
			if r.Ping.UDP != nil {
				fmt.Fprintf(w, "      ├─ UDP/QUIC  : %s\n", formatUDPSubPingLine(r.Ping.UDP, r.Ping.TCP))
			}
			if r.Ping.ICMP != nil {
				fmt.Fprintf(w, "      ├─ ICMP 探测 : %s\n", formatICMPSubPingLine(r.Ping.ICMP, r.Ping.TCP))
			}
			fmt.Fprintf(w, "      └─ 综合评估  : 综合丢包率 %.1f%% (%d/%d 丢失) | 最大抖动 %v | %s %s\n",
				r.Ping.LossRate, r.Ping.LossCount, r.Ping.Sent, r.Ping.Jitter.Round(time.Millisecond), statusEmoji, r.Ping.QualityLevel)
		} else {
			fmt.Fprintf(w, "\n[1/3] 📡 连通性与丢包波动测试 (%d 轮 %s Ping)\n", r.Ping.Sent, pingProtoLabel(r.Ping))
			fmt.Fprintf(w, "      ├─ 延迟指标 : Min %v | Avg %v | Max %v\n", r.Ping.MinRTT.Round(time.Millisecond), r.Ping.AvgRTT.Round(time.Millisecond), r.Ping.MaxRTT.Round(time.Millisecond))
			fmt.Fprintf(w, "      ├─ 网络抖动 : %v (Jitter/标准差)\n", r.Ping.Jitter.Round(time.Millisecond))
			fmt.Fprintf(w, "      ├─ 丢包表现 : %.1f%% (%d/%d 丢失) %s %s\n", r.Ping.LossRate, r.Ping.LossCount, r.Ping.Sent, statusEmoji, r.Ping.QualityLevel)
		}

		if verbose && len(r.Ping.RTTs) > 0 {
			var rttStrs []string
			for _, rtt := range r.Ping.RTTs {
				rttStrs = append(rttStrs, fmt.Sprintf("%dms", rtt.Milliseconds()))
			}
			fmt.Fprintf(w, "      │  └─ 往返分布: [%s]\n", strings.Join(rttStrs, ", "))
		}
	}

	// [2/3] 骨干线路追踪与识别
	if r.Trace != nil {
		fmt.Fprintf(w, "\n[2/3] 🛣️ 跨境骨干线路特征分析 (Traceroute %d 跳, 耗时 %.1fs)\n", len(r.Trace.Hops), r.Trace.DurationSecs)
		fmt.Fprintf(w, "      ├─ 判定结论 : 🚀 %s\n", r.Trace.Identified)
		fmt.Fprintf(w, "      ├─ 线路依据 : %s\n", r.Trace.Details)

		var keyHops []string
		for _, h := range r.Trace.Hops {
			if h.Tag != "" {
				keyHops = append(keyHops, fmt.Sprintf("%s (%s)", h.IP, h.Tag))
			}
		}
		if len(keyHops) > 0 {
			fmt.Fprintf(w, "      └─ 核心跳点 : %s\n", strings.Join(keyHops, " -> "))
		} else {
			fmt.Fprintln(w, "      └─ 核心跳点 : 未检测到典型运营商精品骨干跳点")
		}

		if verbose && len(r.Trace.Hops) > 0 {
			fmt.Fprintln(w, "      │  └─ 完整路径跳点明细:")
			for _, h := range r.Trace.Hops {
				tag := ""
				if h.Tag != "" {
					tag = fmt.Sprintf(" [%s]", h.Tag)
				}
				fmt.Fprintf(w, "      │     #%-2d  %-16s  %6s%s\n", h.Hop, h.IP, formatRTT(h.RTT), tag)
			}
		}
	}

	// [3/3] 智能建议与选型指导
	if r.Advice != nil {
		fmt.Fprintln(w, "\n[3/3] 💡 决策建议引擎 (Advice Engine)")
		fmt.Fprintf(w, "      ├─ 协议推荐 : %s\n", r.Advice.RecommendedProtocol)
		fmt.Fprintf(w, "      │  └─ 理由: %s\n", r.Advice.ProtocolReason)
		fmt.Fprintf(w, "      ├─ 带宽建议 : 推荐写入 singctl.yaml -> hy2.up: %d Mbps, hy2.down: %d Mbps\n", r.Advice.SuggestedHy2Up, r.Advice.SuggestedHy2Down)
		fmt.Fprintf(w, "      └─ 本地契合度: %d / 100 分\n", r.Advice.CarrierMatchScore)
		fmt.Fprintf(w, "         └─ 分析: %s\n", r.Advice.CarrierAdvice)
	}

	fmt.Fprintln(w, "\n"+divider)
	return nil
}

func formatSubPingLine(p *PingResult, kind string) string {
	if len(p.RTTs) == 0 {
		return fmt.Sprintf("丢包 100.0%% (%d/%d 超时)", p.Sent, p.Sent)
	}
	if kind == "TCP" && p.LocalProxied {
		return fmt.Sprintf("Min %v | Avg %v | Max %v (⚠️ 本地 TUN/透明代理已接管 TCP 握手，以 UDP/ICMP 物理链路为准)",
			p.MinRTT.Round(time.Millisecond),
			p.AvgRTT.Round(time.Millisecond),
			p.MaxRTT.Round(time.Millisecond),
		)
	}
	lossDetail := fmt.Sprintf("%d/%d 丢失", p.LossCount, p.Sent)
	if kind == "TCP" && p.RetransCount > 0 {
		lossDetail = fmt.Sprintf("%d/%d 异常, 含 %d 次 SYN 丢包重传", p.LossCount, p.Sent, p.RetransCount)
	} else if kind == "UDP" {
		lossDetail = fmt.Sprintf("%d/%d 丢失, QUIC 1200B", p.LossCount, p.Sent)
	}
	return fmt.Sprintf("丢包 %.1f%% (%s) | Min %v | Avg %v | Max %v | Jitter %v",
		p.LossRate,
		lossDetail,
		p.MinRTT.Round(time.Millisecond),
		p.AvgRTT.Round(time.Millisecond),
		p.MaxRTT.Round(time.Millisecond),
		p.Jitter.Round(time.Millisecond),
	)
}

func formatUDPSubPingLine(udp *PingResult, tcp *PingResult) string {
	if udp.Received > 0 {
		return formatSubPingLine(udp, "UDP")
	}
	if udp.PortClosed {
		return fmt.Sprintf("端口 %d 已关闭 (Connection Refused，未运行 Hysteria2/QUIC)", udp.Port)
	}
	if tcp != nil && len(tcp.RTTs) > 0 {
		return fmt.Sprintf("100.0%% 超时 (%d/%d) ⚠️ UDP %d 未响应 QUIC (未开启 Hy2/HTTP3 或被防火墙/运营商阻断)", udp.Sent, udp.Sent, udp.Port)
	}
	return fmt.Sprintf("丢包 100.0%% (%d/%d 超时)", udp.Sent, udp.Sent)
}

func formatICMPSubPingLine(icmp *PingResult, tcp *PingResult) string {
	if icmp.Received > 0 {
		return formatSubPingLine(icmp, "ICMP")
	}
	if tcp != nil && len(tcp.RTTs) > 0 {
		return fmt.Sprintf("100.0%% 超时 (%d/%d，目标机房可能禁 Ping 或全丢)", icmp.Sent, icmp.Sent)
	}
	return fmt.Sprintf("丢包 100.0%% (%d/%d 超时)", icmp.Sent, icmp.Sent)
}

func qualityEmoji(q RouteQuality) string {
	switch q {
	case QualityCongested:
		return "🟠"
	case QualitySevere:
		return "🔴"
	case QualityGood:
		return "🟡"
	default:
		return "🟢"
	}
}

// PrintPingResult 单独格式化输出 Ping 报告
func PrintPingResult(w io.Writer, p *PingResult) {
	if p.TCP != nil || p.UDP != nil || p.ICMP != nil {
		fmt.Fprintf(w, "📡 目标: %s (端口: %d, 多维并发 Ping: TCP + UDP/QUIC + ICMP)\n", p.Target, p.Port)
		if p.TCP != nil {
			fmt.Fprintf(w, "  ├─ TCP 握手  : %s\n", formatSubPingLine(p.TCP, "TCP"))
		}
		if p.UDP != nil {
			fmt.Fprintf(w, "  ├─ UDP/QUIC  : %s\n", formatUDPSubPingLine(p.UDP, p.TCP))
		}
		if p.ICMP != nil {
			fmt.Fprintf(w, "  ├─ ICMP 探测 : %s\n", formatICMPSubPingLine(p.ICMP, p.TCP))
		}
		fmt.Fprintf(w, "  └─ 综合评估  : 丢包率 %.1f%% (%d/%d) | 抖动 %v | 链路质量: %s\n",
			p.LossRate, p.LossCount, p.Sent, p.Jitter.Round(time.Millisecond), p.QualityLevel)
		return
	}

	fmt.Fprintf(w, "📡 目标: %s (端口: %d, %s Ping)\n", p.Target, p.Port, pingProtoLabel(p))
	if p.RetransCount > 0 {
		fmt.Fprintf(w, "已发: %d, 正常收到: %d, 丢包/重传: %d (%.1f%%, 含 %d 次 SYN 重传)\n",
			p.Sent, p.Received, p.LossCount, p.LossRate, p.RetransCount)
	} else {
		fmt.Fprintf(w, "已发: %d, 收到: %d, 丢包: %d (%.1f%%)\n", p.Sent, p.Received, p.LossCount, p.LossRate)
	}
	if len(p.RTTs) > 0 {
		fmt.Fprintf(w, "往返延迟: Min = %v, Avg = %v, Max = %v, Jitter = %v\n",
			p.MinRTT.Round(time.Millisecond), p.AvgRTT.Round(time.Millisecond), p.MaxRTT.Round(time.Millisecond), p.Jitter.Round(time.Millisecond))
	}
	fmt.Fprintf(w, "链路质量: %s\n", p.QualityLevel)
}

// PrintTraceResult 单独格式化输出路由追踪结果
func PrintTraceResult(w io.Writer, t *TraceResult) {
	fmt.Fprintf(w, "🛣️ 目标: %s | 识别线路: %s\n", t.Target, t.Identified)
	fmt.Fprintf(w, "分析依据: %s\n", t.Details)
	fmt.Fprintln(w, strings.Repeat("-", 60))
	for _, h := range t.Hops {
		tag := ""
		if h.Tag != "" {
			tag = fmt.Sprintf(" [%s]", h.Tag)
		}
		fmt.Fprintf(w, "%-3d  %-18s  %8s%s\n", h.Hop, h.IP, formatRTT(h.RTT), tag)
	}
	fmt.Fprintln(w, strings.Repeat("-", 60))
}

// PrintReturnSummary 格式化输出 VPS 回程三网评测报告
func PrintReturnSummary(w io.Writer, s *ReturnSummary) {
	divider := strings.Repeat("=", 64)
	fmt.Fprintln(w, "\n"+divider)
	fmt.Fprintf(w, "🌏 VPS 服务端回程三网探测报告 (Return Route)\n")
	if s.ServerIP != "" {
		fmt.Fprintf(w, "🖥️  本机公网: %s\n", s.ServerIP)
	}
	fmt.Fprintf(w, "⏱️  探测时间: %s\n", s.ScanTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintln(w, divider)

	for i, r := range s.Results {
		status := "🟢"
		if r.LossRate > 10 {
			status = "🔴"
		} else if r.LossRate > 2 {
			status = "🟡"
		}

		fmt.Fprintf(w, "\n[%d/%d] %s (%s)\n", i+1, len(s.Results), r.Name, r.TargetIP)
		fmt.Fprintf(w, "      ├─ 回程线路 : %s\n", r.RouteName)
		fmt.Fprintf(w, "      ├─ 延迟丢包 : 平均 %v | 丢包 %.1f%% %s\n", r.AvgRTT.Round(time.Millisecond), r.LossRate, status)
		if len(r.KeyHops) > 0 {
			fmt.Fprintf(w, "      └─ 核心跳点 : %s\n", strings.Join(r.KeyHops, " -> "))
		}
	}

	fmt.Fprintln(w, "\n"+divider)
	fmt.Fprintf(w, "💡 综合回程结论: %s\n", s.Summary)
	fmt.Fprintln(w, divider)
}

// PrintJSON 输出标准 JSON 数据
func PrintJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func pingProtoLabel(p *PingResult) string {
	if p.Protocol != "" && p.Protocol != "MULTI" {
		if p.Protocol == "UDP" {
			return "UDP/QUIC"
		}
		return p.Protocol
	}
	if p.IsUDP {
		return "UDP/QUIC"
	}
	if p.IsTCP {
		return "TCP"
	}
	return "ICMP"
}

func formatRTT(rtt time.Duration) string {
	if rtt <= 0 {
		return "*"
	}
	return fmt.Sprintf("%.1fms", float64(rtt.Microseconds())/1000.0)
}
