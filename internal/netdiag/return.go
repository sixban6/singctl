package netdiag

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// DefaultReturnTargets 默认三网代表性骨干探测节点
var DefaultReturnTargets = []ReturnTarget{
	{Carrier: ISPTelecom, Name: "上海电信 (163 骨干)", TargetIP: "202.96.209.133", City: "上海", Expected: "AS4134 (163)"},
	{Carrier: ISPTelecom, Name: "上海电信 (CN2 节点)", TargetIP: "59.43.247.1", City: "上海", Expected: "AS4809 (CN2)"},
	{Carrier: ISPUnicom, Name: "北京联通 (4837 骨干)", TargetIP: "219.158.113.1", City: "北京", Expected: "AS4837 (CU169)"},
	{Carrier: ISPUnicom, Name: "北京联通 (9929 精品)", TargetIP: "218.105.10.1", City: "北京", Expected: "AS9929 (A网)"},
	{Carrier: ISPMobile, Name: "广州移动 (CMI 出口)", TargetIP: "221.183.55.1", City: "广州", Expected: "AS9808 (CMI)"},
	{Carrier: ISPMobile, Name: "广州移动 (CMIN2 精品)", TargetIP: "223.120.22.1", City: "广州", Expected: "AS58807 (CMIN2)"},
}

// RunReturnRoute 测试当前 VPS 回程到国内三网主要骨干节点的真实线路与丢包
func RunReturnRoute(ctx context.Context, count int) (*ReturnSummary, error) {
	if count <= 0 {
		count = 5
	}

	summary := &ReturnSummary{
		ScanTime: time.Now(),
		Results:  make([]ReturnHopResult, len(DefaultReturnTargets)),
	}

	// 1. 获取本机公网 IP
	if isp, err := GetPublicISP(ctx); err == nil && isp != nil {
		summary.ServerIP = isp.IP
	}

	// 2. 并发或受控测试各国内目标
	var wg sync.WaitGroup
	results := make([]ReturnHopResult, len(DefaultReturnTargets))

	for i, target := range DefaultReturnTargets {
		wg.Add(1)
		go func(idx int, tgt ReturnTarget) {
			defer wg.Done()

			hopRes := ReturnHopResult{
				Carrier:  tgt.Carrier,
				Name:     tgt.Name,
				TargetIP: tgt.TargetIP,
				City:     tgt.City,
			}

			// 测试 RTT 与丢包
			pingRes, err := RunPing(ctx, PingOptions{
				Host:      tgt.TargetIP,
				Port:      80, // 回程测试常用 80 端口或系统 ICMP
				Count:     count,
				Timeout:   1200 * time.Millisecond,
				ForceICMP: true,
			})
			if err == nil && pingRes != nil {
				hopRes.AvgRTT = pingRes.AvgRTT
				hopRes.LossRate = pingRes.LossRate
			}

			// 轻量追踪前 15 跳
			traceRes, err := RunTrace(ctx, TraceOptions{
				Target:  tgt.TargetIP,
				MaxHops: 15,
				Timeout: 800 * time.Millisecond,
			})
			if err == nil && traceRes != nil {
				hopRes.RouteName = traceRes.Identified
				hopRes.RouteType = traceRes.RouteType

				var keys []string
				for _, h := range traceRes.Hops {
					if h.Tag != "" {
						keys = append(keys, fmt.Sprintf("%s (%s)", h.IP, h.Tag))
					}
				}
				hopRes.KeyHops = keys
			} else {
				hopRes.RouteName = "普通公网回程"
				hopRes.RouteType = "UNKNOWN"
			}

			results[idx] = hopRes
		}(i, target)
	}

	wg.Wait()
	summary.Results = results

	// 3. 统计适配的运营商
	summary.BestForISP = evaluateBestISPs(results)
	summary.Summary = buildReturnSummaryText(results, summary.BestForISP)

	return summary, nil
}

func evaluateBestISPs(results []ReturnHopResult) []ISPType {
	var best []ISPType
	var ctScore, cuScore, cmScore int

	for _, r := range results {
		switch r.Carrier {
		case ISPTelecom:
			if strings.Contains(r.RouteName, "CN2") || (r.LossRate < 5.0 && r.AvgRTT < 180*time.Millisecond) {
				ctScore += 2
			} else if r.LossRate < 10.0 {
				ctScore++
			}
		case ISPUnicom:
			if strings.Contains(r.RouteName, "9929") || strings.Contains(r.RouteName, "4837") || r.LossRate < 5.0 {
				cuScore += 2
			}
		case ISPMobile:
			if strings.Contains(r.RouteName, "CMIN2") || strings.Contains(r.RouteName, "CMI") || r.LossRate < 5.0 {
				cmScore += 2
			}
		}
	}

	if ctScore >= 2 {
		best = append(best, ISPTelecom)
	}
	if cuScore >= 2 {
		best = append(best, ISPUnicom)
	}
	if cmScore >= 2 {
		best = append(best, ISPMobile)
	}
	return best
}

func buildReturnSummaryText(results []ReturnHopResult, best []ISPType) string {
	if len(best) == 3 {
		return "三网回程均非常均衡优秀（全网优化线路）"
	}
	if len(best) == 0 {
		return "三网回程多走普通国际 BGP 转接，晚高峰可能存在丢包，建议搭配 Hysteria 2 协议使用"
	}

	var names []string
	for _, b := range best {
		switch b {
		case ISPTelecom:
			names = append(names, "电信")
		case ISPUnicom:
			names = append(names, "联通")
		case ISPMobile:
			names = append(names, "移动")
		}
	}
	return fmt.Sprintf("该 VPS 回程更适合: %s 用户直连", strings.Join(names, " / "))
}
