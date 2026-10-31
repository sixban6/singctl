package netdiag

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	// 正则匹配 IP 地址
	ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// 正则匹配延迟数字 (e.g. 15.2 ms 或 15 ms)
	rttRegex = regexp.MustCompile(`([\d\.]+)\s*ms`)
)

// TraceOptions 路由追踪参数
type TraceOptions struct {
	Target  string
	MaxHops int           // 默认 25
	Timeout time.Duration // 单跳超时，默认 1s
}

// RunTrace 执行路由追踪并分析骨干网线路特征
func RunTrace(ctx context.Context, opts TraceOptions) (*TraceResult, error) {
	if opts.MaxHops <= 0 {
		opts.MaxHops = 25
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1 * time.Second
	}

	start := time.Now()
	res := &TraceResult{
		Target: opts.Target,
	}

	// 1. 优先尝试解析域名为 IP
	targetIP := opts.Target
	if parsed := net.ParseIP(targetIP); parsed == nil {
		ips, err := net.LookupIP(opts.Target)
		if err == nil && len(ips) > 0 {
			targetIP = ips[0].String()
		}
	}

	// 2. 调用跨平台底层追踪命令
	hops, err := executeSystemTrace(ctx, targetIP, opts.MaxHops, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("trace execution failed: %w", err)
	}

	// 3. 增强跳点信息并标注骨干特征
	for i := range hops {
		if hops[i].IP != "" && hops[i].IP != "*" {
			tag, carrier, route, asn := InspectHop(hops[i].IP, hops[i].Host)
			hops[i].Tag = tag
			hops[i].Carrier = carrier
			hops[i].ASN = asn

			if route == "CN2" {
				res.HasCN2 = true
			}
			if route == "163" {
				res.Has163 = true
			}
			if route == "4837" {
				res.Has4837 = true
			}
			if route == "9929" {
				res.Has9929 = true
			}
			if route == "CMI" {
				res.HasCMI = true
			}
			if route == "CMIN2" {
				res.HasCMIN2 = true
			}
		}
	}

	res.Hops = hops
	res.DurationSecs = time.Since(start).Seconds()

	// 4. 判定整条路线分类
	identified, routeType, details := ClassifyRoute(hops)
	res.Identified = identified
	res.RouteType = routeType
	res.Details = details

	return res, nil
}

func executeSystemTrace(ctx context.Context, target string, maxHops int, timeout time.Duration) ([]HopInfo, error) {
	var cmd *exec.Cmd
	timeoutMs := int(timeout.Milliseconds())
	timeoutSec := int(timeout.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}

	switch runtime.GOOS {
	case "windows":
		// Windows: tracert -d (不解析域名) -h (最大跃点) -w (超时毫秒)
		cmd = exec.CommandContext(ctx, "tracert", "-d", "-h", strconv.Itoa(maxHops), "-w", strconv.Itoa(timeoutMs), target)
	case "darwin":
		// macOS: traceroute -n (不解析域名) -m (最大跃点) -w (超时秒) -q 1 (单次探测，加速)
		cmd = exec.CommandContext(ctx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(timeoutSec), "-q", "1", target)
	default: // Linux / OpenWrt
		// 优先探测是否有 traceroute，没有则探测 tracepath
		if _, err := exec.LookPath("traceroute"); err == nil {
			cmd = exec.CommandContext(ctx, "traceroute", "-n", "-m", strconv.Itoa(maxHops), "-w", strconv.Itoa(timeoutSec), "-q", "1", target)
		} else if _, err := exec.LookPath("tracepath"); err == nil {
			cmd = exec.CommandContext(ctx, "tracepath", "-n", "-m", strconv.Itoa(maxHops), target)
		} else {
			return nil, fmt.Errorf("traceroute/tracepath command not found on system")
		}
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var hops []HopInfo
	scanner := bufio.NewScanner(stdout)
	hopIndex := 1

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 忽略开头的提示信息行
		if strings.HasPrefix(strings.ToLower(line), "traceroute") || strings.HasPrefix(strings.ToLower(line), "tracing") || strings.Contains(line, "over a maximum") {
			continue
		}

		hop := parseTraceLine(line, hopIndex)
		if hop != nil {
			hops = append(hops, *hop)
			hopIndex++
		}
	}

	_ = cmd.Wait()
	return hops, nil
}

func parseTraceLine(line string, expectedHop int) *HopInfo {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}

	// 检查首字段是否为跳点序号 (e.g. 1, 2, 3...)
	hopNum, err := strconv.Atoi(fields[0])
	if err != nil {
		// 有些输出可能格式不同，尝试在行内提取数字
		fields0Clean := strings.TrimSuffix(fields[0], ":")
		if n, err := strconv.Atoi(fields0Clean); err == nil {
			hopNum = n
		} else {
			hopNum = expectedHop
		}
	}

	hop := &HopInfo{
		Hop: hopNum,
	}

	// 提取 IP 地址
	ipMatch := ipRegex.FindString(line)
	if ipMatch != "" {
		hop.IP = ipMatch
	} else if strings.Contains(line, "*") {
		hop.IP = "*"
	}

	// 提取 RTT
	rttMatch := rttRegex.FindStringSubmatch(line)
	if len(rttMatch) >= 2 {
		if val, err := strconv.ParseFloat(rttMatch[1], 64); err == nil {
			hop.RTT = time.Duration(val * float64(time.Millisecond))
		}
	}

	return hop
}
