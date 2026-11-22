// 文件职责：实现行为审计“限速不拉黑”策略的 iptables/ip6tables xt_limit 隔离链渲染与下发后端。
package audit

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	// ThrottleIPTablesChain 是行为审计“限速不拉黑”专用的 iptables/ip6tables 隔离链名（挂 filter 表 FORWARD 与 OUTPUT 顶部）。
	ThrottleIPTablesChain = "SINGCTL_AUDIT_THROTTLE"

	throttleAvgPacketBytes = 1400
	xtLimitMaxPPS          = 10000
	xtLimitMinBurst        = 5
)

// CalcThrottlePPS 按标准 1400 B/pkt 将 KB/s 速率换算为 Linux xt_limit 的每秒包速率与突发桶容量。
// 下限 1/sec，burst 为 max(5, pps)，并钳制在内核 XT_LIMIT_SCALE (10000/sec) 安全范围内。
func CalcThrottlePPS(rateKBps int) (pps int, burst int) {
	if rateKBps < MinThrottleRateKBps {
		rateKBps = MinThrottleRateKBps
	}
	pps = min(max(1, (rateKBps*1024)/throttleAvgPacketBytes), xtLimitMaxPPS)
	burst = min(max(xtLimitMinBurst, pps), xtLimitMaxPPS)
	return pps, burst
}

type iptablesThrottleBackend struct {
	runCmd    func(ctx context.Context, name string, args ...string) ([]byte, error)
	hasBinary func(name string) bool
}

func (b *iptablesThrottleBackend) Name() string {
	return "iptables"
}

func (b *iptablesThrottleBackend) Apply(ctx context.Context, lines []resolvedThrottleLine) error {
	var v4Lines, v6Lines []resolvedThrottleLine
	for _, ln := range lines {
		if ln.isV6 {
			v6Lines = append(v6Lines, ln)
		} else {
			v4Lines = append(v4Lines, ln)
		}
	}

	if len(v4Lines) > 0 {
		if err := b.applyFamily(ctx, "iptables", v4Lines); err != nil {
			return err
		}
	} else {
		b.clearFamily(ctx, "iptables")
	}

	if b.hasBinary("ip6tables") {
		if len(v6Lines) > 0 {
			_ = b.applyFamily(ctx, "ip6tables", v6Lines)
		} else {
			b.clearFamily(ctx, "ip6tables")
		}
	}
	return nil
}

func (b *iptablesThrottleBackend) Clear(ctx context.Context) error {
	if b.hasBinary("iptables") {
		b.clearFamily(ctx, "iptables")
	}
	if b.hasBinary("ip6tables") {
		b.clearFamily(ctx, "ip6tables")
	}
	return nil
}

func (b *iptablesThrottleBackend) applyFamily(ctx context.Context, bin string, lines []resolvedThrottleLine) error {
	if out, err := b.runCmd(ctx, bin, "-N", ThrottleIPTablesChain); err != nil {
		msg := strings.ToLower(string(out))
		if !strings.Contains(msg, "already exists") {
			if _, fErr := b.runCmd(ctx, bin, "-F", ThrottleIPTablesChain); fErr != nil {
				return fmt.Errorf("%s 创建限速隔离链失败: %v (%s)", bin, err, strings.TrimSpace(string(out)))
			}
		}
	}
	if out, err := b.runCmd(ctx, bin, "-F", ThrottleIPTablesChain); err != nil {
		return fmt.Errorf("%s 清空限速隔离链失败: %v (%s)", bin, err, strings.TrimSpace(string(out)))
	}
	if out, err := b.runCmd(ctx, bin, "-A", ThrottleIPTablesChain, "-o", "lo", "-j", "RETURN"); err != nil {
		return fmt.Errorf("%s 写入回环豁免规则失败: %v (%s)", bin, err, strings.TrimSpace(string(out)))
	}

	for _, ln := range lines {
		pps, burst := CalcThrottlePPS(ln.rate)
		limitExpr := fmt.Sprintf("%d/sec", pps)
		burstExpr := strconv.Itoa(burst)

		for _, proto := range []string{"tcp", "udp"} {
			acceptArgs := []string{"-A", ThrottleIPTablesChain, "-d", ln.expr, "-p", proto}
			dropArgs := []string{"-A", ThrottleIPTablesChain, "-d", ln.expr, "-p", proto}
			if ln.port > 0 {
				portStr := strconv.Itoa(ln.port)
				acceptArgs = append(acceptArgs, "--dport", portStr)
				dropArgs = append(dropArgs, "--dport", portStr)
			}
			acceptArgs = append(acceptArgs, "-m", "limit", "--limit", limitExpr, "--limit-burst", burstExpr, "-j", "ACCEPT")
			dropArgs = append(dropArgs, "-j", "DROP")

			if out, err := b.runCmd(ctx, bin, acceptArgs...); err != nil {
				return fmt.Errorf("%s 写入限速放行规则失败: %v (%s)", bin, err, strings.TrimSpace(string(out)))
			}
			if out, err := b.runCmd(ctx, bin, dropArgs...); err != nil {
				return fmt.Errorf("%s 写入限速超限丢弃规则失败: %v (%s)", bin, err, strings.TrimSpace(string(out)))
			}
		}
	}

	for _, hook := range []string{"FORWARD", "OUTPUT"} {
		if _, err := b.runCmd(ctx, bin, "-C", hook, "-j", ThrottleIPTablesChain); err != nil {
			if out, iErr := b.runCmd(ctx, bin, "-I", hook, "1", "-j", ThrottleIPTablesChain); iErr != nil {
				return fmt.Errorf("%s 挂载 %s 限速钩子失败: %v (%s)", bin, hook, iErr, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func (b *iptablesThrottleBackend) clearFamily(ctx context.Context, bin string) {
	for _, hook := range []string{"FORWARD", "OUTPUT"} {
		for range 8 {
			if _, err := b.runCmd(ctx, bin, "-C", hook, "-j", ThrottleIPTablesChain); err != nil {
				break
			}
			_, _ = b.runCmd(ctx, bin, "-D", hook, "-j", ThrottleIPTablesChain)
		}
	}
	_, _ = b.runCmd(ctx, bin, "-F", ThrottleIPTablesChain)
	_, _ = b.runCmd(ctx, bin, "-X", ThrottleIPTablesChain)
}
