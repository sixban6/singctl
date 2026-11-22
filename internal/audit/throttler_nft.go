// 文件职责：实现行为审计“限速不拉黑”策略的 nftables 隔离表渲染与下发后端。
package audit

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"singctl/internal/config"
)

type nftThrottleBackend struct {
	runNFT    func(ctx context.Context, script string) error
	deleteNFT func(ctx context.Context) error
}

func (b *nftThrottleBackend) Name() string {
	return "nftables"
}

func (b *nftThrottleBackend) Apply(ctx context.Context, lines []resolvedThrottleLine) error {
	if b.runNFT == nil {
		return fmt.Errorf("未配置 nftables 执行器")
	}
	return b.runNFT(ctx, renderThrottleNFTScript(lines))
}

func (b *nftThrottleBackend) Clear(ctx context.Context) error {
	if b.deleteNFT == nil {
		return nil
	}
	return b.deleteNFT(ctx)
}

func defaultRunNFT(ctx context.Context, script string) error {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("未检测到 nft 命令，跳过内核限速规则下发")
	}
	cmd := exec.CommandContext(ctx, nftBin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft 执行失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func defaultDeleteNFT(ctx context.Context) error {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		return nil
	}
	out, err := exec.CommandContext(ctx, nftBin, "delete", "table", "inet", ThrottleNFTTable).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "No such file or directory") || strings.Contains(msg, "does not exist") {
			return nil
		}
		return fmt.Errorf("清理 nftables 限速表失败: %v (%s)", err, msg)
	}
	return nil
}

func renderThrottleNFTScript(lines []resolvedThrottleLine) string {
	if len(lines) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("add table inet ")
	sb.WriteString(ThrottleNFTTable)
	sb.WriteByte('\n')
	sb.WriteString("flush table inet ")
	sb.WriteString(ThrottleNFTTable)
	sb.WriteByte('\n')
	sb.WriteString("table inet ")
	sb.WriteString(ThrottleNFTTable)
	sb.WriteString(" {\n")
	sb.WriteString("  chain prerouting {\n")
	sb.WriteString("    type filter hook prerouting priority -160; policy accept;\n")
	sb.WriteString("    iifname \"lo\" return\n")
	for _, ln := range lines {
		family := "ip"
		if ln.isV6 {
			family = "ip6"
		}
		burst := min(max(16, ln.rate*3), 256)
		if ln.port > 0 {
			fmt.Fprintf(&sb, "    %s daddr %s meta l4proto { tcp, udp } th dport %d limit rate over %d kbytes/second burst %d kbytes drop\n",
				family, ln.expr, ln.port, ln.rate, burst)
		} else {
			fmt.Fprintf(&sb, "    %s daddr %s meta l4proto { tcp, udp } limit rate over %d kbytes/second burst %d kbytes drop\n",
				family, ln.expr, ln.rate, burst)
		}
	}
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	return sb.String()
}

// BuildNFTScript 将 cfg.Audit.Throttles 编译为完整的原子 nftables 限速脚本文本。
func (t *Throttler) BuildNFTScript(ctx context.Context, cfg *config.Config) (script string, activeRules int, activeIPs int) {
	lines, rules, ips := t.resolveThrottleLines(ctx, cfg)
	if rules == 0 || len(lines) == 0 {
		return "", 0, 0
	}
	return renderThrottleNFTScript(lines), rules, ips
}
