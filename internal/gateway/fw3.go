// 文件职责：生成并同步 OpenWrt 21 (fw3 / iptables) 旁路由防火墙持久化 include 脚本，避免 fw3 restart 后丢规则。
package gateway

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"singctl/internal/common/fsx"
	"singctl/internal/logger"
)

const (
	// DefaultFW3IncludePath 为 OpenWrt 21 fw3 旁路由防火墙持久化脚本默认路径。
	DefaultFW3IncludePath = "/etc/singctl/singctl-side.fw3.sh"
	fw3SideUCISection     = "singctl_side"
)

// BuildSideRouterFW3Script 生成 OpenWrt 21 fw3 重载后幂等重建旁路由转发与单臂 MASQUERADE 的脚本（禁止使用 exit，兼容 source/. 与 sh 调用）。
func BuildSideRouterFW3Script(plan ResolvedPlan) string {
	var b strings.Builder
	b.WriteString("# Managed by singctl side-router guard (OpenWrt fw3 include)\n")
	b.WriteString("singctl_side_clean() {\n")
	b.WriteString("  tbl=\"$1\"; ch=\"$2\"\n")
	b.WriteString("  iptables -w 2 -t \"$tbl\" -S \"$ch\" 2>/dev/null | while IFS= read -r line; do\n")
	b.WriteString("    case \"$line\" in\n")
	b.WriteString("      \"-A $ch \"*" + ruleCommentTag + "*)\n")
	b.WriteString("        spec=\"${line#-A $ch }\"\n")
	b.WriteString("        eval \"set -- $spec\"\n")
	b.WriteString("        iptables -w 2 -t \"$tbl\" -D \"$ch\" \"$@\" 2>/dev/null || true\n")
	b.WriteString("        ;;\n")
	b.WriteString("    esac\n")
	b.WriteString("  done\n")
	b.WriteString("}\n\n")

	b.WriteString("singctl_side_clean filter INPUT\n")
	b.WriteString("singctl_side_clean filter FORWARD\n")
	b.WriteString("singctl_side_clean mangle PREROUTING\n\n")

	if plan.InterceptLocalDNS && plan.LANIP != "" {
		b.WriteString(fmt.Sprintf("iptables -w 2 -t mangle -I PREROUTING 1 ! -i lo -d %s -p udp --dport 53 -m comment --comment %s -j TPROXY --on-port 7895 --tproxy-mark 0x1 2>/dev/null || true\n", plan.LANIP, ruleCommentTag))
		b.WriteString(fmt.Sprintf("iptables -w 2 -t mangle -I PREROUTING 1 ! -i lo -d %s -p tcp --dport 53 -m comment --comment %s -j TPROXY --on-port 7895 --tproxy-mark 0x1 2>/dev/null || true\n", plan.LANIP, ruleCommentTag))
	}

	b.WriteString("iptables -w 2 -t mangle -D FORWARD -j " + legacySideChainFwd + " 2>/dev/null || true\n")
	b.WriteString("iptables -w 2 -t mangle -N " + legacySideChainFwd + " 2>/dev/null || true\n")
	b.WriteString("iptables -w 2 -t mangle -F " + legacySideChainFwd + "\n")
	b.WriteString("iptables -w 2 -t mangle -A " + legacySideChainFwd + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\n")
	b.WriteString("iptables -w 2 -t mangle -I FORWARD 1 -j " + legacySideChainFwd + "\n\n")

	b.WriteString("iptables -w 2 -t nat -D POSTROUTING -j " + legacySideChainNat + " 2>/dev/null || true\n")
	b.WriteString("iptables -w 2 -t nat -N " + legacySideChainNat + " 2>/dev/null || true\n")
	b.WriteString("iptables -w 2 -t nat -F " + legacySideChainNat + "\n")
	cidrs := sidePrivateCIDRs(plan.LANCIDR)
	for _, cidr := range cidrs {
		b.WriteString(fmt.Sprintf("iptables -w 2 -t nat -A %s -d %s -j RETURN\n", legacySideChainNat, cidr))
	}
	for _, cidr := range cidrs {
		b.WriteString(fmt.Sprintf("iptables -w 2 -t nat -A %s -o %s -s %s -j MASQUERADE\n", legacySideChainNat, plan.LANIface, cidr))
	}
	b.WriteString("iptables -w 2 -t nat -I POSTROUTING 1 -j " + legacySideChainNat + "\n\n")

	b.WriteString("iptables -w 2 -I INPUT 1 -m mark --mark 0x1 -m comment --comment " + ruleCommentTag + " -j ACCEPT\n")
	b.WriteString("iptables -w 2 -I INPUT 1 -m mark --mark 0x2 -m comment --comment " + ruleCommentTag + " -j ACCEPT\n")
	if plan.LANIface != "" {
		b.WriteString(fmt.Sprintf("iptables -w 2 -I INPUT 1 -i %s -m comment --comment %s -j ACCEPT\n", plan.LANIface, ruleCommentTag))
		b.WriteString(fmt.Sprintf("iptables -w 2 -I FORWARD 1 -i %s -m comment --comment %s -j ACCEPT\n", plan.LANIface, ruleCommentTag))
		b.WriteString(fmt.Sprintf("iptables -w 2 -I FORWARD 1 -o %s -m comment --comment %s -j ACCEPT\n", plan.LANIface, ruleCommentTag))
	}
	return b.String()
}

func (c *Controller) fw3IncludePath() string {
	return cmp.Or(strings.TrimSpace(c.FW3IncludePath), DefaultFW3IncludePath)
}

func (c *Controller) applyFW3Include(ctx context.Context, plan ResolvedPlan) {
	if !c.isHostOpenWrt() && strings.TrimSpace(c.FW3IncludePath) == "" {
		return
	}
	target := c.fw3IncludePath()
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0700); err != nil {
		logger.Warn("创建 fw3 include 目录 %s 失败: %v", dir, err)
		return
	}
	_ = os.Chmod(dir, 0700)
	if err := fsx.WriteAtomic0600(target, []byte(BuildSideRouterFW3Script(plan))); err != nil {
		logger.Warn("写入 fw3 持久化脚本 %s 失败: %v", target, err)
		return
	}
	if !c.hasCommand("uci") {
		return
	}
	sec := "firewall." + fw3SideUCISection
	_, _ = c.runCmd(ctx, "uci", "set", sec+"=include")
	_, _ = c.runCmd(ctx, "uci", "set", sec+".type=script")
	_, _ = c.runCmd(ctx, "uci", "set", sec+".path="+target)
	_, _ = c.runCmd(ctx, "uci", "set", sec+".reload=1")
	_, _ = c.runCmd(ctx, "uci", "commit", "firewall")
}

func (c *Controller) cleanupFW3Include(ctx context.Context) {
	if !c.isHostOpenWrt() && strings.TrimSpace(c.FW3IncludePath) == "" {
		return
	}
	_ = os.Remove(c.fw3IncludePath())
	if !c.hasCommand("uci") {
		return
	}
	sec := "firewall." + fw3SideUCISection
	if _, err := c.runCmd(ctx, "uci", "-q", "get", sec); err == nil {
		_, _ = c.runCmd(ctx, "uci", "delete", sec)
		_, _ = c.runCmd(ctx, "uci", "commit", "firewall")
	}
}
