// 文件职责：维护内核策略路由双通防锁死护盾（5260 本地网段防劫持 + 5265 旁路由非通告源对称回程）与 OpenWrt netfilter-mode=off 收敛。
package tailscale

import (
	"cmp"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const (
	// LANShieldLocalSubnetPref 在 Tailscale 表 52 (5270) 之前保护本机直连及下级内网网段永远走 main，防止对端误通告引发断网劫持。
	LANShieldLocalSubnetPref = 5260
	// LANShieldSymmetricSrcPref 仅在节点不通告本地 LAN 网段（如旁路由误开启 Tailscale）时保证本地 IP 经 LAN 回程对称路由。
	LANShieldSymmetricSrcPref = 5265
)

// LANShieldOptions 描述同步 Tailscale 内网共存与防劫持护盾所需的明确参数。
type LANShieldOptions struct {
	Runner             CmdRunner
	BinPath            string
	LocalCIDRs         []string
	LocalLANIP         string
	AdvertiseLocalLAN  bool
	IsOpenWrt          bool
	EnsureNetfilterOff bool
}

// SyncLANCoexistenceShield 幂等同步内核 5260/5265 防劫持与对称回程规则，并在 OpenWrt 下关闭 Tailscale 自带 netfilter 锁死链。
func SyncLANCoexistenceShield(ctx context.Context, opts LANShieldOptions) error {
	run := opts.Runner
	if run == nil {
		run = defaultCmdRunner
	}

	if opts.IsOpenWrt && opts.EnsureNetfilterOff {
		bin := cmp.Or(strings.TrimSpace(opts.BinPath), FindInstalledTailscaleBin(), "tailscale")
		_, _ = run(ctx, "", bin, "set", "--netfilter-mode=off")
	}

	desiredCIDRs := normalizeLocalShieldCIDRs(opts.LocalCIDRs)
	wantSrcIP := ""
	if !opts.AdvertiseLocalLAN {
		if addr, err := netip.ParseAddr(strings.TrimSpace(opts.LocalLANIP)); err == nil && isRFC1918V4(addr.Unmap()) {
			wantSrcIP = addr.Unmap().String()
		}
	}

	ruleLines := readIPv4RuleLines(ctx, run)
	if !ruleSetMatches5260(ruleLines[LANShieldLocalSubnetPref], desiredCIDRs) {
		for range len(ruleLines[LANShieldLocalSubnetPref]) {
			_, _ = run(ctx, "", "ip", "-4", "rule", "del", "pref", strconv.Itoa(LANShieldLocalSubnetPref))
		}
		for _, cidr := range desiredCIDRs {
			if out, err := run(ctx, "", "ip", "-4", "rule", "add", "to", cidr, "lookup", "main", "pref", strconv.Itoa(LANShieldLocalSubnetPref)); err != nil {
				return fmt.Errorf("添加本机网段防劫持规则 (pref %d, %s) 失败: %w (%s)", LANShieldLocalSubnetPref, cidr, err, strings.TrimSpace(string(out)))
			}
		}
	}

	cur5265 := ruleLines[LANShieldSymmetricSrcPref]
	want5265Match := wantSrcIP != "" && ruleSetMatches5265(cur5265, wantSrcIP)
	if !want5265Match {
		for range len(cur5265) {
			_, _ = run(ctx, "", "ip", "-4", "rule", "del", "pref", strconv.Itoa(LANShieldSymmetricSrcPref))
		}
		if wantSrcIP != "" {
			if out, err := run(ctx, "", "ip", "-4", "rule", "add", "from", wantSrcIP, "to", "100.64.0.0/10", "lookup", "main", "pref", strconv.Itoa(LANShieldSymmetricSrcPref)); err != nil {
				return fmt.Errorf("添加旁路由对称回程规则 (pref %d, %s) 失败: %w (%s)", LANShieldSymmetricSrcPref, wantSrcIP, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// RemoveLANCoexistenceShield 干净移除由 SingCtl 管理的 5260 与 5265 策略路由规则，不影响 Tailscale 5270 或系统规则。
func RemoveLANCoexistenceShield(ctx context.Context, runner CmdRunner) error {
	run := runner
	if run == nil {
		run = defaultCmdRunner
	}
	ruleLines := readIPv4RuleLines(ctx, run)
	for _, pref := range []int{LANShieldLocalSubnetPref, LANShieldSymmetricSrcPref} {
		for range len(ruleLines[pref]) {
			_, _ = run(ctx, "", "ip", "-4", "rule", "del", "pref", strconv.Itoa(pref))
		}
	}
	return nil
}

func normalizeLocalShieldCIDRs(raw []string) []string {
	var out []string
	seen := make(map[string]struct{}, len(raw))
	for _, item := range raw {
		for part := range strings.SplitSeq(item, ",") {
			if c, ok := normalizePrivateCIDR(part, true); ok {
				if _, dup := seen[c]; !dup {
					seen[c] = struct{}{}
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func readIPv4RuleLines(ctx context.Context, run CmdRunner) map[int][]string {
	out, err := run(ctx, "", "ip", "-4", "rule", "show")
	if err != nil {
		return nil
	}
	grouped := make(map[int][]string)
	for line := range strings.SplitSeq(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		prefStr, rest, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		pref, convErr := strconv.Atoi(strings.TrimSpace(prefStr))
		if convErr != nil {
			continue
		}
		grouped[pref] = append(grouped[pref], strings.TrimSpace(rest))
	}
	return grouped
}

func ruleSetMatches5260(existing []string, desiredCIDRs []string) bool {
	if len(existing) != len(desiredCIDRs) {
		return false
	}
	if len(desiredCIDRs) == 0 {
		return true
	}
	got := make([]string, 0, len(existing))
	for _, line := range existing {
		fields := strings.Fields(line)
		var dst, tbl string
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "to":
				dst = fields[i+1]
			case "lookup", "table":
				tbl = fields[i+1]
			}
		}
		if tbl != "main" || dst == "" {
			return false
		}
		got = append(got, dst)
	}
	want := slices.Clone(desiredCIDRs)
	slices.Sort(got)
	slices.Sort(want)
	return slices.Equal(got, want)
}

func ruleSetMatches5265(existing []string, wantSrcIP string) bool {
	if len(existing) != 1 || wantSrcIP == "" {
		return false
	}
	fields := strings.Fields(existing[0])
	var src, dst, tbl string
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "from":
			src = fields[i+1]
		case "to":
			dst = fields[i+1]
		case "lookup", "table":
			tbl = fields[i+1]
		}
	}
	return src == wantSrcIP && dst == "100.64.0.0/10" && tbl == "main"
}
