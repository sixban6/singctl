// 文件职责：实现主机安全防火墙 iptables+ipset 后端的实时内核态势解析、统计聚合、黑白名单热增删与规则文本预览。
package firewall

import (
	"cmp"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"singctl/internal/config"
)

// IsSecurityTableActive 检测 SINGCTL_SECURITY 隔离链当前是否在内核中处于活跃态。
func (b *IPTablesBackend) IsSecurityTableActive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()
	_, err := b.run(ctx, "", "iptables", "-L", IPTablesSecurityChain, "-n")
	return err == nil
}

// InspectSnapshot 读取 `iptables/ip6tables -L SINGCTL_SECURITY -vxn` 与 5 大 `ipset list` 并构造成与 nftables 完全等价的 KernelSnapshot。
func (b *IPTablesBackend) InspectSnapshot() (*KernelSnapshot, error) {
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()

	v4Out, err := b.run(ctx, "", "iptables", "-L", IPTablesSecurityChain, "-vxn")
	if err != nil {
		return nil, err
	}
	var v6Out []byte
	if b.hasBinary("ip6tables") {
		v6Out, _ = b.run(ctx, "", "ip6tables", "-L", IPTablesSecurityChain, "-vxn")
	}

	ipsets := make(map[string]string, 5)
	for _, name := range []string{"blocklist_ip4_forever", "blocklist_ip4", "blocklist_ip6", "whitelist_ip", "whitelist_ip6"} {
		if out, sErr := b.run(ctx, "", "ipset", "list", name); sErr == nil {
			ipsets[name] = string(out)
		}
	}
	return ParseIPTablesSecuritySnapshot(string(v4Out), string(v6Out), ipsets), nil
}

// InspectSecurityStats 返回与 nftables 1:1 字段对齐的 SecurityStats 汇总战果。
func (b *IPTablesBackend) InspectSecurityStats() (SecurityStats, error) {
	snap, err := b.InspectSnapshot()
	if err != nil || snap == nil {
		return SecurityStats{}, err
	}
	return snap.Stats, nil
}

// ParseIPTablesSecuritySnapshot 纯函数解析 `iptables/ip6tables -L SINGCTL_SECURITY -vxn` 与 `ipset list` 输出。
func ParseIPTablesSecuritySnapshot(v4ChainOut, v6ChainOut string, ipsetLists map[string]string) *KernelSnapshot {
	snap := &KernelSnapshot{
		Mode:            "minimal",
		BanTimeoutDays:  7,
		PingLimitPerSec: 10,
	}

	hasHoneypot := false
	portSet := make(map[int]struct{})

	parseChain := func(raw string, isV6 bool) {
		if strings.Contains(raw, "Chain "+IPTablesSecurityChain) {
			snap.Active = true
		}
		for line := range strings.SplitSeq(raw, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "Chain ") || strings.HasPrefix(trimmed, "pkts ") {
				continue
			}
			fields := strings.Fields(trimmed)
			if len(fields) < 4 {
				continue
			}
			pkts, errP := strconv.ParseInt(fields[0], 10, 64)
			byteCnt, errB := strconv.ParseInt(fields[1], 10, 64)
			if errP != nil || errB != nil {
				continue
			}
			target := fields[2]
			ctr := CounterStat{Packets: pkts, Bytes: byteCnt}

			if target == "ACCEPT" && (strings.Contains(trimmed, "icmptype 8") || strings.Contains(trimmed, "icmpv6")) {
				if rate := parseIPTablesLimitPerSec(trimmed); rate > 0 {
					snap.PingLimitPerSec = rate
				}
				continue
			}
			if target != "DROP" {
				continue
			}

			if ports := parseMultiportDports(trimmed); len(ports) > 0 {
				hasHoneypot = true
				for _, p := range ports {
					portSet[p] = struct{}{}
				}
			}

			switch {
			case strings.Contains(trimmed, commentForeverV4) || strings.Contains(trimmed, "blocklist_ip4_forever"):
				snap.Stats.ForeverBlocked = addCounterStat(snap.Stats.ForeverBlocked, ctr)
			case strings.Contains(trimmed, commentDynamicV4) || (!isV6 && strings.Contains(trimmed, "match-set blocklist_ip4 ")):
				snap.Stats.DynamicV4Blocked = addCounterStat(snap.Stats.DynamicV4Blocked, ctr)
			case strings.Contains(trimmed, commentDynamicV6) || (isV6 && strings.Contains(trimmed, "match-set blocklist_ip6 ")):
				snap.Stats.DynamicV6Blocked = addCounterStat(snap.Stats.DynamicV6Blocked, ctr)
			case strings.Contains(trimmed, commentHoneypotTCPV4) || (!isV6 && fields[3] == "tcp" && strings.Contains(trimmed, "multiport")):
				hasHoneypot = true
				snap.Stats.HoneypotTCPV4 = addCounterStat(snap.Stats.HoneypotTCPV4, ctr)
			case strings.Contains(trimmed, commentHoneypotUDPv4) || (!isV6 && fields[3] == "udp" && strings.Contains(trimmed, "multiport")):
				hasHoneypot = true
				snap.Stats.HoneypotUDPv4 = addCounterStat(snap.Stats.HoneypotUDPv4, ctr)
			case strings.Contains(trimmed, commentHoneypotTCPV6) || (isV6 && fields[3] == "tcp" && strings.Contains(trimmed, "multiport")):
				hasHoneypot = true
				snap.Stats.HoneypotTCPV6 = addCounterStat(snap.Stats.HoneypotTCPV6, ctr)
			case strings.Contains(trimmed, commentHoneypotUDPv6) || (isV6 && fields[3] == "udp" && strings.Contains(trimmed, "multiport")):
				hasHoneypot = true
				snap.Stats.HoneypotUDPv6 = addCounterStat(snap.Stats.HoneypotUDPv6, ctr)
			}
		}
	}

	parseChain(v4ChainOut, false)
	parseChain(v6ChainOut, true)

	for p := range portSet {
		snap.ProtectedPorts = append(snap.ProtectedPorts, p)
	}

	if raw, ok := ipsetLists["blocklist_ip4_forever"]; ok {
		entries, _ := parseIPSetListOutput(raw)
		for _, e := range entries {
			snap.ForeverV4 = append(snap.ForeverV4, e.target)
		}
	}
	if raw, ok := ipsetLists["blocklist_ip4"]; ok {
		entries, timeoutSec := parseIPSetListOutput(raw)
		if timeoutSec > 0 {
			snap.BanTimeoutDays = max(1, int(timeoutSec/86400))
		}
		for _, e := range entries {
			snap.DynamicV4 = append(snap.DynamicV4, BanItem{Target: e.target, Scope: "dynamic_v4", ExpiresSec: e.expiresSec})
		}
	}
	if raw, ok := ipsetLists["blocklist_ip6"]; ok {
		entries, timeoutSec := parseIPSetListOutput(raw)
		if timeoutSec > 0 {
			snap.BanTimeoutDays = max(1, int(timeoutSec/86400))
		}
		for _, e := range entries {
			snap.DynamicV6 = append(snap.DynamicV6, BanItem{Target: e.target, Scope: "dynamic_v6", ExpiresSec: e.expiresSec})
		}
	}
	if raw, ok := ipsetLists["whitelist_ip"]; ok {
		entries, _ := parseIPSetListOutput(raw)
		for _, e := range entries {
			snap.WhitelistV4 = append(snap.WhitelistV4, e.target)
		}
	}
	if raw, ok := ipsetLists["whitelist_ip6"]; ok {
		entries, _ := parseIPSetListOutput(raw)
		for _, e := range entries {
			snap.WhitelistV6 = append(snap.WhitelistV6, e.target)
		}
	}

	sort.Strings(snap.ForeverV4)
	sort.Strings(snap.WhitelistV4)
	sort.Strings(snap.WhitelistV6)
	finalizeKernelSnapshot(snap, hasHoneypot)
	return snap
}

type parsedIPSetEntry struct {
	target     string
	expiresSec int64
}

func parseIPSetListOutput(raw string) ([]parsedIPSetEntry, int64) {
	var entries []parsedIPSetEntry
	var defaultTimeout int64
	inMembers := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Header:") {
			fields := strings.Fields(trimmed)
			for i := 0; i+1 < len(fields); i++ {
				if fields[i] == "timeout" {
					if v, err := strconv.ParseInt(fields[i+1], 10, 64); err == nil && v > 0 {
						defaultTimeout = v
					}
				}
			}
			continue
		}
		if strings.EqualFold(trimmed, "Members:") {
			inMembers = true
			continue
		}
		if !inMembers {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		var exp int64
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "timeout" {
				if v, err := strconv.ParseInt(fields[i+1], 10, 64); err == nil {
					exp = v
				}
			}
		}
		entries = append(entries, parsedIPSetEntry{target: fields[0], expiresSec: exp})
	}
	return entries, defaultTimeout
}

func parseIPTablesLimitPerSec(line string) int {
	_, after, ok := strings.Cut(line, "limit: avg ")
	if !ok {
		return 0
	}
	token, _, _ := strings.Cut(after, " ")
	numStr, found := strings.CutSuffix(token, "/sec")
	if !found {
		return 0
	}
	v, err := strconv.Atoi(numStr)
	if err != nil || v <= 0 {
		return 0
	}
	return v
}

func parseMultiportDports(line string) []int {
	_, after, ok := strings.Cut(line, "multiport dports ")
	if !ok {
		return nil
	}
	token, _, _ := strings.Cut(after, " ")
	var ports []int
	for part := range strings.SplitSeq(token, ",") {
		if loStr, hiStr, isRange := strings.Cut(part, ":"); isRange {
			lo, err1 := strconv.Atoi(loStr)
			hi, err2 := strconv.Atoi(hiStr)
			if err1 == nil && err2 == nil && lo >= 1 && hi <= 65535 && lo <= hi && hi-lo <= 512 {
				for p := lo; p <= hi; p++ {
					ports = append(ports, p)
				}
			}
			continue
		}
		if p, err := strconv.Atoi(part); err == nil && p >= 1 && p <= 65535 {
			ports = append(ports, p)
		}
	}
	return ports
}

// AddLiveBan 校验防自锁护栏并将 IP/CIDR 实时注入对应 ipset 黑名单集合。
func (b *IPTablesBackend) AddLiveBan(target, scope string, timeoutDays int, callerIP string, cfg *config.Config) (string, bool, error) {
	norm, isV6, err := ValidateBanTarget(target, scope, callerIP, cfg)
	if err != nil {
		return "", false, err
	}
	if !b.IsSecurityTableActive() {
		return norm, isV6, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()

	days := cmp.Or(timeoutDays, 7)
	days = min(30, max(1, days))
	if strings.EqualFold(scope, "forever") {
		if out, err := b.run(ctx, "", "ipset", "add", "blocklist_ip4_forever", norm, "-exist"); err != nil {
			return "", isV6, fmt.Errorf("ipset add blocklist_ip4_forever failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return norm, isV6, nil
	}

	setName := "blocklist_ip4"
	if isV6 {
		setName = "blocklist_ip6"
	}
	if out, err := b.run(ctx, "", "ipset", "add", setName, norm, "timeout", strconv.Itoa(days*86400), "-exist"); err != nil {
		return "", isV6, fmt.Errorf("ipset add %s failed: %w (%s)", setName, err, strings.TrimSpace(string(out)))
	}
	return norm, isV6, nil
}

// RemoveLiveBan 从对应 ipset 黑名单集合实时移除指定条目。
func (b *IPTablesBackend) RemoveLiveBan(target, scope string) error {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return fmt.Errorf("解封目标不能为空")
	}
	if !b.IsSecurityTableActive() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()

	var sets []string
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "forever":
		sets = []string{"blocklist_ip4_forever"}
	case "dynamic_v6":
		sets = []string{"blocklist_ip6"}
	case "dynamic_v4":
		sets = []string{"blocklist_ip4"}
	default:
		if strings.Contains(trimmed, ":") {
			sets = []string{"blocklist_ip6"}
		} else if strings.Contains(trimmed, "/") {
			sets = []string{"blocklist_ip4_forever"}
		} else {
			sets = []string{"blocklist_ip4", "blocklist_ip4_forever"}
		}
	}
	for _, setName := range sets {
		out, err := b.run(ctx, "", "ipset", "del", setName, trimmed, "-exist")
		if err == nil {
			continue
		}
		msg := strings.ToLower(string(out))
		if strings.Contains(msg, "not in set") || strings.Contains(msg, "does not exist") {
			continue
		}
		return fmt.Errorf("ipset del %s %s failed: %w (%s)", setName, trimmed, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FlushDynamicBans 清空 7 天动态扫描黑名单 ipset（保留永久黑名单与链计数器）。
func (b *IPTablesBackend) FlushDynamicBans(family string) error {
	if !b.IsSecurityTableActive() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()

	var sets []string
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "ipv4", "v4":
		sets = []string{"blocklist_ip4"}
	case "ipv6", "v6":
		sets = []string{"blocklist_ip6"}
	default:
		sets = []string{"blocklist_ip4", "blocklist_ip6"}
	}
	for _, setName := range sets {
		if out, err := b.run(ctx, "", "ipset", "flush", setName); err != nil {
			if setName == "blocklist_ip6" && strings.Contains(strings.ToLower(string(out)), "does not exist") {
				continue
			}
			return fmt.Errorf("ipset flush %s failed: %w (%s)", setName, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// AddWhitelist 校验并向内核白名单 ipset 集合实时添加 IP/CIDR。
func (b *IPTablesBackend) AddWhitelist(target string) (string, bool, error) {
	norm, isV6, err := ValidateWhitelistTarget(target)
	if err != nil {
		return "", false, err
	}
	_, err = b.SyncWhitelistElementLive(norm, isV6, true)
	return norm, isV6, err
}

// RemoveWhitelist 校验（拦截内置防锁死白名单）并从内核白名单 ipset 集合实时移除 IP/CIDR。
func (b *IPTablesBackend) RemoveWhitelist(target string) (string, bool, error) {
	norm, isV6, err := ValidateWhitelistTarget(target)
	if err != nil {
		return "", false, err
	}
	if IsBuiltinWhitelist(norm) {
		return "", isV6, fmt.Errorf("安全拦截: 系统内置私网/Tailscale 防锁死白名单不可删除 (%s)", norm)
	}
	_, err = b.SyncWhitelistElementLive(norm, isV6, false)
	return norm, isV6, err
}

// SyncWhitelistElementLive 实时向 whitelist_ip/whitelist_ip6 ipset 增删成员。
func (b *IPTablesBackend) SyncWhitelistElementLive(norm string, isV6 bool, add bool) (bool, error) {
	if !b.IsSecurityTableActive() {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()

	setName := "whitelist_ip"
	if isV6 {
		setName = "whitelist_ip6"
	}
	op := "add"
	if !add {
		op = "del"
	}
	out, err := b.run(ctx, "", "ipset", op, setName, norm, "-exist")
	if err != nil {
		msg := strings.ToLower(string(out))
		if !add && (strings.Contains(msg, "not in set") || strings.Contains(msg, "does not exist")) {
			return false, nil
		}
		if isV6 && strings.Contains(msg, "does not exist") {
			return true, nil
		}
		return false, fmt.Errorf("ipset %s %s %s failed: %w (%s)", op, setName, norm, err, strings.TrimSpace(string(out)))
	}
	return false, nil
}

// CompactRuleText 生成用于 WebUI 抽屉展示的精简 iptables+ipset 规则概览文本。
func (b *IPTablesBackend) CompactRuleText(snap *KernelSnapshot) string {
	ctx, cancel := context.WithTimeout(context.Background(), iptablesCmdTimeout)
	defer cancel()

	v4Out, _ := b.run(ctx, "", "iptables", "-S", IPTablesSecurityChain)
	var v6Out []byte
	if b.hasBinary("ip6tables") {
		v6Out, _ = b.run(ctx, "", "ip6tables", "-S", IPTablesSecurityChain)
	}
	var sb strings.Builder
	sb.WriteString("# Backend: iptables + ip6tables + ipset\n")
	if snap != nil {
		fmt.Fprintf(&sb, "# Sets: blocklist_ip4_forever=%d, blocklist_ip4=%d, blocklist_ip6=%d, whitelist=%d\n\n",
			snap.Stats.ForeverCount, snap.Stats.DynamicV4Count, snap.Stats.DynamicV6Count, snap.Stats.WhitelistCount)
	}
	if len(v4Out) > 0 {
		sb.WriteString("# IPv4 (iptables -S SINGCTL_SECURITY)\n")
		sb.Write(v4Out)
	}
	if len(v6Out) > 0 {
		sb.WriteString("\n# IPv6 (ip6tables -S SINGCTL_SECURITY)\n")
		sb.Write(v6Out)
	}
	return sb.String()
}
