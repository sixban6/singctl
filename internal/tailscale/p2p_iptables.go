// 文件职责：实现 Tailscale P2P 防线的 iptables + ip6tables + ipset 独立后端（适配 OpenWrt 21.02 / fw3 等纯 iptables 固件）。
package tailscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/common/fsx"
	"singctl/internal/config"
)

const (
	// ApplyModeIPTablesIPSet 表示 Tailscale P2P 防线通过纯 iptables + ip6tables + ipset 独立隔离链生效。
	ApplyModeIPTablesIPSet = "iptables_ipset"

	// DefaultFirewallUserPath 是 OpenWrt fw3 的自定义用户防火墙持久脚本路径。
	DefaultFirewallUserPath = "/etc/firewall.user"

	// IPTablesChainTSJIT 是 Tailscale P2P 入站 UDP JIT 瞬时打洞隔离链（挂载于 INPUT 顶部）。
	IPTablesChainTSJIT = "SINGCTL_TS_JIT"
	// IPTablesChainTSInACL 是 Tailscale 隧道入站访问控制链（挂载于 INPUT 顶部，过滤 -i tailscale+）。
	IPTablesChainTSInACL = "SINGCTL_TS_IN_ACL"
	// IPTablesChainTSFwdACL 是 Tailscale 隧道转发 LAN 隔离链（挂载于 FORWARD 顶部，过滤 -i tailscale+）。
	IPTablesChainTSFwdACL = "SINGCTL_TS_FWD_ACL"
	// IPTablesChainTSOutACL 是本机 LAN/设备出站进入 Tailscale 隧道的源网段门禁链（挂载于 FORWARD 顶部，过滤 -o tailscale+）。
	IPTablesChainTSOutACL = "SINGCTL_TS_OUT_ACL"

	tsFirewallUserBegin = "# BEGIN SINGCTL_TS_P2P"
	tsFirewallUserEnd   = "# END SINGCTL_TS_P2P"

	defaultIPSetTimeoutSec = 300
)

// IPTablesP2PRuleSet 保存经严格白名单校验渲染出的 Tailscale P2P 防线 iptables/ip6tables 规则集。
type IPTablesP2PRuleSet struct {
	ListenPort    int
	JITWindowSec  int
	PayloadFilter bool

	V4JIT    [][]string
	V6JIT    [][]string
	V4InACL  [][]string
	V6InACL  [][]string
	V4FwdACL [][]string
	V6FwdACL [][]string
	V4OutACL [][]string
	V6OutACL [][]string
}

// Digest 返回用于幂等变更比对的 SHA-256 摘要。
func (r IPTablesP2PRuleSet) Digest() string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%d|%v\n", r.ListenPort, r.JITWindowSec, r.PayloadFilter)
	for _, group := range [][][]string{r.V4JIT, r.V6JIT, r.V4InACL, r.V6InACL, r.V4FwdACL, r.V6FwdACL, r.V4OutACL, r.V6OutACL} {
		h.Write([]byte("---\n"))
		for _, args := range group {
			h.Write([]byte(strings.Join(args, " ")))
			h.Write([]byte{'\n'})
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RenderIPTablesP2P 根据 P2P 防线配置与已解析对端拓扑生成与 nftables 1:1 等价的 iptables/ip6tables 规则集。
func RenderIPTablesP2P(cfg config.TailscaleP2PAssistConfig, peers []ResolvedPeerACL, defaultLANCIDR string, now time.Time) (IPTablesP2PRuleSet, error) {
	port := cfg.EffectiveListenPort()
	winSec := cfg.EffectiveJITWindowSec()
	payloadFilter := cfg.EffectivePayloadFilter()

	v4JIT := buildTSJITRules(setTSJITAllow4, false, payloadFilter)
	v6JIT := buildTSJITRules(setTSJITAllow6, true, payloadFilter)

	defaultTargets := parseDefaultLANTargets(defaultLANCIDR)
	resolvedLocal, enforceEgressDrop := resolveEffectiveLocalRules(cfg, defaultTargets)

	v4In := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}
	v6In := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}
	v4Fwd := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}
	v6Fwd := [][]string{{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}}
	v4Out := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "REPLY", "-j", "ACCEPT"},
		{"-s", "100.64.0.0/10", "-j", "ACCEPT"},
	}
	v6Out := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "--ctdir", "REPLY", "-j", "ACCEPT"},
		{"-s", "fd7a:115c:a1e0::/48", "-j", "ACCEPT"},
	}

	var defaultFwdTargets []LANTarget
	for _, lr := range resolvedLocal {
		switch lr.scope {
		case config.TailscaleScopeAllowlist:
			if len(lr.devices) == 0 {
				if lr.target.IsV6 {
					v6Fwd = append(v6Fwd, []string{"-d", lr.target.AddrExpr, "-j", "DROP"})
				} else {
					v4Fwd = append(v4Fwd, []string{"-d", lr.target.AddrExpr, "-j", "DROP"})
				}
			} else {
				for _, dev := range lr.devices {
					if lr.target.IsV6 {
						v6Out = append(v6Out, []string{"-s", dev, "-j", "ACCEPT"})
					} else {
						v4Out = append(v4Out, []string{"-s", dev, "-j", "ACCEPT"})
					}
					defaultFwdTargets = append(defaultFwdTargets, LANTarget{Raw: dev, AddrExpr: dev, IsV6: lr.target.IsV6})
				}
			}
		case config.TailscaleScopeDenylist:
			for _, dev := range lr.devices {
				if lr.target.IsV6 {
					v6Out = append(v6Out, []string{"-s", dev, "-j", "DROP"})
					v6Fwd = append(v6Fwd, []string{"-d", dev, "-j", "DROP"})
				} else {
					v4Out = append(v4Out, []string{"-s", dev, "-j", "DROP"})
					v4Fwd = append(v4Fwd, []string{"-d", dev, "-j", "DROP"})
				}
			}
			if lr.target.IsV6 {
				v6Out = append(v6Out, []string{"-s", lr.target.AddrExpr, "-j", "ACCEPT"})
			} else {
				v4Out = append(v4Out, []string{"-s", lr.target.AddrExpr, "-j", "ACCEPT"})
			}
			defaultFwdTargets = append(defaultFwdTargets, lr.target)
		default:
			if lr.target.IsV6 {
				v6Out = append(v6Out, []string{"-s", lr.target.AddrExpr, "-j", "ACCEPT"})
			} else {
				v4Out = append(v4Out, []string{"-s", lr.target.AddrExpr, "-j", "ACCEPT"})
			}
			defaultFwdTargets = append(defaultFwdTargets, lr.target)
		}
	}
	if enforceEgressDrop {
		v4Out = append(v4Out, []string{"-j", "DROP"})
		v6Out = append(v6Out, []string{"-j", "DROP"})
	} else {
		v4Out = append(v4Out, []string{"-j", "RETURN"})
		v6Out = append(v6Out, []string{"-j", "RETURN"})
	}

	for _, peer := range peers {
		srcs := peer.sourceExpressions()
		if len(srcs) == 0 {
			continue
		}

		effMode := peer.Config.EffectiveAccessMode(now)
		isBidir := effMode == config.TailscaleAccessBidirectional || effMode == config.TailscaleAccessBidirectionalTimed
		var parsedTargets []LANTarget
		if isBidir {
			parsedTargets = make([]LANTarget, 0, len(peer.Config.AllowedLANTargets))
			for _, rawTarget := range peer.Config.AllowedLANTargets {
				t, err := ParseAllowedLANTarget(rawTarget)
				if err != nil {
					return IPTablesP2PRuleSet{}, err
				}
				parsedTargets = append(parsedTargets, t)
			}
			if len(parsedTargets) == 0 {
				parsedTargets = defaultFwdTargets
			}
		}

		if effMode == config.TailscaleAccessBidirectional {
			inTargets := parsedTargets
			if len(peer.Config.AllowedLANTargets) == 0 {
				inTargets = defaultTargets
			}
			for _, src := range srcs {
				for _, tgt := range inTargets {
					if src.isV6 != tgt.IsV6 {
						continue
					}
					rules := buildTSForwardAcceptRules(src.expr, tgt)
					if src.isV6 {
						v6In = append(v6In, rules...)
					} else {
						v4In = append(v4In, rules...)
					}
				}
				if len(peer.Config.AllowedLANTargets) == 0 {
					if src.isV6 {
						v6In = append(v6In, []string{"-s", src.expr, "-d", "fd7a:115c:a1e0::/48", "-j", "ACCEPT"})
					} else {
						v4In = append(v4In, []string{"-s", src.expr, "-d", "100.64.0.0/10", "-j", "ACCEPT"})
					}
				}
			}
		}

		for _, src := range srcs {
			if src.isV6 {
				v6In = append(v6In, []string{"-s", src.expr, "-j", "DROP"})
			} else {
				v4In = append(v4In, []string{"-s", src.expr, "-j", "DROP"})
			}
		}

		if isBidir {
			for _, src := range srcs {
				for _, tgt := range parsedTargets {
					if src.isV6 != tgt.IsV6 {
						continue
					}
					rules := buildTSForwardAcceptRules(src.expr, tgt)
					if src.isV6 {
						v6Fwd = append(v6Fwd, rules...)
					} else {
						v4Fwd = append(v4Fwd, rules...)
					}
				}
			}
		}

		for _, src := range srcs {
			if src.isV6 {
				v6Fwd = append(v6Fwd, []string{"-s", src.expr, "-j", "DROP"})
			} else {
				v4Fwd = append(v4Fwd, []string{"-s", src.expr, "-j", "DROP"})
			}
		}
	}

	// 个人随身设备走链路末端透传，若某本机网段启用了仅指定设备模式，同样在尾部收口拦截非白名单主机。
	for _, lr := range resolvedLocal {
		if lr.scope == config.TailscaleScopeAllowlist && len(lr.devices) > 0 {
			for _, dev := range lr.devices {
				if lr.target.IsV6 {
					v6Fwd = append(v6Fwd, []string{"-d", dev, "-j", "RETURN"})
				} else {
					v4Fwd = append(v4Fwd, []string{"-d", dev, "-j", "RETURN"})
				}
			}
			if lr.target.IsV6 {
				v6Fwd = append(v6Fwd, []string{"-d", lr.target.AddrExpr, "-j", "DROP"})
			} else {
				v4Fwd = append(v4Fwd, []string{"-d", lr.target.AddrExpr, "-j", "DROP"})
			}
		}
	}

	return IPTablesP2PRuleSet{
		ListenPort:    port,
		JITWindowSec:  winSec,
		PayloadFilter: payloadFilter,
		V4JIT:         v4JIT,
		V6JIT:         v6JIT,
		V4InACL:       v4In,
		V6InACL:       v6In,
		V4FwdACL:      v4Fwd,
		V6FwdACL:      v6Fwd,
		V4OutACL:      v4Out,
		V6OutACL:      v6Out,
	}, nil
}

func buildTSJITRules(setName string, isV6 bool, dropNonWhitelist bool) [][]string {
	rules := [][]string{
		{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-i", "lo", "-j", "RETURN"},
		{"-m", "set", "--match-set", setName, "src", "-m", "limit", "--limit", "300/sec", "--limit-burst", "600", "-j", "ACCEPT"},
		{"-m", "set", "--match-set", setName, "src", "-j", "DROP"},
	}
	if isV6 {
		rules = append(rules,
			[]string{"-s", "fe80::/10", "-j", "RETURN"},
			[]string{"-s", "fc00::/7", "-j", "RETURN"},
		)
	} else {
		rules = append(rules,
			[]string{"-s", "10.0.0.0/8", "-j", "RETURN"},
			[]string{"-s", "172.16.0.0/12", "-j", "RETURN"},
			[]string{"-s", "192.168.0.0/16", "-j", "RETURN"},
			[]string{"-s", "100.64.0.0/10", "-j", "RETURN"},
		)
	}
	if dropNonWhitelist {
		rules = append(rules, []string{"-j", "DROP"})
	} else {
		rules = append(rules, []string{"-j", "RETURN"})
	}
	return rules
}

func buildTSForwardAcceptRules(srcExpr string, tgt LANTarget) [][]string {
	if tgt.Port == 0 {
		return [][]string{{"-s", srcExpr, "-d", tgt.AddrExpr, "-j", "ACCEPT"}}
	}
	portStr := strconv.Itoa(tgt.Port)
	if tgt.Proto == "tcp" || tgt.Proto == "udp" {
		return [][]string{{"-s", srcExpr, "-d", tgt.AddrExpr, "-p", tgt.Proto, "--dport", portStr, "-j", "ACCEPT"}}
	}
	return [][]string{
		{"-s", srcExpr, "-d", tgt.AddrExpr, "-p", "tcp", "--dport", portStr, "-j", "ACCEPT"},
		{"-s", srcExpr, "-d", tgt.AddrExpr, "-p", "udp", "--dport", portStr, "-j", "ACCEPT"},
	}
}

// RenderFirewallUserBlock 渲染可幂等嵌入 OpenWrt `/etc/firewall.user` 的 POSIX 恢复脚本块。
func (r IPTablesP2PRuleSet) RenderFirewallUserBlock() string {
	port := r.ListenPort
	if port <= 0 || port > 65535 {
		port = 41641
	}
	var b strings.Builder
	b.WriteString(tsFirewallUserBegin + "\n")
	b.WriteString("# Managed by SingCtl Tailscale P2P Defense (iptables+ipset) — DO NOT EDIT MANUALLY\n")
	b.WriteString("if command -v ipset >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then\n")
	fmt.Fprintf(&b, "    ipset create %s hash:ip family inet timeout %d -exist 2>/dev/null || true\n", setTSJITAllow4, defaultIPSetTimeoutSec)
	fmt.Fprintf(&b, "    ipset create %s hash:ip family inet6 timeout %d -exist 2>/dev/null || true\n", setTSJITAllow6, defaultIPSetTimeoutSec)
	writeFirewallUserFamily(&b, "iptables", port, r.V4JIT, r.V4InACL, r.V4FwdACL, r.V4OutACL)
	b.WriteString("    if command -v ip6tables >/dev/null 2>&1; then\n")
	writeFirewallUserFamily(&b, "ip6tables", port, r.V6JIT, r.V6InACL, r.V6FwdACL, r.V6OutACL)
	b.WriteString("    fi\n")
	b.WriteString("fi\n")
	b.WriteString(tsFirewallUserEnd + "\n")
	return b.String()
}

func writeFirewallUserFamily(b *strings.Builder, bin string, port int, jit, inACL, fwdACL, outACL [][]string) {
	indent := "    "
	if bin == "ip6tables" {
		indent = "        "
	}
	cmd := bin + " -w 5"
	for _, ch := range []string{IPTablesChainTSJIT, IPTablesChainTSInACL, IPTablesChainTSFwdACL, IPTablesChainTSOutACL} {
		fmt.Fprintf(b, "%s%s -N %s 2>/dev/null || true\n", indent, cmd, ch)
		fmt.Fprintf(b, "%s%s -F %s\n", indent, cmd, ch)
	}
	for _, args := range jit {
		fmt.Fprintf(b, "%s%s -A %s %s\n", indent, cmd, IPTablesChainTSJIT, strings.Join(args, " "))
	}
	for _, args := range inACL {
		fmt.Fprintf(b, "%s%s -A %s %s\n", indent, cmd, IPTablesChainTSInACL, strings.Join(args, " "))
	}
	for _, args := range fwdACL {
		fmt.Fprintf(b, "%s%s -A %s %s\n", indent, cmd, IPTablesChainTSFwdACL, strings.Join(args, " "))
	}
	for _, args := range outACL {
		fmt.Fprintf(b, "%s%s -A %s %s\n", indent, cmd, IPTablesChainTSOutACL, strings.Join(args, " "))
	}
	fmt.Fprintf(b, "%s%s -C INPUT -p udp --dport %d -m comment --comment %s -j %s 2>/dev/null || %s -I INPUT 1 -p udp --dport %d -m comment --comment %s -j %s\n",
		indent, cmd, port, jitCommentTag, IPTablesChainTSJIT, cmd, port, jitCommentTag, IPTablesChainTSJIT)
	fmt.Fprintf(b, "%s%s -C INPUT -i tailscale+ -m comment --comment %s -j %s 2>/dev/null || %s -I INPUT 1 -i tailscale+ -m comment --comment %s -j %s\n",
		indent, cmd, aclCommentTag, IPTablesChainTSInACL, cmd, aclCommentTag, IPTablesChainTSInACL)
	fmt.Fprintf(b, "%s%s -C FORWARD -i tailscale+ -m comment --comment %s -j %s 2>/dev/null || %s -I FORWARD 1 -i tailscale+ -m comment --comment %s -j %s\n",
		indent, cmd, aclCommentTag, IPTablesChainTSFwdACL, cmd, aclCommentTag, IPTablesChainTSFwdACL)
	fmt.Fprintf(b, "%s%s -C FORWARD -o tailscale+ -m comment --comment %s -j %s 2>/dev/null || %s -I FORWARD 1 -o tailscale+ -m comment --comment %s -j %s\n",
		indent, cmd, aclCommentTag, IPTablesChainTSOutACL, cmd, aclCommentTag, IPTablesChainTSOutACL)
}

// IPTablesP2PManager 实现基于 iptables + ip6tables + ipset 的 Tailscale P2P 防线独立后端。
type IPTablesP2PManager struct {
	Runner           CmdRunner
	LookPath         func(file string) (string, error)
	FirewallUserPath string

	mu         sync.Mutex
	lastDigest string
}

func (m *IPTablesP2PManager) run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	if m.Runner != nil {
		return m.Runner(ctx, stdin, name, args...)
	}
	return defaultCmdRunner(ctx, stdin, name, args...)
}

func (m *IPTablesP2PManager) hasBinary(name string) bool {
	if m.LookPath != nil {
		_, err := m.LookPath(name)
		return err == nil
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func (m *IPTablesP2PManager) firewallUserPath() string {
	if p := strings.TrimSpace(m.FirewallUserPath); p != "" {
		return p
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return DefaultFirewallUserPath
	}
	if _, err := os.Stat(DefaultFirewallUserPath); err == nil {
		return DefaultFirewallUserPath
	}
	return ""
}

// Apply 幂等创建 ipset 集合、隔离链与挂载钩子，并在 OpenWrt fw3 下持久化至 `/etc/firewall.user`。
func (m *IPTablesP2PManager) Apply(ctx context.Context, rs IPTablesP2PRuleSet) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rs.ListenPort <= 0 || rs.ListenPort > 65535 {
		rs.ListenPort = 41641
	}
	if len(rs.V4JIT) == 0 {
		rs.V4JIT = buildTSJITRules(setTSJITAllow4, false, rs.PayloadFilter)
	}
	if len(rs.V6JIT) == 0 {
		rs.V6JIT = buildTSJITRules(setTSJITAllow6, true, rs.PayloadFilter)
	}

	digest := rs.Digest()
	if m.lastDigest == digest && m.liveChainExists(ctx) {
		_ = m.syncFirewallUserLocked(rs.RenderFirewallUserBlock())
		return ApplyModeIPTablesIPSet, nil
	}

	if out, err := m.run(ctx, "", "ipset", "create", setTSJITAllow4, "hash:ip", "family", "inet", "timeout", strconv.Itoa(defaultIPSetTimeoutSec), "-exist"); err != nil {
		return "", fmt.Errorf("ipset create %s failed: %w (%s)", setTSJITAllow4, err, strings.TrimSpace(string(out)))
	}
	// IPv6 ipset 在禁用 IPv6 的内核上可能失败，容错不阻断 IPv4。
	_, _ = m.run(ctx, "", "ipset", "create", setTSJITAllow6, "hash:ip", "family", "inet6", "timeout", strconv.Itoa(defaultIPSetTimeoutSec), "-exist")

	if err := m.applyFamilyLocked(ctx, "iptables", rs.ListenPort, rs.V4JIT, rs.V4InACL, rs.V4FwdACL, rs.V4OutACL); err != nil {
		return "", err
	}
	if m.hasBinary("ip6tables") {
		_ = m.applyFamilyLocked(ctx, "ip6tables", rs.ListenPort, rs.V6JIT, rs.V6InACL, rs.V6FwdACL, rs.V6OutACL)
	}

	if err := m.syncFirewallUserLocked(rs.RenderFirewallUserBlock()); err != nil {
		return "", fmt.Errorf("persist %s: %w", m.firewallUserPath(), err)
	}
	m.lastDigest = digest
	return ApplyModeIPTablesIPSet, nil
}

func (m *IPTablesP2PManager) liveChainExists(ctx context.Context) bool {
	_, err := m.run(ctx, "", "iptables", "-L", IPTablesChainTSJIT, "-n")
	return err == nil
}

func (m *IPTablesP2PManager) applyFamilyLocked(ctx context.Context, bin string, listenPort int, jit, inACL, fwdACL, outACL [][]string) error {
	chains := []struct {
		name  string
		rules [][]string
	}{
		{name: IPTablesChainTSJIT, rules: jit},
		{name: IPTablesChainTSInACL, rules: inACL},
		{name: IPTablesChainTSFwdACL, rules: fwdACL},
		{name: IPTablesChainTSOutACL, rules: outACL},
	}

	for _, ch := range chains {
		if out, err := m.run(ctx, "", bin, "-N", ch.name); err != nil {
			msg := strings.ToLower(string(out))
			if !strings.Contains(msg, "already exists") {
				// 忽略极老版 iptables 对已存在链返回不同文案的情况，紧随 -F 验证链真实存在。
				if _, fErr := m.run(ctx, "", bin, "-F", ch.name); fErr != nil {
					return fmt.Errorf("%s -N %s failed: %w (%s)", bin, ch.name, err, strings.TrimSpace(string(out)))
				}
			} else if outF, fErr := m.run(ctx, "", bin, "-F", ch.name); fErr != nil {
				return fmt.Errorf("%s -F %s failed: %w (%s)", bin, ch.name, fErr, strings.TrimSpace(string(outF)))
			}
		} else if outF, fErr := m.run(ctx, "", bin, "-F", ch.name); fErr != nil {
			return fmt.Errorf("%s -F %s failed: %w (%s)", bin, ch.name, fErr, strings.TrimSpace(string(outF)))
		}
		for _, ruleArgs := range ch.rules {
			args := append([]string{"-A", ch.name}, ruleArgs...)
			if out, err := m.run(ctx, "", bin, args...); err != nil {
				return fmt.Errorf("%s -A %s failed: %w (%s)", bin, ch.name, err, strings.TrimSpace(string(out)))
			}
		}
	}

	// 清理可能存在的历史端口或重复跳转钩子后再幂等挂到链首。
	m.detachChainJumps(ctx, bin, "INPUT", IPTablesChainTSJIT)
	m.detachChainJumps(ctx, bin, "INPUT", IPTablesChainTSInACL)
	m.detachChainJumps(ctx, bin, "FORWARD", IPTablesChainTSFwdACL)
	m.detachChainJumps(ctx, bin, "FORWARD", IPTablesChainTSOutACL)

	hooks := []struct {
		parent string
		spec   []string
	}{
		{parent: "INPUT", spec: []string{"-i", "tailscale+", "-m", "comment", "--comment", aclCommentTag, "-j", IPTablesChainTSInACL}},
		{parent: "INPUT", spec: []string{"-p", "udp", "--dport", strconv.Itoa(listenPort), "-m", "comment", "--comment", jitCommentTag, "-j", IPTablesChainTSJIT}},
		{parent: "FORWARD", spec: []string{"-i", "tailscale+", "-m", "comment", "--comment", aclCommentTag, "-j", IPTablesChainTSFwdACL}},
		{parent: "FORWARD", spec: []string{"-o", "tailscale+", "-m", "comment", "--comment", aclCommentTag, "-j", IPTablesChainTSOutACL}},
	}
	for _, h := range hooks {
		checkArgs := append([]string{"-C", h.parent}, h.spec...)
		if _, err := m.run(ctx, "", bin, checkArgs...); err != nil {
			insArgs := append([]string{"-I", h.parent, "1"}, h.spec...)
			if out, iErr := m.run(ctx, "", bin, insArgs...); iErr != nil {
				return fmt.Errorf("%s -I %s failed: %w (%s)", bin, h.parent, iErr, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func (m *IPTablesP2PManager) detachChainJumps(ctx context.Context, bin, parent, targetChain string) {
	raw, err := m.run(ctx, "", bin, "-S", parent)
	if err != nil {
		return
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "-A "+parent+" ") || !strings.Contains(trimmed, "-j "+targetChain) {
			continue
		}
		fields := splitIPTablesSpecFields(strings.TrimPrefix(trimmed, "-A "+parent+" "))
		if len(fields) == 0 {
			continue
		}
		delArgs := append([]string{"-D", parent}, fields...)
		_, _ = m.run(ctx, "", bin, delArgs...)
	}
}

// splitIPTablesSpecFields 切分 `iptables -S` 输出行，保留双引号内的 comment 内容作为单一参数。
func splitIPTablesSpecFields(spec string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := range len(spec) {
		ch := spec[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
		case (ch == ' ' || ch == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Remove 彻底卸载隔离链、清理 ipset 集合并从 `/etc/firewall.user` 干净剥离受管块。
func (m *IPTablesP2PManager) Remove(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, bin := range []string{"iptables", "ip6tables"} {
		if bin == "ip6tables" && !m.hasBinary("ip6tables") {
			continue
		}
		m.detachChainJumps(ctx, bin, "INPUT", IPTablesChainTSJIT)
		m.detachChainJumps(ctx, bin, "INPUT", IPTablesChainTSInACL)
		m.detachChainJumps(ctx, bin, "FORWARD", IPTablesChainTSFwdACL)
		m.detachChainJumps(ctx, bin, "FORWARD", IPTablesChainTSOutACL)
		for _, ch := range []string{IPTablesChainTSJIT, IPTablesChainTSInACL, IPTablesChainTSFwdACL, IPTablesChainTSOutACL} {
			_, _ = m.run(ctx, "", bin, "-F", ch)
			_, _ = m.run(ctx, "", bin, "-X", ch)
		}
	}

	for _, setName := range []string{setTSJITAllow4, setTSJITAllow6} {
		_, _ = m.run(ctx, "", "ipset", "flush", setName)
		_, _ = m.run(ctx, "", "ipset", "destroy", setName)
	}

	if err := m.syncFirewallUserLocked(""); err != nil {
		return err
	}
	m.lastDigest = ""
	return nil
}

// AddPinhole 在瞬时窗口秒数内将经校验的公网候选 IP 写入 `TS_JIT_ALLOW4/6` ipset 集合。
func (m *IPTablesP2PManager) AddPinhole(ctx context.Context, v4 []netip.Addr, v6 []netip.Addr, windowSec int) error {
	win := strconv.Itoa(min(max(3, windowSec), 10))
	for _, rawIP := range v4 {
		ip := rawIP.Unmap()
		if !ip.IsValid() || !ip.Is4() {
			continue
		}
		if out, err := m.run(ctx, "", "ipset", "add", setTSJITAllow4, ip.String(), "timeout", win, "-exist"); err != nil {
			return fmt.Errorf("ipset add %s %s: %w (%s)", setTSJITAllow4, ip.String(), err, strings.TrimSpace(string(out)))
		}
	}
	for _, rawIP := range v6 {
		ip := rawIP.Unmap()
		if !ip.IsValid() || !ip.Is6() {
			continue
		}
		if out, err := m.run(ctx, "", "ipset", "add", setTSJITAllow6, ip.String(), "timeout", win, "-exist"); err != nil {
			return fmt.Errorf("ipset add %s %s: %w (%s)", setTSJITAllow6, ip.String(), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// RemovePinhole 立即从 `TS_JIT_ALLOW4/6` 集合中撤销候选 IP（不存在时静默忽略）。
func (m *IPTablesP2PManager) RemovePinhole(ctx context.Context, v4 []netip.Addr, v6 []netip.Addr) error {
	delOne := func(setName string, rawIP netip.Addr) error {
		ip := rawIP.Unmap()
		if !ip.IsValid() {
			return nil
		}
		out, err := m.run(ctx, "", "ipset", "del", setName, ip.String(), "-exist")
		if err == nil {
			return nil
		}
		msg := strings.ToLower(string(out) + " " + err.Error())
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "not in set") || errors.Is(err, exec.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("ipset del %s %s: %w (%s)", setName, ip.String(), err, strings.TrimSpace(string(out)))
	}
	for _, ip := range v4 {
		if err := delOne(setTSJITAllow4, ip); err != nil {
			return err
		}
	}
	for _, ip := range v6 {
		if err := delOne(setTSJITAllow6, ip); err != nil {
			return err
		}
	}
	return nil
}

// ListActivePinholes 读取并解析 `ipset list TS_JIT_ALLOW4/6` 中的当前活跃公网 IP 列表。
func (m *IPTablesP2PManager) ListActivePinholes(ctx context.Context) (int, []string) {
	var ips []string
	for _, setName := range []string{setTSJITAllow4, setTSJITAllow6} {
		out, err := m.run(ctx, "", "ipset", "list", setName)
		if err != nil || len(out) == 0 {
			continue
		}
		ips = append(ips, ParseIPSetMembers(string(out))...)
	}
	slices.Sort(ips)
	ips = slices.Compact(ips)
	return len(ips), ips
}

// ParseIPSetMembers 从 `ipset list <name>` 输出的 Members 段中提取全部合法 IP 地址。
func ParseIPSetMembers(raw string) []string {
	var out []string
	inMembers := false
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
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
		if addr, err := netip.ParseAddr(fields[0]); err == nil {
			out = append(out, addr.Unmap().String())
		}
	}
	return out
}

func (m *IPTablesP2PManager) syncFirewallUserLocked(block string) error {
	targetPath := m.firewallUserPath()
	if targetPath == "" {
		return nil
	}
	raw, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			if block == "" {
				return nil
			}
			return fsx.WriteAtomic0600(targetPath, []byte(block))
		}
		return err
	}

	updated := upsertManagedBlock(string(raw), tsFirewallUserBegin, tsFirewallUserEnd, block)
	if updated == string(raw) {
		return nil
	}
	return fsx.WriteAtomic0600(targetPath, []byte(updated))
}

func upsertManagedBlock(existing, beginMarker, endMarker, newBlock string) string {
	var kept []string
	skipping := false
	for line := range strings.SplitSeq(existing, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == beginMarker {
			skipping = true
			continue
		}
		if skipping {
			if trimmed == endMarker {
				skipping = false
			}
			continue
		}
		kept = append(kept, line)
	}

	base := strings.TrimRight(strings.Join(kept, "\n"), "\n")
	if newBlock == "" {
		if base == "" {
			return ""
		}
		return base + "\n"
	}
	blockClean := strings.TrimRight(newBlock, "\n") + "\n"
	if base == "" {
		return blockClean
	}
	return base + "\n\n" + blockClean
}

func (m *FW4Manager) iptablesBackend(lookPath func(string) (string, error)) *IPTablesP2PManager {
	lp := lookPath
	if lp == nil {
		lp = m.LookPath
	}
	if m.iptMgr == nil {
		fwUser := strings.TrimSpace(m.FirewallUserPath)
		if fwUser == "" && strings.TrimSpace(m.BaseDir) != "" {
			fwUser = m.BaseDir + string(os.PathSeparator) + "firewall.user"
		}
		m.iptMgr = &IPTablesP2PManager{
			Runner:           m.Runner,
			LookPath:         lp,
			FirewallUserPath: fwUser,
		}
	} else {
		m.iptMgr.Runner = m.Runner
		if lp != nil {
			m.iptMgr.LookPath = lp
		}
	}
	return m.iptMgr
}
