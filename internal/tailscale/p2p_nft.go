package tailscale

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"singctl/internal/config"
)

const (
	DefaultNFTablesDDir = "/usr/share/nftables.d"

	ApplyModeFW4Reload = "fw4_reload"
	ApplyModeNFTDirect = "nft_direct"

	jitCommentTag = "singctl-ts-jit"
	aclCommentTag = "singctl-ts-acl"

	setTSJITAllow4 = "TS_JIT_ALLOW4"
	setTSJITAllow6 = "TS_JIT_ALLOW6"

	chainJITGuard   = "singctl_ts_jit_guard"
	chainInputACL   = "singctl_ts_input_acl"
	chainForwardACL = "singctl_ts_forward_acl"
)

var (
	nftHandleRe    = regexp.MustCompile(`#\s*handle\s+(\d+)\s*$`)
	openBraceSelRe = regexp.MustCompile(`^(set|chain)\s+([A-Za-z0-9_]+)\s*\{`)
)

// CmdRunner 允许注入外部命令执行器，便于单元测试与可控 E2E 校验。
type CmdRunner func(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)

func defaultCmdRunner(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// LANTarget 表示一条经严格白名单校验后的局域网目标规则（支持 IP/CIDR 与可选协议/端口）。
type LANTarget struct {
	Raw      string
	AddrExpr string
	IsV6     bool
	Proto    string // "", "tcp", or "udp"
	Port     int    // 0 means any port
}

// ParseAllowedLANTarget 解析并严格校验允许远端互访的本地 LAN 目标表达式。
// 支持格式: "192.168.1.0/24", "192.168.1.10", "192.168.1.10:445", "tcp/192.168.1.10:445",
// "udp/192.168.1.0/24:5353", "[2001:db8:1::10]:445", "2001:db8:1::/64"。
func ParseAllowedLANTarget(raw string) (LANTarget, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return LANTarget{}, fmt.Errorf("empty allowed_lan_targets entry")
	}
	if strings.ContainsAny(s, ";{}|\n\r\t`$()\\\"' ") {
		return LANTarget{}, fmt.Errorf("invalid characters in allowed_lan_targets entry %q", raw)
	}

	proto := ""
	rest := s
	lower := strings.ToLower(rest)
	switch {
	case strings.HasPrefix(lower, "tcp/"):
		proto = "tcp"
		rest = rest[4:]
	case strings.HasPrefix(lower, "udp/"):
		proto = "udp"
		rest = rest[4:]
	default:
		if before, _, hasSlash := strings.Cut(lower, "/"); hasSlash {
			// If prefix before slash isn't numeric CIDR host bits (contains non-hex letters), reject unknown proto.
			hasNonAddrAlpha := false
			for i := 0; i < len(before); i++ {
				ch := before[i]
				if ch >= 'g' && ch <= 'z' {
					hasNonAddrAlpha = true
					break
				}
			}
			if hasNonAddrAlpha {
				return LANTarget{}, fmt.Errorf("unsupported protocol prefix in %q (only tcp/ or udp/ allowed)", raw)
			}
		}
	}

	var addrPart, portPart string
	if strings.HasPrefix(rest, "[") {
		closeIdx := strings.IndexByte(rest, ']')
		if closeIdx <= 1 {
			return LANTarget{}, fmt.Errorf("malformed IPv6 bracket target %q", raw)
		}
		addrPart = rest[1:closeIdx]
		rem := rest[closeIdx+1:]
		if rem != "" {
			if !strings.HasPrefix(rem, ":") {
				return LANTarget{}, fmt.Errorf("malformed port separator in %q", raw)
			}
			portPart = rem[1:]
		}
	} else if strings.Count(rest, ":") == 1 {
		host, portStr, _ := strings.Cut(rest, ":")
		addrPart = host
		portPart = portStr
	} else {
		addrPart = rest
	}

	port := 0
	if portPart != "" {
		p, err := strconv.Atoi(portPart)
		if err != nil || p < 1 || p > 65535 {
			return LANTarget{}, fmt.Errorf("invalid port %q in %q", portPart, raw)
		}
		port = p
	} else if proto != "" {
		return LANTarget{}, fmt.Errorf("protocol prefix %q requires an explicit port", raw)
	}

	var addrExpr string
	var isV6 bool
	if strings.Contains(addrPart, "/") {
		pfx, err := netip.ParsePrefix(addrPart)
		if err != nil {
			return LANTarget{}, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
		addrExpr = pfx.String()
		isV6 = pfx.Addr().Is6()
	} else {
		addr, err := netip.ParseAddr(addrPart)
		if err != nil {
			return LANTarget{}, fmt.Errorf("invalid IP address %q: %w", raw, err)
		}
		addr = addr.Unmap()
		addrExpr = addr.String()
		isV6 = addr.Is6()
	}

	return LANTarget{
		Raw:      s,
		AddrExpr: addrExpr,
		IsV6:     isV6,
		Proto:    proto,
		Port:     port,
	}, nil
}

func parseSourceExpr(raw string) (expr string, isV6 bool, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false, false
	}
	if strings.Contains(s, "/") {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return "", false, false
		}
		pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
		return pfx.String(), pfx.Addr().Is6(), true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", false, false
	}
	addr = addr.Unmap()
	return addr.String(), addr.Is6(), true
}

// ResolvedPeerACL 携带配置项与从 LocalAPI / 静态配置解析出的全部源 IP 与广播子网。
type ResolvedPeerACL struct {
	Config        config.TailscaleP2PPeerConfig
	TailscaleIPs  []string
	PrimaryRoutes []string
}

func (r ResolvedPeerACL) sourceExpressions() []struct {
	expr string
	isV6 bool
} {
	var candidates []string
	if r.Config.TailscaleIP != "" {
		candidates = append(candidates, r.Config.TailscaleIP)
	}
	candidates = append(candidates, r.TailscaleIPs...)
	candidates = append(candidates, r.PrimaryRoutes...)

	seen := make(map[string]struct{}, len(candidates))
	var out []struct {
		expr string
		isV6 bool
	}
	for _, raw := range candidates {
		expr, isV6, ok := parseSourceExpr(raw)
		if !ok {
			continue
		}
		if _, dup := seen[expr]; dup {
			continue
		}
		seen[expr] = struct{}{}
		out = append(out, struct {
			expr string
			isV6 bool
		}{expr: expr, isV6: isV6})
	}
	return out
}

// FW4DropIns 保存为 fw4 生成的 4 份 drop-in 文件与直写 nft 所需的单源规则集。
type FW4DropIns struct {
	TablePre            string
	InputWANPre         string
	InputTailscalePre   string
	ForwardTailscalePre string

	JITGuardRules   []string
	InputACLRules   []string
	ForwardACLRules []string

	ListenPort   int
	JITWindowSec int
}

// Digest 返回用于幂等对比的内容摘要。
func (d FW4DropIns) Digest() string {
	h := sha256.New()
	for _, s := range []string{d.TablePre, d.InputWANPre, d.InputTailscalePre, d.ForwardTailscalePre} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RenderDryRunCheckScript 生成独立临时表的完整 nftables 脚本，用于 `nft -c -f -` 前置语法预校验。
func (d FW4DropIns) RenderDryRunCheckScript() string {
	var b strings.Builder
	b.WriteString("table inet singctl_p2p_dryrun {\n")
	for line := range strings.SplitSeq(d.TablePre, "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	b.WriteString("    chain input_wan {\n")
	b.WriteString("        " + d.inputWANRule() + "\n")
	b.WriteString("    }\n")
	b.WriteString("    chain input_tailscale {\n")
	b.WriteString("        " + d.inputTailscaleRule() + "\n")
	b.WriteString("    }\n")
	b.WriteString("    chain forward_tailscale {\n")
	b.WriteString("        " + d.forwardTailscaleRule() + "\n")
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

func (d FW4DropIns) inputWANRule() string {
	return fmt.Sprintf(`udp dport %d jump %s comment "%s"`, d.ListenPort, chainJITGuard, jitCommentTag)
}

func (d FW4DropIns) inputTailscaleRule() string {
	return fmt.Sprintf(`jump %s comment "%s"`, chainInputACL, aclCommentTag)
}

func (d FW4DropIns) forwardTailscaleRule() string {
	return fmt.Sprintf(`jump %s comment "%s"`, chainForwardACL, aclCommentTag)
}

// RenderFW4DropIns 根据 P2P 防线配置与对端拓扑渲染全部 Layer 1 / Layer 2 / Layer 4 防火墙规则。
func RenderFW4DropIns(cfg config.TailscaleP2PAssistConfig, peers []ResolvedPeerACL, defaultLANCIDR string, now time.Time) (FW4DropIns, error) {
	port := cfg.EffectiveListenPort()
	winSec := cfg.EffectiveJITWindowSec()

	jitGuard := []string{
		fmt.Sprintf("udp dport != %d return", port),
		fmt.Sprintf("meta nfproto ipv4 ip saddr != @%s return", setTSJITAllow4),
		fmt.Sprintf("meta nfproto ipv6 ip6 saddr != @%s return", setTSJITAllow6),
		"limit rate over 300/second burst 600 packets counter drop",
	}
	if cfg.EffectivePayloadFilter() {
		jitGuard = append(jitGuard,
			"@th,64,48 0x5453f09f92ac counter accept",
			"@th,64,32 0x01000000 udp length 156 counter accept",
			"@th,64,32 0x02000000 udp length 100 counter accept",
			"@th,64,32 0x03000000 udp length 72 counter accept",
			"@th,64,32 0x04000000 udp length >= 40 counter accept",
			"@th,96,32 0x2112a442 udp length >= 28 counter accept",
			"counter drop",
		)
	} else {
		jitGuard = append(jitGuard, "counter accept")
	}

	var defaultTargets []LANTarget
	if trimmedDef := strings.TrimSpace(defaultLANCIDR); trimmedDef != "" {
		if parsed, err := ParseAllowedLANTarget(trimmedDef); err == nil {
			defaultTargets = append(defaultTargets, parsed)
		}
	}

	var inputACLRules []string
	var forwardACLRules []string

	for _, peer := range peers {
		srcs := peer.sourceExpressions()
		if len(srcs) == 0 {
			continue
		}

		// Router management plane stays closed to remote site peers across all modes; unlisted admin devices stay unrestricted.
		for _, src := range srcs {
			if src.isV6 {
				inputACLRules = append(inputACLRules, fmt.Sprintf("ip6 saddr %s counter drop", src.expr))
			} else {
				inputACLRules = append(inputACLRules, fmt.Sprintf("ip saddr %s counter drop", src.expr))
			}
		}

		effMode := peer.Config.EffectiveAccessMode(now)
		if effMode == config.TailscaleAccessBidirectional || effMode == config.TailscaleAccessBidirectionalTimed {
			var parsedTargets []LANTarget
			for _, rawTarget := range peer.Config.AllowedLANTargets {
				t, err := ParseAllowedLANTarget(rawTarget)
				if err != nil {
					return FW4DropIns{}, err
				}
				parsedTargets = append(parsedTargets, t)
			}
			if len(parsedTargets) == 0 {
				parsedTargets = defaultTargets
			}
			for _, src := range srcs {
				for _, tgt := range parsedTargets {
					if src.isV6 != tgt.IsV6 {
						continue
					}
					family := "ip"
					if src.isV6 {
						family = "ip6"
					}
					switch {
					case tgt.Port == 0:
						forwardACLRules = append(forwardACLRules, fmt.Sprintf("%s saddr %s %s daddr %s counter accept", family, src.expr, family, tgt.AddrExpr))
					case tgt.Proto == "tcp" || tgt.Proto == "udp":
						forwardACLRules = append(forwardACLRules, fmt.Sprintf("%s saddr %s %s daddr %s %s dport %d counter accept", family, src.expr, family, tgt.AddrExpr, tgt.Proto, tgt.Port))
					default:
						forwardACLRules = append(forwardACLRules, fmt.Sprintf("%s saddr %s %s daddr %s meta l4proto { tcp, udp } th dport %d counter accept", family, src.expr, family, tgt.AddrExpr, tgt.Port))
					}
				}
			}
		}

		// Default-deny catch-all for this peer after any specific bidirectional target accepts.
		for _, src := range srcs {
			if src.isV6 {
				forwardACLRules = append(forwardACLRules, fmt.Sprintf("ip6 saddr %s counter drop", src.expr))
			} else {
				forwardACLRules = append(forwardACLRules, fmt.Sprintf("ip saddr %s counter drop", src.expr))
			}
		}
	}

	var tb strings.Builder
	tb.WriteString("# Managed by SingCtl Tailscale P2P Defense — DO NOT EDIT MANUALLY\n")
	fmt.Fprintf(&tb, "set %s {\n    type ipv4_addr\n    flags timeout\n    timeout %ds\n}\n\n", setTSJITAllow4, winSec)
	fmt.Fprintf(&tb, "set %s {\n    type ipv6_addr\n    flags timeout\n    timeout %ds\n}\n\n", setTSJITAllow6, winSec)
	writeChainBlock(&tb, chainJITGuard, jitGuard)
	tb.WriteByte('\n')
	writeChainBlock(&tb, chainInputACL, inputACLRules)
	tb.WriteByte('\n')
	writeChainBlock(&tb, chainForwardACL, forwardACLRules)

	out := FW4DropIns{
		TablePre:        tb.String(),
		JITGuardRules:   jitGuard,
		InputACLRules:   inputACLRules,
		ForwardACLRules: forwardACLRules,
		ListenPort:      port,
		JITWindowSec:    winSec,
	}
	out.InputWANPre = "# Managed by SingCtl Tailscale P2P Defense — DO NOT EDIT MANUALLY\n" + out.inputWANRule() + "\n"
	out.InputTailscalePre = "# Managed by SingCtl Tailscale P2P Defense — DO NOT EDIT MANUALLY\n" + out.inputTailscaleRule() + "\n"
	out.ForwardTailscalePre = "# Managed by SingCtl Tailscale P2P Defense — DO NOT EDIT MANUALLY\n" + out.forwardTailscaleRule() + "\n"
	return out, nil
}

func writeChainBlock(b *strings.Builder, name string, rules []string) {
	fmt.Fprintf(b, "chain %s {\n", name)
	for _, r := range rules {
		fmt.Fprintf(b, "    %s\n", r)
	}
	b.WriteString("}\n")
}

// FW4Manager 负责将 SingCtl P2P 防线规则通过 OpenWrt fw4 drop-in + 原子直写 nftables 兜底生效，
// 并提供 JIT 白名单元素的毫秒级开关与计数查询。
type FW4Manager struct {
	BaseDir string
	Runner  CmdRunner

	mu            sync.Mutex
	lastDigest    string
	lastApplyMode string
}

func (m *FW4Manager) baseDir() string {
	return cmp.Or(strings.TrimSpace(m.BaseDir), DefaultNFTablesDDir)
}

func (m *FW4Manager) run(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	if m.Runner != nil {
		return m.Runner(ctx, stdin, name, args...)
	}
	return defaultCmdRunner(ctx, stdin, name, args...)
}

func (m *FW4Manager) dropInPaths() map[string]string {
	base := m.baseDir()
	return map[string]string{
		"table-pre":         filepath.Join(base, "table-pre", "singctl-ts-jit.nft"),
		"input-wan":         filepath.Join(base, "chain-pre", "input_wan", "singctl-ts-jit.nft"),
		"input-tailscale":   filepath.Join(base, "chain-pre", "input_tailscale", "singctl-ts-acl.nft"),
		"forward-tailscale": filepath.Join(base, "chain-pre", "forward_tailscale", "singctl-ts-acl.nft"),
	}
}

type fileSnapshot struct {
	existed bool
	data    []byte
}

func snapshotFiles(paths map[string]string) map[string]fileSnapshot {
	snaps := make(map[string]fileSnapshot, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			snaps[p] = fileSnapshot{existed: true, data: data}
		} else {
			snaps[p] = fileSnapshot{existed: false}
		}
	}
	return snaps
}

func restoreFiles(snaps map[string]fileSnapshot) {
	for p, s := range snaps {
		if s.existed {
			_ = os.MkdirAll(filepath.Dir(p), 0755)
			_ = os.WriteFile(p, s.data, 0644)
		} else {
			_ = os.Remove(p)
		}
	}
}

// Apply 将渲染后的防线规则安全落盘并通过 fw4 reload（健康时）或原子 nftables 直写（当第三方 /etc/nftables.d/*.nft 破坏 fw4 check 时）生效。
func (m *FW4Manager) Apply(ctx context.Context, d FW4DropIns) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if out, err := m.run(ctx, d.RenderDryRunCheckScript(), "nft", "-c", "-f", "-"); err != nil {
		return "", fmt.Errorf("nft syntax self-check failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}

	paths := m.dropInPaths()
	wantContents := map[string]string{
		paths["table-pre"]:         d.TablePre,
		paths["input-wan"]:         d.InputWANPre,
		paths["input-tailscale"]:   d.InputTailscalePre,
		paths["forward-tailscale"]: d.ForwardTailscalePre,
	}

	snaps := snapshotFiles(paths)
	filesMatch := true
	for p, want := range wantContents {
		snap, ok := snaps[p]
		if !ok || !snap.existed || string(snap.data) != want {
			filesMatch = false
			break
		}
	}

	digest := d.Digest()
	if filesMatch && m.lastDigest == digest && m.liveChainExists(ctx) {
		return cmp.Or(m.lastApplyMode, ApplyModeFW4Reload), nil
	}

	for p, content := range wantContents {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			restoreFiles(snaps)
			return "", fmt.Errorf("create nftables drop-in dir: %w", err)
		}
		tmp := p + ".tmp"
		if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
			_ = os.Remove(tmp)
			restoreFiles(snaps)
			return "", fmt.Errorf("write %s: %w", p, err)
		}
		if err := os.Rename(tmp, p); err != nil {
			_ = os.Remove(tmp)
			restoreFiles(snaps)
			return "", fmt.Errorf("rename %s: %w", p, err)
		}
	}

	if _, err := m.run(ctx, "", "fw4", "check"); err == nil {
		if out, reloadErr := m.run(ctx, "", "fw4", "reload"); reloadErr != nil {
			restoreFiles(snaps)
			_, _ = m.run(ctx, "", "fw4", "reload")
			return "", fmt.Errorf("fw4 reload failed: %w (%s)", reloadErr, strings.TrimSpace(string(out)))
		}
		m.lastDigest = digest
		m.lastApplyMode = ApplyModeFW4Reload
		return ApplyModeFW4Reload, nil
	}

	// Fallback when router has unrelated broken third-party /etc/nftables.d/*.nft blocking global fw4 check.
	if err := m.applyNFTDirect(ctx, d); err != nil {
		restoreFiles(snaps)
		return "", err
	}
	m.lastDigest = digest
	m.lastApplyMode = ApplyModeNFTDirect
	return ApplyModeNFTDirect, nil
}

func (m *FW4Manager) liveChainExists(ctx context.Context) bool {
	_, err := m.run(ctx, "", "nft", "list", "chain", "inet", "fw4", chainJITGuard)
	return err == nil
}

type fw4TableInspection struct {
	setsPresent   map[string]bool
	chainsPresent map[string]bool
	taggedHandles map[string][]int
}

func parseFW4Inspection(raw string) fw4TableInspection {
	res := fw4TableInspection{
		setsPresent:   make(map[string]bool),
		chainsPresent: make(map[string]bool),
		taggedHandles: make(map[string][]int),
	}
	var currentKind, currentName string
	for line := range strings.SplitSeq(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if m := openBraceSelRe.FindStringSubmatch(trimmed); len(m) == 3 {
			currentKind = m[1]
			currentName = m[2]
			switch currentKind {
			case "set":
				res.setsPresent[currentName] = true
			case "chain":
				res.chainsPresent[currentName] = true
			}
			continue
		}
		if trimmed == "}" {
			currentKind = ""
			currentName = ""
			continue
		}
		if currentKind == "chain" && (currentName == "input_wan" || currentName == "input_tailscale" || currentName == "forward_tailscale") {
			if strings.Contains(trimmed, jitCommentTag) || strings.Contains(trimmed, aclCommentTag) {
				if hm := nftHandleRe.FindStringSubmatch(trimmed); len(hm) == 2 {
					if handle, err := strconv.Atoi(hm[1]); err == nil && handle > 0 {
						res.taggedHandles[currentName] = append(res.taggedHandles[currentName], handle)
					}
				}
			}
		}
	}
	return res
}

func (m *FW4Manager) applyNFTDirect(ctx context.Context, d FW4DropIns) error {
	raw, err := m.run(ctx, "", "nft", "-a", "list", "table", "inet", "fw4")
	if err != nil {
		return fmt.Errorf("fw4 check failed and table inet fw4 unavailable for atomic nft reconcile: %w (%s)", err, strings.TrimSpace(string(raw)))
	}
	insp := parseFW4Inspection(string(raw))

	var b strings.Builder
	if !insp.setsPresent[setTSJITAllow4] {
		fmt.Fprintf(&b, "add set inet fw4 %s { type ipv4_addr; flags timeout; timeout %ds; }\n", setTSJITAllow4, d.JITWindowSec)
	}
	if !insp.setsPresent[setTSJITAllow6] {
		fmt.Fprintf(&b, "add set inet fw4 %s { type ipv6_addr; flags timeout; timeout %ds; }\n", setTSJITAllow6, d.JITWindowSec)
	}

	writeChainPatch := func(chain string, rules []string) {
		fmt.Fprintf(&b, "add chain inet fw4 %s\n", chain)
		fmt.Fprintf(&b, "flush chain inet fw4 %s\n", chain)
		for _, r := range rules {
			fmt.Fprintf(&b, "add rule inet fw4 %s %s\n", chain, r)
		}
	}
	writeChainPatch(chainJITGuard, d.JITGuardRules)
	writeChainPatch(chainInputACL, d.InputACLRules)
	writeChainPatch(chainForwardACL, d.ForwardACLRules)

	patchJump := func(parent string, ruleExpr string) {
		for _, h := range insp.taggedHandles[parent] {
			fmt.Fprintf(&b, "delete rule inet fw4 %s handle %d\n", parent, h)
		}
		if insp.chainsPresent[parent] {
			fmt.Fprintf(&b, "insert rule inet fw4 %s %s\n", parent, ruleExpr)
		}
	}
	patchJump("input_wan", d.inputWANRule())
	patchJump("input_tailscale", d.inputTailscaleRule())
	patchJump("forward_tailscale", d.forwardTailscaleRule())

	script := b.String()
	if out, err := m.run(ctx, script, "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("atomic nft patch check failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	if out, err := m.run(ctx, script, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("atomic nft patch apply failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove 彻底清理全部 drop-in 文件并撤销运行时防火墙规则（幂等安全）。
func (m *FW4Manager) Remove(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	paths := m.dropInPaths()
	snaps := snapshotFiles(paths)
	anyRemoved := false
	for _, s := range snaps {
		if s.existed {
			anyRemoved = true
			break
		}
	}
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove drop-in %s: %w", p, err)
		}
	}

	if _, err := m.run(ctx, "", "fw4", "check"); err == nil {
		if anyRemoved || m.liveChainExists(ctx) {
			if out, reloadErr := m.run(ctx, "", "fw4", "reload"); reloadErr != nil {
				restoreFiles(snaps)
				return fmt.Errorf("fw4 reload after remove failed: %w (%s)", reloadErr, strings.TrimSpace(string(out)))
			}
		}
		m.lastDigest = ""
		m.lastApplyMode = ""
		return nil
	}

	raw, err := m.run(ctx, "", "nft", "-a", "list", "table", "inet", "fw4")
	if err != nil {
		m.lastDigest = ""
		m.lastApplyMode = ""
		return nil
	}
	insp := parseFW4Inspection(string(raw))

	var b strings.Builder
	for _, parent := range []string{"input_wan", "input_tailscale", "forward_tailscale"} {
		for _, h := range insp.taggedHandles[parent] {
			fmt.Fprintf(&b, "delete rule inet fw4 %s handle %d\n", parent, h)
		}
	}
	for _, ch := range []string{chainJITGuard, chainInputACL, chainForwardACL} {
		if insp.chainsPresent[ch] {
			fmt.Fprintf(&b, "flush chain inet fw4 %s\n", ch)
			fmt.Fprintf(&b, "delete chain inet fw4 %s\n", ch)
		}
	}
	for _, setName := range []string{setTSJITAllow4, setTSJITAllow6} {
		if insp.setsPresent[setName] {
			fmt.Fprintf(&b, "delete set inet fw4 %s\n", setName)
		}
	}

	if b.Len() > 0 {
		if out, err := m.run(ctx, b.String(), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("atomic nft remove failed: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	m.lastDigest = ""
	m.lastApplyMode = ""
	return nil
}

// OpenPinhole 仅在打洞窗口秒数内向内核动态集合插入候选公网 IPv4/IPv6，超时由内核自动驱逐。
func (m *FW4Manager) OpenPinhole(ctx context.Context, v4 []netip.Addr, v6 []netip.Addr, windowSec int) error {
	win := min(max(3, windowSec), 10)
	for _, ip := range v4 {
		elem := fmt.Sprintf("{ %s timeout %ds }", ip.String(), win)
		if out, err := m.run(ctx, "", "nft", "add", "element", "inet", "fw4", setTSJITAllow4, elem); err != nil {
			return fmt.Errorf("nft add element v4: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	for _, ip := range v6 {
		elem := fmt.Sprintf("{ %s timeout %ds }", ip.String(), win)
		if out, err := m.run(ctx, "", "nft", "add", "element", "inet", "fw4", setTSJITAllow6, elem); err != nil {
			return fmt.Errorf("nft add element v6: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ClosePinhole 在直连切换完成或打洞结束时立即吊销瞬时集合元素，若已被内核超时回收则静默忽略。
func (m *FW4Manager) ClosePinhole(ctx context.Context, v4 []netip.Addr, v6 []netip.Addr) error {
	deleteOne := func(setName string, ip netip.Addr) error {
		elem := fmt.Sprintf("{ %s }", ip.String())
		out, err := m.run(ctx, "", "nft", "delete", "element", "inet", "fw4", setName, elem)
		if err == nil {
			return nil
		}
		msg := strings.ToLower(string(out) + " " + err.Error())
		if strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "enoent") {
			return nil
		}
		return fmt.Errorf("nft delete element %s: %w (%s)", setName, err, strings.TrimSpace(string(out)))
	}
	for _, ip := range v4 {
		if err := deleteOne(setTSJITAllow4, ip); err != nil {
			return err
		}
	}
	for _, ip := range v6 {
		if err := deleteOne(setTSJITAllow6, ip); err != nil {
			return err
		}
	}
	return nil
}

// CountOpenPinholes 实时读取内核 TS_JIT_ALLOW4 / TS_JIT_ALLOW6 集合中的活跃条目数量。
func (m *FW4Manager) CountOpenPinholes(ctx context.Context) (int, []string) {
	var ips []string
	for _, setName := range []string{setTSJITAllow4, setTSJITAllow6} {
		out, err := m.run(ctx, "", "nft", "-j", "list", "set", "inet", "fw4", setName)
		if err != nil || len(bytes.TrimSpace(out)) == 0 {
			continue
		}
		ips = append(ips, parseNFTSetJSONElems(out)...)
	}
	slices.Sort(ips)
	return len(ips), ips
}

func parseNFTSetJSONElems(raw []byte) []string {
	var doc struct {
		NFTables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	var out []string
	for _, entry := range doc.NFTables {
		if entry.Set == nil {
			continue
		}
		for _, elemRaw := range entry.Set.Elem {
			var strVal string
			if json.Unmarshal(elemRaw, &strVal) == nil && strVal != "" {
				out = append(out, strVal)
				continue
			}
			var obj struct {
				Elem *struct {
					Val string `json:"val"`
				} `json:"elem"`
			}
			if json.Unmarshal(elemRaw, &obj) == nil && obj.Elem != nil && obj.Elem.Val != "" {
				out = append(out, obj.Elem.Val)
			}
		}
	}
	return out
}

// IsFW4Available 检测当前宿主机是否处于存在 inet fw4 防火墙表的 OpenWrt 环境。
func IsFW4Available() bool {
	if _, err := exec.LookPath("fw4"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "nft", "list", "table", "inet", "fw4").Run() == nil
}
