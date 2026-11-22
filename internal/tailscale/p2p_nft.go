// 文件职责：负责 Tailscale P2P 打洞防线的 LAN 目标白名单解析与 OpenWrt fw4 / nftables 规则集渲染。
package tailscale

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"singctl/internal/config"
)

const (
	DefaultNFTablesDDir = "/usr/share/nftables.d"

	ApplyModeFW4Reload = "fw4_reload"
	ApplyModeNFTDirect = "nft_direct"

	jitCommentTag = "singctl-ts-jit"
	aclCommentTag = "singctl-ts-acl"

	SetTSJITAllow4Name = "TS_JIT_ALLOW4"
	setTSJITAllow4     = SetTSJITAllow4Name
	setTSJITAllow6     = "TS_JIT_ALLOW6"

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
