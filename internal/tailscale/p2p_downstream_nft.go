// 文件职责：渲染并管理主路由边界「出站触发式动态 JIT 微窗」nftables 规则（保护局域网下游 Tailscale 设备穿透对称 NAT 且平时 0 包进内网）。
package tailscale

import (
	"fmt"
	"strings"
	"time"

	"singctl/internal/config"
)

const (
	lanJITCommentTag = "singctl-ts-lan-jit"

	mapTSLanPunch4 = "TS_LAN_PUNCH4"
	setTSLanPunch6 = "TS_LAN_PUNCH6"

	chainLanLearn4 = "singctl_ts_lan_learn4"
	chainLanLearn6 = "singctl_ts_lan_learn6"
	chainLanDNAT4  = "singctl_ts_lan_dnat4"
	chainLanFwd    = "singctl_ts_lan_fwd"

	downstreamPunchMapSize = 64
)

// FW4RenderOptions 控制 fw4 P2P 防线渲染时的运行态上下文（例如本机是否正在运行 Tailscale）。
type FW4RenderOptions struct {
	LocalTailscaleRunning bool
}

var tailscaleMagicMatchers = []string{
	"@th,64,48 0x5453f09f92ac",
	"@th,64,32 0x01000000 udp length 156",
	"@th,64,32 0x02000000 udp length 100",
	"@th,64,32 0x03000000 udp length 72",
	"@th,64,32 0x04000000 udp length >= 40",
}

// RenderFW4DropInsWithOptions 在 RenderFW4DropIns 基础上结合本机 Tailscale 运行态，
// 自动互斥渲染本机 JIT 防线与全屋下游设备边界动态微窗（IPv4/IPv6）。
func RenderFW4DropInsWithOptions(
	cfg config.TailscaleP2PAssistConfig,
	peers []ResolvedPeerACL,
	defaultLANCIDR string,
	now time.Time,
	opts FW4RenderOptions,
) (FW4DropIns, error) {
	base, err := renderFW4BaseDropIns(cfg, peers, defaultLANCIDR, now)
	if err != nil {
		return FW4DropIns{}, err
	}
	if !cfg.EffectiveDownstreamAssist() {
		return base, nil
	}

	port := base.ListenPort
	winSec := base.JITWindowSec
	payloadFilter := cfg.EffectivePayloadFilter()

	// 严格互斥：仅当本机未运行 Tailscale 时才启用 IPv4 41641 下游动态 DNAT，避免与本机抢占 UDP 41641；
	// IPv6 因每台下游设备拥有独立公网 IPv6 地址，不与本机端口冲突，可长期共存。
	v4Active := !opts.LocalTailscaleRunning
	v6Active := true

	base.DownstreamV4Active = v4Active
	base.DownstreamV6Active = v6Active

	var extra strings.Builder
	if v4Active {
		fmt.Fprintf(&extra, "\nmap %s {\n    type ipv4_addr : ipv4_addr\n    size %d\n    flags dynamic, timeout\n    timeout %ds\n}\n",
			mapTSLanPunch4, downstreamPunchMapSize, winSec)
		base.LanLearn4Rules = buildLanLearn4Rules(port, winSec, payloadFilter)
		base.LanDNAT4Rules = buildLanDNAT4Rules(port, payloadFilter)
	}
	if v6Active {
		fmt.Fprintf(&extra, "\nset %s {\n    type ipv6_addr . ipv6_addr\n    size %d\n    flags dynamic, timeout\n    timeout %ds\n}\n",
			setTSLanPunch6, downstreamPunchMapSize, winSec)
		base.LanLearn6Rules = buildLanLearn6Rules(port, winSec, payloadFilter)
	}
	base.LanFwdRules = buildLanFwdRules(port, v4Active, v6Active, payloadFilter)

	if v4Active {
		extra.WriteByte('\n')
		writeChainBlock(&extra, chainLanLearn4, base.LanLearn4Rules)
		extra.WriteByte('\n')
		writeChainBlock(&extra, chainLanDNAT4, base.LanDNAT4Rules)
	}
	if v6Active {
		extra.WriteByte('\n')
		writeChainBlock(&extra, chainLanLearn6, base.LanLearn6Rules)
	}
	extra.WriteByte('\n')
	writeChainBlock(&extra, chainLanFwd, base.LanFwdRules)

	base.TablePre += extra.String()

	const header = "# Managed by SingCtl Tailscale P2P Defense — DO NOT EDIT MANUALLY\n"
	if v4Active {
		base.ForwardLanLearnPre = header + base.forwardLanLearn4Rule() + "\n"
		base.DstnatPre = header + base.dstnatLanRule() + "\n"
		base.SrcnatLanPre = header + base.srcnatLanBypassRule() + "\n"
	}
	if v6Active {
		base.ForwardLanV6LearnPre = header + base.forwardLanLearn6Rule() + "\n"
	}
	if v4Active || v6Active {
		base.ForwardWANPre = header + base.forwardWANLanRule() + "\n"
	}
	return base, nil
}

func buildLanLearn4Rules(port, winSec int, payloadFilter bool) []string {
	rules := []string{
		fmt.Sprintf("udp sport != %d return", port),
		"udp dport 3478 return",
		"ip saddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } return",
		"ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 224.0.0.0/4 } return",
	}
	if payloadFilter {
		for _, m := range tailscaleMagicMatchers {
			rules = append(rules, fmt.Sprintf("%s update @%s { ip daddr timeout %ds : ip saddr } return", m, mapTSLanPunch4, winSec))
		}
	} else {
		rules = append(rules, fmt.Sprintf("update @%s { ip daddr timeout %ds : ip saddr } return", mapTSLanPunch4, winSec))
	}
	return rules
}

func buildLanLearn6Rules(port, winSec int, payloadFilter bool) []string {
	rules := []string{
		fmt.Sprintf("udp sport != %d return", port),
		"udp dport 3478 return",
		"ip6 daddr { ::1/128, fc00::/7, fe80::/10, ff00::/8 } return",
	}
	if payloadFilter {
		for _, m := range tailscaleMagicMatchers {
			rules = append(rules, fmt.Sprintf("%s update @%s { ip6 daddr . ip6 saddr timeout %ds } return", m, setTSLanPunch6, winSec))
		}
	} else {
		rules = append(rules, fmt.Sprintf("update @%s { ip6 daddr . ip6 saddr timeout %ds } return", setTSLanPunch6, winSec))
	}
	return rules
}

func buildLanDNAT4Rules(port int, payloadFilter bool) []string {
	rules := []string{
		fmt.Sprintf("udp dport != %d return", port),
		"fib daddr type != local return",
		fmt.Sprintf("ip saddr != @%s return", mapTSLanPunch4),
		"limit rate over 300/second burst 600 packets return",
	}
	if payloadFilter {
		for _, m := range tailscaleMagicMatchers {
			rules = append(rules, fmt.Sprintf("udp dport %d %s counter dnat ip to ip saddr map @%s : %d", port, m, mapTSLanPunch4, port))
		}
	} else {
		rules = append(rules, fmt.Sprintf("udp dport %d counter dnat ip to ip saddr map @%s : %d", port, mapTSLanPunch4, port))
	}
	return rules
}

func buildLanFwdRules(port int, v4Active, v6Active, payloadFilter bool) []string {
	var rules []string
	if v4Active {
		rules = append(rules, fmt.Sprintf("ct status dnat udp dport %d ip saddr @%s counter accept", port, mapTSLanPunch4))
	}
	if v6Active {
		if payloadFilter {
			for _, m := range tailscaleMagicMatchers {
				rules = append(rules, fmt.Sprintf("udp dport %d ip6 saddr . ip6 daddr @%s limit rate 300/second burst 600 packets %s counter accept", port, setTSLanPunch6, m))
			}
		} else {
			rules = append(rules, fmt.Sprintf("udp dport %d ip6 saddr . ip6 daddr @%s limit rate 300/second burst 600 packets counter accept", port, setTSLanPunch6))
		}
	}
	return rules
}

func (d FW4DropIns) forwardLanLearn4Rule() string {
	return fmt.Sprintf(`jump %s comment "%s"`, chainLanLearn4, lanJITCommentTag)
}

func (d FW4DropIns) forwardLanLearn6Rule() string {
	return fmt.Sprintf(`jump %s comment "%s"`, chainLanLearn6, lanJITCommentTag)
}

func (d FW4DropIns) dstnatLanRule() string {
	return fmt.Sprintf(`jump %s comment "%s"`, chainLanDNAT4, lanJITCommentTag)
}

func (d FW4DropIns) forwardWANLanRule() string {
	return fmt.Sprintf(`jump %s comment "%s"`, chainLanFwd, lanJITCommentTag)
}

func (d FW4DropIns) srcnatLanBypassRule() string {
	return fmt.Sprintf(`ct status dnat udp dport %d ip saddr @%s return comment "%s"`, d.ListenPort, mapTSLanPunch4, lanJITCommentTag)
}
