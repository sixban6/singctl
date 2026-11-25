package gateway

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

var baseSidePrivateCIDRs = []string{
	"10.0.0.0/8",
	"100.64.0.0/10",
	"172.16.0.0/12",
	"192.168.0.0/16",
}

func sidePrivateCIDRs(lanCIDR string) []string {
	out := slices.Clone(baseSidePrivateCIDRs)
	pfx, err := netip.ParsePrefix(strings.TrimSpace(lanCIDR))
	if err != nil || !pfx.Addr().Is4() {
		return out
	}
	norm := netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()).Masked()
	covered := false
	for _, baseStr := range baseSidePrivateCIDRs {
		if basePfx, bErr := netip.ParsePrefix(baseStr); bErr == nil {
			if basePfx.Bits() <= norm.Bits() && basePfx.Contains(norm.Addr()) {
				covered = true
				break
			}
		}
	}
	if !covered && !slices.Contains(out, norm.String()) {
		out = append(out, norm.String())
	}
	return out
}

// BuildSideRouterNFT 生成旁路由模式专属的独立隔离表 `table inet singctl-side`：
//  1. 当宿主无本地 53 监听进程（如裸 Debian）时，prerouting 链将发往本机 :53 的请求透明导向 TProxy 7895；
//     若宿主已有 dnsmasq 监听 :53（如 OpenWrt），则完全沿用主路由机制（fib local 交由 dnsmasq -> output 链标记进 sing-box），彻底避免 :53 回包 EADDRINUSE 冲突；
//  2. forward 链自动钳制 TCP SYN MSS 至路由 MTU（消除上级 PPPoE 1492 MTU 导致的 TLS 握手卡死）；
//  3. postrouting 链对绕过 TProxy 走内核三层直转出单臂口的全私网+CGNAT 外网报文做单臂 MASQUERADE（消除多 VLAN 真实终端 IP 透传时主路由 ct state invalid 非对称丢包，同时保留 TProxy 内客户端真实源 IP）。
func BuildSideRouterNFT(plan ResolvedPlan) string {
	preroutingBlock := ""
	if plan.InterceptLocalDNS {
		preroutingBlock = `    chain prerouting {
        type filter hook prerouting priority mangle - 5; policy accept;
        # 宿主无本地 53 监听进程时，将发往旁路由本机 IP (<lan_ip>:53) 的请求透明重定向至 sing-box TProxy 7895 (hijack-dns)
        iifname != "lo" fib daddr type local meta l4proto { tcp, udp } th dport 53 tproxy to :7895 meta mark set 0x1 accept
    }

`
	}

	privateSet := "{ " + strings.Join(sidePrivateCIDRs(plan.LANCIDR), ", ") + " }"

	return fmt.Sprintf(`#!/usr/sbin/nft -f
add table inet singctl-side
flush table inet singctl-side
table inet singctl-side {
%s    chain forward {
        type filter hook forward priority filter - 5; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname %q ip saddr %s ip daddr != %s masquerade
    }
}
`, preroutingBlock, plan.LANIface, privateSet, privateSet)
}

// BuildSideRouterSysctls 返回旁路由单臂透明代理必需的内核参数列表。
func BuildSideRouterSysctls(lanIface string, hasBridgeNF bool) []SysctlKV {
	kvs := []SysctlKV{
		{Key: "net.ipv4.ip_forward", Value: "1"},
		{Key: "net.ipv4.conf.all.rp_filter", Value: "0"},
		{Key: "net.ipv4.conf.default.rp_filter", Value: "0"},
		{Key: "net.ipv4.conf.all.send_redirects", Value: "0"},
		{Key: "net.ipv4.conf.default.send_redirects", Value: "0"},
	}
	if lanIface != "" {
		kvs = append(kvs,
			SysctlKV{Key: "net.ipv4.conf." + lanIface + ".rp_filter", Value: "0"},
			SysctlKV{Key: "net.ipv4.conf." + lanIface + ".send_redirects", Value: "0"},
		)
	}
	if hasBridgeNF {
		kvs = append(kvs,
			SysctlKV{Key: "net.bridge.bridge-nf-call-iptables", Value: "0"},
			SysctlKV{Key: "net.bridge.bridge-nf-call-ip6tables", Value: "0"},
		)
	}
	return kvs
}
