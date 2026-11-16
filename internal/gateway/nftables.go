package gateway

import "fmt"

// BuildSideRouterNFT 生成旁路由模式专属的独立隔离表 `table inet singctl-side`：
//  1. forward 链自动钳制 TCP SYN MSS 至路由 MTU（消除上级 PPPoE 1492 MTU 导致的 TLS 握手卡死）
//  2. postrouting 链对绕过 TProxy 走内核三层直转出单臂口的外网报文做单臂 MASQUERADE（消除主路由 ct state invalid 非对称丢包，同时保留 TProxy 内客户端真实源 IP）
func BuildSideRouterNFT(plan ResolvedPlan) string {
	return fmt.Sprintf(`#!/usr/sbin/nft -f
table inet singctl-side {
    chain prerouting {
        type filter hook prerouting priority mangle - 5; policy accept;
        # 当局域网终端将 DNS 设为旁路由本机 IP (<lan_ip>:53) 时，先于 fib local 放行将其透明重定向至 sing-box TProxy 7895 (hijack-dns)
        iifname != "lo" fib daddr type local meta l4proto { tcp, udp } th dport 53 tproxy to :7895 meta mark set 0x1 accept
    }

    chain forward {
        type filter hook forward priority filter - 5; policy accept;
        tcp flags syn tcp option maxseg size set rt mtu
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname %q ip saddr %s ip daddr != %s masquerade
    }
}
`, plan.LANIface, plan.LANCIDR, plan.LANCIDR)
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
