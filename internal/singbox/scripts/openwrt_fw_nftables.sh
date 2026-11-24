# 模块职责：OpenWrt nftables 透明代理防火墙后端策略（独立隔离，零旧版防火墙代码），实现 fw_check_deps / fw_cleanup_pre / fw_apply / fw_stop_cleanup 契约。

LOCAL_IPV4='{127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32, 100.64.0.0/10}'

fw_check_deps() {
    check_command "nft"
}

fw_cleanup_pre() {
    if nft list tables 2>/dev/null | grep -q 'inet sing-box'; then
        nft delete table inet sing-box 2>/dev/null || true
    fi
}

fw_apply() {
    echo_succ "创建 nftables 防火墙规则文件..."
    collect_bypass_dns_ips
    collect_vlan_proxy_bypass_cidrs
    collect_lan_ipv6_prefixes

    local bypass_dns_nft4 bypass_dns_nft6 bypass_vlan_rule
    bypass_dns_nft4=$(echo "$BYPASS_DNS_V4_IPS" | awk '{$1=$1; gsub(/ /, ", "); print}')
    bypass_dns_nft6=$(echo "$BYPASS_DNS_V6_IPS" | awk '{$1=$1; gsub(/ /, ", "); print}')
    bypass_vlan_rule=""
    if [ -n "$BYPASS_VLAN_V4_CIDRS" ]; then
        local bypass_vlan_nft4
        bypass_vlan_nft4=$(echo "$BYPASS_VLAN_V4_CIDRS" | awk '{$1=$1; gsub(/ /, ", "); print}')
        bypass_vlan_rule="            ip saddr { $bypass_vlan_nft4 } fib daddr type != local accept comment \"singctl-vlan-bypass\""
    fi

    local local_ipv6_elems="::1/128, fc00::/7, fe80::/10, ff00::/8"
    local pfx
    for pfx in $LAN_IPV6_PFXS; do
        local_ipv6_elems="$local_ipv6_elems, $pfx"
    done

    nft flush table inet sing-box 2>/dev/null || true
    nft delete table inet sing-box 2>/dev/null || true
    nft add table inet sing-box 2>/dev/null || true
    cat > /etc/sing-box/singbox.nft << EOF
    #!/usr/sbin/nft -f
    # 添加规则
    table inet sing-box {

        set LOCAL_IPV4_SET {
            type ipv4_addr
            flags interval
            auto-merge
            elements = $LOCAL_IPV4
        }

        set LOCAL_IPV6_SET {
            type ipv6_addr
            flags interval
            auto-merge
            elements = { $local_ipv6_elems }
        }

        chain prerouting {
            type filter hook prerouting priority mangle; policy accept;

            # 需要让 ExitNode 转发流量被 TProxy 劫持，因此不豁免 wg*/tailscale* 入站接口
            # iifname "wg*" counter accept
            # iifname "tailscale*" counter accept

            # 1.拒绝外部尝试直接访问本机 TProxy 端口并放行本机目标流量
            fib daddr type local meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable
            fib daddr type local accept

            # 优先承接本机 output 链 (mark 0x2 -> table 101) 回环进来的流量（含发往上级光猫/私网网关 192.168.x.1:53 的 DNS），避免命中表 100 throw 逃逸
            iifname "lo" meta mark $PROXY_LOCAL_FWMARK meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_LOCAL_FWMARK accept

            # 放行配置为「纯直连绕过代理」的隔离 VLAN 子网（目标为路由器本机服务时已在上方 fib daddr type local 放行）
${bypass_vlan_rule}

            # 先豁免回环与 Tailscale MagicDNS，防止内网域名解析受影响
            ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
            ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept

            # 放行所有经过 DNAT 的流量（端口转发流量）
            ct status dnat accept comment "Allow forwarded traffic"

            # 2.劫持 DNS 请求到 sing-box（置于局域网网段放行之前，堵死上级光猫 192.168.x.1:53 / fe80::1:53 明文漏网）
            meta l4proto { tcp, udp } th dport 53 tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK accept comment "DNS透明代理"

            # 放行其余局域网、组播与广播流量
            ip daddr @LOCAL_IPV4_SET accept
            ip6 daddr @LOCAL_IPV6_SET accept

            # 3.将其他流量标记并转发到 TProxy
            meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK accept
        }

        chain output {
            type route hook output priority mangle; policy accept;

            # 1.放行 sing-box 自身出站 (default_mark=0x1) 与已重路由标记流量，防止回环自锁
            meta mark 0x1 accept
            meta mark $PROXY_LOCAL_FWMARK accept

            # 放行 Tailscale 进程自身发出的流量
            meta mark 0x80000 accept comment "Bypass Tailscale fwmark"
            udp sport 41641 accept comment "Bypass Tailscale UDP port"
            oifname "tailscale*" accept comment "Bypass outbound traffic to tailscale interface"

            # 放行本地 AdGuard Home / SmartDNS 加密上游 (DoH/DoT) 直连流量，防止冷启动或全局模式下产生解析死锁
            ip daddr { $bypass_dns_nft4 } tcp dport { 443, 853 } accept comment "Bypass local encrypted DNS upstreams"
            ip6 daddr { $bypass_dns_nft6 } tcp dport { 443, 853 } accept comment "Bypass local IPv6 encrypted DNS upstreams"

            # 2.放行 IPv6 ICMP 基础流量
            meta l4proto ipv6-icmp accept comment "Allow ICMPv6 traffic"

            # 3.先豁免回环与 Tailscale CGNAT/MagicDNS，再以独立标记 0x2 (走纯 local 表 101) 拦截发往外部/上级光猫的 53 端口明文 DNS
            ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
            ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept
            meta l4proto { tcp, udp } th dport 53 meta mark set $PROXY_LOCAL_FWMARK accept

            # 4.放行其余局域网流量
            ip daddr @LOCAL_IPV4_SET accept
            ip6 daddr @LOCAL_IPV6_SET accept

            # 5.标记其余本机出站流量 (走表 101 回环至 TProxy)
            meta l4proto { tcp, udp } meta mark set $PROXY_LOCAL_FWMARK accept
        }
    }
EOF

    chmod 644 /etc/sing-box/singbox.nft
    if ! nft -f /etc/sing-box/singbox.nft; then
        error_exit "应用 nftables 防火墙规则失败"
    fi
}

fw_stop_cleanup() {
    echo_succ "清理 nftables 规则..."
    rm -f /etc/sing-box/singbox.nft 2>/dev/null && echo_succ "已删除防火墙规则文件" || true
    if nft delete table inet sing-box 2>/dev/null; then
        echo_succ "已删除 sing-box 表"
    fi
}
