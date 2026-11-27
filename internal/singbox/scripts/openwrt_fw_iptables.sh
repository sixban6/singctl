# 模块职责：OpenWrt iptables + ip6tables 透明代理防火墙后端策略（独立隔离链 SING_BOX / SING_BOX_OUTPUT，严禁暴力清空宿主链），实现 fw_check_deps / fw_cleanup_pre / fw_apply / fw_stop_cleanup 契约。

fw_check_deps() {
    check_command "iptables"
}

# 仅安全摘除自定义跳转并清理自身隔离链（绝不清空宿主 PREROUTING / OUTPUT 链）
iptables_cleanup_family() {
    local ipt="$1"
    command -v "$ipt" >/dev/null 2>&1 || return 0

    local n=0
    while [ $n -lt 16 ]; do
        "$ipt" -t mangle -D PREROUTING -j SING_BOX 2>/dev/null || break
        n=$((n + 1))
    done

    n=0
    while [ $n -lt 16 ]; do
        "$ipt" -t mangle -D OUTPUT -j SING_BOX_OUTPUT 2>/dev/null || break
        n=$((n + 1))
    done

    "$ipt" -t mangle -F SING_BOX 2>/dev/null || true
    "$ipt" -t mangle -X SING_BOX 2>/dev/null || true
    "$ipt" -t mangle -F SING_BOX_OUTPUT 2>/dev/null || true
    "$ipt" -t mangle -X SING_BOX_OUTPUT 2>/dev/null || true
}

# 探测指定协议族是否同时具备 userspace 与内核 xt_addrtype (--dst-type LOCAL) 能力
iptables_supports_addrtype() {
    local ipt="$1"
    "$ipt" -t mangle -m addrtype --help >/dev/null 2>&1 || return 1
    "$ipt" -t mangle -F SING_BOX_PROBE 2>/dev/null || true
    "$ipt" -t mangle -X SING_BOX_PROBE 2>/dev/null || true
    "$ipt" -t mangle -N SING_BOX_PROBE 2>/dev/null || return 1
    local ok=1
    if "$ipt" -t mangle -A SING_BOX_PROBE -m addrtype --dst-type LOCAL -j RETURN 2>/dev/null; then
        ok=0
    fi
    "$ipt" -t mangle -F SING_BOX_PROBE 2>/dev/null || true
    "$ipt" -t mangle -X SING_BOX_PROBE 2>/dev/null || true
    return "$ok"
}

# 探测 ip6tables 是否支持 mangle 表 TPROXY 目标（部分精简固件无 IPv6 TProxy 内核模块）
ip6tables_supports_tproxy() {
    command -v ip6tables >/dev/null 2>&1 || return 1
    ip6tables -t mangle -L PREROUTING >/dev/null 2>&1 || return 1
    ip6tables -t mangle -F SING_BOX_PROBE 2>/dev/null || true
    ip6tables -t mangle -X SING_BOX_PROBE 2>/dev/null || true
    ip6tables -t mangle -N SING_BOX_PROBE 2>/dev/null || return 1
    local ok=1
    if ip6tables -t mangle -A SING_BOX_PROBE -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK" 2>/dev/null; then
        ok=0
    fi
    ip6tables -t mangle -F SING_BOX_PROBE 2>/dev/null || true
    ip6tables -t mangle -X SING_BOX_PROBE 2>/dev/null || true
    return "$ok"
}

# 拒绝外部直连本机 TProxy 端口（优先尝试 REJECT；内核 mangle 表不支持 REJECT 时自动退回 DROP）
iptables_add_local_tproxy_guard() {
    local ipt="$1"
    local chain="$2"
    shift 2
    "$ipt" -t mangle -A "$chain" "$@" -p tcp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || \
        "$ipt" -t mangle -A "$chain" "$@" -p tcp --dport "$TPROXY_PORT" -j DROP
    "$ipt" -t mangle -A "$chain" "$@" -p udp --dport "$TPROXY_PORT" -j REJECT 2>/dev/null || \
        "$ipt" -t mangle -A "$chain" "$@" -p udp --dport "$TPROXY_PORT" -j DROP
}

fw_cleanup_pre() {
    iptables_cleanup_family iptables
    iptables_cleanup_family ip6tables
}

fw_apply_ipv4() {
    echo_succ "配置 IPv4 iptables 隔离链规则..."
    iptables -t mangle -N SING_BOX || error_exit "创建 IPv4 SING_BOX 链失败"
    iptables -t mangle -N SING_BOX_OUTPUT || error_exit "创建 IPv4 SING_BOX_OUTPUT 链失败"

    # === SING_BOX (PREROUTING) ===
    # 1. 拒绝外部直接访问本机 TProxy 端口并放行本机目标流量
    if iptables_supports_addrtype iptables; then
        iptables_add_local_tproxy_guard iptables SING_BOX -m addrtype --dst-type LOCAL
        iptables -t mangle -A SING_BOX -m addrtype --dst-type LOCAL -j RETURN
    else
        echo_warn "固件缺少 xt_addrtype 模块，自动遍历本机 IPv4 接口地址配置等效防护与放行"
        local local_ip
        for local_ip in $(ip -4 addr show 2>/dev/null | awk '/inet / {split($2,a,"/"); print a[1]}'); do
            iptables_add_local_tproxy_guard iptables SING_BOX -d "$local_ip"
            iptables -t mangle -A SING_BOX -d "$local_ip" -j RETURN
        done
    fi

    # 2. 优先承接本机 OUTPUT 链 (mark 0x2 -> table 101) 回环进来的流量
    iptables -t mangle -A SING_BOX -i lo -m mark --mark "$PROXY_LOCAL_FWMARK" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_LOCAL_FWMARK" || {
        fw_cleanup_pre
        error_exit "应用 IPv4 TProxy 规则失败（请确认已安装 kmod-ipt-tproxy）"
    }
    iptables -t mangle -A SING_BOX -i lo -m mark --mark "$PROXY_LOCAL_FWMARK" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_LOCAL_FWMARK" || {
        fw_cleanup_pre
        error_exit "应用 IPv4 TProxy UDP 规则失败（请确认已安装 kmod-ipt-tproxy）"
    }

    # 2.5 放行配置为「纯直连绕过代理」的隔离 VLAN 子网（目标为本机已在第 1 步 RETURN）
    local vlan_cidr
    for vlan_cidr in $BYPASS_VLAN_V4_CIDRS; do
        iptables -t mangle -A SING_BOX -s "$vlan_cidr" -m comment --comment singctl-vlan-bypass -j RETURN 2>/dev/null || \
            iptables -t mangle -A SING_BOX -s "$vlan_cidr" -j RETURN
    done

    # 3. 放行回环与 Tailscale MagicDNS / CGNAT（注意不放行 -i tailscale+，保留 ExitNode 透明代理能力）
    iptables -t mangle -A SING_BOX -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A SING_BOX -d 100.64.0.0/10 -j RETURN

    # 4. 放行端口转发 (DNAT) 流量
    iptables -t mangle -A SING_BOX -m conntrack --ctstate DNAT -j RETURN 2>/dev/null || true

    # 5. 放行 DHCP 67:68
    iptables -t mangle -A SING_BOX -p udp --dport 67:68 -j RETURN

    # 6. 优先劫持 53 端口 TCP/UDP DNS（置于私网放行之前，堵死上级光猫明文 DNS 漏网）
    iptables -t mangle -A SING_BOX -p udp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"
    iptables -t mangle -A SING_BOX -p tcp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"

    # 7. 放行其余局域网、链路本地、组播与广播地址
    iptables -t mangle -A SING_BOX -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SING_BOX -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SING_BOX -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SING_BOX -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A SING_BOX -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A SING_BOX -d 255.255.255.255/32 -j RETURN

    # 7.5 放行下游设备（二级路由/手机/电脑/NAS）的 Tailscale UDP 41641 P2P 打洞流量
    iptables -t mangle -A SING_BOX -p udp --sport 41641 -j RETURN
    iptables -t mangle -A SING_BOX -p udp --dport 41641 -j RETURN

    # 8. 其余 TCP/UDP 全部交由 TProxy 代理
    iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"
    iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"

    # === SING_BOX_OUTPUT (OUTPUT) ===
    # 1. 放行 sing-box 自身出站、已重路由流量及 Tailscale 出站
    iptables -t mangle -A SING_BOX_OUTPUT -m mark --mark "$PROXY_FWMARK" -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -m mark --mark "$PROXY_LOCAL_FWMARK" -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -m mark --mark 0x80000 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -p udp --sport 41641 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -o tailscale+ -j RETURN

    # 2. 放行本地 AdGuard Home / SmartDNS 加密 DNS 上游 (TCP 443/853)，防止解析死锁
    local dns_ip
    for dns_ip in $BYPASS_DNS_V4_IPS; do
        iptables -t mangle -A SING_BOX_OUTPUT -d "$dns_ip" -p tcp --dport 443 -j RETURN
        iptables -t mangle -A SING_BOX_OUTPUT -d "$dns_ip" -p tcp --dport 853 -j RETURN
    done

    # 3. 先豁免回环与 Tailscale MagicDNS，再标记全部 53 端口明文 DNS 走表 101
    iptables -t mangle -A SING_BOX_OUTPUT -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -d 100.64.0.0/10 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -p udp --dport 53 -j MARK --set-mark "$PROXY_LOCAL_FWMARK"
    iptables -t mangle -A SING_BOX_OUTPUT -p tcp --dport 53 -j MARK --set-mark "$PROXY_LOCAL_FWMARK"

    # 4. 放行其余私网、链路本地、组播与广播地址
    iptables -t mangle -A SING_BOX_OUTPUT -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A SING_BOX_OUTPUT -d 255.255.255.255/32 -j RETURN

    # 5. 标记其余本机 TCP/UDP 流量进入表 101 回环至 TProxy
    iptables -t mangle -A SING_BOX_OUTPUT -p tcp -j MARK --set-mark "$PROXY_LOCAL_FWMARK"
    iptables -t mangle -A SING_BOX_OUTPUT -p udp -j MARK --set-mark "$PROXY_LOCAL_FWMARK"

    # 挂载独立隔离链到 PREROUTING 与 OUTPUT
    iptables -t mangle -A PREROUTING -j SING_BOX
    iptables -t mangle -A OUTPUT -j SING_BOX_OUTPUT
    echo_succ "IPv4 iptables 隔离链规则配置完成"
}

fw_apply_ipv6() {
    if ! ip6tables_supports_tproxy; then
        echo_warn "当前固件 ip6tables 不可用或不支持 mangle TPROXY，跳过 IPv6 规则配置"
        return 0
    fi

    echo_succ "配置 IPv6 ip6tables 隔离链规则..."
    ip6tables -t mangle -N SING_BOX 2>/dev/null || {
        echo_warn "创建 IPv6 SING_BOX 链失败，跳过 IPv6 规则配置"
        return 0
    }
    ip6tables -t mangle -N SING_BOX_OUTPUT 2>/dev/null || {
        iptables_cleanup_family ip6tables
        echo_warn "创建 IPv6 SING_BOX_OUTPUT 链失败，跳过 IPv6 规则配置"
        return 0
    }

    # === IPv6 SING_BOX (PREROUTING) ===
    # 1. 拒绝外部直连本机 TProxy 端口并放行本机目标流量
    if iptables_supports_addrtype ip6tables; then
        iptables_add_local_tproxy_guard ip6tables SING_BOX -m addrtype --dst-type LOCAL
        ip6tables -t mangle -A SING_BOX -m addrtype --dst-type LOCAL -j RETURN
    else
        local local_ip6
        for local_ip6 in $(ip -6 addr show 2>/dev/null | awk '/inet6 / {split($2,a,"/"); print a[1]}'); do
            iptables_add_local_tproxy_guard ip6tables SING_BOX -d "$local_ip6"
            ip6tables -t mangle -A SING_BOX -d "$local_ip6" -j RETURN
        done
    fi

    # 2. 优先承接 lo + mark $PROXY_LOCAL_FWMARK 回环流量
    ip6tables -t mangle -A SING_BOX -i lo -m mark --mark "$PROXY_LOCAL_FWMARK" -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_LOCAL_FWMARK"
    ip6tables -t mangle -A SING_BOX -i lo -m mark --mark "$PROXY_LOCAL_FWMARK" -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_LOCAL_FWMARK"

    # 3. 放行回环、Tailscale IPv6 与 DNAT 转发流量
    ip6tables -t mangle -A SING_BOX -d ::1/128 -j RETURN
    ip6tables -t mangle -A SING_BOX -d fd7a:115c:a1e0::/48 -j RETURN
    ip6tables -t mangle -A SING_BOX -m conntrack --ctstate DNAT -j RETURN 2>/dev/null || true

    # 4. 优先劫持 IPv6 53 端口 TCP/UDP DNS
    ip6tables -t mangle -A SING_BOX -p udp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"
    ip6tables -t mangle -A SING_BOX -p tcp --dport 53 -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"

    # 5. 放行 ULA、链路本地、组播与动态采集的局域网全局 IPv6 前缀
    ip6tables -t mangle -A SING_BOX -d fc00::/7 -j RETURN
    ip6tables -t mangle -A SING_BOX -d fe80::/10 -j RETURN
    ip6tables -t mangle -A SING_BOX -d ff00::/8 -j RETURN
    local pfx
    for pfx in $LAN_IPV6_PFXS; do
        ip6tables -t mangle -A SING_BOX -d "$pfx" -j RETURN
    done

    # 5.5 放行下游设备的 IPv6 Tailscale UDP 41641 P2P 打洞流量
    ip6tables -t mangle -A SING_BOX -p udp --sport 41641 -j RETURN
    ip6tables -t mangle -A SING_BOX -p udp --dport 41641 -j RETURN

    # 6. 其余 IPv6 TCP/UDP 全部走 TProxy
    ip6tables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"
    ip6tables -t mangle -A SING_BOX -p udp -j TPROXY --on-port "$TPROXY_PORT" --tproxy-mark "$PROXY_FWMARK"

    # === IPv6 SING_BOX_OUTPUT (OUTPUT) ===
    # 1. 放行已标记流量、Tailscale 与 ICMPv6
    ip6tables -t mangle -A SING_BOX_OUTPUT -m mark --mark "$PROXY_FWMARK" -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -m mark --mark "$PROXY_LOCAL_FWMARK" -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -m mark --mark 0x80000 -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -p udp --sport 41641 -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -o tailscale+ -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -p icmpv6 -j RETURN

    # 2. 放行本地 IPv6 加密 DNS 上游 (TCP 443/853)
    local dns_v6
    for dns_v6 in $BYPASS_DNS_V6_IPS; do
        ip6tables -t mangle -A SING_BOX_OUTPUT -d "$dns_v6" -p tcp --dport 443 -j RETURN
        ip6tables -t mangle -A SING_BOX_OUTPUT -d "$dns_v6" -p tcp --dport 853 -j RETURN
    done

    # 3. 放行回环与 Tailscale IPv6，标记全部 IPv6 53 端口 DNS
    ip6tables -t mangle -A SING_BOX_OUTPUT -d ::1/128 -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -d fd7a:115c:a1e0::/48 -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -p udp --dport 53 -j MARK --set-mark "$PROXY_LOCAL_FWMARK"
    ip6tables -t mangle -A SING_BOX_OUTPUT -p tcp --dport 53 -j MARK --set-mark "$PROXY_LOCAL_FWMARK"

    # 4. 放行 ULA、链路本地、组播与局域网 IPv6 前缀
    ip6tables -t mangle -A SING_BOX_OUTPUT -d fc00::/7 -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -d fe80::/10 -j RETURN
    ip6tables -t mangle -A SING_BOX_OUTPUT -d ff00::/8 -j RETURN
    for pfx in $LAN_IPV6_PFXS; do
        ip6tables -t mangle -A SING_BOX_OUTPUT -d "$pfx" -j RETURN
    done

    # 5. 标记其余本机 IPv6 TCP/UDP 流量
    ip6tables -t mangle -A SING_BOX_OUTPUT -p tcp -j MARK --set-mark "$PROXY_LOCAL_FWMARK"
    ip6tables -t mangle -A SING_BOX_OUTPUT -p udp -j MARK --set-mark "$PROXY_LOCAL_FWMARK"

    ip6tables -t mangle -A PREROUTING -j SING_BOX
    ip6tables -t mangle -A OUTPUT -j SING_BOX_OUTPUT
    echo_succ "IPv6 ip6tables 隔离链规则配置完成"
}

fw_apply() {
    collect_bypass_dns_ips
    collect_vlan_proxy_bypass_cidrs
    collect_lan_ipv6_prefixes
    fw_cleanup_pre
    fw_apply_ipv4
    fw_apply_ipv6
}

fw_stop_cleanup() {
    echo_succ "清理 iptables / ip6tables 隔离链规则..."
    iptables_cleanup_family iptables
    iptables_cleanup_family ip6tables
    echo_succ "已安全清理 SING_BOX 与 SING_BOX_OUTPUT 隔离链"
}
