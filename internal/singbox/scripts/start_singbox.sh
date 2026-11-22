#!/bin/sh

#################################################
# 描述: OpenWrt sing-box TProxy模式 配置脚本
# 用途: 配置和启动 sing-box TProxy模式 代理服务
#################################################

# 确保能找到 sing-box 命令
export PATH="/usr/local/bin:/usr/bin:$PATH"
TPROXY_PORT=7895  # sing-box tproxy 端口，和配置文件（规则模板）里的端口一致！
PROXY_FWMARK=1
PROXY_ROUTE_TABLE=100
PROXY_LOCAL_FWMARK=2
PROXY_LOCAL_ROUTE_TABLE=101
MAX_RETRIES=3  # 最大重试次数
RETRY_DELAY=3  # 重试间隔时间（秒）
CONFIG_FILE="/etc/sing-box/config.json"
CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'
OPENWRT_MAIN_VERSION=$(sed -n 's/VERSION="\([0-9]*\).*/\1/p' /etc/os-release 2>/dev/null)
if [ -z "$OPENWRT_MAIN_VERSION" ]; then
    if command -v nft >/dev/null 2>&1; then
        OPENWRT_MAIN_VERSION=23
    else
        OPENWRT_MAIN_VERSION=22
    fi
fi
LOCAL_IPV4='{127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32, 100.64.0.0/10}'
# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# 错误处理函数
error_exit() {
    echo -e "${RED}错误: $1 ${NC}"
    exit 1
}

echo_succ() {
    echo -e "${CYAN}$(timestamp) $1${NC}"
}

echo_warn() {
    echo -e "${YLW}$(timestamp) $1${NC}"
}

echo_err() {
    echo -e "${RED}$(timestamp) $1${NC}"
}

# 检查命令是否存在
check_command() {
    local cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "$cmd 未安装，请安装后再运行此脚本"
    fi
}

# 检查网络连接（使用国内公共 DNS 快速探测，超时 2 秒；禁 Ping 环境仅告警不阻断启动）
check_network() {
    echo_succ "检查网络连接..."
    if ! ping -c 1 -W 2 223.5.5.5 >/dev/null 2>&1 && ! ping -c 1 -W 2 119.29.29.29 >/dev/null 2>&1; then
        echo_warn "ICMP 探测未响应（可能处于禁 Ping 网络），继续启动流程..."
    fi
}

# 探测本地 TCP/UDP 端口是否处于监听状态（依次兼容 netstat / ss / 内核 /proc/net 套接字表，适配无 netstat 的精简固件）
is_port_listening() {
    local port=$1
    if command -v netstat >/dev/null 2>&1; then
        netstat -tuln 2>/dev/null | grep -Eq ":${port}([[:space:]]|\$)" && return 0
    fi
    if command -v ss >/dev/null 2>&1; then
        ss -tuln 2>/dev/null | grep -Eq ":${port}([[:space:]]|\$)" && return 0
    fi
    local port_hex
    port_hex=$(printf '%04X' "$port" 2>/dev/null || echo "")
    if [ -n "$port_hex" ] && [ -r /proc/net/tcp ]; then
        awk -v p=":$port_hex" '
            FNR > 1 && toupper($2) ~ p"$" && $3 ~ /^0+:0+$/ { found = 1; exit }
            END { exit !found }
        ' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null && return 0
    fi
    return 1
}

# 检查端口占用（停止残留 sing-box 后若仍被其他进程如 OpenClash 占用则及时报错触发回滚）
check_port() {
    local port=$1
    if is_port_listening "$port"; then
        echo_warn "端口 $port 已被占用，正在清理残留 sing-box..."
        killall -9 sing-box 2>/dev/null || true
        sleep 1
        if is_port_listening "$port"; then
            error_exit "端口 $port 仍被其他进程占用，请先停止占用该端口的代理服务（如 OpenClash/PassWall）"
        fi
    fi
}

init_env() {
    # 若存在 procd 托管的 /etc/init.d/sing-box，先通知 procd 停止，防止其 respawn 抢占端口
    if [ -x /etc/init.d/sing-box ]; then
        /etc/init.d/sing-box stop >/dev/null 2>&1 || true
    fi

    # 停止 sing-box 服务
    if killall sing-box 2>/dev/null; then
        pkill -f "ujail.*sing-box" 2>/dev/null || true
        echo_succ "已停止现有 sing-box 服务"
    else
        pkill -f "ujail.*sing-box" 2>/dev/null || true
        echo_succ "没有运行中的 sing-box 服务"
    fi

    # 根据版本检查并清理防火墙规则
    if [ $OPENWRT_MAIN_VERSION -ge 23 ]; then
        # OpenWrt 23+ 使用 nftables
        if nft list tables 2>/dev/null | grep -q 'inet sing-box'; then
            nft delete table inet sing-box
        fi
    else
        # OpenWrt 22 及以下使用 iptables
        # 清理可能存在的 iptables 规则
        iptables -t mangle -F SING_BOX 2>/dev/null || true
        iptables -t mangle -X SING_BOX 2>/dev/null || true
    fi

    # 检查是否以 root 权限运行
    if [ "$(id -u)" != "0" ]; then
        error_exit "此脚本需要 root 权限运行"
    fi

    # 检查必要命令是否安装
    check_command "sing-box"
    
    # 根据版本检查防火墙工具
    if [ $OPENWRT_MAIN_VERSION -ge 23 ]; then
        check_command "nft"
    else
        check_command "iptables"
    fi
    
    check_command "ip"
    check_command "ping"

    # 检查网络和端口
    check_network
    check_port "$TPROXY_PORT"

    # 创建配置目录
    if [ ! -f /etc/sing-box ]
    then
      mkdir -p /etc/sing-box
    fi

    # 验证配置
    if ! sing-box check -c "$CONFIG_FILE"; then
        echo_succ "配置文件验证失败"
        error_exit "配置验证失败"
    fi
}

setup_nft() {
    # 创建防火墙规则文件
    echo_succ "创建防火墙规则文件..."
    AGH_BYPASS_IPS="223.5.5.5 223.6.6.6 1.12.12.12 120.53.53.53"
    if [ -f /etc/AdGuardHome/AdGuardHome.yaml ]; then
        EXTRA_AGH_IPS=$(sed -n 's#.*\(https\|tls\)://\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\).*#\2#p' /etc/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true)
        for extra_ip in $EXTRA_AGH_IPS; do
            case " $AGH_BYPASS_IPS " in
                *" $extra_ip "*) ;;
                *) AGH_BYPASS_IPS="$AGH_BYPASS_IPS $extra_ip" ;;
            esac
        done
    fi
    AGH_BYPASS_NFT=$(echo "$AGH_BYPASS_IPS" | sed 's/ /, /g')
    AGH_BYPASS_V6_IPS="2400:3200::1 2400:3200:baba::1"
    if [ -f /etc/AdGuardHome/AdGuardHome.yaml ]; then
        EXTRA_AGH_V6=$(sed -n 's#.*\(https\|tls\)://\[\([0-9a-fA-F:]\{2,\}\)\].*#\2#p' /etc/AdGuardHome/AdGuardHome.yaml 2>/dev/null || true)
        for extra_v6 in $EXTRA_AGH_V6; do
            case " $AGH_BYPASS_V6_IPS " in
                *" $extra_v6 "*) ;;
                *) AGH_BYPASS_V6_IPS="$AGH_BYPASS_V6_IPS $extra_v6" ;;
            esac
        done
    fi
    AGH_BYPASS_NFT6=$(echo "$AGH_BYPASS_V6_IPS" | sed 's/ /, /g')

    LAN_IPV6_PFXS=""
    for lan_if in br-lan eth0; do
        if ip link show "$lan_if" >/dev/null 2>&1; then
            for pfx in $(ip -6 route show dev "$lan_if" proto kernel scope global 2>/dev/null | awk '$1 ~ /:/ && $1 !~ /^f[cd]/ {print $1}'); do
                case " $LAN_IPV6_PFXS " in
                    *" $pfx "*) ;;
                    *) LAN_IPV6_PFXS="$LAN_IPV6_PFXS $pfx" ;;
                esac
            done
        fi
    done
    LOCAL_IPV6_ELEMS="::1/128, fc00::/7, fe80::/10, ff00::/8"
    for pfx in $LAN_IPV6_PFXS; do
        LOCAL_IPV6_ELEMS="$LOCAL_IPV6_ELEMS, $pfx"
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
            elements = { $LOCAL_IPV6_ELEMS }
        }

        chain prerouting {
            type filter hook prerouting priority mangle; policy accept;

            # 需要让ExitNode转发流量被 TProxy 劫持,所以得注释掉
            # iifname "wg*" counter accept
            # iifname "tailscale*" counter accept

            # 1.主要为了拒绝 外部尝试访问公网端口.
            fib daddr type local meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable
            #
            fib daddr type local accept

            # 优先承接本机 output 链 (mark 0x2 -> table 101) 回环进来的流量（含发往上级光猫/私网网关 192.168.x.1:53 的 DNS），避免命中表 100 throw 逃逸
            iifname "lo" meta mark $PROXY_LOCAL_FWMARK meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_LOCAL_FWMARK accept

            # 先豁免回环与 Tailscale MagicDNS，防止内网域名解析受影响
            ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
            ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept

            # 放行所有经过 DNAT 的流量.即端口转发流量
            ct status dnat accept comment "Allow forwarded traffic"

            # 2.劫持dns请求到sing-box（置于局域网网段放行之前，堵死上级光猫 192.168.x.1:53 / fe80::1:53 明文漏网）
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

            # 放行本地 AdGuard Home 加密上游 (DoH/DoT) 直连流量，防止冷启动或 Global 全局模式下产生解析死锁
            ip daddr { $AGH_BYPASS_NFT } tcp dport { 443, 853 } accept comment "Bypass AdGuard Home encrypted DNS upstreams"
            ip6 daddr { $AGH_BYPASS_NFT6 } tcp dport { 443, 853 } accept comment "Bypass AdGuard Home IPv6 encrypted DNS upstreams"

            # 2.放行ipv6的icmp基础流量
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

    # 设置权限
    chmod 644 /etc/sing-box/singbox.nft
    # 应用防火墙规则
    if ! nft -f /etc/sing-box/singbox.nft; then
        error_exit "应用防火墙规则失败"
    fi
}

setup_iptables() {
    echo_succ "配置 iptables 规则 (OpenWrt 22 及以下版本)..."
    
    # 清除现有的 iptables 规则
    echo_succ "清除现有的 iptables 规则..."
    iptables -t mangle -F PREROUTING 2>/dev/null || true
    iptables -t mangle -F OUTPUT 2>/dev/null || true
    iptables -t mangle -F SING_BOX 2>/dev/null || true
    iptables -t mangle -X SING_BOX 2>/dev/null || true
    
    # 创建新的 iptables 链
    echo_succ "创建 SING_BOX 链..."
    iptables -t mangle -N SING_BOX
    
    # 优先承接本机 OUTPUT 链 (mark 0x2 -> table 101) 回环进来的流量
    iptables -t mangle -A SING_BOX -i lo -m mark --mark $PROXY_LOCAL_FWMARK -p tcp -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A SING_BOX -i lo -m mark --mark $PROXY_LOCAL_FWMARK -p udp -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $PROXY_LOCAL_FWMARK

    # 放行局域网地址 (包含 Tailscale CGNAT 流量及 MagicDNS 流量)
    echo_succ "配置局域网地址放行规则..."
    iptables -t mangle -A SING_BOX -i tailscale+ -j RETURN
    iptables -t mangle -A SING_BOX -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A SING_BOX -d 100.64.0.0/10 -j RETURN     # Tailscale CGNAT

    # 放行 DHCP (67-68端口) 并优先劫持外部/光猫 53 端口 DNS
    iptables -t mangle -A SING_BOX -p udp --dport 67:68 -j RETURN
    iptables -t mangle -A SING_BOX -p udp --dport 53 -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $PROXY_FWMARK
    iptables -t mangle -A SING_BOX -p tcp --dport 53 -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $PROXY_FWMARK

    iptables -t mangle -A SING_BOX -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SING_BOX -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SING_BOX -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SING_BOX -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A SING_BOX -d 224.0.0.0/4 -j RETURN       # 组播地址
    iptables -t mangle -A SING_BOX -d 255.255.255.255/32 -j RETURN # 广播地址

    # 代理其余 TCP 和 UDP 流量
    echo_succ "配置 TProxy 代理规则..."
    iptables -t mangle -A SING_BOX -p tcp -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $PROXY_FWMARK
    iptables -t mangle -A SING_BOX -p udp -j TPROXY --on-port $TPROXY_PORT --tproxy-mark $PROXY_FWMARK
    
    # 将 SING_BOX 链添加到 PREROUTING 链
    echo_succ "将规则应用到 PREROUTING 链..."
    iptables -t mangle -A PREROUTING -j SING_BOX
    
    # 配置 OUTPUT 链规则（用于路由器本机流量）
    echo_succ "配置 OUTPUT 链规则..."
    # 放行已标记的流量，防止回环
    iptables -t mangle -A OUTPUT -m mark --mark $PROXY_FWMARK -j RETURN
    iptables -t mangle -A OUTPUT -m mark --mark $PROXY_LOCAL_FWMARK -j RETURN

    # 放行 Tailscale 自身发出的流量
    iptables -t mangle -A OUTPUT -m mark --mark 0x80000 -j RETURN
    iptables -t mangle -A OUTPUT -p udp --sport 41641 -j RETURN
    iptables -t mangle -A OUTPUT -o tailscale+ -j RETURN

    # 放行本地 AdGuard Home 加密上游 (DoH/DoT) 直连流量，防止回环死锁
    for agh_ip in 223.5.5.5 223.6.6.6 1.12.12.12 120.53.53.53; do
        iptables -t mangle -A OUTPUT -d "$agh_ip" -p tcp --dport 443 -j RETURN
        iptables -t mangle -A OUTPUT -d "$agh_ip" -p tcp --dport 853 -j RETURN
    done
    
    # 先豁免回环与 Tailscale MagicDNS，再拦截所有 53 端口明文 DNS (含上级光猫私网 DNS)
    iptables -t mangle -A OUTPUT -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A OUTPUT -d 100.64.0.0/10 -j RETURN
    iptables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A OUTPUT -p tcp --dport 53 -j MARK --set-mark $PROXY_LOCAL_FWMARK

    # 放行其余局域网地址
    iptables -t mangle -A OUTPUT -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A OUTPUT -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A OUTPUT -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A OUTPUT -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A OUTPUT -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A OUTPUT -d 255.255.255.255/32 -j RETURN
    
    # 标记其他 TCP 和 UDP 流量
    iptables -t mangle -A OUTPUT -p tcp -j MARK --set-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A OUTPUT -p udp -j MARK --set-mark $PROXY_LOCAL_FWMARK
    
    echo_succ "iptables 规则配置完成"
}

setup_firewall() {
    if [ $OPENWRT_MAIN_VERSION -ge 23 ]
    then
        setup_nft
    else
        setup_iptables
    fi
}

flush_ip_rules_for_table() {
    local family="$1"
    local tbl="$2"
    local n=0
    while [ $n -lt 16 ]; do
        if [ "$family" = "-6" ]; then
            ip -6 rule del table "$tbl" >/dev/null 2>&1 || break
        else
            ip rule del table "$tbl" >/dev/null 2>&1 || break
        fi
        n=$((n + 1))
    done
}

setup_route() {
    echo_succ "初始化IPV4路由"
    # 配置外部转发流量策略路由表 100 (fwmark 0x1, 带私网/CGNAT throw 逃生路由兼容 src_valid_mark=1)
    flush_ip_rules_for_table -4 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -4 "$PROXY_LOCAL_ROUTE_TABLE"
    ip rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE
    ip rule add fwmark $PROXY_LOCAL_FWMARK table $PROXY_LOCAL_ROUTE_TABLE

    # 清理并添加表 100 路由
    ip route flush table $PROXY_ROUTE_TABLE >/dev/null 2>&1
    ip route add local default dev lo table $PROXY_ROUTE_TABLE

    # 逃生路由：当宿主启用 net.ipv4.conf.all.src_valid_mark=1（如 Tailscale/WireGuard 策略路由）时，
    # 内核 fib_validate_source() 会带 fwmark 查表 100；必须对内网/CGNAT 网段配置 throw 穿透回 main/table 52，
    # 否则即使 rp_filter=0，所有局域网设备报文也会因源 IP 命中 local default dev lo 被判定为 martian source 静默丢弃。
    for throw_cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16; do
        ip route replace throw "$throw_cidr" table $PROXY_ROUTE_TABLE >/dev/null 2>&1 || \
            ip route add throw "$throw_cidr" table $PROXY_ROUTE_TABLE >/dev/null 2>&1 || true
    done

    # 配置本机出站重路由表 101 (fwmark 0x2, 纯 local default dev lo 不含 throw，确保主路由发往光猫 192.168.x.1:53 等私网 DNS 绝不逃逸)
    ip route flush table $PROXY_LOCAL_ROUTE_TABLE >/dev/null 2>&1
    ip route add local default dev lo table $PROXY_LOCAL_ROUTE_TABLE

    echo_succ "初始化IPV6路由"
    # 配置 IPv6 路由规则
    flush_ip_rules_for_table -6 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -6 "$PROXY_LOCAL_ROUTE_TABLE"
    ip -6 rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 rule add fwmark $PROXY_LOCAL_FWMARK table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true

    # 清理并添加 IPv6 路由（同步注入内网与 Tailscale throw 逃生路由）
    ip -6 route flush table $PROXY_ROUTE_TABLE >/dev/null 2>&1
    ip -6 route replace local default dev lo table $PROXY_ROUTE_TABLE 2>/dev/null || true
    for throw_v6 in ::1/128 fc00::/7 fe80::/10 fd7a:115c:a1e0::/48 $LAN_IPV6_PFXS; do
        ip -6 route replace throw "$throw_v6" table $PROXY_ROUTE_TABLE >/dev/null 2>&1 || true
    done
    ip -6 route flush table $PROXY_LOCAL_ROUTE_TABLE >/dev/null 2>&1
    ip -6 route replace local default dev lo table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
}

wait_tproxy_ready() {
    local i=0
    while [ $i -lt 10 ]; do
        if pgrep "sing-box" >/dev/null 2>&1 && is_port_listening "$TPROXY_PORT"; then
            return 0
        fi
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# 根据宿主机 /proc/meminfo 自适应注入 Go 软内存上限 (GOMEMLIMIT / GOGC) 与低内存日志限流标记
setup_singbox_mem_env() {
    local mem_total_kb=0
    if [ -r /proc/meminfo ]; then
        mem_total_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)
    fi
    case "$mem_total_kb" in
        ''|*[!0-9]*) mem_total_kb=0 ;;
    esac
    if [ "${SINGCTL_LOW_MEMORY:-}" != "0" ]; then
        if [ -z "${GOMEMLIMIT:-}" ] && [ "$mem_total_kb" -gt 0 ]; then
            if [ "$mem_total_kb" -le 294912 ]; then
                GOMEMLIMIT="40MiB"
                [ -z "${GOGC:-}" ] && GOGC="50"
            elif [ "$mem_total_kb" -le 524288 ]; then
                GOMEMLIMIT="44MiB"
                [ -z "${GOGC:-}" ] && GOGC="50"
            fi
        fi
        if [ -z "${SINGCTL_LOW_MEMORY:-}" ]; then
            if [ "$mem_total_kb" -gt 0 ] && [ "$mem_total_kb" -le 524288 ]; then
                SINGCTL_LOW_MEMORY=1
            else
                SINGCTL_LOW_MEMORY=0
            fi
        fi
    fi
    [ -n "${GOMEMLIMIT:-}" ] && export GOMEMLIMIT
    [ -n "${GOGC:-}" ] && export GOGC
}

# 低内存模式下将 tmpfs 沙盒日志原地截断限制在 256 KiB (262144 字节) 以内，防止吃光内存盘
cap_singbox_log_256k() {
    local log_file="$1"
    [ "${SINGCTL_LOW_MEMORY:-0}" = "1" ] || return 0
    [ -f "$log_file" ] || return 0
    local sz
    sz=$(wc -c < "$log_file" 2>/dev/null || echo 0)
    case "$sz" in
        ''|*[!0-9]*) sz=0 ;;
    esac
    if [ "$sz" -gt 262144 ]; then
        local cap_tmp="${log_file}.cap.$$"
        tail -c 262144 "$log_file" > "$cap_tmp" 2>/dev/null && cat "$cap_tmp" > "$log_file" 2>/dev/null
        rm -f "$cap_tmp" 2>/dev/null || true
    fi
    chmod 0600 "$log_file" 2>/dev/null || true
}

start_singbox() {
    setup_singbox_mem_env
    if [ -n "${GOMEMLIMIT:-}" ]; then
        echo_succ "已启用低内存自适应护栏: GOMEMLIMIT=${GOMEMLIMIT} GOGC=${GOGC:-100}"
    fi

    # 检查ujail是否可用
    if ! command -v ujail >/dev/null 2>&1; then
        sing-box run -c "/etc/sing-box/config.json" >/dev/null 2>&1 &
        if wait_tproxy_ready; then
           echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
        else
           error_exit "sing-box 启动失败或未监听 TProxy 端口 :$TPROXY_PORT，请检查日志"
        fi
        return
    fi

    echo_succ "启动 sing-box 服务(沙盒模式)..."
    
    # 准备沙盒环境和配置
    echo_succ "准备沙盒环境..."
    mkdir -p /tmp/sing-box-work
    
    # 创建沙盒专用配置，修改状态缓存路径到可写 tmpfs 目录并清理历史外置 UI 残留
    rm -rf /tmp/sing-box-work/ui /tmp/sing-box-work/dashboard 2>/dev/null || true
    if [ -f "/etc/sing-box/config.json" ]; then
        sed 's|"/etc/sing-box/cache.db"|"/tmp/sing-box-work/cache.db"|g' \
            /etc/sing-box/config.json > /tmp/sing-box-work/config.json
        chmod 0600 /tmp/sing-box-work/config.json 2>/dev/null || true
    else
        echo_warn "配置文件不存在，使用原路径"
        cp /etc/sing-box/config.json /tmp/sing-box-work/config.json 2>/dev/null || true
        chmod 0600 /tmp/sing-box-work/config.json 2>/dev/null || true
    fi
    
    # 找到sing-box的绝对路径
    SINGBOX_EXEC=""
    if [ -f "/usr/bin/sing-box" ]; then
        SINGBOX_EXEC="/usr/bin/sing-box"
    elif [ -f "/usr/local/bin/sing-box" ]; then
        SINGBOX_EXEC="/usr/local/bin/sing-box"
    else
        SINGBOX_EXEC=$(which sing-box 2>/dev/null || echo "")
    fi
    
    if [ -z "$SINGBOX_EXEC" ] || [ ! -f "$SINGBOX_EXEC" ]; then
        echo_warn "找不到sing-box可执行文件，跳过沙盒模式"
        # 使用普通模式启动
        sing-box run -c "/etc/sing-box/config.json" >/dev/null 2>&1 &
        if wait_tproxy_ready; then
           echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
        else
           error_exit "sing-box 启动失败或未监听 TProxy 端口 :$TPROXY_PORT，请检查配置和日志"
        fi
        return
    fi
    
    echo_succ "发现 sing-box 路径: $SINGBOX_EXEC"
    
    # 先测试最基本的ujail功能 - 使用namespace选项避免段错误
    echo_succ "测试ujail基础功能..."
    if ! ujail -n test-basic -w /tmp -- /bin/echo "test" >/tmp/ujail-test.log 2>&1; then
        echo_warn "ujail基础功能异常，查看 /tmp/ujail-test.log"
        echo_warn "跳过沙盒模式，使用普通模式启动..."
        sing-box run -c "/etc/sing-box/config.json" >/dev/null 2>&1 &
        if wait_tproxy_ready; then
           echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
        else
           error_exit "sing-box 启动失败或未监听 TProxy 端口 :$TPROXY_PORT，请检查配置和日志"
        fi
        return
    fi
    
    # 尝试最简单的沙盒模式 - 添加必要的证书和配置访问
    echo_succ "尝试基础沙盒模式(证书+配置访问)..."
    if [ "${SINGCTL_LOW_MEMORY:-0}" = "1" ] && [ -f /tmp/sing-box-basic.log ]; then
        cap_singbox_log_256k /tmp/sing-box-basic.log
    else
        : > /tmp/sing-box-basic.log && chmod 0600 /tmp/sing-box-basic.log
    fi
    UJAIL_HAS_ENV=0
    if [ -n "${GOMEMLIMIT:-}" ] || [ -n "${GOGC:-}" ]; then
        if ujail -n test-env -w /tmp -e PATH -- /bin/echo "ok" >/dev/null 2>&1; then
            UJAIL_HAS_ENV=1
        fi
    fi
    set -- -n sing-box -w /tmp
    if [ "$UJAIL_HAS_ENV" = "1" ]; then
        [ -n "${GOMEMLIMIT:-}" ] && set -- "$@" -e GOMEMLIMIT
        [ -n "${GOGC:-}" ] && set -- "$@" -e GOGC
    fi
    for ro_path in /etc/ssl /etc/sing-box /usr/share/ca-certificates /etc/hosts /etc/resolv.conf /proc; do
        if [ -e "$ro_path" ]; then
            set -- "$@" -r "$ro_path"
        fi
    done
    ujail "$@" -- "$SINGBOX_EXEC" run -c /tmp/sing-box-work/config.json >>/tmp/sing-box-basic.log 2>&1 &
    UJAIL_PID=$!
    
    if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null && wait_tproxy_ready; then
       cap_singbox_log_256k /tmp/sing-box-basic.log
       echo_succ "sing-box 启动成功 运行模式--TProxy(基础沙盒)"
       echo_succ "沙盒特性: 进程隔离 + 临时目录访问"
       return
    fi
    
    # 基础沙盒失败，尝试最简沙盒（仍保留 /tmp 可写与 TLS 证书只读挂载，防止 cache.db 与 DoH 失败）
    echo_warn "基础沙盒失败，尝试最简沙盒..."
    kill $UJAIL_PID 2>/dev/null || true
    pkill -f "ujail.*sing-box" 2>/dev/null || true
    
    : > /tmp/sing-box-simple.log && chmod 0600 /tmp/sing-box-simple.log
    set -- -n sing-box -p -w /tmp -r /etc/sing-box
    if [ "$UJAIL_HAS_ENV" = "1" ]; then
        [ -n "${GOMEMLIMIT:-}" ] && set -- "$@" -e GOMEMLIMIT
        [ -n "${GOGC:-}" ] && set -- "$@" -e GOGC
    fi
    [ -e /etc/ssl ] && set -- "$@" -r /etc/ssl
    [ -e /etc/resolv.conf ] && set -- "$@" -r /etc/resolv.conf
    ujail "$@" -- "$SINGBOX_EXEC" run -c /tmp/sing-box-work/config.json >>/tmp/sing-box-simple.log 2>&1 &
    UJAIL_PID=$!
    
    if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null && wait_tproxy_ready; then
       cap_singbox_log_256k /tmp/sing-box-simple.log
       echo_succ "sing-box 启动成功 运行模式--TProxy(最简沙盒)"
       echo_succ "沙盒特性: 基础进程隔离"
       return
    fi
    
    # 所有沙盒模式失败，回退到普通模式
    echo_warn "所有沙盒模式失败，回退到普通模式..."
    echo_warn "查看日志: /tmp/ujail-test.log, /tmp/sing-box-basic.log 和 /tmp/sing-box-simple.log"
    kill $UJAIL_PID 2>/dev/null || true
    pkill -f "ujail.*sing-box" 2>/dev/null || true
    
    # 使用普通模式启动
    sing-box run -c "/etc/sing-box/config.json" >/dev/null 2>&1 &
    if wait_tproxy_ready; then
       echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
    else
       error_exit "sing-box 启动失败或未监听 TProxy 端口 :$TPROXY_PORT，请检查配置和日志"
    fi
}

check_page_connect() {
    local url="$1"
    local timeout="${2:-5}"  # 默认超时时间为5秒
    local retry_count="${3:-2}"  # 默认重试2次
    local silent="${4:-false}"  # 是否静默模式

    # 参数验证
    if [ -z "$url" ]; then
        echo_err "错误: 请提供要检查的URL"
        return 1
    fi

    # 如果URL不包含http前缀，自动添加https://
    if ! echo "$url" | grep -q "^http[s]\?://"; then
        url="https://$url"
    fi

    # 非静默模式下显示检查信息
    if [ "$silent" != "true" ]; then
        echo_succ "正在检查网页连接: $url (超时: ${timeout}秒, 重试: $retry_count 次)"
    fi

    local attempt=0
    local http_code
    local connect_time
    local success=false

    while [ $attempt -lt $retry_count ]; do
        attempt=$((attempt + 1))

        if [ "$silent" != "true" ]; then
            [ $attempt -gt 1 ] && echo_succ "尝试第 $attempt 次..."
        fi

        # 使用curl检查连接
        # -s: 静默模式，不显示进度条
        # -o /dev/null: 不保存响应内容
        # --connect-timeout: 连接超时时间
        # --max-time: 最大总操作时间
        # -w: 输出指定格式的信息
        # -L: 跟随重定向
        result=$(curl -s -L -o /dev/null \
            --connect-timeout $timeout \
            --max-time $((timeout + 2)) \
            -w "http_code=%{http_code}\ntime_connect=%{time_connect}\ntime_total=%{time_total}" \
            "$url" 2>/dev/null)

        # 解析结果
        http_code=$(echo "$result" | grep "http_code" | cut -d= -f2)
        connect_time=$(echo "$result" | grep "time_connect" | cut -d= -f2)
        total_time=$(echo "$result" | grep "time_total" | cut -d= -f2)

        # 判断HTTP状态码
        if [ -n "$http_code" ] && [ "$http_code" -ge 200 ] && [ "$http_code" -lt 400 ]; then
            success=true
            break
        fi

        if [ "$silent" != "true" ]; then
            if [ -z "$http_code" ]; then
                echo_warn "连接失败，无法获取响应"
            else
                echo_warn "收到HTTP状态码: $http_code (可能表示网站不可访问)"
            fi
        fi

        # 如果不是最后一次尝试，则等待一会儿再重试
        if [ $attempt -lt $retry_count ]; then
            sleep 1
        fi
    done

    # 输出结果
    if [ "$success" = true ]; then
        if [ "$silent" != "true" ]; then
            echo_succ "网页可访问: $url"
            echo_succ "HTTP状态码: $http_code, 连接时间: ${connect_time}秒, 总时间: ${total_time}秒"
        fi
        return 0
    else
        if [ "$silent" != "true" ]; then
            echo_err "网页不可访问: $url"
            [ -n "$http_code" ] && echo_err "最后HTTP状态码: $http_code"
        fi
        return 1
    fi
}

# 双向同步 OpenWrt dnsmasq 的 filter_aaaa 与 sing-box DNS 策略：
# ipv4_only 时设为 1 防止泄漏；启用双栈分流时自动恢复为 0 放行 AAAA，并刷新缓存。
sync_dnsmasq_ipv4_only() {
    if ! command -v uci >/dev/null 2>&1; then
        killall -HUP dnsmasq 2>/dev/null || true
        return 0
    fi
    local target_filter="0"
    if [ -f "$CONFIG_FILE" ] && grep -q '"ipv4_only"' "$CONFIG_FILE" 2>/dev/null; then
        target_filter="1"
    fi
    local current_filter
    current_filter=$(uci -q get dhcp.@dnsmasq[0].filter_aaaa 2>/dev/null || echo "")
    if [ "$current_filter" != "$target_filter" ]; then
        if [ "$target_filter" = "1" ]; then
            echo_succ "检测到 ipv4_only 策略，同步开启 dnsmasq AAAA (IPv6) 记录过滤..."
        else
            echo_succ "检测到启用 IPv6 双栈分流策略，恢复 dnsmasq AAAA 记录解析..."
        fi
        uci set dhcp.@dnsmasq[0].filter_aaaa="$target_filter" 2>/dev/null || true
        uci commit dhcp 2>/dev/null || true
        if [ -x /etc/init.d/dnsmasq ]; then
            /etc/init.d/dnsmasq reload >/dev/null 2>&1 || /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
        fi
    fi
    # 刷新 dnsmasq 缓存，清除启动前可能残留的旧记录
    killall -HUP dnsmasq 2>/dev/null || true
}

main() {
  init_env
  setup_firewall
  setup_route
  start_singbox
  sync_dnsmasq_ipv4_only
}

main
