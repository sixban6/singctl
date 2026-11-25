#!/bin/bash

#################################################
# 描述: Debian sing-box TProxy模式 配置脚本
# 用途: 配置和启动 sing-box TProxy模式 代理服务
# 系统: Debian/Ubuntu (使用 iptables/nftables + systemd)
#################################################

# 确保能找到 sing-box 命令
export PATH="/usr/local/bin:/usr/bin:$PATH"
TPROXY_PORT=7895  # sing-box tproxy 端口，和配置文件里的端口一致！
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
GREEN='\033[0;32m'
NC='\033[0m'

# Debian 系统检测
DEBIAN_VERSION=$(lsb_release -r 2>/dev/null | awk '{print $2}' | cut -d. -f1)
[ -z "$DEBIAN_VERSION" ] && DEBIAN_VERSION=$(cat /etc/debian_version 2>/dev/null | cut -d. -f1)
[ -z "$DEBIAN_VERSION" ] && DEBIAN_VERSION="11"  # 默认

LOCAL_IPV4='{127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, 224.0.0.0/4, 255.255.255.255/32}'

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# 输出函数
echo_succ() {
    printf "${CYAN}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_warn() {
    printf "${YLW}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_err() {
    printf "${RED}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_info() {
    printf "${GREEN}%s [INFO] %s${NC}\n" "$(timestamp)" "$1"
}

# 错误处理函数
error_exit() {
    echo_err "$1"
    cleanup
    exit 1
}

flush_ip_rules_for_table() {
    local family="$1"
    local tbl="$2"
    local n=0
    while [ $n -lt 16 ]; do
        if [ "$family" = "-6" ]; then
            ip -6 rule del table "$tbl" 2>/dev/null || break
        else
            ip rule del table "$tbl" 2>/dev/null || break
        fi
        n=$((n + 1))
    done
}

# 清理函数
cleanup() {
    # 清理可能的残留规则
    while iptables -t mangle -D PREROUTING -j SINGBOX 2>/dev/null; do :; done
    while iptables -t mangle -D OUTPUT -j SINGBOX_OUTPUT 2>/dev/null; do :; done
    iptables -t mangle -F SINGBOX 2>/dev/null || true
    iptables -t mangle -X SINGBOX 2>/dev/null || true
    iptables -t mangle -F SINGBOX_OUTPUT 2>/dev/null || true
    iptables -t mangle -X SINGBOX_OUTPUT 2>/dev/null || true
    nft delete table inet sing-box 2>/dev/null || true
    flush_ip_rules_for_table -4 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -4 "$PROXY_LOCAL_ROUTE_TABLE"
    ip route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip route flush table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
    flush_ip_rules_for_table -6 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -6 "$PROXY_LOCAL_ROUTE_TABLE"
    ip -6 route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 route flush table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
}

# 检查命令是否存在
check_command() {
    local cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "$cmd 未安装，请先安装: apt install $cmd"
    fi
}

# 检查网络连接（快速 1s 探测，禁 Ping 环境仅提示不阻塞）
check_network() {
    echo_succ "检查网络连接..."
    if ! ping -c 1 -W 1 223.5.5.5 >/dev/null 2>&1 && ! ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1; then
        echo_warn "ICMP 探测未响应（可能处于禁 Ping 环境），继续启动服务"
    fi
}

# 探测本地端口监听状态（兼容 netstat / ss / /proc/net）
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

# 检查端口占用
check_port() {
    local port=$1
    if is_port_listening "$port"; then
        echo_warn "端口 $port 已被占用，正在清理残留 sing-box..."
        pkill -9 -f "sing-box" 2>/dev/null || true
        sleep 1
        if is_port_listening "$port"; then
            error_exit "端口 $port 仍被其他进程占用，请先停止占用该端口的其他代理服务"
        fi
    fi
}

# 创建沙盒配置文件（仅在宿主已预装 firejail 时生成，不在启动期执行 apt update 避免阻塞；保留 TProxy 所需网络命名空间与 CAP_NET_ADMIN 能力）
create_debian_sandbox() {
    if ! command -v firejail >/dev/null 2>&1; then
        return 1
    fi
    echo_info "检测到已安装的 firejail，生成 TProxy 兼容沙盒配置..."
    cat > /etc/sing-box/sing-box.profile << 'EOF'
# Firejail profile for sing-box (TProxy compatible)
seccomp
nonewprivs
caps.keep net_admin,net_raw,net_bind_service,dac_read_search
disable-mnt
x11 none
read-only /usr
read-only /lib
read-only /lib64
read-only /bin
read-only /sbin
rlimit-nofile 65536
EOF
    chmod 0600 /etc/sing-box/sing-box.profile 2>/dev/null || true
    return 0
}

init_env() {
    # 检查是否以 root 权限运行
    if [ "$(id -u)" != "0" ]; then
        error_exit "此脚本需要 root 权限运行"
    fi

    # 停止现有服务
    echo_succ "停止现有 sing-box 服务..."
    systemctl stop sing-box 2>/dev/null || true
    pkill -f "sing-box" 2>/dev/null || true
    sleep 2

    # 检查必要命令
    check_command "sing-box"
    check_command "ip"
    check_command "ping"
    
    # 检查防火墙工具
    if command -v nft >/dev/null 2>&1; then
        USE_NFTABLES=true
        echo_info "使用 nftables 防火墙"
    elif command -v iptables >/dev/null 2>&1; then
        USE_NFTABLES=false
        echo_info "使用 iptables 防火墙"
        check_command "iptables"
    else
        error_exit "未找到防火墙工具 (nftables/iptables)"
    fi

    # 检查网络和端口
    check_network
    check_port "$TPROXY_PORT"

    # 创建配置目录
    mkdir -p /etc/sing-box
    
    # 创建沙盒环境（可选）
    create_debian_sandbox || true

    # 验证配置
    if [ ! -f "$CONFIG_FILE" ]; then
        error_exit "配置文件不存在: $CONFIG_FILE"
    fi
    
    if ! sing-box check -c "$CONFIG_FILE"; then
        error_exit "配置文件验证失败"
    fi
    echo_succ "配置文件验证通过"
}

# 使用 nftables 设置防火墙规则 (Debian 11+)
setup_nftables() {
    echo_succ "配置 nftables 防火墙规则..."
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
    for pfx in $(ip -6 route show proto kernel scope global 2>/dev/null | awk '$1 ~ /:/ && $1 !~ /^f[cd]/ && $0 !~ /tailscale|wg|tun/ {print $1}'); do
        case " $LAN_IPV6_PFXS " in
            *" $pfx "*) ;;
            *) LAN_IPV6_PFXS="$LAN_IPV6_PFXS $pfx" ;;
        esac
    done
    LOCAL_IPV6_ELEMS="::1/128, fc00::/7, fe80::/10, ff00::/8"
    for pfx in $LAN_IPV6_PFXS; do
        LOCAL_IPV6_ELEMS="$LOCAL_IPV6_ELEMS, $pfx"
    done
    
    # 单流原子创建规则文件（0ms 切换空窗）
    cat > /etc/sing-box/singbox.nft << EOF
#!/usr/sbin/nft -f
# Debian sing-box nftables 配置
add table inet sing-box
flush table inet sing-box
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

        # 放行 Tailscale 接口流量，避免 router/exit-node 转发流量被 TProxy 劫持
        iifname "tailscale*" counter accept

        # 拒绝外部访问代理端口
        fib daddr type local meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable
        fib daddr type local accept

        # 优先承接本机 output 链 (mark 0x2 -> table 101) 回环进来的流量（含发往上级私网网关 192.168.x.1:53 的 DNS），避免命中表 100 throw 逃逸
        iifname "lo" meta mark $PROXY_LOCAL_FWMARK meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_LOCAL_FWMARK accept

        # 先豁免回环与 Tailscale MagicDNS
        ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
        ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept

        # 放行端口转发流量
        ct status dnat accept comment "Allow forwarded traffic"

        # DNS 透明代理（置于局域网网段放行之前，防止上级光猫明文 DNS 绕过）
        meta l4proto { tcp, udp } th dport 53 tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK accept comment "DNS transparent proxy"

        # 放行其余局域网流量
        ip daddr @LOCAL_IPV4_SET accept
        ip6 daddr @LOCAL_IPV6_SET accept

        # TProxy 流量处理
        meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK accept
    }

    chain output {
        type route hook output priority mangle; policy accept;

        # 放行 sing-box 自身出站 (default_mark=0x1) 与已重路由标记流量，防止回环
        meta mark $PROXY_FWMARK accept
        meta mark $PROXY_LOCAL_FWMARK accept
        meta mark 0x80000 accept comment "Bypass Tailscale fwmark"
        udp sport 41641 accept comment "Bypass Tailscale UDP port"
        oifname "tailscale*" accept comment "Bypass outbound traffic to tailscale interface"

        # 放行本地 AdGuard Home 加密上游 (DoH/DoT) 直连流量，防止冷启动或 Global 全局模式下死锁
        ip daddr { $AGH_BYPASS_NFT } tcp dport { 443, 853 } accept comment "Bypass AdGuard Home encrypted DNS upstreams"
        ip6 daddr { $AGH_BYPASS_NFT6 } tcp dport { 443, 853 } accept comment "Bypass AdGuard Home IPv6 encrypted DNS upstreams"

        # 放行 IPv6 ICMP
        meta l4proto ipv6-icmp accept

        # 先豁免回环与 Tailscale CGNAT/MagicDNS，再以独立标记 0x2 (走纯 local 表 101) 拦截其余 53 端口 DNS 流量
        ip daddr { 127.0.0.0/8, 100.64.0.0/10 } accept
        ip6 daddr { ::1, fd7a:115c:a1e0::/48 } accept
        meta l4proto { tcp, udp } th dport 53 meta mark set $PROXY_LOCAL_FWMARK accept

        # 放行其余局域网流量
        ip daddr @LOCAL_IPV4_SET accept
        ip6 daddr @LOCAL_IPV6_SET accept

        # 标记其他本机出站流量 (走表 101 回环至 TProxy)
        meta l4proto { tcp, udp } meta mark set $PROXY_LOCAL_FWMARK accept
    }
}
EOF

    # 应用规则
    chmod 644 /etc/sing-box/singbox.nft
    if ! nft -f /etc/sing-box/singbox.nft; then
        error_exit "应用 nftables 规则失败"
    fi
    echo_succ "nftables 规则配置完成"
}

# 使用 iptables 设置防火墙规则 (Debian 10 及以下)
setup_iptables() {
    echo_succ "配置 iptables 防火墙规则..."
    
    # 创建自定义链
    iptables -t mangle -N SINGBOX 2>/dev/null || true
    iptables -t mangle -F SINGBOX
    iptables -t mangle -N SINGBOX_OUTPUT 2>/dev/null || true
    iptables -t mangle -F SINGBOX_OUTPUT

    # 删除旧引用，避免重复执行脚本后规则叠加
    while iptables -t mangle -D PREROUTING -j SINGBOX 2>/dev/null; do :; done
    while iptables -t mangle -D OUTPUT -j SINGBOX_OUTPUT 2>/dev/null; do :; done
    
    # PREROUTING 规则
    iptables -t mangle -A PREROUTING -j SINGBOX
    iptables -t mangle -A SINGBOX -i lo -m mark --mark $PROXY_LOCAL_FWMARK -p tcp -j TPROXY --tproxy-mark $PROXY_LOCAL_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A SINGBOX -i lo -m mark --mark $PROXY_LOCAL_FWMARK -p udp -j TPROXY --tproxy-mark $PROXY_LOCAL_FWMARK --on-port $TPROXY_PORT
    
    # 放行局域网与优先劫持外部/上级网关 DNS
    iptables -t mangle -A SINGBOX -i tailscale+ -j RETURN
    iptables -t mangle -A SINGBOX -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX -d 100.64.0.0/10 -j RETURN
    iptables -t mangle -A SINGBOX -p tcp --dport 53 -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A SINGBOX -p udp --dport 53 -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A SINGBOX -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SINGBOX -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SINGBOX -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A SINGBOX -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A SINGBOX -d 255.255.255.255/32 -j RETURN
    
    # 其他流量重定向
    iptables -t mangle -A SINGBOX -p tcp -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A SINGBOX -p udp -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    
    # OUTPUT 链规则
    iptables -t mangle -A SINGBOX_OUTPUT -m mark --mark $PROXY_FWMARK -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -m mark --mark $PROXY_LOCAL_FWMARK -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -m mark --mark 0x80000 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -p udp --sport 41641 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -o tailscale+ -j RETURN
    for agh_ip in 223.5.5.5 223.6.6.6 1.12.12.12 120.53.53.53; do
        iptables -t mangle -A SINGBOX_OUTPUT -d "$agh_ip" -p tcp --dport 443 -j RETURN
        iptables -t mangle -A SINGBOX_OUTPUT -d "$agh_ip" -p tcp --dport 853 -j RETURN
    done
    iptables -t mangle -A SINGBOX_OUTPUT -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -d 100.64.0.0/10 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -p tcp --dport 53 -j MARK --set-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A SINGBOX_OUTPUT -p udp --dport 53 -j MARK --set-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A SINGBOX_OUTPUT -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -d 169.254.0.0/16 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -d 224.0.0.0/4 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -d 255.255.255.255/32 -j RETURN
    iptables -t mangle -A SINGBOX_OUTPUT -p tcp -j MARK --set-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A SINGBOX_OUTPUT -p udp -j MARK --set-mark $PROXY_LOCAL_FWMARK
    iptables -t mangle -A OUTPUT -j SINGBOX_OUTPUT
    
    echo_succ "iptables 规则配置完成"
}

# 设置防火墙
setup_firewall() {
    if [ "$USE_NFTABLES" = "true" ]; then
        setup_nftables
    else
        setup_iptables
    fi
}

# 设置路由规则
setup_route() {
    echo_succ "配置路由规则..."
    
    # 清理现有规则
    flush_ip_rules_for_table -4 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -4 "$PROXY_LOCAL_ROUTE_TABLE"
    flush_ip_rules_for_table -6 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -6 "$PROXY_LOCAL_ROUTE_TABLE"
    
    # 添加 IPv4 路由规则（表 100 供外部进入流量带 throw 兼容 src_valid_mark=1；表 101 供本机出站纯 local 重路由防私网 DNS 逃逸）
    ip rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE
    ip rule add fwmark $PROXY_LOCAL_FWMARK table $PROXY_LOCAL_ROUTE_TABLE
    ip route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip route add local default dev lo table $PROXY_ROUTE_TABLE
    for throw_cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16; do
        ip route replace throw "$throw_cidr" table $PROXY_ROUTE_TABLE 2>/dev/null || \
            ip route add throw "$throw_cidr" table $PROXY_ROUTE_TABLE 2>/dev/null || true
    done
    ip route flush table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
    ip route add local default dev lo table $PROXY_LOCAL_ROUTE_TABLE
    
    # 添加 IPv6 路由规则（兼容禁用 IPv6 的内核或容器环境）
    ip -6 rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 rule add fwmark $PROXY_LOCAL_FWMARK table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
    ip -6 route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 route add local default dev lo table $PROXY_ROUTE_TABLE 2>/dev/null || true
    for throw_v6 in ::1/128 fc00::/7 fe80::/10 fd7a:115c:a1e0::/48 $LAN_IPV6_PFXS; do
        ip -6 route replace throw "$throw_v6" table $PROXY_ROUTE_TABLE 2>/dev/null || true
    done
    ip -6 route flush table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
    ip -6 route add local default dev lo table $PROXY_LOCAL_ROUTE_TABLE 2>/dev/null || true
    
    echo_succ "路由规则配置完成"
}

# 根据宿主机 /proc/meminfo 自适应计算 Go 软内存上限 (GOMEMLIMIT / GOGC)
setup_singbox_mem_env() {
    local mem_total_kb=0
    if [ -r /proc/meminfo ]; then
        mem_total_kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)
    fi
    case "$mem_total_kb" in
        ''|*[!0-9]*) mem_total_kb=0 ;;
    esac
    if [ "${SINGCTL_LOW_MEMORY:-}" != "0" ] && [ -z "${GOMEMLIMIT:-}" ] && [ "$mem_total_kb" -gt 0 ]; then
        if [ "$mem_total_kb" -le 294912 ]; then
            if [ -f "${CONFIG_FILE:-}" ] && ! grep -qE '"type"[[:space:]]*:[[:space:]]*"(selector|urltest)"' "$CONFIG_FILE" 2>/dev/null; then
                GOMEMLIMIT="20MiB"
                [ -z "${GOGC:-}" ] && GOGC="25"
            else
                GOMEMLIMIT="28MiB"
                [ -z "${GOGC:-}" ] && GOGC="30"
            fi
        elif [ "$mem_total_kb" -le 524288 ]; then
            GOMEMLIMIT="44MiB"
            [ -z "${GOGC:-}" ] && GOGC="50"
        elif [ "$mem_total_kb" -le 1048576 ]; then
            GOMEMLIMIT="160MiB"
        elif [ "$mem_total_kb" -le 2097152 ]; then
            GOMEMLIMIT="256MiB"
        else
            GOMEMLIMIT="512MiB"
        fi
    fi
    [ -n "${GOMEMLIMIT:-}" ] && export GOMEMLIMIT
    [ -n "${GOGC:-}" ] && export GOGC
}

# 启动 sing-box (支持沙盒)
start_singbox() {
    setup_singbox_mem_env
    echo_succ "启动 sing-box 服务 (TProxy模式)..."
    local singbox_bin
    singbox_bin=$(command -v sing-box)
    mkdir -p /var/log
    local systemd_env_lines=""
    if [ -n "${GOMEMLIMIT:-}" ]; then
        systemd_env_lines="${systemd_env_lines}Environment=\"GOMEMLIMIT=${GOMEMLIMIT}\"
"
    fi
    if [ -n "${GOGC:-}" ]; then
        systemd_env_lines="${systemd_env_lines}Environment=\"GOGC=${GOGC}\"
"
    fi

    # 1) 若宿主机 PID 1 为 systemd，优先采用带文件系统隔离与网络能力的 systemd 服务托管
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        echo_info "使用 systemd 安全托管模式启动..."
        cat > /etc/systemd/system/sing-box-temp.service << EOF
[Unit]
Description=sing-box client TProxy service
After=network.target

[Service]
Type=simple
${systemd_env_lines}ExecStart=$singbox_bin run -c $CONFIG_FILE
Restart=no
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/sing-box /tmp /var/log
PrivateTmp=true
ProtectControlGroups=true
RestrictRealtime=true
PrivateNetwork=false
EOF

        systemctl daemon-reload
        if systemctl start sing-box-temp 2>/dev/null; then
            sleep 1
            if systemctl is-active --quiet sing-box-temp; then
                echo_succ "sing-box 启动成功 (systemd 安全模式)"
                return 0
            fi
        fi
        echo_warn "systemd 托管启动未就绪，回退后台守护模式..."
        systemctl stop sing-box-temp 2>/dev/null || true
    fi

    # 2) 若已安装 firejail，尝试轻量沙盒
    if command -v firejail >/dev/null 2>&1 && [ -f /etc/sing-box/sing-box.profile ]; then
        echo_info "使用 firejail 沙盒模式启动..."
        nohup firejail --profile=/etc/sing-box/sing-box.profile \
            --name=sing-box \
            "$singbox_bin" run -c "$CONFIG_FILE" \
            </dev/null >/var/log/sing-box.log 2>&1 &
        sleep 1
        if pgrep -f "sing-box" >/dev/null; then
            echo_succ "sing-box 启动成功 (firejail 沙盒模式)"
            return 0
        fi
        echo_warn "firejail 沙盒启动失败，回退直接启动模式..."
    fi

    # 3) 标准后台守护模式（彻底脱离标准输入输出管道，防止阻塞调用方）
    nohup "$singbox_bin" run -c "$CONFIG_FILE" </dev/null >/var/log/sing-box.log 2>&1 &
    sleep 1

    if pgrep -x "sing-box" >/dev/null 2>&1 || pgrep -f "$singbox_bin run" >/dev/null 2>&1; then
        echo_succ "sing-box 启动成功 (TProxy 守护模式)"
    else
        error_exit "sing-box 启动失败，请检查日志: /var/log/sing-box.log"
    fi
}

# 主函数
main() {
    echo_info "开始配置 Debian sing-box TProxy 模式..."
    
    init_env
    if [ "${SINGCTL_GO_DATAPLANE:-0}" != "1" ]; then
        setup_firewall
        setup_route
    fi
    start_singbox
    
    echo_succ "Debian sing-box TProxy 配置完成！"
    echo_info "配置文件: $CONFIG_FILE"
    echo_info "日志文件: /var/log/sing-box.log"
    echo_info "代理端口: $TPROXY_PORT"
}

# 仅在收到中断/终止信号时回滚清理（严禁注册 EXIT，否则正常启动结束瞬间会误删刚创建的 nftables 与路由规则！）
trap cleanup INT TERM

# 执行主函数
main "$@"
