# 模块职责：OpenWrt 透明代理共享主干（基础常量、日志、动态加密 DNS 采集、IPv6 前缀发现、策略路由表 100/101、低内存护栏、procd-ujail 自动安装与沙盒降级启停、dnsmasq 双向同步）。

# 确保能找到 sing-box、ip、opkg、ujail 等系统命令（保留调用方 PATH 优先级，补齐标准系统路径）
export PATH="$PATH:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TPROXY_PORT=7895  # sing-box tproxy 端口，和配置文件（规则模板）里的端口一致！
PROXY_FWMARK=1
PROXY_ROUTE_TABLE=100
PROXY_LOCAL_FWMARK=2
PROXY_LOCAL_ROUTE_TABLE=101
MAX_RETRIES=3  # 最大重试次数
RETRY_DELAY=3  # 重试间隔时间（秒）
CONFIG_FILE="${CONFIG_FILE:-/etc/sing-box/config.json}"
ADGUARD_CONFIG_FILE="${ADGUARD_CONFIG_FILE:-/etc/AdGuardHome/AdGuardHome.yaml}"
SMARTDNS_CONFIG_FILE="${SMARTDNS_CONFIG_FILE:-/etc/singctl/smartdns.conf}"
CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

echo_succ() {
    printf "${CYAN}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_warn() {
    printf "${YLW}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_err() {
    printf "${RED}%s %s${NC}\n" "$(timestamp)" "$1"
}

# 错误处理函数
error_exit() {
    echo_err "错误: $1"
    exit "${2:-1}"
}

# 检查是否以 root 权限运行
require_root() {
    if [ "$(id -u)" != "0" ]; then
        error_exit "此脚本需要 root 权限运行"
    fi
}

# 检查命令是否存在
check_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "$cmd 未安装，请安装后再运行此脚本"
    fi
}

# 纯 POSIX 限时执行封装（规避老版 BusyBox timeout -t 语法差异，不遗留孤儿 sleep 进程）
run_with_timeout() {
    local secs="$1"
    shift
    "$@" &
    local cmd_pid=$!
    local elapsed=0
    while kill -0 "$cmd_pid" 2>/dev/null; do
        if [ "$elapsed" -ge "$secs" ]; then
            kill "$cmd_pid" 2>/dev/null || true
            sleep 1
            kill -9 "$cmd_pid" 2>/dev/null || true
            wait "$cmd_pid" 2>/dev/null || true
            return 124
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    local rc=0
    wait "$cmd_pid" 2>/dev/null || rc=$?
    return "$rc"
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
    local port="$1"
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
    local port="$1"
    if is_port_listening "$port"; then
        echo_warn "端口 $port 已被占用，正在清理残留 sing-box..."
        killall -9 sing-box 2>/dev/null || true
        sleep 1
        if is_port_listening "$port"; then
            error_exit "端口 $port 仍被其他进程占用，请先停止占用该端口的代理服务（如 OpenClash/PassWall）"
        fi
    fi
}

# 检测是否存在正在运行的 ujail sing-box 沙盒实例（兼容 BusyBox ps w 与标准 ps）
is_ujail_singbox_running() {
    (ps w 2>/dev/null || ps) | grep -v grep | grep -q "ujail.*sing-box"
}

# 追加去重后的合法纯 IPv4 到 BYPASS_DNS_V4_IPS
append_bypass_dns_v4() {
    local ip="$1"
    case "$ip" in
        ''|*[!0-9.]*) return 0 ;;
    esac
    case " $BYPASS_DNS_V4_IPS " in
        *" $ip "*) ;;
        *) BYPASS_DNS_V4_IPS="$BYPASS_DNS_V4_IPS $ip" ;;
    esac
}

# 追加去重后的合法纯 IPv6 到 BYPASS_DNS_V6_IPS
append_bypass_dns_v6() {
    local ip="$1"
    case "$ip" in
        ''|*[!0-9a-fA-F:]*) return 0 ;;
        *:*) ;;
        *) return 0 ;;
    esac
    case " $BYPASS_DNS_V6_IPS " in
        *" $ip "*) ;;
        *) BYPASS_DNS_V6_IPS="$BYPASS_DNS_V6_IPS $ip" ;;
    esac
}

# 统一动态采集 AdGuard Home 与 SmartDNS 中的全部纯 IPv4/IPv6 加密 DoH/DoT/DoQ 上游，
# 产出空格分隔、已去重的 BYPASS_DNS_V4_IPS 与 BYPASS_DNS_V6_IPS，防止冷启动或全局代理模式产生 DNS 解析死锁。
collect_bypass_dns_ips() {
    BYPASS_DNS_V4_IPS="223.5.5.5 223.6.6.6 1.12.12.12 120.53.53.53"
    BYPASS_DNS_V6_IPS="2400:3200::1 2400:3200:baba::1"

    local extra_ip extra_v6

    # 1. 采集 AdGuard Home (/etc/AdGuardHome/AdGuardHome.yaml) 加密上游
    if [ -f "$ADGUARD_CONFIG_FILE" ]; then
        for extra_ip in $(awk '
            { gsub(/\r/, "") }
            /^[[:space:]]*#/ { next }
            {
                line = $0
                sub(/[[:space:]]+#.*/, "", line)
                if (match(line, /(https|tls|quic|h3):\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+([:\/\?"\047,[:space:]]|$)/)) {
                    s = substr(line, RSTART, RLENGTH)
                    sub(/^(https|tls|quic|h3):\/\//, "", s)
                    sub(/[^0-9.].*$/, "", s)
                    n = split(s, o, ".")
                    if (n == 4 && o[1]+0 > 0 && o[1]+0 != 127 && o[1]+0 <= 255 && o[2]+0 <= 255 && o[3]+0 <= 255 && o[4]+0 <= 255) {
                        print s
                    }
                }
            }
        ' "$ADGUARD_CONFIG_FILE" 2>/dev/null || true); do
            append_bypass_dns_v4 "$extra_ip"
        done

        for extra_v6 in $(awk '
            { gsub(/\r/, "") }
            /^[[:space:]]*#/ { next }
            {
                line = $0
                sub(/[[:space:]]+#.*/, "", line)
                if (match(line, /(https|tls|quic|h3):\/\/\[[0-9a-fA-F:]+\]/)) {
                    s = substr(line, RSTART, RLENGTH)
                    sub(/^(https|tls|quic|h3):\/\/\[/, "", s)
                    sub(/\]$/, "", s)
                    if (index(s, ":") > 0 && s != "::1" && s != "::") {
                        print s
                    }
                }
            }
        ' "$ADGUARD_CONFIG_FILE" 2>/dev/null || true); do
            append_bypass_dns_v6 "$extra_v6"
        done
    fi

    # 2. 采集 SmartDNS (/etc/singctl/smartdns.conf) 加密上游 (server-https / server-tls / server-quic / server-h3)
    if [ -f "$SMARTDNS_CONFIG_FILE" ]; then
        for extra_ip in $(awk '
            { gsub(/\r/, "") }
            /^[[:space:]]*#/ { next }
            $1 ~ /^server-(https|tls|quic|h3)$/ && NF >= 2 {
                ep = $2
                sub(/^(https|tls|quic|h3):\/\//, "", ep)
                if (match(ep, /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+([:\/\?]|$)/)) {
                    s = substr(ep, RSTART, RLENGTH)
                    sub(/[^0-9.].*$/, "", s)
                    n = split(s, o, ".")
                    if (n == 4 && o[1]+0 > 0 && o[1]+0 != 127 && o[1]+0 <= 255 && o[2]+0 <= 255 && o[3]+0 <= 255 && o[4]+0 <= 255) {
                        print s
                    }
                }
            }
        ' "$SMARTDNS_CONFIG_FILE" 2>/dev/null || true); do
            append_bypass_dns_v4 "$extra_ip"
        done

        for extra_v6 in $(awk '
            { gsub(/\r/, "") }
            /^[[:space:]]*#/ { next }
            $1 ~ /^server-(https|tls|quic|h3)$/ && NF >= 2 {
                ep = $2
                sub(/^(https|tls|quic|h3):\/\//, "", ep)
                if (match(ep, /^\[[0-9a-fA-F:]+\]/)) {
                    s = substr(ep, 2, RLENGTH - 2)
                    if (index(s, ":") > 0 && s != "::1" && s != "::") {
                        print s
                    }
                } else if (match(ep, /^[0-9a-fA-F:]+$/) && index(ep, ":") > 0) {
                    if (ep != "::1" && ep != "::") {
                        print ep
                    }
                }
            }
        ' "$SMARTDNS_CONFIG_FILE" 2>/dev/null || true); do
            append_bypass_dns_v6 "$extra_v6"
        done
    fi
}

# 动态采集 br-lan / eth0 的全局 IPv6 前缀，产出 LAN_IPV6_PFXS
collect_lan_ipv6_prefixes() {
    LAN_IPV6_PFXS=""
    local lan_if pfx
    for lan_if in br-lan eth0; do
        if ip link show "$lan_if" >/dev/null 2>&1; then
            for pfx in $(ip -6 route show dev "$lan_if" proto kernel scope global 2>/dev/null | awk '$1 ~ /:/ && $1 !~ /^f[cd]/ {print $1}'); do
                case " $LAN_IPV6_PFXS " in
                    *" $pfx "*) ;;
                    *)
                        if [ -z "$LAN_IPV6_PFXS" ]; then
                            LAN_IPV6_PFXS="$pfx"
                        else
                            LAN_IPV6_PFXS="$LAN_IPV6_PFXS $pfx"
                        fi
                        ;;
                esac
            done
        fi
    done
    LAN_IPV6_PFXS_COLLECTED=1
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

# 配置 IPv4/IPv6 策略路由表 100/101 及 throw 逃生路由
setup_route() {
    if [ "${LAN_IPV6_PFXS_COLLECTED:-0}" != "1" ]; then
        collect_lan_ipv6_prefixes
    fi

    echo_succ "初始化 IPV4 路由"
    # 配置外部转发流量策略路由表 100 (fwmark 0x1, 带私网/CGNAT throw 逃生路由兼容 src_valid_mark=1)
    flush_ip_rules_for_table -4 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -4 "$PROXY_LOCAL_ROUTE_TABLE"
    ip rule add fwmark "$PROXY_FWMARK" table "$PROXY_ROUTE_TABLE"
    ip rule add fwmark "$PROXY_LOCAL_FWMARK" table "$PROXY_LOCAL_ROUTE_TABLE"

    # 清理并添加表 100 路由
    ip route flush table "$PROXY_ROUTE_TABLE" >/dev/null 2>&1 || true
    ip route add local default dev lo table "$PROXY_ROUTE_TABLE"

    # 逃生路由：当宿主启用 net.ipv4.conf.all.src_valid_mark=1（如 Tailscale/WireGuard 策略路由）时，
    # 内核 fib_validate_source() 会带 fwmark 查表 100；必须对内网/CGNAT 网段配置 throw 穿透回 main/table 52，
    # 否则即使 rp_filter=0，所有局域网设备报文也会因源 IP 命中 local default dev lo 被判定为 martian source 静默丢弃。
    local throw_cidr
    for throw_cidr in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16; do
        ip route replace throw "$throw_cidr" table "$PROXY_ROUTE_TABLE" >/dev/null 2>&1 || \
            ip route add throw "$throw_cidr" table "$PROXY_ROUTE_TABLE" >/dev/null 2>&1 || true
    done

    # 配置本机出站重路由表 101 (fwmark 0x2, 纯 local default dev lo 不含 throw，确保主路由发往光猫 192.168.x.1:53 等私网 DNS 绝不逃逸)
    ip route flush table "$PROXY_LOCAL_ROUTE_TABLE" >/dev/null 2>&1 || true
    ip route add local default dev lo table "$PROXY_LOCAL_ROUTE_TABLE"

    echo_succ "初始化 IPV6 路由"
    flush_ip_rules_for_table -6 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -6 "$PROXY_LOCAL_ROUTE_TABLE"
    ip -6 rule add fwmark "$PROXY_FWMARK" table "$PROXY_ROUTE_TABLE" 2>/dev/null || true
    ip -6 rule add fwmark "$PROXY_LOCAL_FWMARK" table "$PROXY_LOCAL_ROUTE_TABLE" 2>/dev/null || true

    # 清理并添加 IPv6 路由（同步注入内网与 Tailscale throw 逃生路由）
    ip -6 route flush table "$PROXY_ROUTE_TABLE" >/dev/null 2>&1 || true
    ip -6 route replace local default dev lo table "$PROXY_ROUTE_TABLE" 2>/dev/null || true
    local throw_v6
    for throw_v6 in ::1/128 fc00::/7 fe80::/10 fd7a:115c:a1e0::/48 $LAN_IPV6_PFXS; do
        ip -6 route replace throw "$throw_v6" table "$PROXY_ROUTE_TABLE" >/dev/null 2>&1 || true
    done
    ip -6 route flush table "$PROXY_LOCAL_ROUTE_TABLE" >/dev/null 2>&1 || true
    ip -6 route replace local default dev lo table "$PROXY_LOCAL_ROUTE_TABLE" 2>/dev/null || true
}

# 安全清理 IPv4/IPv6 策略路由表 100/101（幂等，防止死循环）
cleanup_route() {
    flush_ip_rules_for_table -4 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -4 "$PROXY_LOCAL_ROUTE_TABLE"
    ip route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null || true
    ip route flush table "$PROXY_LOCAL_ROUTE_TABLE" 2>/dev/null || true

    flush_ip_rules_for_table -6 "$PROXY_ROUTE_TABLE"
    flush_ip_rules_for_table -6 "$PROXY_LOCAL_ROUTE_TABLE"
    ip -6 route flush table "$PROXY_ROUTE_TABLE" 2>/dev/null || true
    ip -6 route flush table "$PROXY_LOCAL_ROUTE_TABLE" 2>/dev/null || true
    echo_succ "已清理 IPv4/IPv6 策略路由与路由表"
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
    sz=$(wc -c < "$log_file" 2>/dev/null | tr -d '[:space:]' || echo 0)
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

# 统一停止 sing-box 服务（含 procd 托管与 ujail 沙盒实例）
stop_singbox_proc() {
    if [ -x /etc/init.d/sing-box ]; then
        /etc/init.d/sing-box stop >/dev/null 2>&1 || true
    fi

    if is_ujail_singbox_running; then
        echo_succ "检测到沙盒运行的 sing-box，正在停止..."
        killall sing-box 2>/dev/null || true
        sleep 2
        if is_ujail_singbox_running || pgrep "sing-box" >/dev/null 2>&1; then
            killall -9 sing-box 2>/dev/null || true
            sleep 1
        fi
        pkill -f "ujail.*sing-box" 2>/dev/null || true
        echo_succ "已停止 sing-box 沙盒实例"
    elif pgrep "sing-box" >/dev/null 2>&1; then
        echo_succ "检测到普通模式的 sing-box，正在停止..."
        killall sing-box 2>/dev/null || true
        sleep 1
        if pgrep "sing-box" >/dev/null 2>&1; then
            killall -9 sing-box 2>/dev/null || true
        fi
        echo_succ "已停止现有 sing-box 服务"
    else
        pkill -f "ujail.*sing-box" 2>/dev/null || true
        echo_succ "没有运行中的 sing-box 服务"
    fi
}

# 统一清理沙盒工作目录与临时调试日志
cleanup_sandbox_work() {
    rm -rf /tmp/sing-box-work 2>/dev/null && echo_succ "已清理沙盒工作目录" || true
    rm -f /tmp/ujail-test.log /tmp/sing-box-basic.log /tmp/sing-box-simple.log 2>/dev/null && echo_succ "已清理沙盒调试日志" || true
}

# 自动检测并按需安装 OpenWrt procd-ujail 沙盒组件（离线/超时/闪存不足均自动跳过并回退普通模式，绝不阻断启动）
ensure_openwrt_ujail() {
    UJAIL_ENSURE_DONE=1

    if command -v ujail >/dev/null 2>&1; then
        return 0
    fi

    local release_file="${OPENWRT_RELEASE_FILE:-/etc/openwrt_release}"
    if [ ! -f "$release_file" ] || ! command -v opkg >/dev/null 2>&1; then
        return 1
    fi

    local overlay_dir="${OVERLAY_DIR:-/overlay}"
    local avail_kb=0
    if [ -d "$overlay_dir" ]; then
        local df_out
        df_out=$(df -Pk "$overlay_dir" 2>/dev/null || df -k "$overlay_dir" 2>/dev/null || true)
        avail_kb=$(printf '%s\n' "$df_out" | awk 'NR > 1 { if (NF >= 4) a = $(NF-2) } END { print a + 0 }')
    fi
    case "$avail_kb" in
        ''|*[!0-9]*) avail_kb=0 ;;
    esac
    if [ "$avail_kb" -lt 512 ]; then
        echo_warn "检测到 ${overlay_dir} 剩余空间不足 (${avail_kb} KB < 512 KB)，跳过自动安装 procd-ujail，回退普通模式"
        return 1
    fi

    echo_succ "未检测到 ujail，尝试自动安装 procd-ujail 沙盒组件 (剩余空间 ${avail_kb} KB)..."
    local opkg_timeout="${UJAIL_OPKG_TIMEOUT:-20}"
    local installed=0

    # 优先检查本地 opkg list 缓存，避免无谓拉取软件源索引
    if opkg list 2>/dev/null | grep -Eq '^procd-ujail([[:space:]]|$)'; then
        echo_succ "本地 opkg 缓存已包含 procd-ujail，直接安装..."
        if run_with_timeout "$opkg_timeout" opkg install procd-ujail >/dev/null 2>&1 && command -v ujail >/dev/null 2>&1; then
            installed=1
        fi
    fi

    # 缓存未命中或旧缓存安装失败时，限时刷新索引再试一次
    if [ "$installed" = "0" ]; then
        echo_succ "刷新本地 opkg 软件源并尝试安装 procd-ujail (超时 ${opkg_timeout}s)..."
        if run_with_timeout "$opkg_timeout" opkg update >/dev/null 2>&1; then
            run_with_timeout "$opkg_timeout" opkg install procd-ujail >/dev/null 2>&1 || true
        else
            echo_warn "opkg update 超时或离线失败，跳过 procd-ujail 安装，自动回退普通模式"
            return 1
        fi
    fi

    if command -v ujail >/dev/null 2>&1; then
        echo_succ "procd-ujail 自动安装成功，已启用沙盒隔离"
        return 0
    fi

    echo_warn "procd-ujail 自动安装未成功，将自动回退普通模式启动 sing-box"
    return 1
}

start_singbox_plain() {
    sing-box run -c "$CONFIG_FILE" >/dev/null 2>&1 &
    if wait_tproxy_ready; then
        echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
    else
        error_exit "sing-box 启动失败或未监听 TProxy 端口 :$TPROXY_PORT，请检查配置和日志"
    fi
}

start_singbox() {
    setup_singbox_mem_env
    if [ -n "${GOMEMLIMIT:-}" ]; then
        echo_succ "已启用低内存自适应护栏: GOMEMLIMIT=${GOMEMLIMIT} GOGC=${GOGC:-100}"
    fi

    # 若尚未执行过 procd-ujail 自动补装探测，进入 ujail 检测前尝试一次
    if [ "${UJAIL_ENSURE_DONE:-0}" != "1" ]; then
        ensure_openwrt_ujail || true
    fi

    # 检查 ujail 是否可用
    if ! command -v ujail >/dev/null 2>&1; then
        start_singbox_plain
        return
    fi

    echo_succ "启动 sing-box 服务(沙盒模式)..."

    # 准备沙盒环境和配置
    echo_succ "准备沙盒环境..."
    mkdir -p /tmp/sing-box-work

    # 创建沙盒专用配置，修改状态缓存路径到可写 tmpfs 目录并清理历史外置 UI 残留
    rm -rf /tmp/sing-box-work/ui /tmp/sing-box-work/dashboard 2>/dev/null || true
    if [ -f "$CONFIG_FILE" ]; then
        sed 's|"/etc/sing-box/cache.db"|"/tmp/sing-box-work/cache.db"|g' \
            "$CONFIG_FILE" > /tmp/sing-box-work/config.json
        chmod 0600 /tmp/sing-box-work/config.json 2>/dev/null || true
    else
        echo_warn "配置文件不存在，使用原路径"
        cp "$CONFIG_FILE" /tmp/sing-box-work/config.json 2>/dev/null || true
        chmod 0600 /tmp/sing-box-work/config.json 2>/dev/null || true
    fi

    # 找到 sing-box 的绝对路径
    SINGBOX_EXEC=""
    if [ -f "/usr/bin/sing-box" ]; then
        SINGBOX_EXEC="/usr/bin/sing-box"
    elif [ -f "/usr/local/bin/sing-box" ]; then
        SINGBOX_EXEC="/usr/local/bin/sing-box"
    else
        SINGBOX_EXEC=$(command -v sing-box 2>/dev/null || echo "")
    fi

    if [ -z "$SINGBOX_EXEC" ] || [ ! -f "$SINGBOX_EXEC" ]; then
        echo_warn "找不到 sing-box 可执行文件，跳过沙盒模式"
        start_singbox_plain
        return
    fi

    echo_succ "发现 sing-box 路径: $SINGBOX_EXEC"

    # 1. 探测最基本的 ujail 功能（兼容 OpenWrt 21.02 老版 ujail 2021-03-08 与新版 ujail）
    echo_succ "测试 ujail 基础功能..."
    if ! ujail -n test-basic -w /tmp -- /bin/echo "test" >/tmp/ujail-test.log 2>&1; then
        echo_warn "ujail 基础功能异常，查看 /tmp/ujail-test.log"
        echo_warn "跳过沙盒模式，使用普通模式启动..."
        start_singbox_plain
        return
    fi

    # 2. 探测 -e 环境变量透传支持（OpenWrt 21.02 老版 ujail 不支持 -e，探测失败时自动省略）
    UJAIL_HAS_ENV=0
    if [ -n "${GOMEMLIMIT:-}" ] || [ -n "${GOGC:-}" ]; then
        if ujail -n test-env -w /tmp -e PATH -- /bin/echo "ok" >/dev/null 2>&1; then
            UJAIL_HAS_ENV=1
        fi
    fi

    # 3. 探测 /proc 挂载兼容模式（优先 -r /proc；若老版 ujail 报挂载错则退回 -p 或完全省略）
    UJAIL_PROC_MODE="none"
    if [ -e /proc ] && ujail -n test-proc -w /tmp -r /proc -- /bin/echo "ok" >/dev/null 2>&1; then
        UJAIL_PROC_MODE="ro"
    elif ujail -n test-proc -w /tmp -p -- /bin/echo "ok" >/dev/null 2>&1; then
        UJAIL_PROC_MODE="flag"
    fi

    # 4. 尝试基础沙盒模式（完整证书 + 配置 + 兼容 /proc 挂载）
    echo_succ "尝试基础沙盒模式(证书+配置访问)..."
    if [ "${SINGCTL_LOW_MEMORY:-0}" = "1" ] && [ -f /tmp/sing-box-basic.log ]; then
        cap_singbox_log_256k /tmp/sing-box-basic.log
    else
        : > /tmp/sing-box-basic.log && chmod 0600 /tmp/sing-box-basic.log
    fi

    set -- -n sing-box -w /tmp
    if [ "$UJAIL_HAS_ENV" = "1" ]; then
        [ -n "${GOMEMLIMIT:-}" ] && set -- "$@" -e GOMEMLIMIT
        [ -n "${GOGC:-}" ] && set -- "$@" -e GOGC
    fi
    if [ "$UJAIL_PROC_MODE" = "flag" ]; then
        set -- "$@" -p
    fi
    local ro_path
    for ro_path in /etc/ssl /etc/sing-box /usr/share/ca-certificates /etc/hosts /etc/resolv.conf; do
        if [ -e "$ro_path" ]; then
            set -- "$@" -r "$ro_path"
        fi
    done
    if [ "$UJAIL_PROC_MODE" = "ro" ] && [ -e /proc ]; then
        set -- "$@" -r /proc
    fi
    ujail "$@" -- "$SINGBOX_EXEC" run -c /tmp/sing-box-work/config.json >>/tmp/sing-box-basic.log 2>&1 &
    UJAIL_PID=$!

    sleep 1
    if is_ujail_singbox_running && wait_tproxy_ready; then
        cap_singbox_log_256k /tmp/sing-box-basic.log
        echo_succ "sing-box 启动成功 运行模式--TProxy(基础沙盒)"
        echo_succ "沙盒特性: 进程隔离 + 临时目录访问"
        return
    fi

    # 5. 基础沙盒失败，降级尝试最简沙盒（剥离 /proc 与非必需挂载，仍保留 /tmp、/etc/sing-box、/etc/ssl 与 /etc/resolv.conf）
    echo_warn "基础沙盒失败，尝试最简沙盒..."
    kill "$UJAIL_PID" 2>/dev/null || true
    pkill -f "ujail.*sing-box" 2>/dev/null || true

    if [ "${SINGCTL_LOW_MEMORY:-0}" = "1" ] && [ -f /tmp/sing-box-simple.log ]; then
        cap_singbox_log_256k /tmp/sing-box-simple.log
    else
        : > /tmp/sing-box-simple.log && chmod 0600 /tmp/sing-box-simple.log
    fi
    set -- -n sing-box -w /tmp
    if [ "$UJAIL_HAS_ENV" = "1" ]; then
        [ -n "${GOMEMLIMIT:-}" ] && set -- "$@" -e GOMEMLIMIT
        [ -n "${GOGC:-}" ] && set -- "$@" -e GOGC
    fi
    [ -e /etc/sing-box ] && set -- "$@" -r /etc/sing-box
    [ -e /etc/ssl ] && set -- "$@" -r /etc/ssl
    [ -e /etc/resolv.conf ] && set -- "$@" -r /etc/resolv.conf
    ujail "$@" -- "$SINGBOX_EXEC" run -c /tmp/sing-box-work/config.json >>/tmp/sing-box-simple.log 2>&1 &
    UJAIL_PID=$!

    sleep 1
    if is_ujail_singbox_running && wait_tproxy_ready; then
        cap_singbox_log_256k /tmp/sing-box-simple.log
        echo_succ "sing-box 启动成功 运行模式--TProxy(最简沙盒)"
        echo_succ "沙盒特性: 基础进程隔离"
        return
    fi

    # 6. 所有沙盒模式失败，回退到普通模式
    echo_warn "所有沙盒模式失败，回退到普通模式..."
    echo_warn "查看日志: /tmp/ujail-test.log, /tmp/sing-box-basic.log 和 /tmp/sing-box-simple.log"
    kill "$UJAIL_PID" 2>/dev/null || true
    pkill -f "ujail.*sing-box" 2>/dev/null || true

    start_singbox_plain
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
