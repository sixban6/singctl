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
MAX_RETRIES=3  # 最大重试次数
RETRY_DELAY=3  # 重试间隔时间（秒）
CONFIG_FILE="/etc/sing-box/config.json"
CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'
OPENWRT_MAIN_VERSION=$(sed -n 's/VERSION="\([0-9]*\).*/\1/p' /etc/os-release)
LOCAL_IPV4='{127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16}'
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

# 检查网络连接
check_network() {
    local ping_count=3
    local test_host="8.8.8.8"
    echo_succ "检查网络连接..."
    if ! ping -c $ping_count $test_host >/dev/null 2>&1; then
        error_exit "网络连接失败，请检查网络设置"
    fi
}

# 检查端口占用
check_port() {
    local port=$1
    if netstat -tuln | grep -q ":$port "; then
        echo_succ "端口 $port 已被占用.强制重启"
        pgrep "sing-box" | xargs kill -9
    fi
}

init_env() {
    # 停止 sing-box 服务
    if killall sing-box 2>/dev/null; then
        echo_succ "已停止现有 sing-box 服务"
    else
        echo_succ "没有运行中的 sing-box 服务"
    fi

    # 检查并删除已存在的 sing-box 表（如果存在）
    if nft list tables | grep -q 'inet sing-box'; then
        nft delete table inet sing-box
    fi

    # 检查是否以 root 权限运行
    if [ "$(id -u)" != "0" ]; then
        error_exit "此脚本需要 root 权限运行"
    fi

    # 检查必要命令是否安装
    check_command "sing-box"
    check_command "nft"
    check_command "ip"
    check_command "ping"
    check_command "netstat"

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

        chain prerouting {
            type filter hook prerouting priority mangle; policy accept;

            # 1.主要为了拒绝 外部尝试访问公网端口.
            fib daddr type local meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable
            #
            fib daddr type local accept

            # 放行局域网流量
            ip daddr @LOCAL_IPV4_SET accept
            ip6 daddr { ::1, fc00::/7, fe80::/10 } accept

            # 放行所有经过 DNAT 的流量.即端口转发流量
            ct status dnat accept comment "Allow forwarded traffic"

            # 2.劫持dns请求到sing-box
            meta l4proto { tcp, udp } th dport 53 tproxy to :$TPROXY_PORT accept comment "DNS透明代理"

            # 3.将其他流量标记并转发到 TProxy
            meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK accept
        }

        chain output {
            type route hook output priority mangle; policy accept;

            # 1.放行标记过的流量.防止回环问题.
            meta mark 0x1 accept

            # 2.放行ipv6的icmp基础流量
            meta l4proto ipv6-icmp accept comment "Allow ICMPv6 traffic"

            # 3.并放行DNS流量
            meta l4proto { tcp, udp } th dport 53 meta mark set $PROXY_FWMARK accept

            # 4.放行局域网流量
            ip daddr @LOCAL_IPV4_SET accept
            ip6 daddr { ::1, fc00::/7, fe80::/10 } accept

            # 5.标记其余流量
            meta l4proto { tcp, udp } meta mark set $PROXY_FWMARK accept
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
  echo "setup_iptables"
}

setup_firewall() {
    if [ $OPENWRT_MAIN_VERSION -ge 23 ]
    then
        setup_nft
    else
        setup_iptables
    fi
}

setup_route() {
    echo_succ "初始化IPV4路由"
    # 配置路由规则
    ip rule del table $PROXY_ROUTE_TABLE >/dev/null 2>&1  # 删除已存在的规则
    ip rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE

    # 清理并添加路由
    ip route flush table $PROXY_ROUTE_TABLE >/dev/null 2>&1
    ip route add local default dev lo table $PROXY_ROUTE_TABLE

    echo_succ "初始化IPV6路由"
    # 配置 IPv6 路由规则
    ip -6 rule del table $PROXY_ROUTE_TABLE >/dev/null 2>&1  # 删除已存在的规则
    ip -6 rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE

    # 清理并添加 IPv6 路由
    ip -6 route flush table $PROXY_ROUTE_TABLE >/dev/null 2>&1
    ip -6 route replace local default dev lo table $PROXY_ROUTE_TABLE
}

start_singbox() {
    # 检查ujail是否可用
    if ! command -v ujail >/dev/null 2>&1; then
        echo_warn "ujail 不可用，使用普通模式启动 sing-box"
        sing-box run -c "/etc/sing-box/config.json" >/dev/null 2>&1 &
        sleep 2
        if pgrep "sing-box" > /dev/null; then
           echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
        else
           error_exit "sing-box 启动失败，请检查日志"
        fi
        return
    fi

    # 创建安全配置文件
    echo_succ "创建安全沙盒配置..."
    mkdir -p /tmp/sing-box-security
    
    # 创建capabilities配置文件 - 只保留网络必需权限
    cat > /tmp/sing-box-security/capabilities.drop << EOF
CAP_AUDIT_CONTROL
CAP_AUDIT_READ
CAP_AUDIT_WRITE
CAP_BLOCK_SUSPEND
CAP_CHOWN
CAP_DAC_OVERRIDE
CAP_DAC_READ_SEARCH
CAP_FOWNER
CAP_FSETID
CAP_IPC_LOCK
CAP_IPC_OWNER
CAP_KILL
CAP_LEASE
CAP_LINUX_IMMUTABLE
CAP_MAC_ADMIN
CAP_MAC_OVERRIDE
CAP_MKNOD
CAP_SETFCAP
CAP_SETGID
CAP_SETPCAP
CAP_SETUID
CAP_SYS_ADMIN
CAP_SYS_BOOT
CAP_SYS_CHROOT
CAP_SYS_MODULE
CAP_SYS_NICE
CAP_SYS_PACCT
CAP_SYS_PTRACE
CAP_SYS_RAWIO
CAP_SYS_RESOURCE
CAP_SYS_TIME
CAP_SYS_TTY_CONFIG
CAP_SYSLOG
CAP_WAKE_ALARM
EOF

    echo_succ "启动 sing-box 服务(增强沙盒模式)..."
    
    # 使用ujail启动sing-box - 网络命名空间 + capabilities限制
    ujail -n sing-box \
          -C /tmp/sing-box-security/capabilities.drop \
          -c \
          -r /etc/sing-box \
          -r /usr/bin/sing-box \
          -r /lib \
          -r /usr/lib \
          -w /tmp \
          -p \
          -- sing-box run -c /etc/sing-box/config.json >/tmp/sing-box.log 2>&1 &

    UJAIL_PID=$!
    
    # 检查服务状态
    sleep 3
    if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null; then
       echo_succ "sing-box 启动成功 运行模式--TProxy(增强沙盒)"
       echo_succ "沙盒特性: capabilities限制 + 文件系统隔离"
    else
       echo_warn "增强沙盒启动失败，尝试简单沙盒模式..."
       # 清理失败的ujail
       kill $UJAIL_PID 2>/dev/null || true
       pkill -f "ujail.*sing-box" 2>/dev/null || true
       
       # 尝试简单沙盒模式
       ujail -n sing-box -c -- sing-box run -c /etc/sing-box/config.json >/tmp/sing-box-simple.log 2>&1 &
       UJAIL_PID=$!
       
       sleep 3
       if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null; then
          echo_succ "sing-box 启动成功 运行模式--TProxy(简单沙盒)"
       else
          echo_warn "沙盒模式均失败，回退到普通模式..."
          echo_warn "查看日志: /tmp/sing-box.log 和 /tmp/sing-box-simple.log"
          # 清理ujail残留
          kill $UJAIL_PID 2>/dev/null || true
          pkill -f "ujail.*sing-box" 2>/dev/null || true
          # 使用普通模式启动
          sing-box run -c "/etc/sing-box/config.json" >/dev/null 2>&1 &
          sleep 2
          if pgrep "sing-box" > /dev/null; then
             echo_succ "sing-box 启动成功 运行模式--TProxy(普通模式)"
          else
             error_exit "sing-box 启动失败，请检查配置和日志"
          fi
       fi
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

main() {
  init_env
  setup_firewall
  setup_route
  start_singbox
}

main


