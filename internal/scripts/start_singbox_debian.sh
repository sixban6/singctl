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

LOCAL_IPV4='{127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255/32}'

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

# 清理函数
cleanup() {
    # 清理可能的残留规则
    iptables -t mangle -F SINGBOX 2>/dev/null || true
    iptables -t mangle -X SINGBOX 2>/dev/null || true
    nft delete table inet sing-box 2>/dev/null || true
    ip rule del table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 rule del table $PROXY_ROUTE_TABLE 2>/dev/null || true
}

# 检查命令是否存在
check_command() {
    local cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "$cmd 未安装，请先安装: apt install $cmd"
    fi
}

# 检查网络连接
check_network() {
    local ping_count=3
    local test_host="8.8.8.8"
    echo_succ "检查网络连接..."
    if ! ping -c $ping_count $test_host >/dev/null 2>&1; then
        echo_warn "网络连接检查失败，但将继续启动服务"
    fi
}

# 检查端口占用
check_port() {
    local port=$1
    if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
        echo_warn "端口 $port 已被占用，强制重启相关进程"
        pkill -f "sing-box" 2>/dev/null || true
        sleep 2
    fi
}

# 安装并配置 firejail 沙盒
install_firejail() {
    echo_info "检查 firejail 沙盒工具..."
    
    if ! command -v firejail >/dev/null 2>&1; then
        echo_info "firejail 未安装，开始自动安装..."
        
        # 更新包索引
        apt update -qq
        
        # 安装 firejail
        if apt install -y firejail; then
            echo_succ "firejail 安装成功"
        else
            echo_err "firejail 安装失败"
            return 1
        fi
    else
        echo_info "firejail 已安装"
    fi
    
    return 0
}

# 创建沙盒配置文件
create_debian_sandbox() {
    echo_info "创建 Debian 沙盒配置..."
    
    # 安装 firejail
    if ! install_firejail; then
        echo_warn "firejail 安装失败，将使用普通模式"
        return 1
    fi
        # 创建 firejail 配置文件
        cat > /etc/sing-box/sing-box.profile << 'EOF'
# Firejail profile for sing-box
# 支持所有翻墙协议的安全配置

# 网络访问
net none
netfilter

# 文件系统访问
private-etc sing-box,ssl,ca-certificates,nsswitch.conf,host.conf,hosts,resolv.conf
private-tmp
private-dev

# 允许必要的系统调用
seccomp
caps.drop all
nonewprivs
noroot

# 禁用危险功能
disable-mnt
apparmor
x11 none

# 允许的目录
whitelist /etc/sing-box
whitelist /tmp
whitelist /var/log
whitelist /dev/urandom
whitelist /dev/random

# 只读系统目录
read-only /usr
read-only /lib
read-only /lib64
read-only /bin
read-only /sbin

# 进程限制
rlimit-nofile 65536
rlimit-nproc 100
EOF
        echo_info "Firejail 配置已创建: /etc/sing-box/sing-box.profile"
        return 0
    fi
    
    # 检查是否支持 systemd 用户命名空间
    if systemctl --version >/dev/null 2>&1; then
        echo_info "将使用 systemd 安全特性"
        return 0
    fi
    
    echo_warn "未找到合适的沙盒工具，将使用普通模式"
    return 1
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
    
    # 创建沙盒环境
    create_debian_sandbox

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
    
    # 清理现有规则
    nft delete table inet sing-box 2>/dev/null || true
    
    # 创建规则文件
    cat > /etc/sing-box/singbox.nft << EOF
#!/usr/sbin/nft -f
# Debian sing-box nftables 配置
table inet sing-box {
    set LOCAL_IPV4_SET {
        type ipv4_addr
        flags interval
        auto-merge
        elements = $LOCAL_IPV4
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # 拒绝外部访问代理端口
        fib daddr type local meta l4proto { tcp, udp } th dport $TPROXY_PORT reject with icmpx type host-unreachable
        fib daddr type local accept

        # 放行局域网流量
        ip daddr @LOCAL_IPV4_SET accept
        ip6 daddr { ::1, fc00::/7, fe80::/10 } accept

        # 放行端口转发流量
        ct status dnat accept comment "Allow forwarded traffic"

        # DNS 透明代理
        meta l4proto { tcp, udp } th dport 53 tproxy to :$TPROXY_PORT accept comment "DNS transparent proxy"

        # TProxy 流量处理
        meta l4proto { tcp, udp } tproxy to :$TPROXY_PORT meta mark set $PROXY_FWMARK accept
    }

    chain output {
        type route hook output priority mangle; policy accept;

        # 放行已标记流量，防止回环
        meta mark $PROXY_FWMARK accept

        # 放行 IPv6 ICMP
        meta l4proto ipv6-icmp accept

        # DNS 流量标记
        meta l4proto { tcp, udp } th dport 53 meta mark set $PROXY_FWMARK accept

        # 放行局域网流量
        ip daddr @LOCAL_IPV4_SET accept
        ip6 daddr { ::1, fc00::/7, fe80::/10 } accept

        # 标记其他流量
        meta l4proto { tcp, udp } meta mark set $PROXY_FWMARK accept
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
    
    # PREROUTING 规则
    iptables -t mangle -I PREROUTING -j SINGBOX
    
    # 放行局域网
    iptables -t mangle -A SINGBOX -d 127.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX -d 10.0.0.0/8 -j RETURN
    iptables -t mangle -A SINGBOX -d 172.16.0.0/12 -j RETURN
    iptables -t mangle -A SINGBOX -d 192.168.0.0/16 -j RETURN
    iptables -t mangle -A SINGBOX -d 169.254.0.0/16 -j RETURN
    
    # DNS 重定向
    iptables -t mangle -A SINGBOX -p tcp --dport 53 -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A SINGBOX -p udp --dport 53 -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    
    # 其他流量重定向
    iptables -t mangle -A SINGBOX -p tcp -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    iptables -t mangle -A SINGBOX -p udp -j TPROXY --tproxy-mark $PROXY_FWMARK --on-port $TPROXY_PORT
    
    # OUTPUT 链规则
    iptables -t mangle -I OUTPUT -m mark --mark $PROXY_FWMARK -j RETURN
    iptables -t mangle -I OUTPUT -p tcp --dport 53 -j MARK --set-mark $PROXY_FWMARK
    iptables -t mangle -I OUTPUT -p udp --dport 53 -j MARK --set-mark $PROXY_FWMARK
    
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
    ip rule del table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 rule del table $PROXY_ROUTE_TABLE 2>/dev/null || true
    
    # 添加 IPv4 路由规则
    ip rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE
    ip route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip route add local default dev lo table $PROXY_ROUTE_TABLE
    
    # 添加 IPv6 路由规则
    ip -6 rule add fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE
    ip -6 route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
    ip -6 route add local default dev lo table $PROXY_ROUTE_TABLE
    
    echo_succ "路由规则配置完成"
}

# 启动 sing-box (支持沙盒)
start_singbox() {
    echo_succ "启动 sing-box 服务 (TProxy模式)..."
    
    # 尝试使用 firejail 沙盒
    if command -v firejail >/dev/null 2>&1 && [ -f /etc/sing-box/sing-box.profile ]; then
        echo_info "使用 firejail 沙盒模式启动..."
        
        # 使用 firejail 启动
        nohup firejail --profile=/etc/sing-box/sing-box.profile \
            --name=sing-box \
            sing-box run -c "$CONFIG_FILE" \
            >/var/log/sing-box.log 2>&1 &
            
        sleep 3
        if pgrep -f "firejail.*sing-box" >/dev/null; then
            echo_succ "sing-box 启动成功 (firejail 沙盒模式)"
            echo_info "沙盒特性: 文件系统隔离 + 网络过滤 + 系统调用限制"
            return 0
        else
            echo_warn "firejail 沙盒启动失败，尝试普通模式..."
        fi
    fi
    
    # 尝试使用 systemd 安全特性
    if systemctl --version >/dev/null 2>&1; then
        echo_info "使用 systemd 安全特性启动..."
        
        # 创建临时 systemd 服务
        cat > /etc/systemd/system/sing-box-temp.service << EOF
[Unit]
Description=sing-box temporary service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c $CONFIG_FILE
Restart=no
User=nobody
Group=nogroup

# 安全限制
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/sing-box /tmp /var/log
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
MemoryDenyWriteExecute=true

# 网络命名空间保持开放 (代理需要)
PrivateNetwork=false
EOF

        systemctl daemon-reload
        systemctl start sing-box-temp
        sleep 3
        
        if systemctl is-active --quiet sing-box-temp; then
            echo_succ "sing-box 启动成功 (systemd 安全模式)"
            echo_info "安全特性: 用户降权 + 文件系统保护 + 内存保护"
            return 0
        else
            echo_warn "systemd 安全模式启动失败，使用普通模式..."
            systemctl stop sing-box-temp 2>/dev/null || true
        fi
    fi
    
    # 普通模式启动
    echo_warn "使用普通模式启动 (无沙盒保护)..."
    nohup sing-box run -c "$CONFIG_FILE" >/var/log/sing-box.log 2>&1 &
    sleep 3
    
    if pgrep "sing-box" >/dev/null; then
        echo_succ "sing-box 启动成功 (普通模式)"
        echo_warn "注意: 未使用沙盒保护，建议安装 firejail"
    else
        error_exit "sing-box 启动失败，请检查日志: /var/log/sing-box.log"
    fi
}

# 主函数
main() {
    echo_info "开始配置 Debian sing-box TProxy 模式..."
    
    init_env
    setup_firewall
    setup_route
    start_singbox
    
    echo_succ "Debian sing-box TProxy 配置完成！"
    echo_info "配置文件: $CONFIG_FILE"
    echo_info "日志文件: /var/log/sing-box.log"
    echo_info "代理端口: $TPROXY_PORT"
}

# 捕获退出信号
trap cleanup EXIT INT TERM

# 执行主函数
main "$@"