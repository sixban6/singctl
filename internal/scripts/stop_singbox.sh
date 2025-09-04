#!/bin/sh
PROXY_ROUTE_TABLE=100
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'
# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

echo_succ() {
    echo -e "${CYAN}$1${NC}"
}

# 错误处理函数
error_exit() {
    echo "$(timestamp) 错误: $1" >&2
    exit "${2:-1}"
}
# 检查命令是否存在
check_command() {
    local cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "$cmd 未安装，请安装后再运行此脚本"
    fi
}
# 捕获中断信号以进行清理
trap 'error_exit "脚本被中断"' INT TERM
# 检查是否以 root 权限运行
if [ "$(id -u)" != "0" ]; then
    error_exit "此脚本需要 root 权限运行"
fi
# 检查必要命令是否安装
check_command "sing-box"
check_command "nft"
check_command "ip"

# 停止 sing-box 服务（优先处理沙盒实例）
if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null; then
    echo_succ "$(timestamp) 检测到沙盒运行的 sing-box，正在停止..."
    
    # 先尝试优雅停止ujail容器
    pkill -TERM -f "ujail.*sing-box"
    sleep 2
    
    # 如果还在运行，强制终止
    if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null; then
        pkill -KILL -f "ujail.*sing-box"
        sleep 1
    fi
    echo_succ "$(timestamp) 已停止 sing-box 沙盒实例"
    
elif pgrep "sing-box" > /dev/null; then
    echo_succ "$(timestamp) 检测到普通模式的 sing-box，正在停止..."
    # 先尝试正常终止
    killall sing-box
    sleep 1
    # 如果还在运行，强制终止
    if pgrep "sing-box" > /dev/null; then
        killall -9 sing-box
    fi
    echo_succ "$(timestamp) 已停止现有 sing-box 服务"
else
    echo_succ "$(timestamp) 没有运行中的 sing-box 服务"
fi

# 删除防火墙规则文件
rm -f /etc/sing-box/singbox.nft && echo_succ "$(timestamp) 已删除防火墙规则文件"

# 删除 sing-box 表
nft delete table inet sing-box 2>/dev/null && echo_succ "$(timestamp) 已删除 sing-box 表"

# 删除路由规则和清理路由表
ip rule del fwmark 1 table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已删除路由规则"
ip route flush table $PROXY_ROUTE_TABLE && echo_succ "$(timestamp) 已清理路由表"

# 清理 IPv6 路由规则（如果有）
ip -6 rule del fwmark 1 table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已删除 IPv6 路由规则"
ip -6 route flush table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已清理 IPv6 路由表"

# 删除缓存
rm -f /etc/sing-box/cache.db && echo_succ "$(timestamp) 已清理缓存文件"

# 清理沙盒工作目录和日志文件
rm -rf /tmp/sing-box-work && echo_succ "$(timestamp) 已清理沙盒工作目录"
rm -f /tmp/ujail-test.log /tmp/sing-box-basic.log /tmp/sing-box-simple.log && echo_succ "$(timestamp) 已清理沙盒调试日志"