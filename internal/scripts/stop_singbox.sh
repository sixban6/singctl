#!/bin/sh

#################################################
# 描述: OpenWrt sing-box TProxy模式 停止脚本
# 用途: 停止 sing-box 服务并清理防火墙规则
#################################################

PROXY_FWMARK=1
PROXY_ROUTE_TABLE=100
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

# 检测 OpenWrt 版本
OPENWRT_MAIN_VERSION=$(sed -n 's/VERSION="\([0-9]*\).*/\1/p' /etc/os-release 2>/dev/null)

# 如果无法检测到版本，默认为旧版本（使用 iptables）
if [ -z "$OPENWRT_MAIN_VERSION" ]; then
    OPENWRT_MAIN_VERSION=22
fi

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

echo_succ() {
    echo -e "${CYAN}$1${NC}"
}

echo_err() {
    echo -e "${RED}$1${NC}"
}

# 错误处理函数
error_exit() {
    echo_err "$(timestamp) 错误: $1"
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
check_command "ip"

# 根据版本检查防火墙工具
if [ $OPENWRT_MAIN_VERSION -ge 23 ]; then
    check_command "nft"
else
    check_command "iptables"
fi

# 停止 sing-box 服务（优先处理沙盒实例）
if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null; then
    echo_succ "$(timestamp) 检测到沙盒运行的 sing-box，正在停止..."
    
    # 先尝试优雅停止
    killall sing-box 2>/dev/null
    sleep 2
    
    # 如果还在运行，强制终止
    if ps | grep -v grep | grep "ujail.*sing-box" > /dev/null; then
        killall -9 sing-box 2>/dev/null
        sleep 1
    fi
    
    # 清理 ujail 实例
    pkill -f "ujail.*sing-box" 2>/dev/null
    echo_succ "$(timestamp) 已停止 sing-box 沙盒实例"
    
elif pgrep "sing-box" > /dev/null; then
    echo_succ "$(timestamp) 检测到普通模式的 sing-box，正在停止..."
    # 先尝试正常终止
    killall sing-box 2>/dev/null
    sleep 1
    # 如果还在运行，强制终止
    if pgrep "sing-box" > /dev/null; then
        killall -9 sing-box 2>/dev/null
    fi
    echo_succ "$(timestamp) 已停止现有 sing-box 服务"
else
    echo_succ "$(timestamp) 没有运行中的 sing-box 服务"
fi

# 清理防火墙规则
if [ $OPENWRT_MAIN_VERSION -ge 23 ]; then
    echo_succ "$(timestamp) 清理 nftables 规则 (OpenWrt 23+)..."
    
    # 删除防火墙规则文件
    rm -f /etc/sing-box/singbox.nft && echo_succ "$(timestamp) 已删除防火墙规则文件"
    
    # 删除 sing-box 表
    nft delete table inet sing-box 2>/dev/null && echo_succ "$(timestamp) 已删除 sing-box 表"
else
    echo_succ "$(timestamp) 清理 iptables 规则 (OpenWrt 22-)..."
    
    # 清除 iptables 规则
    iptables -t mangle -F PREROUTING 2>/dev/null && echo_succ "$(timestamp) 已清理 PREROUTING 链"
    iptables -t mangle -F OUTPUT 2>/dev/null && echo_succ "$(timestamp) 已清理 OUTPUT 链"
    iptables -t mangle -F SING_BOX 2>/dev/null && echo_succ "$(timestamp) 已清理 SING_BOX 链"
    iptables -t mangle -X SING_BOX 2>/dev/null && echo_succ "$(timestamp) 已删除 SING_BOX 链"
fi

# 删除路由规则和清理路由表（IPv4）
ip rule del fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已删除 IPv4 路由规则"
ip route flush table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已清理 IPv4 路由表"

# 清理 IPv6 路由规则（如果有）
ip -6 rule del fwmark $PROXY_FWMARK table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已删除 IPv6 路由规则"
ip -6 route flush table $PROXY_ROUTE_TABLE 2>/dev/null && echo_succ "$(timestamp) 已清理 IPv6 路由表"

# 删除缓存
rm -f /etc/sing-box/cache.db && echo_succ "$(timestamp) 已清理缓存文件"

# 清理沙盒工作目录和日志文件
rm -rf /tmp/sing-box-work 2>/dev/null && echo_succ "$(timestamp) 已清理沙盒工作目录"
rm -f /tmp/ujail-test.log /tmp/sing-box-basic.log /tmp/sing-box-simple.log 2>/dev/null && echo_succ "$(timestamp) 已清理沙盒调试日志"

echo_succ "$(timestamp) 停止 sing-box 并清理完毕"