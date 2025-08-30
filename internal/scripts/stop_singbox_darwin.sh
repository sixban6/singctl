#!/bin/sh

#################################################
# 描述: macOS sing-box TUN模式 停止脚本
# 用途: 在macOS上停止sing-box TUN模式代理服务
#################################################

# 确保能找到 sing-box 命令
export PATH="/usr/local/bin:/usr/bin:$PATH"

CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

echo_succ() {
    printf "${CYAN}%s %s${NC}\n" "$(timestamp)" "$1"
}

# 错误处理函数
error_exit() {
    printf "${RED}%s 错误: %s${NC}\n" "$(timestamp)" "$1" >&2
    exit "${2:-1}"
}

# 捕获中断信号以进行清理
trap 'error_exit "脚本被中断"' INT TERM

# 停止 sing-box 服务
if pgrep "sing-box" > /dev/null; then
    echo_succ "发现运行中的 sing-box 进程，正在停止..."
    
    # 先尝试正常终止
    pkill sing-box
    sleep 2
    
    # 如果还在运行，强制终止
    if pgrep "sing-box" > /dev/null; then
        echo_succ "正在强制终止 sing-box 进程..."
        pkill -9 sing-box
        sleep 1
    fi
    
    # 再次检查是否完全停止
    if pgrep "sing-box" > /dev/null; then
        error_exit "无法停止 sing-box 进程，请手动检查"
    else
        echo_succ "sing-box 服务已成功停止"
    fi
else
    echo_succ "没有运行中的 sing-box 服务"
fi

# macOS TUN模式不需要额外的网络配置清理
echo_succ "macOS TUN模式停止完成"