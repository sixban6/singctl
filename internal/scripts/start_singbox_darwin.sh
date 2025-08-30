#!/bin/sh

#################################################
# 描述: macOS sing-box TUN模式 启动脚本
# 用途: 在macOS上启动sing-box TUN模式代理服务
#################################################

# 确保能找到 sing-box 命令
export PATH="/usr/local/bin:/usr/bin:$PATH"

CONFIG_FILE="/etc/sing-box/config.json"
CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m'

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# 错误处理函数
error_exit() {
    printf "${RED}错误: %s${NC}\n" "$1"
    exit 1
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
        echo_warn "网络连接检查失败，但将继续启动服务"
    fi
}

init_env() {
    # 停止现有的 sing-box 进程
    if pgrep "sing-box" > /dev/null; then
        echo_succ "发现运行中的 sing-box 进程，正在停止..."
        pkill sing-box
        sleep 2
        # 如果还在运行，强制终止
        if pgrep "sing-box" > /dev/null; then
            pkill -9 sing-box
            echo_succ "已强制停止现有 sing-box 服务"
        else
            echo_succ "已停止现有 sing-box 服务"
        fi
    else
        echo_succ "没有运行中的 sing-box 服务"
    fi

    # 检查必要命令是否安装
    check_command "sing-box"
    check_command "ping"

    # 检查网络
    check_network

    # 创建配置目录
    if [ ! -d "/etc/sing-box" ]; then
        sudo mkdir -p /etc/sing-box
        echo_succ "已创建配置目录: /etc/sing-box"
    fi

    # 验证配置文件
    if [ ! -f "$CONFIG_FILE" ]; then
        error_exit "配置文件不存在: $CONFIG_FILE"
    fi

    if ! sing-box check -c "$CONFIG_FILE"; then
        error_exit "配置文件验证失败"
    fi
    echo_succ "配置文件验证通过"
}

start_singbox() {
    echo_succ "启动 sing-box 服务 (TUN模式)..."
    
    # macOS需要sudo权限来创建TUN设备
    sudo sing-box run -c "$CONFIG_FILE" > /dev/null 2>&1 &
    
    # 记录进程ID
    local pid=$!
    echo_succ "sing-box 进程已启动，PID: $pid"
    
    # 检查服务状态
    sleep 3
    if pgrep "sing-box" > /dev/null; then
        echo_succ "sing-box 启动成功 (TUN模式)"
        echo_succ "服务已在后台运行"
    else
        error_exit "sing-box 启动失败，请检查日志"
    fi
}

main() {
    init_env
    start_singbox
}

main