#!/bin/sh

#################################################
# 描述: macOS sing-box TUN模式 启动脚本
# 用途: 在macOS上启动sing-box TUN模式代理服务
#################################################

# 确保能找到 sing-box 命令
export PATH="/usr/local/bin:/usr/bin:$PATH"

CONFIG_FILE="/etc/sing-box/config.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SANDBOX_STRICT="$SCRIPT_DIR/sing-box-sandbox.sb"
SANDBOX_LOOSE="$SCRIPT_DIR/sing-box-sandbox-loose.sb"
CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
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

echo_info() {
    printf "${GREEN}%s [INFO] %s${NC}\n" "$(timestamp)" "$1"
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

# 检查 macOS 沙盒是否可用
check_sandbox_available() {
    if ! command -v sandbox-exec >/dev/null 2>&1; then
        echo_warn "sandbox-exec 不可用，跳过沙盒模式"
        return 1
    fi
    
    # 检查自定义沙盒配置文件
    if [ ! -f "$SANDBOX_STRICT" ]; then
        echo_warn "自定义沙盒配置文件不存在: $SANDBOX_STRICT"
        return 1
    fi
    
    # 测试自定义沙盒配置
    if ! sandbox-exec -f "$SANDBOX_STRICT" /bin/echo "test" >/dev/null 2>&1; then
        echo_warn "自定义沙盒配置测试失败"
        return 1
    fi
    
    echo_info "沙盒环境检查通过"
    return 0
}

# 测试自定义沙盒配置
test_custom_sandbox() {
    local sandbox_file="$1"
    local test_name="$2"
    
    echo_info "测试${test_name}沙盒配置..."
    
    # 测试基础沙盒功能
    if ! sandbox-exec -f "$sandbox_file" /bin/echo "sandbox test" >/tmp/sandbox-test.log 2>&1; then
        echo_warn "${test_name}沙盒配置测试失败，查看 /tmp/sandbox-test.log"
        return 1
    fi
    
    # 测试 sing-box 版本查询（不启动服务）
    if ! sandbox-exec -f "$sandbox_file" sing-box version >/tmp/sandbox-singbox-test.log 2>&1; then
        echo_warn "${test_name}沙盒下 sing-box 无法运行，查看 /tmp/sandbox-singbox-test.log"
        return 1
    fi
    
    echo_succ "${test_name}沙盒配置测试通过"
    return 0
}

# 使用自定义沙盒配置启动 sing-box
start_with_custom_sandbox() {
    local sandbox_file="$1"
    local mode_name="$2"
    
    echo_succ "使用${mode_name}沙盒启动 sing-box..."
    
    # 使用自定义沙盒启动 sing-box
    sudo sandbox-exec -f "$sandbox_file" sing-box run -c "$CONFIG_FILE" >/tmp/sing-box-sandbox.log 2>&1 &
    local pid=$!
    
    echo_info "sing-box 沙盒进程已启动，PID: $pid"
    
    # 等待服务启动
    sleep 3
    
    # 检查进程是否还在运行
    if kill -0 $pid 2>/dev/null; then
        # 进程存在，检查是否是我们的 sing-box 进程
        if ps -p $pid | grep -q "sing-box"; then
            echo_succ "sing-box 启动成功 (${mode_name}沙盒模式)"
            echo_info "沙盒特性: 自定义翻墙优化沙盒保护"
            echo_info "安全限制: 禁止执行其他程序 + 限制系统目录写入"
            echo_info "日志文件: /tmp/sing-box-sandbox.log"
            return 0
        fi
    fi
    
    echo_warn "${mode_name}沙盒启动失败，查看日志: /tmp/sing-box-sandbox.log"
    return 1
}

# 原生模式启动（无沙盒）
start_without_sandbox() {
    echo_warn "回退到原生模式启动 sing-box（无沙盒保护）..."
    
    sudo sing-box run -c "$CONFIG_FILE" >/dev/null 2>&1 &
    local pid=$!
    echo_info "sing-box 进程已启动，PID: $pid"
    
    sleep 3
    if pgrep "sing-box" > /dev/null; then
        echo_succ "sing-box 启动成功 (原生模式，无沙盒)"
        echo_warn "注意: 未使用沙盒保护，安全性较低"
        return 0
    else
        error_exit "sing-box 启动失败，请检查日志"
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
    echo_info "尝试使用自定义沙盒保护启动..."
    
    # 策略1: 检查沙盒是否可用
    if check_sandbox_available; then
        echo_info "开始自定义沙盒模式启动流程..."
        
        # 策略2: 尝试自定义沙盒模式（专为翻墙优化）
        if test_custom_sandbox "$SANDBOX_STRICT" "自定义"; then
            echo_info "尝试自定义沙盒模式启动..."
            if start_with_custom_sandbox "$SANDBOX_STRICT" "自定义"; then
                return 0  # 成功启动，退出函数
            fi
            echo_warn "自定义沙盒模式启动失败，尝试宽松模式..."
        else
            echo_warn "自定义沙盒配置测试失败，尝试宽松模式..."
        fi
        
        # 策略3: 尝试宽松沙盒模式（备选方案）
        if [ -f "$SANDBOX_LOOSE" ] && test_custom_sandbox "$SANDBOX_LOOSE" "宽松"; then
            echo_info "尝试宽松沙盒模式启动..."
            if start_with_custom_sandbox "$SANDBOX_LOOSE" "宽松"; then
                return 0  # 成功启动，退出函数
            fi
            echo_warn "宽松沙盒模式启动失败，回退到原生模式..."
        fi
        
        # 清理失败的沙盒测试日志
        rm -f /tmp/sandbox-test.log /tmp/sandbox-singbox-test.log /tmp/sing-box-sandbox.log 2>/dev/null || true
    else
        echo_warn "沙盒环境不可用，使用原生模式..."
    fi
    
    # 策略4: 原生模式启动（最后回退方案）
    echo_warn "所有沙盒模式尝试失败或不可用"
    start_without_sandbox
}

main() {
    init_env
    start_singbox
}

main