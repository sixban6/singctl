#!/bin/sh

#################################################
# 描述: macOS sing-box TUN模式 停止脚本
# 用途: 在macOS上停止sing-box TUN模式代理服务
#################################################

# 确保能找到 sing-box 命令
export PATH="/usr/local/bin:/usr/bin:$PATH"

CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

echo_succ() {
    printf "${CYAN}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_warn() {
    printf "${YELLOW}%s %s${NC}\n" "$(timestamp)" "$1"
}

echo_info() {
    printf "${GREEN}%s [INFO] %s${NC}\n" "$(timestamp)" "$1"
}

# 错误处理函数
error_exit() {
    printf "${RED}%s 错误: %s${NC}\n" "$(timestamp)" "$1" >&2
    exit "${2:-1}"
}

# 捕获中断信号以进行清理
trap 'error_exit "脚本被中断"' INT TERM

# 检测沙盒进程
check_sandbox_processes() {
    # 检查是否有 sandbox-exec 运行的 sing-box 进程
    if pgrep -f "sandbox-exec.*sing-box" >/dev/null 2>&1; then
        echo_info "检测到沙盒模式的 sing-box 进程"
        return 0
    fi
    
    # 检查是否有预定义沙盒配置的进程
    if pgrep -f "sandbox-exec -n.*sing-box" >/dev/null 2>&1; then
        echo_info "检测到预定义沙盒模式的 sing-box 进程"
        return 0
    fi
    
    return 1
}

# 停止沙盒进程
stop_sandbox_processes() {
    echo_info "停止沙盒模式的 sing-box 进程..."
    
    # 获取所有相关的进程ID
    local sandbox_pids
    local singbox_pids
    
    # 查找 sandbox-exec 进程
    sandbox_pids=$(pgrep -f "sandbox-exec.*sing-box" 2>/dev/null || echo "")
    
    # 查找在沙盒中运行的 sing-box 进程
    singbox_pids=$(pgrep -f "sing-box run" 2>/dev/null || echo "")
    
    # 首先尝试优雅停止
    if [ -n "$sandbox_pids" ]; then
        echo_info "尝试优雅停止沙盒进程..."
        for pid in $sandbox_pids; do
            kill -TERM "$pid" 2>/dev/null || true
        done
        
        # 等待进程停止
        sleep 2
    fi
    
    if [ -n "$singbox_pids" ]; then
        echo_info "尝试优雅停止 sing-box 进程..."
        for pid in $singbox_pids; do
            kill -TERM "$pid" 2>/dev/null || true
        done
        
        sleep 2
    fi
    
    # 检查是否还有进程运行，如果有就强制终止
    if pgrep -f "sandbox-exec.*sing-box" >/dev/null 2>&1; then
        echo_warn "优雅停止失败，强制终止沙盒进程..."
        pkill -KILL -f "sandbox-exec.*sing-box" 2>/dev/null || true
        sleep 1
    fi
    
    if pgrep -f "sing-box run" >/dev/null 2>&1; then
        echo_warn "强制终止剩余的 sing-box 进程..."
        pkill -KILL -f "sing-box run" 2>/dev/null || true
        sleep 1
    fi
    
    # 验证是否完全停止
    if pgrep -f "sandbox-exec.*sing-box" >/dev/null 2>&1 || pgrep -f "sing-box run" >/dev/null 2>&1; then
        echo_warn "部分进程可能仍在运行，请手动检查"
        return 1
    fi
    
    echo_succ "沙盒模式的 sing-box 进程已停止"
    return 0
}

# 停止普通 sing-box 进程
stop_normal_processes() {
    echo_info "停止普通模式的 sing-box 进程..."
    
    # 先尝试正常终止
    pkill sing-box 2>/dev/null || true
    sleep 2
    
    # 如果还在运行，强制终止
    if pgrep "sing-box" >/dev/null 2>&1; then
        echo_info "正在强制终止 sing-box 进程..."
        pkill -9 sing-box 2>/dev/null || true
        sleep 1
    fi
    
    # 检查是否完全停止
    if pgrep "sing-box" >/dev/null 2>&1; then
        echo_warn "部分 sing-box 进程可能仍在运行"
        return 1
    fi
    
    echo_succ "普通模式的 sing-box 进程已停止"
    return 0
}

# 清理沙盒相关文件
cleanup_sandbox_files() {
    echo_info "清理沙盒相关文件..."
    
    # 清理沙盒测试和日志文件
    rm -f /tmp/sandbox-test.log \
          /tmp/sandbox-singbox-test.log \
          /tmp/sing-box-sandbox.log 2>/dev/null || true
    
    echo_info "沙盒文件清理完成"
}

# 主停止函数
stop_sing_box_service() {
    echo_info "检查 sing-box 服务运行状态..."
    
    local has_sandbox=false
    local has_normal=false
    local stop_success=true
    
    # 检查沙盒进程
    if check_sandbox_processes; then
        has_sandbox=true
        if ! stop_sandbox_processes; then
            stop_success=false
        fi
    fi
    
    # 检查普通进程（非沙盒）
    if pgrep "sing-box" >/dev/null 2>&1; then
        has_normal=true
        if ! stop_normal_processes; then
            stop_success=false
        fi
    fi
    
    # 如果没有发现任何进程
    if [ "$has_sandbox" = false ] && [ "$has_normal" = false ]; then
        echo_succ "没有运行中的 sing-box 服务"
        cleanup_sandbox_files  # 清理可能存在的残留文件
        return 0
    fi
    
    # 最终验证所有进程都已停止
    if pgrep -f "sandbox-exec.*sing-box" >/dev/null 2>&1 || pgrep "sing-box" >/dev/null 2>&1; then
        echo_warn "警告: 部分 sing-box 进程可能仍在运行"
        echo_info "手动检查命令: ps aux | grep sing-box"
        stop_success=false
    fi
    
    # 清理沙盒相关文件
    cleanup_sandbox_files
    
    if [ "$stop_success" = true ]; then
        echo_succ "sing-box 服务已成功停止"
        echo_succ "macOS TUN模式停止完成"
    else
        error_exit "sing-box 停止过程中出现问题，请手动检查"
    fi
}

# 执行主停止函数
stop_sing_box_service