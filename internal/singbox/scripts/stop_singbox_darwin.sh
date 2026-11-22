#!/bin/sh

#################################################
# 描述: macOS sing-box TUN模式 停止脚本
# 用途: 在macOS上停止sing-box TUN模式代理服务 (支持 launchd 优雅停止)
#################################################

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

PLIST_PATH="/Library/LaunchDaemons/com.singctl.sing-box.plist"

CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

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

error_exit() {
    printf "${RED}%s 错误: %s${NC}\n" "$(timestamp)" "$1" >&2
    exit "${2:-1}"
}

trap 'error_exit "脚本被中断"' INT TERM

# 清理遗留沙盒与临时文件
cleanup_temp_files() {
    rm -f /tmp/sing-box-sandbox* \
          /tmp/sandbox-*.log \
          /tmp/sandbox-test.log \
          /tmp/sandbox-singbox-test.log 2>/dev/null || true
}

# 停止 launchd 守护进程
stop_launchd_service() {
    if [ -f "$PLIST_PATH" ]; then
        echo_info "检测到 LaunchDaemon 配置，正在卸载 launchd 服务..."
        sudo launchctl unload -w "$PLIST_PATH" 2>/dev/null || true
        sudo rm -f "$PLIST_PATH"
        echo_info "已移除 $PLIST_PATH"
    fi
}

# 优雅停止任何残留的 sing-box 进程
graceful_stop_singbox() {
    if ! pgrep "sing-box" >/dev/null 2>&1; then
        return 0
    fi

    echo_info "发送 SIGTERM 信号通知 sing-box 优雅停止 (恢复系统 TUN/DNS 路由)..."
    sudo pkill -TERM sing-box 2>/dev/null || true

    # 最多等待 15 秒，确保 sing-box 完整清理 utun 接口和 DNS 配置
    local stopped=false
    for i in $(seq 1 15); do
        if ! pgrep "sing-box" >/dev/null 2>&1; then
            stopped=true
            break
        fi
        sleep 1
    done

    if [ "$stopped" = true ]; then
        echo_succ "sing-box 进程已优雅退出，系统网络已恢复"
        return 0
    fi

    # 15 秒超时仍未退出，才使用 SIGKILL 作为兜底保障
    echo_warn "sing-box 进程在 15 秒内未完成优雅退出，执行强制终止..."
    sudo pkill -KILL sing-box 2>/dev/null || true
    sleep 1

    if pgrep "sing-box" >/dev/null 2>&1; then
        echo_warn "警告: 仍有 sing-box 进程未停止，请手动检查: ps aux | grep sing-box"
        return 1
    fi

    return 0
}

stop_sing_box_service() {
    echo_info "开始停止 macOS sing-box 服务..."

    # 1. 卸载 launchd 服务
    stop_launchd_service

    # 2. 优雅停止进程并等待系统网络恢复
    if ! graceful_stop_singbox; then
        cleanup_temp_files
        error_exit "停止 sing-box 服务失败"
    fi

    # 3. 清理遗留临时文件
    cleanup_temp_files

    echo_succ "sing-box 服务已成功停止"
    echo_succ "macOS TUN模式停止完成"
}

stop_sing_box_service
