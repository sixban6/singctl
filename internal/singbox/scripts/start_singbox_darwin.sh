#!/bin/sh

#################################################
# 描述: macOS sing-box TUN模式 启动脚本
# 用途: 在macOS上启动sing-box TUN模式代理服务 (使用 launchd 守护进程)
#################################################

export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

CONFIG_FILE="/etc/sing-box/config.json"
PLIST_PATH="/Library/LaunchDaemons/com.singctl.sing-box.plist"
LOG_DIR="/var/log/sing-box"
STDOUT_LOG="$LOG_DIR/sing-box.log"
STDERR_LOG="$LOG_DIR/sing-box.err.log"

CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

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

# 查找 sing-box 二进制路径
find_singbox_bin() {
    if command -v sing-box >/dev/null 2>&1; then
        command -v sing-box
        return 0
    fi
    for path in "/opt/homebrew/bin/sing-box" "/usr/local/bin/sing-box" "/usr/bin/sing-box"; do
        if [ -x "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    return 1
}

# 检查网络连接
check_network() {
    local ping_count=2
    local test_host="8.8.8.8"
    echo_succ "检查网络连接..."
    if ! ping -c $ping_count $test_host >/dev/null 2>&1; then
        echo_warn "网络连接检查未通过，继续尝试启动服务"
    fi
}

init_env() {
    # 查找 sing-box
    SING_BOX_BIN=$(find_singbox_bin)
    if [ -z "$SING_BOX_BIN" ]; then
        error_exit "未找到 sing-box 可执行文件，请先安装 sing-box"
    fi
    echo_info "sing-box 路径: $SING_BOX_BIN"

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

    if ! "$SING_BOX_BIN" check -c "$CONFIG_FILE"; then
        error_exit "配置文件验证失败"
    fi
    echo_succ "配置文件验证通过"

    # 确保日志目录存在
    if [ ! -d "$LOG_DIR" ]; then
        sudo mkdir -p "$LOG_DIR"
        sudo chmod 755 "$LOG_DIR"
    fi
}

# 创建并注册 macOS launchd 守护进程
start_launchd_service() {
    echo_succ "配置 macOS launchd 守护进程..."

    # 如果已有服务在运行，先平滑卸载
    if [ -f "$PLIST_PATH" ]; then
        echo_info "检测到已有服务配置，先卸载旧服务..."
        sudo launchctl unload -w "$PLIST_PATH" 2>/dev/null || true
        sleep 1
    fi

    # 写入 LaunchDaemon plist
    cat <<EOF | sudo tee "$PLIST_PATH" > /dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.singctl.sing-box</string>
    <key>ProgramArguments</key>
    <array>
        <string>${SING_BOX_BIN}</string>
        <string>run</string>
        <string>-c</string>
        <string>${CONFIG_FILE}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>${STDOUT_LOG}</string>
    <key>StandardErrorPath</key>
    <string>${STDERR_LOG}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>
</dict>
</plist>
EOF

    sudo chown root:wheel "$PLIST_PATH"
    sudo chmod 644 "$PLIST_PATH"
    echo_info "已生成 LaunchDaemon plist: $PLIST_PATH"

    # 加载并启动守护进程
    echo_info "加载并启动 com.singctl.sing-box 服务..."
    if ! sudo launchctl load -w "$PLIST_PATH"; then
        error_exit "launchctl load 失败"
    fi

    # 轮询验证服务启动状态
    echo_info "等待 sing-box 初始化并建立 TUN 路由..."
    local started=false
    for i in $(seq 1 10); do
        if pgrep -f "${SING_BOX_BIN} run" >/dev/null 2>&1 || pgrep "sing-box" >/dev/null 2>&1; then
            started=true
            break
        fi
        sleep 1
    done

    if [ "$started" = true ]; then
        echo_succ "sing-box 启动成功 (launchd 守护进程模式)"
        echo_info "服务标签: com.singctl.sing-box"
        echo_info "标准日志: $STDOUT_LOG"
        echo_info "错误日志: $STDERR_LOG"
    else
        echo_err "sing-box 启动超时，请查看错误日志: $STDERR_LOG"
        exit 1
    fi
}

main() {
    init_env
    start_launchd_service
}

main
