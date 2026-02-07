#!/bin/sh

#################################################
# SingCtl 自动安装脚本
# 功能：从GitHub自动下载最新版本并安装
# 兼容：POSIX sh (busybox, dash, ash等)
#################################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'    # 青色，比蓝色更清晰
NC='\033[0m' # No Color

# 配置变量
GITHUB_REPO="sixban6/singctl"
# OpenWrt 使用 /usr/bin，其他系统使用 /usr/local/bin
if [ -f "/etc/openwrt_release" ] || [ -f "/etc/openwrt_version" ]; then
    INSTALL_DIR="/usr/bin"
else
    INSTALL_DIR="/usr/local/bin"
fi
CONFIG_DIR="/etc/singctl"
CONFIG_FILE="$CONFIG_DIR/singctl.yaml"
TEMP_DIR="/tmp/singctl-install"

# 获取当前时间
timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

# 检测终端颜色支持
supports_color() {
    [ -t 1 ] && [ -n "$TERM" ] && [ "$TERM" != "dumb" ]
}

# 输出函数 (POSIX兼容) - 修复颜色输出
echo_info() {
    if supports_color; then
        printf "\033[0;36m%s [INFO] %s\033[0m\n" "$(timestamp)" "$1"
    else
        printf "%s [INFO] %s\n" "$(timestamp)" "$1"
    fi
}

echo_success() {
    if supports_color; then
        printf "\033[0;32m%s [SUCCESS] %s\033[0m\n" "$(timestamp)" "$1"
    else
        printf "%s [SUCCESS] %s\n" "$(timestamp)" "$1"
    fi
}

echo_warning() {
    if supports_color; then
        printf "\033[0;33m%s [WARNING] %s\033[0m\n" "$(timestamp)" "$1"
    else
        printf "%s [WARNING] %s\n" "$(timestamp)" "$1"
    fi
}

echo_error() {
    if supports_color; then
        printf "\033[0;31m%s [ERROR] %s\033[0m\n" "$(timestamp)" "$1"
    else
        printf "%s [ERROR] %s\n" "$(timestamp)" "$1"
    fi
}

# 错误处理
error_exit() {
    echo_error "$1"
    cleanup
    exit 1
}

# 清理函数
cleanup() {
    if [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
        echo_info "清理临时目录: $TEMP_DIR"
    fi
}

# 捕获退出信号进行清理
trap cleanup EXIT

# 检查权限
check_permissions() {
    if [ "$(id -u)" -ne 0 ]; then
        echo_error "此脚本需要 root 权限运行"
        echo_info "请使用: sudo sh $0"
        exit 1
    fi
}

# 检查系统依赖
check_dependencies() {
    echo_info "检查系统依赖..."
    
    # POSIX兼容的依赖检查
    for dep in curl tar uname; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            error_exit "缺少依赖: $dep，请先安装"
        fi
    done
    
    echo_success "系统依赖检查通过"
}

# 检测系统架构
detect_system() {
    echo_info "检测系统信息..."
    
    # 避免使用有问题的 tr 命令，改用 case 语句
    OS_RAW=$(uname -s)
    case $OS_RAW in
        "Linux"|"LINUX")
            OS="linux"
            ;;
        "Darwin"|"DARWIN")
            OS="darwin" 
            ;;
        *)
            OS=$(echo "$OS_RAW" | tr 'A-Z' 'a-z')
            ;;
    esac
    
    ARCH=$(uname -m)
    
    
    # 标准化架构名称
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        armv7l)
            ARCH="armv7"
            ;;
        *)
            error_exit "不支持的架构: $ARCH"
            ;;
    esac
    
    echo_info "系统: $OS, 架构: $ARCH"
    
    # 调试信息：显示实际的uname输出
    echo_info "调试 - uname -s: $(uname -s)"
    echo_info "调试 - uname -m: $(uname -m)"
}

# 获取最新版本
get_latest_version() {
    echo_info "获取最新版本信息..."
    
    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local version
    
    if ! version=$(curl -s "$api_url" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'); then
        error_exit "获取版本信息失败"
    fi
    
    if [ -z "$version" ]; then
        error_exit "无法解析版本信息"
    fi
    
    LATEST_VERSION="$version"
    echo_success "最新版本: $LATEST_VERSION"
}

# 构建下载URL
build_download_url() {
    # 构建文件名
    local filename="singctl-${OS}-${ARCH}.tar.gz"
    DOWNLOAD_URL="https://ghfast.top/https://github.com/$GITHUB_REPO/releases/download/$LATEST_VERSION/$filename"
    
    echo_info "下载链接: $DOWNLOAD_URL"
}

# 下载和解压
# ------------------------------------------------------------
# 跨平台下载并解压 .tar.gz  
# 兼容：POSIX sh (busybox, dash, ash等)
# ------------------------------------------------------------

download_and_extract() {
    echo_info "开始下载安装包..."

    # 1. 创建临时目录
    mkdir -p "$TEMP_DIR"
    tar_file="$TEMP_DIR/singctl.tar.gz"

    # 2. 下载
    if ! curl -fL -o "$tar_file" "$DOWNLOAD_URL"; then
        error_exit "下载失败: $DOWNLOAD_URL"
    fi
    echo_success "下载完成"

    # 3. 解压
    echo_info "解压安装包..."
    if ! tar -xzf "$tar_file" -C "$TEMP_DIR"; then
        error_exit "解压失败"
    fi
    echo_success "解压完成"

    # 4. 修复可执行权限（POSIX 写法）
    echo_info "修复可执行权限..."
    # 用 find 查找所有文件，再用 test -x 判断是否可执行
    find "$TEMP_DIR" -type f | while IFS= read -r binary; do
        if [ -f "$binary" ] && [ -x "$binary" ]; then
            # 已经可执行就跳过（通常 tar 已带 x 位）
            :
        elif [ -f "$binary" ]; then
            # 否则统一加执行位
            chmod +x "$binary"
        fi

        # macOS 移除 quarantine 属性（非 macOS 时静默失败）
        case "$(uname -s)" in
            Darwin*)
                xattr -d com.apple.quarantine "$binary" 2>/dev/null || true
                ;;
        esac
    done

    echo_success "权限修复完成"
}

# 安装文件
install_files() {
    echo_info "开始安装..."

    # ----------------------------------------------------------
    # 1) 简化的查找二进制文件方式（兼容 busybox）
    # ----------------------------------------------------------
    local binary_file
    binary_file=$(find "$TEMP_DIR" -type f -name "singctl" | head -1)
    
    # 如果没找到，尝试查找可执行文件 (POSIX兼容写法)
    if [ ! -f "$binary_file" ]; then
        # 使用-executable替代-perm +111，更安全
        binary_file=$(find "$TEMP_DIR" -type f -name "*singctl*" | head -1)
        # 如果还是没找到，尝试更广泛的查找
        if [ ! -f "$binary_file" ]; then
            binary_file=$(find "$TEMP_DIR" -type f | grep singctl | head -1)
        fi
    fi

    [ -f "$binary_file" ] || error_exit "在解压的文件中未找到 singctl 二进制文件"

    # ----------------------------------------------------------
    # 2) 其余逻辑保持不变
    # ----------------------------------------------------------
    # 停止现有服务
    if command -v singctl >/dev/null 2>&1; then
        echo_info "停止现有 singctl 服务..."
        singctl stop 2>/dev/null || true
    fi

    # 复制二进制
    echo_info "安装二进制文件到 $INSTALL_DIR..."
    cp "$binary_file" "$INSTALL_DIR/singctl"
    chmod +x "$INSTALL_DIR/singctl"

    # 创建配置目录
    echo_info "创建配置目录: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"

    # 查找并安装配置文件
    config_file=$(find "$TEMP_DIR" -type f -name "singctl.yaml" | head -1)

    if [ -f "$config_file" ]; then
        if [ -f "$CONFIG_FILE" ]; then
            backup_file="${CONFIG_FILE}.backup.$(date +%s)"
            echo_warning "配置文件已存在，备份到: $backup_file"
            cp "$CONFIG_FILE" "$backup_file"
        fi

        cp "$config_file" "$CONFIG_FILE"
        chmod 644 "$CONFIG_FILE"
        echo_success "配置文件已安装到: $CONFIG_FILE"
    else
        echo_warning "未找到配置文件，请手动配置"
    fi

    # 如果使用的是 /usr/local/bin 且不在 PATH 中，添加 PATH 配置
    if [ "$INSTALL_DIR" = "/usr/local/bin" ] && ! echo "$PATH" | grep -q "/usr/local/bin"; then
        echo_info "将 /usr/local/bin 添加到 PATH..."
        setup_path
    fi

    echo_success "安装完成"
}

# 设置 PATH 环境变量
setup_path() {
    path_added=false
    
    # 尝试添加到各种可能的配置文件  
    profile_files="/etc/profile"
    
    for profile in $profile_files; do
        if [ -f "$profile" ] && [ -w "$profile" ]; then
            # 检查是否已经存在
            if ! grep -q "/usr/local/bin" "$profile" 2>/dev/null; then
                echo 'export PATH="/usr/local/bin:$PATH"' >> "$profile"
                echo_success "已添加 PATH 到 $profile"
                path_added=true
                break
            fi
        fi
    done
    
    if [ "$path_added" = "false" ]; then
        echo_warning "无法自动添加 PATH，请手动执行："
        echo "  export PATH=\"/usr/local/bin:\$PATH\""
        echo "  或将此命令添加到您的 shell 配置文件中"
    fi
}

# 配置订阅
configure_subscription() {
    echo_info "配置订阅连接..."
    
    # 强制从终端读取输入，即使在管道中运行
    if supports_color; then
        printf "\033[0;33m请输入您的订阅连接 (留空跳过):\033[0m\n"
    else
        printf "请输入您的订阅连接 (留空跳过):\n"
    fi
    
    printf "订阅URL: "
    
    # 直接从 /dev/tty 读取，绕过管道限制
    if [ -c /dev/tty ]; then
        read -r sub_url < /dev/tty
    else
        # 如果没有 /dev/tty，尝试其他方法
        exec < /dev/tty 2>/dev/null || {
            echo_warning "无法获取终端输入，创建配置模板"
            cat > "$CONFIG_FILE" <<EOF
subs:
  - name: "main"
    url: "YOUR_SUBSCRIPTION_URL_HERE"
    skip_tls_verify: false
    remove-emoji: true

github:
  mirror_url: "https://ghfast.top"
EOF
            echo_warning "请手动编辑配置文件: $CONFIG_FILE"
            return 0
        }
        read -r sub_url
    fi

    [ -z "$sub_url" ] && { echo_info "跳过订阅配置"; return 0; }

    # 直接生成全新的 subs 段落覆盖原文件
    cat > "$CONFIG_FILE" <<EOF
subs:
  - name: "main"
    url: "$sub_url"
    skip_tls_verify: false
    remove-emoji: true

github:
  mirror_url: "https://ghfast.top"

gui:
  mac_url: "https://github.com/SagerNet/sing-box/releases/download/v1.13.0-rc.2/SFM-1.13.0-rc.2-Apple.pkg"
  win_url: "https://github.com/SagerNet/sing-box/releases/download/v1.13.0-rc.2/sing-box-1.13.0-rc.2-windows-amd64.zip"
  app_name: "SFM"
EOF

    echo_success "订阅连接已写入 $CONFIG_FILE"
}

# 验证安装
verify_installation() {
    echo_info "验证安装..."
    
    # 检查二进制文件
    if [ ! -f "$INSTALL_DIR/singctl" ]; then
        error_exit "二进制文件未安装"
    fi
    
    # 检查可执行性
    if ! "$INSTALL_DIR/singctl" version >/dev/null 2>&1; then
        error_exit "二进制文件无法执行"
    fi
    
    echo_success "安装验证通过"
}

# 显示完成信息
show_completion_info() {
    printf "\n"
    if supports_color; then
        printf "\033[0;32m========================================\033[0m\n"
        printf "\033[0;32m  SingCtl 安装完成！\033[0m\n"
        printf "\033[0;32m========================================\033[0m\n"
    else
        printf "========================================\n"
        printf "  SingCtl 安装完成！\n"
        printf "========================================\n"
    fi
    printf "\n"
    echo_info "安装位置: $INSTALL_DIR/singctl"
    echo_info "配置文件: $CONFIG_FILE"
    printf "\n"
    echo_info "常用命令:"
    echo " singctl version               - 查看版本信息"
    echo " singctl gen                   - 生成配置"
    echo " sudo singctl start            - 启动singbox服务"
    echo " sudo singctl stop             - 停止singbox服务"
    echo " sudo singctl install sb       - 安装 sing-box"
    echo " sudo singctl gen              - 生成配置到默认位置, 并备份原始配置"
    printf "\n"
    
    if [ -f "$CONFIG_FILE" ]; then
        echo_info "下一步操作:"
        echo "1. 编辑配置文件 (如需要): sudo nano $CONFIG_FILE"
        echo "2. 安装 sing-box: sudo singctl install sb"
        echo "3. 启动服务: sudo singctl start"
    else
        echo_warning "请手动创建并配置 $CONFIG_FILE"
    fi
    
    printf "\n"
}

# 检查 sing-box 是否已安装并获取版本
get_singbox_version() {
    if command -v sing-box >/dev/null 2>&1; then
        local version_output
        version_output=$(sing-box version 2>/dev/null | head -1)
        
        # 从输出中提取版本号，处理不同的版本格式
        # 例如: "sing-box version 1.12.0" 或 "1.12.0"
        local version
        version=$(echo "$version_output" | sed -n 's/.*\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
        
        if [ -n "$version" ]; then
            echo "$version"
            return 0
        fi
    fi
    return 1
}

# 比较版本号，检查是否大于等于指定版本
version_ge() {
    local current_version="$1"
    local required_version="$2"
    
    # 将版本号分解为主版本、次版本、修订版本
    local current_major current_minor current_patch
    local required_major required_minor required_patch
    
    current_major=$(echo "$current_version" | cut -d. -f1)
    current_minor=$(echo "$current_version" | cut -d. -f2)
    current_patch=$(echo "$current_version" | cut -d. -f3)
    
    required_major=$(echo "$required_version" | cut -d. -f1)
    required_minor=$(echo "$required_version" | cut -d. -f2)
    required_patch=$(echo "$required_version" | cut -d. -f3)
    
    # 比较主版本号
    if [ "$current_major" -gt "$required_major" ]; then
        return 0
    elif [ "$current_major" -lt "$required_major" ]; then
        return 1
    fi
    
    # 主版本号相同，比较次版本号
    if [ "$current_minor" -gt "$required_minor" ]; then
        return 0
    elif [ "$current_minor" -lt "$required_minor" ]; then
        return 1
    fi
    
    # 次版本号相同，比较修订版本号
    if [ "$current_patch" -ge "$required_patch" ]; then
        return 0
    else
        return 1
    fi
}

# 检查 sing-box 是否需要安装或更新
check_singbox_installation() {
    local required_version="1.12.0"
    local current_version
    
    echo_info "检查 sing-box 安装状态..."
    
    if current_version=$(get_singbox_version); then
        echo_info "检测到已安装的 sing-box 版本: $current_version"
        
        if version_ge "$current_version" "$required_version"; then
            echo_success "sing-box 版本 $current_version >= $required_version，无需重新安装"
            return 1  # 不需要安装
        else
            echo_warning "sing-box 版本 $current_version < $required_version，需要更新"
            return 0  # 需要安装/更新
        fi
    else
        echo_info "未检测到 sing-box 或无法获取版本信息，需要安装"
        return 0  # 需要安装
    fi
}

init_singbox_config() {
  # === 创建 /etc/sing-box 目录，但不创建空配置文件 ===
  # 让 singctl start 在第一次运行时生成正确的配置
  sudo mkdir -p /etc/sing-box
  echo_info "已创建 /etc/sing-box 目录，配置文件将在首次启动时生成"
}

# 主函数
main() {
    echo_info "开始安装 SingCtl..."
    printf "\n"
    
    check_permissions
    check_dependencies
    detect_system
    get_latest_version
    build_download_url
    download_and_extract
    install_files
    configure_subscription
    verify_installation
    show_completion_info
    init_singbox_config
    echo_success "安装脚本执行完成！"
    
    # 检查配置文件是否有效订阅地址
    if [ -f "$CONFIG_FILE" ] && ! grep -q "YOUR_SUBSCRIPTION_URL_HERE" "$CONFIG_FILE" 2>/dev/null; then
        echo_info "检测到有效配置，检查 sing-box 安装状态..."
        
        # 检查是否需要安装或更新 sing-box
        if check_singbox_installation; then
            echo_info "开始安装/更新 sing-box..."
            "$INSTALL_DIR/singctl" install sb
            echo_success "安装/更新 sing-box 成功"
        fi
        
        echo_info "尝试启动 sing-box..."
        "$INSTALL_DIR/singctl" start
        echo_success "sing-box 启动完成"
    else
        echo_warning "配置文件需要手动编辑或未配置有效订阅"
        echo_info "请先编辑配置文件: $CONFIG_FILE"  
        echo_info "然后运行: sudo singctl install sb && sudo singctl start"
    fi
}

# 执行主函数
main "$@"