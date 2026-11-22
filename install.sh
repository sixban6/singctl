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
IS_OPENWRT="false"
if [ -f "/etc/openwrt_release" ] || [ -f "/etc/openwrt_version" ]; then
    IS_OPENWRT="true"
    INSTALL_DIR="/usr/bin"
else
    INSTALL_DIR="/usr/local/bin"
fi
CONFIG_DIR="/etc/singctl"
CONFIG_FILE="$CONFIG_DIR/singctl.yaml"
TEMP_DIR="/tmp/singctl-install"
IS_FIRST_INSTALL="false"
if [ ! -f "$INSTALL_DIR/singctl" ] && [ ! -f "$CONFIG_FILE" ]; then
    IS_FIRST_INSTALL="true"
fi

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

# 捕获退出信号进行清理（作为测试函数库加载时不注册全局 trap）
if [ "${SINGCTL_INSTALL_LIB_ONLY:-0}" != "1" ]; then
    trap cleanup EXIT
fi

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

# 获取最新版本（优先 GitHub API -> releases/latest 302 重定向防限流 -> 国内镜像兜底）
get_latest_version() {
    echo_info "获取最新版本信息..."
    
    local api_url="https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    local latest_page="https://github.com/$GITHUB_REPO/releases/latest"
    local version=""
    
    # 1) 尝试 GitHub 官方 API（带超时保护）
    version=$(curl -fsSL --connect-timeout 8 --max-time 15 "$api_url" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1 || true)
    
    # 2) 若 API 被限流 (403/429) 或失败，利用 GitHub Web 302 重定向 URL 提取 tag（零 API 配额消耗）
    if [ -z "$version" ]; then
        local effective_url
        effective_url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --connect-timeout 8 --max-time 15 "$latest_page" 2>/dev/null || true)
        case "$effective_url" in
            */releases/tag/*)
                version=$(echo "$effective_url" | sed -E 's|.*/releases/tag/([^/?#]+).*|\1|')
                ;;
        esac
    fi

    # 3) 国内无代理环境兜底：通过多镜像获取版本元数据
    if [ -z "$version" ]; then
        for mirror_prefix in "https://ghfast.top" "https://gh-proxy.com"; do
            version=$(curl -fsSL --connect-timeout 8 --max-time 15 "$mirror_prefix/$api_url" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | head -1 || true)
            if [ -n "$version" ]; then
                echo_info "已通过镜像 ($mirror_prefix) 获取最新版本信息"
                break
            fi
        done
    fi
    
    if [ -z "$version" ]; then
        error_exit "无法获取或解析最新版本信息，请检查网络连接"
    fi
    
    LATEST_VERSION="$version"
    echo_success "最新版本: $LATEST_VERSION"
}

# 探测安装目标挂载点可用空间（KiB，兼容 BusyBox df 与 POSIX df -Pk）
probe_install_avail_kb() {
    if [ -n "${SINGCTL_MOCK_DISK_AVAIL_KB:-}" ]; then
        echo "$SINGCTL_MOCK_DISK_AVAIL_KB"
        return 0
    fi
    local check_dir="${INSTALL_DIR:-/usr/bin}"
    while [ ! -d "$check_dir" ] && [ "$check_dir" != "/" ] && [ "$check_dir" != "." ] && [ -n "$check_dir" ]; do
        check_dir=$(dirname "$check_dir")
    done
    [ -d "$check_dir" ] || check_dir="/"
    local avail=""
    avail=$(df -Pk "$check_dir" 2>/dev/null | awk 'NR==2 {print $4}')
    if [ -z "$avail" ]; then
        avail=$(df -k "$check_dir" 2>/dev/null | awk 'END {if (NF>=4) print $(NF-2)}')
    fi
    echo "$avail"
}

# 判断是否优先下载 -lite 客户端精简包（OpenWrt 低内存 <=512MB / MemAvailable <=256MB / 闪存 <100MB 或显式 --lite）
should_use_lite_package() {
    [ "${OS:-}" = "linux" ] || return 1

    local force_lite="false"
    local force_full="false"
    local explicit_server="false"
    local explicit_client="false"
    local arg

    for arg in "$@"; do
        case "$arg" in
            --lite)
                force_lite="true"
                ;;
            --full|--no-lite)
                force_full="true"
                ;;
            --server|-s|server)
                explicit_server="true"
                ;;
            --client|-c|client)
                explicit_client="true"
                ;;
        esac
    done

    [ "${SINGCTL_FORCE_LITE:-0}" = "1" ] && force_lite="true"
    [ "$force_full" = "true" ] && return 1
    [ "$force_lite" = "true" ] && return 0
    if [ "$explicit_server" = "true" ] || [ "${PRE_EXISTING_ROLE:-}" = "server" ]; then
        return 1
    fi

    local root_prefix="${SINGCTL_ROOT_PREFIX:-}"
    local is_owrt="false"
    if [ "${IS_OPENWRT:-false}" = "true" ] || [ -f "${root_prefix}/etc/openwrt_release" ] || [ -f "${root_prefix}/etc/openwrt_version" ]; then
        is_owrt="true"
    elif [ -r "${root_prefix}/etc/os-release" ] && grep -iq "openwrt" "${root_prefix}/etc/os-release" 2>/dev/null; then
        is_owrt="true"
    fi

    if [ "$is_owrt" != "true" ] && [ "$explicit_client" != "true" ]; then
        return 1
    fi

    local meminfo_path="${SINGCTL_MEMINFO_PATH:-${root_prefix}/proc/meminfo}"
    if [ -r "$meminfo_path" ]; then
        local mem_total_kb mem_avail_kb
        mem_total_kb=$(awk '/^MemTotal:/ {print $2; exit}' "$meminfo_path" 2>/dev/null || true)
        mem_avail_kb=$(awk '/^MemAvailable:/ {print $2; exit}' "$meminfo_path" 2>/dev/null || true)
        # MemTotal <= 512 MiB (524288 KiB) 或驱动预留后 MemAvailable <= 256 MiB (262144 KiB)
        if [ -n "$mem_total_kb" ] && [ "$mem_total_kb" -gt 0 ] 2>/dev/null && [ "$mem_total_kb" -le 524288 ] 2>/dev/null; then
            return 0
        fi
        if [ -n "$mem_avail_kb" ] && [ "$mem_avail_kb" -gt 0 ] 2>/dev/null && [ "$mem_avail_kb" -le 262144 ] 2>/dev/null; then
            return 0
        fi
    fi

    local avail_kb
    avail_kb=$(probe_install_avail_kb)
    # 目标分区可用空间 < 100 MiB (102400 KiB)
    if [ -n "$avail_kb" ] && [ "$avail_kb" -ge 0 ] 2>/dev/null && [ "$avail_kb" -lt 102400 ] 2>/dev/null; then
        return 0
    fi

    return 1
}

set_package_urls() {
    PACKAGE_FILENAME="$1"
    DIRECT_URL="https://github.com/$GITHUB_REPO/releases/download/$LATEST_VERSION/$PACKAGE_FILENAME"
    MIRROR_URL_1="https://ghfast.top/$DIRECT_URL"
    MIRROR_URL_2="https://gh-proxy.com/$DIRECT_URL"
    echo_info "目标安装包: $PACKAGE_FILENAME"
}

# 构建下载URL（OpenWrt 低内存/小闪存自动优先选择 -lite 精简包，不存在时回退标准包）
build_download_url() {
    local std_pkg="singctl-${OS}-${ARCH}.tar.gz"
    FALLBACK_PACKAGE_FILENAME=""
    if should_use_lite_package "$@"; then
        FALLBACK_PACKAGE_FILENAME="$std_pkg"
        echo_info "检测到低内存/小闪存路由器环境或 --lite 参数，优先选择轻量精简包"
        set_package_urls "singctl-${OS}-${ARCH}-lite.tar.gz"
    else
        set_package_urls "$std_pkg"
    fi
}

# 计算文件 sha256（兼容 GNU sha256sum / macOS shasum）
compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo ""
    fi
}

# 下载和解压
# ------------------------------------------------------------
# 跨平台下载并解压 .tar.gz  
# 兼容：POSIX sh (busybox, dash, ash等)
# 安全：sha256 校验和必须从 GitHub 直连获取（不走镜像），校验失败一律中止
# ------------------------------------------------------------

download_archive_from_sources() {
    local out_file="$1"
    echo_info "尝试从 GitHub 官方源直连下载: $DIRECT_URL"
    if curl -fL --connect-timeout 8 --retry 1 -o "$out_file" "$DIRECT_URL"; then
        echo_success "GitHub 官方源直连下载完成"
        return 0
    fi
    echo_warning "GitHub 直连超时或受阻，自动切换镜像 1 加速下载: $MIRROR_URL_1"
    if curl -fL --connect-timeout 10 --retry 2 -o "$out_file" "$MIRROR_URL_1"; then
        echo_success "镜像 1 (ghfast.top) 加速下载完成"
        return 0
    fi
    echo_warning "镜像 1 下载未成功，自动切换镜像 2 加速下载: $MIRROR_URL_2"
    if curl -fL --connect-timeout 10 --retry 2 -o "$out_file" "$MIRROR_URL_2"; then
        echo_success "镜像 2 (gh-proxy.com) 加速下载完成"
        return 0
    fi
    return 1
}

download_and_extract() {
    echo_info "开始下载安装包..."

    # 1. 创建临时目录
    mkdir -p "$TEMP_DIR"
    tar_file="$TEMP_DIR/singctl.tar.gz"

    # 2. 下载（优先直连 GitHub 保障海外 VPS 满速稳定，失败回退多镜像；若 -lite 包不存在则平滑回退标准包）
    if ! download_archive_from_sources "$tar_file"; then
        if [ -n "${FALLBACK_PACKAGE_FILENAME:-}" ] && [ "$PACKAGE_FILENAME" != "$FALLBACK_PACKAGE_FILENAME" ]; then
            echo_warning "轻量精简包 ($PACKAGE_FILENAME) 暂不可用，平滑回退下载标准安装包: $FALLBACK_PACKAGE_FILENAME"
            rm -f "$tar_file"
            local fallback_pkg="$FALLBACK_PACKAGE_FILENAME"
            FALLBACK_PACKAGE_FILENAME=""
            set_package_urls "$fallback_pkg"
            if ! download_archive_from_sources "$tar_file"; then
                error_exit "下载失败，所有下载源均不可达，请检查主机网络连接"
            fi
        else
            error_exit "下载失败，所有下载源均不可达，请检查主机网络连接"
        fi
    fi

    # 3. sha256 校验（优先从 GitHub 直连获取校验和，不可达时回退镜像并严格比对 SHA256）
    verify_checksum

    # 4. 解压并立即释放压缩包占用的 /tmp 内存盘空间
    echo_info "解压安装包..."
    if ! tar -xzf "$tar_file" -C "$TEMP_DIR"; then
        error_exit "解压失败"
    fi
    rm -f "$tar_file"
    echo_success "解压完成"

    # 5. 修复可执行权限（POSIX 写法）
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

# 校验下载包的 sha256
verify_checksum() {
    local filename="$PACKAGE_FILENAME"
    local checksums_url="https://github.com/$GITHUB_REPO/releases/download/$LATEST_VERSION/checksums.txt"
    local expected actual

    if [ "$SINGCTL_SKIP_CHECKSUM" = "1" ]; then
        echo_warning "SINGCTL_SKIP_CHECKSUM=1 已设置，跳过 sha256 校验（自担风险）"
        return 0
    fi

    echo_info "获取官方 SHA256 校验和文件 (checksums.txt)..."
    if ! curl -fsSL --connect-timeout 8 --retry 1 --max-time 30 -o "$TEMP_DIR/checksums.txt" "$checksums_url"; then
        echo_warning "GitHub 直连获取 checksums.txt 超时，尝试通过加速镜像获取..."
        if ! curl -fsSL --connect-timeout 8 --retry 1 --max-time 30 -o "$TEMP_DIR/checksums.txt" "https://ghfast.top/$checksums_url" && \
           ! curl -fsSL --connect-timeout 8 --retry 1 --max-time 30 -o "$TEMP_DIR/checksums.txt" "https://gh-proxy.com/$checksums_url"; then
            error_exit "无法获取 checksums.txt，已中止安装。请检查网络后重试；确要跳过请设置 SINGCTL_SKIP_CHECKSUM=1"
        fi
    fi

    expected=$(awk -v f="$filename" '$2 == f || $2 == "*"f {print tolower($1)}' "$TEMP_DIR/checksums.txt")
    if [ -z "$expected" ]; then
        error_exit "checksums.txt 中没有 $filename 的记录，拒绝安装"
    fi

    actual=$(compute_sha256 "$tar_file")
    if [ -z "$actual" ]; then
        error_exit "系统缺少 sha256sum/shasum，无法校验。请安装后重试或设置 SINGCTL_SKIP_CHECKSUM=1"
    fi

    if [ "$expected" != "$actual" ]; then
        error_exit "sha256 校验失败（安装包可能被篡改或损坏），已中止安装: 期望 $expected, 实际 $actual"
    fi
    echo_success "sha256 校验通过 ($filename)"
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
    # 2) 原子安装二进制（不提前停止现有 sing-box，避免软路由网关升级时断网导致后续无法拉取组件与订阅）
    # ----------------------------------------------------------
    echo_info "安装二进制文件到 $INSTALL_DIR..."
    cp "$binary_file" "$INSTALL_DIR/singctl.new"
    chmod +x "$INSTALL_DIR/singctl.new"
    mv -f "$INSTALL_DIR/singctl.new" "$INSTALL_DIR/singctl"

    # 创建配置目录
    echo_info "创建配置目录: $CONFIG_DIR"
    mkdir -p "$CONFIG_DIR"

    # 查找并安装配置目录
    configs_dir=$(find "$TEMP_DIR" -type d -name "configs" | head -1)

    if [ -d "$configs_dir" ]; then
        if [ -f "$CONFIG_FILE" ]; then
            backup_file="${CONFIG_FILE}.backup.$(date +%s)"
            echo_warning "主配置文件已存在，备份到: $backup_file"
            cp "$CONFIG_FILE" "$backup_file"

            echo_info "保留已有配置并执行配置合并迁移..."
            "$INSTALL_DIR/singctl" internal-migrate --config "$CONFIG_FILE" --template "$configs_dir/singctl.yaml" || echo_warning "配置合并迁移失败，保留现有配置"

            # 仅复制不存在的其余默认配置文件，绝不覆盖已有文件
            for f in "$configs_dir"/*; do
                fname=$(basename "$f")
                if [ "$fname" != "singctl.yaml" ] && [ ! -e "$CONFIG_DIR/$fname" ]; then
                    cp -r "$f" "$CONFIG_DIR/"
                fi
            done
        else
            echo_info "复制所有配置文件到: $CONFIG_DIR"
            cp -r "$configs_dir"/* "$CONFIG_DIR/"
        fi

        # 600：主配置含订阅地址/tailscale auth_key/cloudflare token 等敏感信息
        find "$CONFIG_DIR" -type f -name "*.yaml" -exec chmod 600 {} \;
        find "$CONFIG_DIR" -type f ! -name "*.yaml" -exec chmod 644 {} \;
        echo_success "配置文件检查与安装完成"
    else
        echo_warning "未找到配置目录，请手动配置"
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

# 校验合法单播 IPv4 地址（排除 0.x / 127.x / 组播 >=224 / 全广播）
is_valid_unicast_ipv4() {
    local ip="$1"
    case "$ip" in
        *[!0-9.]*|""|*..*|.*|*.)
            return 1
            ;;
    esac
    local o1 o2 o3 o4 extra
    IFS='.' read -r o1 o2 o3 o4 extra <<EOF
$ip
EOF
    [ -n "$o1" ] && [ -n "$o2" ] && [ -n "$o3" ] && [ -n "$o4" ] && [ -z "$extra" ] || return 1
    for oct in "$o1" "$o2" "$o3" "$o4"; do
        [ "$oct" -ge 0 ] 2>/dev/null && [ "$oct" -le 255 ] 2>/dev/null || return 1
    done
    if [ "$o1" -eq 0 ] || [ "$o1" -eq 127 ] || [ "$o1" -ge 224 ]; then
        return 1
    fi
    if [ "$ip" = "255.255.255.255" ]; then
        return 1
    fi
    return 0
}

# 自动探测本机局域网 IP、网卡与推荐主路由网关 IP（若当前默认网关缺失或自环本机，自动回退同网段 .1 / .254）
detect_lan_ip_and_iface() {
    DETECTED_LAN_IP=""
    DETECTED_LAN_IFACE=""
    DETECTED_MAIN_GW=""

    if command -v ip >/dev/null 2>&1; then
        DETECTED_LAN_IFACE=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
        DETECTED_MAIN_GW=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
        if [ -z "$DETECTED_LAN_IFACE" ]; then
            if ip link show br-lan >/dev/null 2>&1; then
                DETECTED_LAN_IFACE="br-lan"
            else
                DETECTED_LAN_IFACE=$(ip -o -4 addr show up scope global 2>/dev/null | awk '$2 !~ /^(lo|tailscale|tun|utun|wg|docker|veth)/ {print $2; exit}')
            fi
        fi
        if [ -n "$DETECTED_LAN_IFACE" ]; then
            DETECTED_LAN_IP=$(ip -o -4 addr show dev "$DETECTED_LAN_IFACE" scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4; exit}')
        fi
    elif [ "$OS" = "darwin" ] && command -v route >/dev/null 2>&1; then
        DETECTED_LAN_IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
        DETECTED_MAIN_GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')
        if [ -n "$DETECTED_LAN_IFACE" ] && command -v ipconfig >/dev/null 2>&1; then
            DETECTED_LAN_IP=$(ipconfig getifaddr "$DETECTED_LAN_IFACE" 2>/dev/null || true)
        fi
    fi

    if [ -z "$DETECTED_LAN_IP" ] && command -v uci >/dev/null 2>&1; then
        DETECTED_LAN_IP=$(uci -q get network.lan.ipaddr 2>/dev/null || true)
        [ -z "$DETECTED_LAN_IFACE" ] && DETECTED_LAN_IFACE="br-lan"
    fi

    # 若默认网关为空或等于本机 IP（自环），自动推导同网段 .1（若本机即为 .1 则推导 .254）
    if [ -z "$DETECTED_MAIN_GW" ] || [ "$DETECTED_MAIN_GW" = "$DETECTED_LAN_IP" ]; then
        if [ -n "$DETECTED_LAN_IP" ]; then
            local prefix
            prefix=$(echo "$DETECTED_LAN_IP" | awk -F. '{print $1"."$2"."$3}')
            if [ "${prefix}.1" != "$DETECTED_LAN_IP" ]; then
                DETECTED_MAIN_GW="${prefix}.1"
            else
                DETECTED_MAIN_GW="${prefix}.254"
            fi
        fi
    fi
}

# 探测上级主路由二层连通性
probe_gateway_reachable() {
    local target_ip="$1"
    if command -v ping >/dev/null 2>&1; then
        ping -c 1 -W 1 "$target_ip" >/dev/null 2>&1
        return $?
    fi
    return 0
}

# 原子更新 singctl.yaml 中的 gateway 配置段（严格保持 0600 权限）
write_gateway_config() {
    local gw_mode="$1"
    local main_gw_ip="$2"
    [ -f "$CONFIG_FILE" ] || return 0

    local tmp_cfg="${CONFIG_FILE}.gw.tmp"
    if grep -Eq '^gateway:[[:space:]]*(#.*)?$' "$CONFIG_FILE"; then
        awk -v m="$gw_mode" -v ip="$main_gw_ip" '
            BEGIN { in_gw = 0; wrote_m = 0; wrote_ip = 0 }
            /^gateway:[[:space:]]*(#.*)?$/ {
                in_gw = 1
                print
                next
            }
            in_gw && /^[^[:space:]#]/ {
                if (!wrote_m) { printf "  mode: \"%s\"\n", m; wrote_m = 1 }
                if (!wrote_ip) { printf "  main_router_ip: \"%s\"\n", ip; wrote_ip = 1 }
                in_gw = 0
            }
            in_gw && /^[[:space:]]+mode:/ {
                printf "  mode: \"%s\"\n", m
                wrote_m = 1
                next
            }
            in_gw && /^[[:space:]]+main_router_ip:/ {
                printf "  main_router_ip: \"%s\"\n", ip
                wrote_ip = 1
                next
            }
            { print }
            END {
                if (in_gw) {
                    if (!wrote_m) printf "  mode: \"%s\"\n", m
                    if (!wrote_ip) printf "  main_router_ip: \"%s\"\n", ip
                }
            }
        ' "$CONFIG_FILE" > "$tmp_cfg"
    else
        cat "$CONFIG_FILE" > "$tmp_cfg"
        printf "\ngateway:\n  mode: \"%s\"\n  main_router_ip: \"%s\"\n" "$gw_mode" "$main_gw_ip" >> "$tmp_cfg"
    fi
    chmod 600 "$tmp_cfg"
    mv -f "$tmp_cfg" "$CONFIG_FILE"
}

# 记录安装前是否已存在有效配置或系统服务（避免覆盖/模板拷贝后无法继承原角色）
PRE_EXISTING_ROLE=""
AUTO_YES="false"

# 检测运行安装前宿主机是否已有明确的服务端/客户端配置或系统服务
detect_existing_installed_role() {
    local root_prefix="${SINGCTL_ROOT_PREFIX:-}"
    local cfg_file="$CONFIG_FILE"
    if [ -n "$root_prefix" ] && [ "$CONFIG_FILE" = "/etc/singctl/singctl.yaml" ]; then
        cfg_file="${root_prefix}/etc/singctl/singctl.yaml"
    fi

    if [ -f "$cfg_file" ]; then
        local clean_cfg
        clean_cfg=$(sed 's/#.*//' "$cfg_file" 2>/dev/null || true)
        local nd sbd cf_key
        nd=$(printf '%s\n' "$clean_cfg" | awk '/^[[:space:]]*node_domain:/{gsub(/["'\''[:space:]]/, "", $2); print $2; exit}')
        sbd=$(printf '%s\n' "$clean_cfg" | awk '/^[[:space:]]*sb_domain:/{gsub(/["'\''[:space:]]/, "", $2); print $2; exit}')
        cf_key=$(printf '%s\n' "$clean_cfg" | awk '/^[[:space:]]*cf_dns_key:/{gsub(/["'\''[:space:]]/, "", $2); print $2; exit}')

        if [ -n "$nd" ] && [ "$nd" != "node.example.com" ] && [ "$nd" != "node.yourdomain.com" ]; then
            echo "server"
            return 0
        fi
        if [ -n "$sbd" ] && [ "$sbd" != "sub.yourdomain.com" ] && [ "$sbd" != "node.example.com" ] && [ "$sbd" != "node.yourdomain.com" ]; then
            echo "server"
            return 0
        fi
        if [ -n "$cf_key" ] && [ "$cf_key" != "your_cloudflare_api_token" ]; then
            echo "server"
            return 0
        fi

        if printf '%s\n' "$clean_cfg" | grep -Eq '^[[:space:]]*url:[[:space:]]*["'"'"']?https?://' && \
           ! printf '%s\n' "$clean_cfg" | grep -Eq '^[[:space:]]*url:[[:space:]]*["'"'"']?https://example\.com/subscription["'"'"']?[[:space:]]*$'; then
            echo "client"
            return 0
        fi
    fi

    if [ -f "${root_prefix}/etc/systemd/system/singctl-sub.service" ] || [ -f "${root_prefix}/etc/systemd/system/singctl-ui.service" ]; then
        echo "server"
        return 0
    fi
    if [ -f "${root_prefix}/etc/init.d/singctl-firewall" ]; then
        echo "client"
        return 0
    fi

    echo ""
}

# 校验是否为合法公网单播 IPv4（排除 RFC1918 私网、100.64/10 CGNAT、169.254/16 链路本地与 198.18/15 基准测试网段）
is_public_unicast_ipv4() {
    local ip="$1"
    is_valid_unicast_ipv4 "$ip" || return 1
    local o1 o2 o3 o4
    IFS='.' read -r o1 o2 o3 o4 <<EOF
$ip
EOF
    # 10.0.0.0/8
    [ "$o1" -eq 10 ] && return 1
    # 172.16.0.0/12
    [ "$o1" -eq 172 ] && [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 1
    # 192.168.0.0/16
    [ "$o1" -eq 192 ] && [ "$o2" -eq 168 ] && return 1
    # 100.64.0.0/10 (Tailscale / CGNAT)
    [ "$o1" -eq 100 ] && [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 1
    # 169.254.0.0/16 (Link-Local)
    [ "$o1" -eq 169 ] && [ "$o2" -eq 254 ] && return 1
    # 198.18.0.0/15 (Benchmarking)
    [ "$o1" -eq 198 ] && { [ "$o2" -eq 18 ] || [ "$o2" -eq 19 ]; } && return 1
    return 0
}

# 读取物理/主网络接口上的全局 IPv4 地址列表（支持通过 SINGCTL_MOCK_IPV4_LIST 在单测中注入）
list_global_ipv4_addrs() {
    if [ -n "${SINGCTL_MOCK_IPV4_LIST+x}" ]; then
        printf '%s\n' "$SINGCTL_MOCK_IPV4_LIST" | tr ', ' '\n\n' | grep -v '^$' || true
        return 0
    fi
    if command -v ip >/dev/null 2>&1; then
        ip -o -4 addr show up scope global 2>/dev/null | \
            awk '$2 !~ /^(lo|tailscale|tun|utun|wg|docker|veth|virbr|cni|flannel)/ {sub(/\/.*/, "", $4); print $4}'
    fi
}

# 检测是否运行在公有云 VPC（AWS/Oracle/GCP/Azure/阿里云/腾讯云/Vultr/DO/Linode/Hetzner 等）或 OpenVZ VPS
detect_cloud_vendor() {
    local root_prefix="${SINGCTL_ROOT_PREFIX:-}"
    local cloud_regex='Amazon|EC2|Google Compute|GoogleCloud|OracleCloud|Alibaba Cloud|Aliyun|Tencent Cloud|Huawei Cloud|DigitalOcean|Vultr|Choopa|Linode|Akamai Connected Cloud|Hetzner|OVH|Scaleway|Contabo|RackNerd|CloudCone|DMIT|BHost|Microsoft Azure'

    local dmi_file dmi_val
    for dmi_file in \
        "${root_prefix}/sys/class/dmi/id/sys_vendor" \
        "${root_prefix}/sys/class/dmi/id/product_name" \
        "${root_prefix}/sys/class/dmi/id/bios_vendor" \
        "${root_prefix}/sys/class/dmi/id/board_vendor" \
        "${root_prefix}/sys/class/dmi/id/chassis_asset_tag"; do
        if [ -r "$dmi_file" ]; then
            dmi_val=$(cat "$dmi_file" 2>/dev/null || true)
            if printf '%s\n' "$dmi_val" | grep -Eiq "$cloud_regex"; then
                printf '%s\n' "$dmi_val" | head -n 1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
                return 0
            fi
        fi
    done

    local ci_res="${root_prefix}/run/cloud-init/result.json"
    if [ -r "$ci_res" ]; then
        local ci_ds
        ci_ds=$(cat "$ci_res" 2>/dev/null || true)
        if printf '%s\n' "$ci_ds" | grep -Eiq 'DataSource(Ec2|GCE|Azure|Oracle|AliYun|TencentCloud|DigitalOcean|Vultr|Hetzner|Scaleway|OVH|OpenStack)'; then
            echo "Cloud-Init VPS"
            return 0
        fi
    fi

    if [ -d "${root_prefix}/proc/vz" ] && [ ! -d "${root_prefix}/proc/bc" ]; then
        echo "OpenVZ"
        return 0
    fi

    echo ""
}

# 五层零延迟环境角色自动识别（P1 历史继承 -> P2 客户端固件/桌面 -> P3 公网IP/云厂商VPC -> P4 私有局域网网关）
detect_runtime_role() {
    local root_prefix="${SINGCTL_ROOT_PREFIX:-}"
    DETECTED_ROLE=""
    DETECTED_ROLE_REASON=""

    if [ -n "${PRE_EXISTING_ROLE:-}" ]; then
        DETECTED_ROLE="$PRE_EXISTING_ROLE"
        DETECTED_ROLE_REASON="继承已有 SingCtl 配置角色"
        return 0
    fi

    if [ "$OS" = "darwin" ]; then
        DETECTED_ROLE="client"
        DETECTED_ROLE_REASON="macOS 客户端环境"
        return 0
    fi

    if [ "$IS_OPENWRT" = "true" ] || [ -f "${root_prefix}/etc/openwrt_release" ] || [ -f "${root_prefix}/etc/openwrt_version" ]; then
        DETECTED_ROLE="client"
        DETECTED_ROLE_REASON="OpenWrt / 软路由固件环境"
        return 0
    fi

    if [ -f "${root_prefix}/etc/armbian-release" ] || \
       { [ -r "${root_prefix}/proc/device-tree/model" ] && grep -Eiq 'Raspberry Pi|Orange Pi|NanoPi|FriendlyElec|Banana Pi|Rockchip' "${root_prefix}/proc/device-tree/model" 2>/dev/null; }; then
        DETECTED_ROLE="client"
        DETECTED_ROLE_REASON="Armbian / 开发板网关环境"
        return 0
    fi

    if [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ] || \
       { [ -d "${root_prefix}/usr/share/xsessions" ] && [ -n "$(ls "${root_prefix}/usr/share/xsessions" 2>/dev/null | head -n 1)" ]; }; then
        DETECTED_ROLE="client"
        DETECTED_ROLE_REASON="Linux 桌面图形环境"
        return 0
    fi

    local ip_addr
    for ip_addr in $(list_global_ipv4_addrs); do
        if is_public_unicast_ipv4 "$ip_addr"; then
            DETECTED_ROLE="server"
            DETECTED_ROLE_REASON="公网 IPv4 环境 (${ip_addr})"
            return 0
        fi
    done

    local cloud_vendor
    cloud_vendor=$(detect_cloud_vendor)
    if [ -n "$cloud_vendor" ]; then
        DETECTED_ROLE="server"
        DETECTED_ROLE_REASON="云主机 VPC 环境 ($cloud_vendor)"
        return 0
    fi

    if [ -n "$(list_global_ipv4_addrs | head -n 1)" ]; then
        DETECTED_ROLE="client"
        DETECTED_ROLE_REASON="局域网内网环境 (无公网 IP 且非云主机，判定为本地软路由/网关)"
        return 0
    fi

    DETECTED_ROLE="server"
    DETECTED_ROLE_REASON="标准 Linux 服务端环境"
    return 0
}

# 智能推荐客户端网关拓扑模式（main 主路由 vs side 单臂旁路由）
detect_recommended_gateway_mode() {
    if [ -n "${SINGCTL_MOCK_GW_TOPOLOGY:-}" ]; then
        echo "$SINGCTL_MOCK_GW_TOPOLOGY"
        return 0
    fi
    if [ -z "${OS:-}" ] || [ "$OS" = "darwin" ]; then
        echo "main"
        return 0
    fi
    if [ "$IS_OPENWRT" = "true" ] && command -v uci >/dev/null 2>&1; then
        if uci -q get network.wan >/dev/null 2>&1; then
            echo "main"
            return 0
        fi
        if [ -n "$(uci -q get network.lan.gateway 2>/dev/null || true)" ]; then
            echo "side"
            return 0
        fi
    fi
    if command -v ip >/dev/null 2>&1; then
        local nic_count
        nic_count=$(ip -o -4 addr show up scope global 2>/dev/null | awk '$2 !~ /^(lo|tailscale|tun|utun|wg|docker|veth|virbr|cni|flannel|pppoe|wan)/ {print $2}' | sort -u | wc -l | tr -d ' ')
        local has_wan_if
        has_wan_if=$(ip -o link show up 2>/dev/null | awk -F': ' '$2 ~ /^(pppoe|wan)/ {print $2; exit}')
        if [ "$nic_count" = "1" ] && [ -z "$has_wan_if" ] && [ -n "$DETECTED_MAIN_GW" ] && [ -n "$DETECTED_LAN_IP" ] && [ "$DETECTED_MAIN_GW" != "$DETECTED_LAN_IP" ]; then
            local ip_prefix gw_prefix
            ip_prefix=$(echo "$DETECTED_LAN_IP" | awk -F. '{print $1"."$2"."$3}')
            gw_prefix=$(echo "$DETECTED_MAIN_GW" | awk -F. '{print $1"."$2"."$3}')
            if [ "$ip_prefix" = "$gw_prefix" ] && ! is_public_unicast_ipv4 "$DETECTED_LAN_IP"; then
                echo "side"
                return 0
            fi
        fi
    fi
    echo "main"
}

# 客户端网关部署角色选择（自动识别主路由/旁路由并支持全程回车确认）
configure_gateway_mode() {
    SELECTED_GW_MODE="main"
    SELECTED_MAIN_ROUTER_IP=""

    local cli_gw_mode=""
    local cli_main_ip=""
    local gw_auto_yes="${AUTO_YES:-false}"
    while [ $# -gt 0 ]; do
        case "$1" in
            --side-router)
                cli_gw_mode="side"
                ;;
            --main-router)
                cli_gw_mode="main"
                ;;
            --yes|-y|--non-interactive)
                gw_auto_yes="true"
                ;;
            --main-router-ip)
                shift
                cli_main_ip="${1:-}"
                ;;
            --main-router-ip=*)
                cli_main_ip="${1#*=}"
                ;;
        esac
        shift
    done

    detect_lan_ip_and_iface
    local recommended_gw_mode
    recommended_gw_mode=$(detect_recommended_gateway_mode)

    local tty_path="${SINGCTL_TTY_PATH:-/dev/tty}"
    local has_tty="false"
    if [ -n "${SINGCTL_TTY_PATH:-}" ] && [ -f "$SINGCTL_TTY_PATH" ]; then
        has_tty="true"
    elif [ -c "$tty_path" ]; then
        has_tty="true"
    fi

    if [ -n "$cli_gw_mode" ]; then
        SELECTED_GW_MODE="$cli_gw_mode"
    elif [ "$gw_auto_yes" = "true" ] || [ "$has_tty" != "true" ] || [ "$OS" = "darwin" ]; then
        SELECTED_GW_MODE="$recommended_gw_mode"
    else
        exec 3< "$tty_path"
        printf "\n"
        if [ "$recommended_gw_mode" = "side" ]; then
            echo_info "网关拓扑识别: 旁路由/单臂模式 (检测到单网口且存在上级主路由 ${DETECTED_MAIN_GW:-同网段网关})"
            if supports_color; then
                printf "\033[0;33m➜ 按 [回车] 确认使用旁路由模式 (输入 1 或 main 切换为主路由模式): \033[0m"
            else
                printf "➜ 按 [回车] 确认使用旁路由模式 (输入 1 或 main 切换为主路由模式): "
            fi
            local gw_choice=""
            read -r gw_choice <&3 || gw_choice=""
            case "$gw_choice" in
                1|main|Main|MAIN)
                    SELECTED_GW_MODE="main"
                    ;;
                *)
                    SELECTED_GW_MODE="side"
                    ;;
            esac
        else
            echo_info "网关拓扑识别: 主路由模式 (Main Router)"
            if supports_color; then
                printf "\033[0;33m➜ 按 [回车] 确认使用主路由模式 (输入 2 或 side 切换为旁路由模式): \033[0m"
            else
                printf "➜ 按 [回车] 确认使用主路由模式 (输入 2 或 side 切换为旁路由模式): "
            fi
            local gw_choice=""
            read -r gw_choice <&3 || gw_choice=""
            case "$gw_choice" in
                2|side|Side|SIDE)
                    SELECTED_GW_MODE="side"
                    ;;
                *)
                    SELECTED_GW_MODE="main"
                    ;;
            esac
        fi
    fi

    if [ "$SELECTED_GW_MODE" = "main" ]; then
        if [ "$has_tty" = "true" ] && [ -z "$cli_gw_mode" ] && [ "$gw_auto_yes" != "true" ] && [ "$OS" != "darwin" ]; then
            exec 3<&- 2>/dev/null || true
        fi
        write_gateway_config "main" ""
        echo_info "已启用【主路由模式 (main)】"
        return 0
    fi

    echo_info "已启用【旁路由模式 (side)】"
    if [ -n "$DETECTED_LAN_IP" ]; then
        echo_info "检测到本机局域网地址: $DETECTED_LAN_IP (网卡: ${DETECTED_LAN_IFACE:-未知})"
    fi

    if [ -n "$cli_main_ip" ]; then
        if ! is_valid_unicast_ipv4 "$cli_main_ip"; then
            error_exit "指定的 --main-router-ip ($cli_main_ip) 不是合法的 IPv4 单播地址"
        fi
        if [ -n "$DETECTED_LAN_IP" ] && [ "$cli_main_ip" = "$DETECTED_LAN_IP" ]; then
            error_exit "上级主路由 IP 不能等于旁路由本机 IP ($DETECTED_LAN_IP)，否则会导致路由死循环"
        fi
        SELECTED_MAIN_ROUTER_IP="$cli_main_ip"
    elif [ "$gw_auto_yes" != "true" ] && [ "$has_tty" = "true" ]; then
        if [ -n "$cli_gw_mode" ]; then
            exec 3< "$tty_path"
        fi
        while :; do
            if [ -n "$DETECTED_MAIN_GW" ]; then
                printf "➜ 请确认上级主路由(网关) IP [回车确认: %s / 输入新 IP 修改]: " "$DETECTED_MAIN_GW"
            else
                printf "➜ 请输入上级主路由(网关) IP (如 192.168.1.1): "
            fi
            local input_gw=""
            if ! read -r input_gw <&3; then
                input_gw=""
            fi
            input_gw=$(printf "%s" "$input_gw" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            if [ -z "$input_gw" ]; then
                input_gw="$DETECTED_MAIN_GW"
            fi
            if [ -z "$input_gw" ]; then
                echo_error "上级主路由 IP 不能为空，请重新输入！"
                continue
            fi
            if ! is_valid_unicast_ipv4 "$input_gw"; then
                echo_error "输入的 IP ($input_gw) 格式无效，请输入合法的局域网 IPv4 地址！"
                continue
            fi
            if [ -n "$DETECTED_LAN_IP" ] && [ "$input_gw" = "$DETECTED_LAN_IP" ]; then
                echo_error "上级主路由 IP 不能等于旁路由本机 IP ($DETECTED_LAN_IP)，否则会造成路由死循环，请重新输入！"
                continue
            fi
            if ! probe_gateway_reachable "$input_gw"; then
                echo_warning "暂未收到主路由 $input_gw 的 Ping 响应（若主路由开启了禁 Ping 可忽略）"
            fi
            SELECTED_MAIN_ROUTER_IP="$input_gw"
            break
        done
        exec 3<&- 2>/dev/null || true
    else
        if [ -z "$DETECTED_MAIN_GW" ]; then
            error_exit "非交互旁路由安装未能自动探测到默认网关，请通过 --main-router-ip <IP> 指定主路由地址"
        fi
        SELECTED_MAIN_ROUTER_IP="$DETECTED_MAIN_GW"
    fi

    write_gateway_config "side" "$SELECTED_MAIN_ROUTER_IP"
    echo_success "旁路由模式已写入配置 (上级主路由网关: $SELECTED_MAIN_ROUTER_IP)"
}

# 打印旁路由专属终端/主路由 DHCP 接入指引
show_side_router_guide() {
    [ "$SELECTED_GW_MODE" = "side" ] || return 0
    local side_ip="${DETECTED_LAN_IP:-<旁路由IP>}"
    local main_ip="${SELECTED_MAIN_ROUTER_IP:-<主路由IP>}"
    printf "\n"
    echo_info "📌 旁路由接入配置指引 (本机旁路由: $side_ip | 上级主路由: $main_ip):"
    echo "  • 单设备手动接入: 将手机/电脑的【默认网关】与【DNS】同时设为 $side_ip"
    echo "  • 全屋 DHCP 自动生效: 在主路由 ($main_ip) 的【LAN / DHCP 服务器】设置中将默认网关与 DNS 设为 $side_ip（切勿修改主路由 WAN 口上游 DNS）"
    echo "  • 重要防坑提醒: 旁路由自身建议使用静态 IP，并在主路由关闭 LAN 侧 IPv6 RA/DHCPv6 通告以防流量绕过旁路由"
}

# 配置订阅
configure_subscription() {
    local sub_auto_yes="${AUTO_YES:-false}"
    for arg in "$@"; do
        case "$arg" in
            --yes|-y|--non-interactive)
                sub_auto_yes="true"
                ;;
        esac
    done

    if [ -f "$CONFIG_FILE" ] && sed 's/#.*//' "$CONFIG_FILE" | grep -Eq 'url:[[:space:]]*["'"'"']?https?://' && \
       ! sed 's/#.*//' "$CONFIG_FILE" | grep -Eq 'url:[[:space:]]*["'"'"']?https://example\.com/subscription["'"'"']?[[:space:]]*$'; then
        echo_info "检测到已有订阅配置，自动保留现有订阅"
        return 0
    fi

    if [ "$sub_auto_yes" = "true" ]; then
        echo_info "非交互模式跳过订阅输入（安装后可在 :8090 WebUI 配置）"
        return 0
    fi

    echo_info "配置订阅连接..."

    # 强制从终端读取输入，即使在管道中运行
    if supports_color; then
        printf "\033[0;33m请输入您的订阅连接 (直接回车跳过，稍后可在 :8090 WebUI 配置):\033[0m\n"
    else
        printf "请输入您的订阅连接 (直接回车跳过，稍后可在 :8090 WebUI 配置):\n"
    fi

    printf "订阅URL: "

    # 直接从 /dev/tty 读取，绕过管道限制
    if [ -c /dev/tty ]; then
        read -r sub_url < /dev/tty || sub_url=""
    else
        # 如果没有 /dev/tty，尝试其他方法
        exec < /dev/tty 2>/dev/null || {
            echo_warning "无法获取终端输入，请手动编辑配置文件: $CONFIG_FILE"
            return 0
        }
        read -r sub_url || sub_url=""
    fi

    [ -z "$sub_url" ] && { echo_info "跳过订阅配置"; return 0; }

    if [ -f "$CONFIG_FILE" ]; then
        # OSX sed syntax compat
        sed -i.bak "s|url: \"\"|url: \"$sub_url\"|g" "$CONFIG_FILE"
        rm -f "${CONFIG_FILE}.bak"
        echo_success "订阅连接已更新到 $CONFIG_FILE"
    else
        echo_error "配置文件不存在，无法设置订阅，请手动编辑。"
    fi
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
    echo " singctl version          - 查看版本信息"
    echo " singctl dns status       - 查看本地 AdGuard Home 状态与管理面板密码"
    echo " singctl sb gen           - 生成配置到默认位置，并备份原始配置"
    echo " singctl sb start         - 启动 sing-box 与看门狗守护进程"
    echo " singctl sb stop          - 停止 sing-box 与看门狗守护进程"
    echo " singctl sb install       - 安装 sing-box"

    printf "\n"
    
    if [ -f "$CONFIG_FILE" ]; then
        echo_info "下一步操作:"
        echo "1. 编辑配置文件 (如需要): vim $CONFIG_FILE"
        echo "2. 安装 sing-box:singctl sb install"
        echo "3. 启动服务:  singctl sb start"
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

# 首次安装 SingCtl 时若检测到系统已有旧版/第三方 sing-box，自动停止服务并彻底删除，避免版本不兼容或双进程冲突
purge_existing_singbox() {
    if [ "$IS_FIRST_INSTALL" != "true" ]; then
        return 0
    fi

    # macOS 客户端使用图形版 SFM.app 托管，不触碰系统/Homebrew 安装的 sing-box
    if [ "$OS" != "linux" ]; then
        return 0
    fi

    local root_prefix="${SINGCTL_ROOT_PREFIX:-}"
    local sb_bin=""
    sb_bin=$(command -v sing-box 2>/dev/null || true)
    if [ -z "$sb_bin" ] && [ ! -f "${root_prefix}/usr/bin/sing-box" ] && [ ! -f "${root_prefix}/usr/local/bin/sing-box" ] && [ ! -x "${root_prefix}/etc/init.d/sing-box" ]; then
        return 0
    fi

    echo_warning "首次安装检测到系统已存在旧的 sing-box 环境，正在清理以避免内核版本冲突..."

    # 1) 停止并禁用原有自启服务（兼容 OpenWrt procd 与 Linux systemd）
    if [ -x "${root_prefix}/etc/init.d/sing-box" ]; then
        "${root_prefix}/etc/init.d/sing-box" stop >/dev/null 2>&1 || true
        "${root_prefix}/etc/init.d/sing-box" disable >/dev/null 2>&1 || true
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop sing-box >/dev/null 2>&1 || true
        systemctl disable sing-box >/dev/null 2>&1 || true
    fi
    killall sing-box >/dev/null 2>&1 || pkill -x sing-box >/dev/null 2>&1 || true

    # 清理旧版/第三方脚本可能残留的 TProxy 透明代理表与策略路由，防止停止旧进程后本机出站断网
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet sing-box >/dev/null 2>&1 || true
    fi
    if command -v iptables >/dev/null 2>&1; then
        iptables -t mangle -D PREROUTING -j SING_BOX >/dev/null 2>&1 || true
        iptables -t mangle -D OUTPUT -j SING_BOX >/dev/null 2>&1 || true
        iptables -t mangle -F SING_BOX >/dev/null 2>&1 || true
        iptables -t mangle -X SING_BOX >/dev/null 2>&1 || true
    fi
    if command -v ip >/dev/null 2>&1; then
        local rule_iter=0
        while [ $rule_iter -lt 16 ]; do
            ip rule del fwmark 1 table 100 >/dev/null 2>&1 || ip rule del table 100 >/dev/null 2>&1 || break
            rule_iter=$((rule_iter + 1))
        done
        rule_iter=0
        while [ $rule_iter -lt 16 ]; do
            ip rule del fwmark 2 table 101 >/dev/null 2>&1 || ip rule del table 101 >/dev/null 2>&1 || break
            rule_iter=$((rule_iter + 1))
        done
        ip route flush table 100 >/dev/null 2>&1 || true
        ip route flush table 101 >/dev/null 2>&1 || true
        rule_iter=0
        while [ $rule_iter -lt 16 ]; do
            ip -6 rule del fwmark 1 table 100 >/dev/null 2>&1 || ip -6 rule del table 100 >/dev/null 2>&1 || break
            rule_iter=$((rule_iter + 1))
        done
        rule_iter=0
        while [ $rule_iter -lt 16 ]; do
            ip -6 rule del fwmark 2 table 101 >/dev/null 2>&1 || ip -6 rule del table 101 >/dev/null 2>&1 || break
            rule_iter=$((rule_iter + 1))
        done
        ip -6 route flush table 100 >/dev/null 2>&1 || true
        ip -6 route flush table 101 >/dev/null 2>&1 || true
    fi
    rm -f "${root_prefix}/etc/sing-box/singbox.nft" 2>/dev/null || true

    if [ -z "$root_prefix" ]; then
        # 2) 尝试通过包管理器卸载（OpenWrt opkg/apk、Debian/Ubuntu apt）
        if command -v opkg >/dev/null 2>&1 && opkg status sing-box 2>/dev/null | grep -q "Status:.*installed"; then
            echo_info "正在通过 opkg 卸载系统自带 sing-box..."
            opkg remove sing-box >/dev/null 2>&1 || true
        fi
        if command -v apk >/dev/null 2>&1 && apk info -e sing-box >/dev/null 2>&1; then
            echo_info "正在通过 apk 卸载系统自带 sing-box..."
            apk del sing-box >/dev/null 2>&1 || true
        fi
        if command -v dpkg >/dev/null 2>&1 && dpkg -s sing-box >/dev/null 2>&1; then
            echo_info "正在通过 apt-get 卸载系统已有 sing-box..."
            DEBIAN_FRONTEND=noninteractive apt-get remove -y sing-box >/dev/null 2>&1 || true
        fi
    fi

    # 3) 兜底清理残留二进制与旧配置文件，后续将由 singctl 安装匹配的官方内核
    if [ -n "$sb_bin" ] && [ -f "$sb_bin" ]; then
        rm -f "$sb_bin" 2>/dev/null || true
    fi
    rm -f "${root_prefix}/usr/bin/sing-box" "${root_prefix}/usr/local/bin/sing-box" "${root_prefix}/etc/sing-box/config.json" 2>/dev/null || true
    hash -r 2>/dev/null || true

    echo_success "已清理原有 sing-box，后续将自动安装 SingCtl 匹配的官方最新版内核"
}

# 检查 sing-box 是否需要安装或更新
check_singbox_installation() {
    local required_version="1.14.0"
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
  # 脚本开头已强制校验 root 权限，避免 OpenWrt 无 sudo 命令报错
  mkdir -p /etc/sing-box
  echo_info "已创建 /etc/sing-box 目录，配置文件将在首次启动时生成"
}

# 根据运行环境自动判定安装角色，交互场景仅需按回车确认（支持 1 键切换角色或 CLI 显式指定）
resolve_install_mode() {
    SELECTED_INSTALL_MODE=""
    AUTO_YES="false"
    local explicit_mode=""

    for arg in "$@"; do
        case "$arg" in
            --server|-s|server)
                explicit_mode="server"
                ;;
            --client|-c|client)
                explicit_mode="client"
                ;;
            --yes|-y|--non-interactive)
                AUTO_YES="true"
                ;;
        esac
    done

    if [ -n "$explicit_mode" ]; then
        SELECTED_INSTALL_MODE="$explicit_mode"
        echo_info "使用命令行指定模式: $SELECTED_INSTALL_MODE"
        return 0
    fi

    detect_runtime_role
    SELECTED_INSTALL_MODE="$DETECTED_ROLE"

    local role_label="☁️ 服务端模式 (Server)"
    local switch_hint="如需切换客户端请输入 c"
    if [ "$DETECTED_ROLE" = "client" ]; then
        role_label="🏠 客户端模式 (Client)"
        switch_hint="如需切换服务端请输入 s"
    fi

    printf "\n"
    echo_info "环境自动识别: ${role_label} — ${DETECTED_ROLE_REASON}"

    local tty_path="${SINGCTL_TTY_PATH:-/dev/tty}"
    local has_tty="false"
    if [ -n "${SINGCTL_TTY_PATH:-}" ] && [ -f "$SINGCTL_TTY_PATH" ]; then
        has_tty="true"
    elif [ -c "$tty_path" ]; then
        has_tty="true"
    fi

    if [ "$AUTO_YES" = "true" ] || [ "$has_tty" != "true" ]; then
        return 0
    fi

    exec 3< "$tty_path"
    if supports_color; then
        printf "\033[0;33m➜ 按 [回车] 继续安装 (${switch_hint}): \033[0m"
    else
        printf "➜ 按 [回车] 继续安装 (%s): " "$switch_hint"
    fi

    local choice=""
    read -r choice <&3 || choice=""
    exec 3<&- 2>/dev/null || true

    choice=$(printf "%s" "$choice" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    if [ "$DETECTED_ROLE" = "client" ]; then
        case "$choice" in
            s|S|server|Server|SERVER|2)
                SELECTED_INSTALL_MODE="server"
                ;;
        esac
    else
        case "$choice" in
            c|C|client|Client|CLIENT|2)
                SELECTED_INSTALL_MODE="client"
                ;;
        esac
    fi
}

# 模式选择与后续引导
select_mode_and_setup() {
    resolve_install_mode "$@"
    local mode="$SELECTED_INSTALL_MODE"

    if [ "$mode" = "server" ]; then
        echo_info "进入【服务端模式】部署流程"
        echo_info "正在启动 SingCtl 服务端初始化向导..."
        printf "\n"
        if [ -c /dev/tty ] && [ "$AUTO_YES" != "true" ]; then
            "$INSTALL_DIR/singctl" sr init < /dev/tty
        else
            "$INSTALL_DIR/singctl" sr init
        fi

        deploy_now="y"
        if [ "$AUTO_YES" != "true" ] && [ -c /dev/tty ]; then
            printf "\n"
            if supports_color; then
                printf "\033[0;33m是否立即执行四核组件全量部署 (singctl sr install)？[Y/n] (回车默认立即部署): \033[0m"
            else
                printf "是否立即执行四核组件全量部署 (singctl sr install)？[Y/n] (回车默认立即部署): "
            fi
            read -r deploy_choice < /dev/tty || deploy_choice="y"
            case "$deploy_choice" in
                n|N|no|NO|No)
                    deploy_now="n"
                    ;;
                *)
                    deploy_now="y"
                    ;;
            esac
        fi

        if [ "$deploy_now" = "y" ]; then
            echo_info "正在启动四核组件全量部署..."
            printf "\n"
            if [ -c /dev/tty ] && [ "$AUTO_YES" != "true" ]; then
                exec "$INSTALL_DIR/singctl" sr install < /dev/tty
            else
                exec "$INSTALL_DIR/singctl" sr install
            fi
        else
            echo_info "已保留配置文件: $CONFIG_FILE"
            echo_info "确认无误后可随时运行: singctl sr install"
        fi
        exit 0
    fi

    echo_info "进入【客户端模式】部署流程"
    configure_gateway_mode "$@"
    configure_subscription "$@"
    verify_installation
    show_completion_info
    init_singbox_config

    # Linux / OpenWrt 客户端自动安装、免向导配置并启动本地防劫持 AdGuard Home
    if [ "$OS" = "linux" ]; then
        echo_info "正在安装并初始化客户端防劫持 DNS (AdGuard Home)..."
        if [ -c /dev/tty ] && [ "$AUTO_YES" != "true" ]; then
            "$INSTALL_DIR/singctl" dns install --config "$CONFIG_FILE" < /dev/tty || echo_warning "AdGuard Home 自动安装未完成 (将继续部署 sing-box，稍后可手动运行 singctl dns install)"
        else
            "$INSTALL_DIR/singctl" dns install --config "$CONFIG_FILE" --non-interactive || echo_warning "AdGuard Home 自动安装未完成 (将继续部署 sing-box，稍后可手动运行 singctl dns install)"
        fi
    fi

    echo_success "安装脚本基础组件准备完成！"

    # 检查配置文件是否有效订阅地址（先去掉注释行，避免示例被误判）
    if [ -f "$CONFIG_FILE" ] && sed 's/#.*//' "$CONFIG_FILE" | grep -Eq 'url:[[:space:]]*["'"'"']?https?://'; then
        echo_info "检测到有效订阅，检查 sing-box 安装状态..."
        
        # 检查是否需要安装或更新 sing-box
        if check_singbox_installation; then
            echo_info "开始安装/更新 sing-box..."
            "$INSTALL_DIR/singctl" sb install --config "$CONFIG_FILE"
            echo_success "安装/更新 sing-box 成功"
        fi
        
        echo_info "正在生成最新 sing-box 配置文件 (自动对接本地防劫持 DNS)..."
        "$INSTALL_DIR/singctl" sb gen --config "$CONFIG_FILE"
        echo_success "sing-box 配置文件生成完成"

        echo_info "正在启动/重载 sing-box 服务..."
        "$INSTALL_DIR/singctl" sb restart --config "$CONFIG_FILE"
        echo_success "sing-box 启动完成"

        # 无论是否已填订阅，统一启动/热重启客户端 WebUI 管理后台 (:8090)
        echo_info "正在启动/重载 SingCtl WebUI 图形管理后台..."
        "$INSTALL_DIR/singctl" web stop >/dev/null 2>&1 || true
        "$INSTALL_DIR/singctl" web start --config "$CONFIG_FILE" >/dev/null 2>&1 || true

        echo_success "========================================================"
        echo_success "🎉 SingCtl 客户端部署并启动完成！"
        echo_info "🌐 Web 图形管理后台 (设备审计 / 黑名单 / 节点面板):"
        "$INSTALL_DIR/singctl" web status 2>/dev/null | grep -E "http://" || echo "  ➜ http://$(uci get network.lan.ipaddr 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'):8090"
        echo_success "========================================================"

        if [ "$OS" = "linux" ]; then
            "$INSTALL_DIR/singctl" dns status --config "$CONFIG_FILE" 2>/dev/null || true
        fi
        show_side_router_guide
    else
        echo_warning "配置文件中尚未配置有效订阅"
        
        # 预先安装好 sing-box 内核，免去用户后续手动安装步骤
        if check_singbox_installation; then
            echo_info "正在自动预安装 sing-box 核心组件..."
            "$INSTALL_DIR/singctl" sb install --config "$CONFIG_FILE" || true
        fi

        # 自动拉起/重载 WebUI，让用户能直接在浏览器中填入订阅
        echo_info "正在自动启动 SingCtl WebUI 图形管理后台..."
        "$INSTALL_DIR/singctl" web stop >/dev/null 2>&1 || true
        "$INSTALL_DIR/singctl" web start --config "$CONFIG_FILE" >/dev/null 2>&1 || true

        echo_success "========================================================"
        echo_success "🎉 SingCtl 客户端已就绪！"
        echo_info "你可以选择以下任一方式完成订阅配置:"
        echo_info "【方式 1】在手机或电脑浏览器中打开 Web 管理页面 (推荐):"
        "$INSTALL_DIR/singctl" web status 2>/dev/null | grep -E "http://" || echo "  ➜ http://$(uci get network.lan.ipaddr 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1'):8090"
        echo_info "【方式 2】在终端手动编辑配置文件:"
        echo_info "  vim $CONFIG_FILE"
        echo_info "  配置完成后运行: singctl sb gen && singctl sb start"
        echo_success "========================================================"
        if [ "$OS" = "linux" ]; then
            "$INSTALL_DIR/singctl" dns status --config "$CONFIG_FILE" 2>/dev/null || true
        fi
        show_side_router_guide
    fi
}

# 主函数
main() {
    echo_info "开始安装 SingCtl..."
    printf "\n"

    check_permissions
    check_dependencies
    detect_system
    PRE_EXISTING_ROLE=$(detect_existing_installed_role)
    get_latest_version
    build_download_url "$@"
    download_and_extract
    install_files
    purge_existing_singbox
    select_mode_and_setup "$@"
}

# 执行主函数（支持测试按库加载）
if [ "${SINGCTL_INSTALL_LIB_ONLY:-0}" != "1" ]; then
    main "$@"
fi