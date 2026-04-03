#!/bin/bash
#################################################
# 自动更新 GUI URL 脚本
# 功能：从 GitHub 获取 SagerNet/sing-box 最新稳定版 release
#       并更新 internal/constant/default.go 中的 GUI URL 常量
#################################################

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# 获取脚本所在目录的父目录（项目根目录）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 文件路径
CONFIG_FILE="$PROJECT_ROOT/internal/constant/default.go"
INSTALL_SH="$PROJECT_ROOT/install.sh"
INSTALL_PS1="$PROJECT_ROOT/install.ps1"

# GitHub API - 仅获取最新稳定版 release
GITHUB_API_LATEST="https://api.github.com/repos/SagerNet/sing-box/releases/latest"

echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  更新 GUI URL 脚本${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# 检查依赖
check_dependencies() {
    for dep in curl jq sed; do
        if ! command -v "$dep" &>/dev/null; then
            echo -e "${RED}[ERROR] 缺少依赖: $dep${NC}"
            exit 1
        fi
    done
}

# 获取 Release 信息
get_latest_release() {
    echo -e "${CYAN}[INFO] 获取 SagerNet/sing-box release 信息...${NC}"

    RELEASE_JSON=$(curl -fsSL "$GITHUB_API_LATEST")

    if [ -z "$RELEASE_JSON" ]; then
        echo -e "${RED}[ERROR] 无法获取最新稳定版 release 信息${NC}"
        exit 1
    fi

    TAG_NAME=$(echo "$RELEASE_JSON" | jq -r '.tag_name // empty')

    if [ -z "$TAG_NAME" ]; then
        echo -e "${RED}[ERROR] release 信息中缺少 tag_name${NC}"
        exit 1
    fi

    echo -e "${GREEN}[SUCCESS] 使用版本: $TAG_NAME (稳定版)${NC}"
}

# 解析下载 URL
parse_download_urls() {
    echo -e "${CYAN}[INFO] 解析下载链接...${NC}"

    # 优先 Apple，其次 Universal/Intel，最后兜底任意 SFM pkg
    MAC_URL=""
    for pattern in '^SFM-.*-Apple\.pkg$' '^SFM-.*-Universal\.pkg$' '^SFM-.*-Intel\.pkg$' '^SFM-.*\.pkg$'; do
        MAC_URL=$(echo "$RELEASE_JSON" | jq -r --arg pattern "$pattern" '.assets[] | select(.name | test($pattern)) | .browser_download_url' | head -1)
        if [ -n "$MAC_URL" ] && [ "$MAC_URL" != "null" ]; then
            break
        fi
    done

    # 优先非 legacy 的 amd64 包，找不到时再退化
    WIN_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select((.name | test("^sing-box-.*-windows-amd64\\.zip$")) and ((.name | test("legacy")) | not)) | .browser_download_url' | head -1)
    if [ -z "$WIN_URL" ] || [ "$WIN_URL" = "null" ]; then
        WIN_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | test("^sing-box-.*-windows-amd64.*\\.zip$")) | .browser_download_url' | head -1)
    fi
    
    if [ -z "$MAC_URL" ] || [ "$MAC_URL" = "null" ]; then
        echo -e "${YELLOW}[WARNING] 未找到 macOS 下载链接${NC}"
        MAC_URL=""
    else
        echo -e "${GREEN}[SUCCESS] macOS URL: $MAC_URL${NC}"
    fi
    
    if [ -z "$WIN_URL" ] || [ "$WIN_URL" = "null" ]; then
        echo -e "${YELLOW}[WARNING] 未找到 Windows 下载链接${NC}"
        WIN_URL=""
    else
        echo -e "${GREEN}[SUCCESS] Windows URL: $WIN_URL${NC}"
    fi
    
    if [ -z "$MAC_URL" ] && [ -z "$WIN_URL" ]; then
        echo -e "${RED}[ERROR] 两个平台的下载链接都未找到${NC}"
        exit 1
    fi
}

# 更新文件中的 URL
update_file() {
    local file="$1"
    local file_name=$(basename "$file")
    
    if [ ! -f "$file" ]; then
        echo -e "${YELLOW}[WARNING] 文件不存在: $file${NC}"
        return
    fi
    
    echo -e "${CYAN}[INFO] 更新 $file_name...${NC}"
    
    # 备份文件
    cp "$file" "${file}.bak"
    
    local updated=false
    
    # 更新 MacURL
    if [ -n "$MAC_URL" ]; then
        # Go 常量格式：MacURL = "..."
        if grep -qE '^[[:space:]]*MacURL[[:space:]]*=' "$file"; then
            sed -i.tmp -E "s|^([[:space:]]*MacURL[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"$MAC_URL\"|g" "$file"
            updated=true
        # YAML 格式：MacURL: "..."
        elif grep -q 'MacURL:' "$file"; then
            sed -i.tmp -E "s|MacURL: *\"[^\"]*\"|MacURL: \"$MAC_URL\"|g" "$file"
            updated=true
        fi
    fi
    
    # 更新 WinURL
    if [ -n "$WIN_URL" ]; then
        # Go 常量格式：WinURL = "..."
        if grep -qE '^[[:space:]]*WinURL[[:space:]]*=' "$file"; then
            sed -i.tmp -E "s|^([[:space:]]*WinURL[[:space:]]*=[[:space:]]*)\"[^\"]*\"|\1\"$WIN_URL\"|g" "$file"
            updated=true
        # YAML 格式：WinURL: "..."
        elif grep -q 'WinURL:' "$file"; then
            sed -i.tmp -E "s|WinURL: *\"[^\"]*\"|WinURL: \"$WIN_URL\"|g" "$file"
            updated=true
        fi
    fi
    
    # 清理临时文件
    rm -f "${file}.tmp"
    
    if [ "$updated" = true ]; then
        echo -e "${GREEN}[SUCCESS] 已更新 $file_name${NC}"
        # 显示差异
        if diff -q "${file}.bak" "$file" >/dev/null 2>&1; then
            echo -e "${YELLOW}[INFO] 无变化（URL 相同）${NC}"
        else
            echo -e "${CYAN}[INFO] 变更内容:${NC}"
            diff "${file}.bak" "$file" || true
        fi
    else
        echo -e "${YELLOW}[WARNING] $file_name 中未找到需要更新的 URL${NC}"
    fi
    
    # 删除备份
    rm -f "${file}.bak"
}

# 显示汇总
show_summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  更新完成${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "${CYAN}[INFO] 验证更新结果:${NC}"
    echo ""
    
    echo "--- $CONFIG_FILE ---"
    grep -E "(MacURL|WinURL)" "$CONFIG_FILE" 2>/dev/null || echo "(未找到)"
    echo ""
    
}

# 主函数
main() {
    check_dependencies
    get_latest_release
    parse_download_urls
    
    echo ""
    update_file "$CONFIG_FILE"
    
    show_summary
}

main "$@"
