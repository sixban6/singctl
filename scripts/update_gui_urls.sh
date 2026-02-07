#!/bin/bash
#################################################
# 自动更新 GUI URL 脚本
# 功能：从 GitHub 获取 SagerNet/sing-box 最新 release
#       并更新 singctl.yaml, install.sh, install.ps1 中的 URL
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
CONFIG_FILE="$PROJECT_ROOT/configs/singctl.yaml"
INSTALL_SH="$PROJECT_ROOT/install.sh"
INSTALL_PS1="$PROJECT_ROOT/install.ps1"

# GitHub API - 获取所有 releases（包括预发布版本，因为 SFM 只在预发布中提供）
GITHUB_API_ALL="https://api.github.com/repos/SagerNet/sing-box/releases"
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
    
    # 获取所有 releases
    ALL_RELEASES=$(curl -s "$GITHUB_API_ALL")
    
    if [ -z "$ALL_RELEASES" ]; then
        echo -e "${RED}[ERROR] 无法获取 release 信息${NC}"
        exit 1
    fi
    
    # 找到包含 SFM .pkg 的最新 release（通常是预发布版本）
    SFM_RELEASE=$(echo "$ALL_RELEASES" | jq -r '[.[] | select(.assets[] | .name | test("SFM-.*\\.pkg$"))][0]')
    
    if [ -z "$SFM_RELEASE" ] || [ "$SFM_RELEASE" = "null" ]; then
        echo -e "${YELLOW}[WARNING] 未找到包含 SFM 的 release，使用最新稳定版${NC}"
        RELEASE_JSON=$(curl -s "$GITHUB_API_LATEST")
        SFM_RELEASE="$RELEASE_JSON"
    else
        RELEASE_JSON="$SFM_RELEASE"
    fi
    
    TAG_NAME=$(echo "$RELEASE_JSON" | jq -r '.tag_name')
    IS_PRERELEASE=$(echo "$RELEASE_JSON" | jq -r '.prerelease')
    
    if [ "$IS_PRERELEASE" = "true" ]; then
        echo -e "${GREEN}[SUCCESS] 使用版本: $TAG_NAME (预发布版，包含 SFM)${NC}"
    else
        echo -e "${GREEN}[SUCCESS] 使用版本: $TAG_NAME (稳定版)${NC}"
    fi
}

# 解析下载 URL
parse_download_urls() {
    echo -e "${CYAN}[INFO] 解析下载链接...${NC}"
    
    # 获取 macOS .pkg 文件 URL (SFM-*.pkg)
    MAC_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | test("SFM-.*\\.pkg$")) | .browser_download_url' | head -1)
    
    # 如果没找到 SFM，尝试 Apple 命名
    if [ -z "$MAC_URL" ] || [ "$MAC_URL" = "null" ]; then
        MAC_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | test(".*Apple.*\\.pkg$")) | .browser_download_url' | head -1)
    fi
    
    # 获取 Windows amd64 zip 文件 URL（使用同一版本保持一致）
    WIN_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[] | select(.name | test("sing-box-.*-windows-amd64\\.zip$")) | .browser_download_url' | head -1)
    
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
    
    # 更新 mac_url
    if [ -n "$MAC_URL" ]; then
        # 匹配 mac_url: "..." 格式（YAML）
        if grep -q 'mac_url:' "$file"; then
            sed -i.tmp -E "s|mac_url: *\"[^\"]*\"|mac_url: \"$MAC_URL\"|g" "$file"
            updated=true
        fi
    fi
    
    # 更新 win_url
    if [ -n "$WIN_URL" ]; then
        # 匹配 win_url: "..." 格式（YAML）
        if grep -q 'win_url:' "$file"; then
            sed -i.tmp -E "s|win_url: *\"[^\"]*\"|win_url: \"$WIN_URL\"|g" "$file"
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
    
    echo "--- configs/singctl.yaml ---"
    grep -E "(mac_url|win_url)" "$CONFIG_FILE" 2>/dev/null || echo "(未找到)"
    echo ""
    
    echo "--- install.sh ---"
    grep -E "(mac_url|win_url)" "$INSTALL_SH" 2>/dev/null | head -4 || echo "(未找到)"
    echo ""
    
    echo "--- install.ps1 ---"
    grep -E "(mac_url|win_url)" "$INSTALL_PS1" 2>/dev/null | head -4 || echo "(未找到)"
}

# 主函数
main() {
    check_dependencies
    get_latest_release
    parse_download_urls
    
    echo ""
    update_file "$CONFIG_FILE"
    update_file "$INSTALL_SH"
    update_file "$INSTALL_PS1"
    
    show_summary
}

main "$@"
