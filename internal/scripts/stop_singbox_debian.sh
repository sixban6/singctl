#!/bin/bash

#################################################
# 描述: Debian sing-box TProxy模式 停止脚本
# 用途: 停止 sing-box TProxy模式 代理服务并清理规则
# 系统: Debian/Ubuntu
#################################################

# 确保能找到命令
export PATH="/usr/local/bin:/usr/bin:$PATH"

TPROXY_PORT=7895
PROXY_FWMARK=1
PROXY_ROUTE_TABLE=100
CYAN='\033[0;36m'
YLW='\033[0;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# 获取当前时间
timestamp() {
    date +"%Y-%m-%d %H:%M:%S"
}

# 输出函数
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

# 错误处理函数
error_exit() {
    echo_err "$1"
    exit "${2:-1}"
}

# 检测沙盒进程
detect_sandbox_processes() {
    local has_processes=false
    
    # 检查 firejail 沙盒进程
    if pgrep -f "firejail.*sing-box" >/dev/null 2>&1; then
        echo_info "检测到 firejail 沙盒模式的 sing-box 进程"
        has_processes=true
    fi
    
    # 检查 systemd 服务
    if systemctl is-active --quiet sing-box-temp 2>/dev/null; then
        echo_info "检测到 systemd 安全模式的 sing-box 服务"
        has_processes=true
    fi
    
    # 检查普通进程
    if pgrep "sing-box" >/dev/null 2>&1; then
        echo_info "检测到普通模式的 sing-box 进程"
        has_processes=true
    fi
    
    return $([ "$has_processes" = true ] && echo 0 || echo 1)
}

# 停止沙盒进程
stop_sandbox_processes() {
    echo_info "停止沙盒模式的 sing-box 进程..."
    local stopped=false
    
    # 停止 firejail 进程
    if pgrep -f "firejail.*sing-box" >/dev/null 2>&1; then
        echo_info "停止 firejail 沙盒进程..."
        pkill -TERM -f "firejail.*sing-box" 2>/dev/null || true
        sleep 2
        
        # 如果还在运行，强制终止
        if pgrep -f "firejail.*sing-box" >/dev/null 2>&1; then
            pkill -KILL -f "firejail.*sing-box" 2>/dev/null || true
            sleep 1
        fi
        stopped=true
    fi
    
    # 停止 systemd 服务
    if systemctl is-active --quiet sing-box-temp 2>/dev/null; then
        echo_info "停止 systemd 临时服务..."
        systemctl stop sing-box-temp 2>/dev/null || true
        systemctl disable sing-box-temp 2>/dev/null || true
        rm -f /etc/systemd/system/sing-box-temp.service
        systemctl daemon-reload
        stopped=true
    fi
    
    # 停止普通进程
    if pgrep "sing-box" >/dev/null 2>&1; then
        echo_info "停止普通模式的 sing-box 进程..."
        pkill -TERM "sing-box" 2>/dev/null || true
        sleep 2
        
        # 强制终止剩余进程
        if pgrep "sing-box" >/dev/null 2>&1; then
            pkill -KILL "sing-box" 2>/dev/null || true
            sleep 1
        fi
        stopped=true
    fi
    
    return $([ "$stopped" = true ] && echo 0 || echo 1)
}

# 清理防火墙规则
cleanup_firewall() {
    echo_info "清理防火墙规则..."
    
    # 检查并清理 nftables 规则
    if command -v nft >/dev/null 2>&1; then
        if nft list tables 2>/dev/null | grep -q "inet sing-box"; then
            echo_info "清理 nftables 规则..."
            nft delete table inet sing-box 2>/dev/null || true
            echo_succ "nftables 规则已清理"
        fi
    fi
    
    # 检查并清理 iptables 规则
    if command -v iptables >/dev/null 2>&1; then
        if iptables -t mangle -L SINGBOX >/dev/null 2>&1; then
            echo_info "清理 iptables 规则..."
            
            # 删除引用
            iptables -t mangle -D PREROUTING -j SINGBOX 2>/dev/null || true
            
            # 删除 OUTPUT 链中的规则
            iptables -t mangle -D OUTPUT -m mark --mark $PROXY_FWMARK -j RETURN 2>/dev/null || true
            iptables -t mangle -D OUTPUT -p tcp --dport 53 -j MARK --set-mark $PROXY_FWMARK 2>/dev/null || true
            iptables -t mangle -D OUTPUT -p udp --dport 53 -j MARK --set-mark $PROXY_FWMARK 2>/dev/null || true
            
            # 清空并删除自定义链
            iptables -t mangle -F SINGBOX 2>/dev/null || true
            iptables -t mangle -X SINGBOX 2>/dev/null || true
            
            echo_succ "iptables 规则已清理"
        fi
    fi
}

# 清理路由规则
cleanup_routes() {
    echo_info "清理路由规则..."
    
    # 删除 IPv4 路由规则
    if ip rule list | grep -q "fwmark 0x$PROXY_FWMARK lookup $PROXY_ROUTE_TABLE"; then
        ip rule del table $PROXY_ROUTE_TABLE 2>/dev/null || true
        ip route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
        echo_info "IPv4 路由规则已清理"
    fi
    
    # 删除 IPv6 路由规则  
    if ip -6 rule list | grep -q "fwmark 0x$PROXY_FWMARK lookup $PROXY_ROUTE_TABLE"; then
        ip -6 rule del table $PROXY_ROUTE_TABLE 2>/dev/null || true
        ip -6 route flush table $PROXY_ROUTE_TABLE 2>/dev/null || true
        echo_info "IPv6 路由规则已清理"
    fi
}

# 清理配置文件
cleanup_configs() {
    echo_info "清理临时配置文件..."
    
    # 清理 firejail 配置
    if [ -f /etc/sing-box/sing-box.profile ]; then
        rm -f /etc/sing-box/sing-box.profile
        echo_info "firejail 配置文件已删除"
    fi
    
    # 清理防火墙规则文件
    if [ -f /etc/sing-box/singbox.nft ]; then
        rm -f /etc/sing-box/singbox.nft
        echo_info "nftables 规则文件已删除"
    fi
    
    # 清理日志文件（可选）
    if [ -f /var/log/sing-box.log ]; then
        > /var/log/sing-box.log  # 清空而不删除
        echo_info "日志文件已清空"
    fi
}

# 验证清理结果
verify_cleanup() {
    echo_info "验证清理结果..."
    local issues=0
    
    # 检查进程
    if pgrep -f "sing-box\|firejail.*sing-box" >/dev/null 2>&1; then
        echo_warn "警告: 仍有 sing-box 相关进程在运行"
        issues=$((issues + 1))
    fi
    
    # 检查 systemd 服务
    if systemctl is-active --quiet sing-box-temp 2>/dev/null; then
        echo_warn "警告: systemd 临时服务仍在运行"
        issues=$((issues + 1))
    fi
    
    # 检查端口占用
    if netstat -tuln 2>/dev/null | grep -q ":$TPROXY_PORT " || ss -tuln 2>/dev/null | grep -q ":$TPROXY_PORT "; then
        echo_warn "警告: 端口 $TPROXY_PORT 仍被占用"
        issues=$((issues + 1))
    fi
    
    if [ $issues -eq 0 ]; then
        echo_succ "所有清理操作完成，系统状态正常"
    else
        echo_warn "发现 $issues 个问题，可能需要手动检查"
    fi
    
    return $issues
}

# 主停止函数
main() {
    echo_info "开始停止 Debian sing-box TProxy 服务..."
    
    # 检查权限
    if [ "$(id -u)" != "0" ]; then
        error_exit "此脚本需要 root 权限运行"
    fi
    
    # 检测并停止进程
    if detect_sandbox_processes; then
        if stop_sandbox_processes; then
            echo_succ "sing-box 进程已成功停止"
        else
            echo_warn "部分进程可能未完全停止"
        fi
    else
        echo_succ "没有运行中的 sing-box 服务"
    fi
    
    # 清理系统配置
    cleanup_firewall
    cleanup_routes
    cleanup_configs
    
    # 验证清理结果
    verify_cleanup
    cleanup_exit_code=$?
    
    echo_succ "Debian sing-box TProxy 停止完成"
    
    # 显示清理状态
    if [ $cleanup_exit_code -eq 0 ]; then
        echo_info "系统已完全清理，可以安全重新启动服务"
    else
        echo_warn "清理过程中发现问题，建议检查系统状态"
        echo_info "手动检查命令:"
        echo "  ps aux | grep sing-box"
        echo "  systemctl status sing-box-temp"  
        echo "  netstat -tuln | grep $TPROXY_PORT"
    fi
    
    exit $cleanup_exit_code
}

# 捕获中断信号
trap 'echo_warn "停止脚本被中断"; exit 130' INT TERM

# 执行主函数
main "$@"