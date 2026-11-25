# 模块职责：OpenWrt sing-box TProxy 启动极简主流程编排（通过 fw_* 契约与具体防火墙后端解耦）。

init_env() {
    require_root

    # 停止已有 sing-box（含 procd 与沙盒实例）
    stop_singbox_proc

    # 清理残留防火墙规则与策略路由，确保后续网络探测与 procd-ujail 自动安装直通外网
    if [ "${SINGCTL_GO_DATAPLANE:-0}" != "1" ]; then
        fw_cleanup_pre
        cleanup_route
    fi

    # 检查必要依赖
    check_command "sing-box"
    if [ "${SINGCTL_GO_DATAPLANE:-0}" != "1" ]; then
        fw_check_deps
        check_command "ip"
    fi
    check_command "ping"

    # 检查网络和端口
    check_network
    check_port "$TPROXY_PORT"

    # 确保配置目录存在
    if [ ! -d /etc/sing-box ]; then
        mkdir -p /etc/sing-box
    fi

    # 验证配置文件
    if ! sing-box check -c "$CONFIG_FILE"; then
        echo_err "配置文件验证失败"
        error_exit "配置验证失败"
    fi
}

main() {
    init_env
    ensure_openwrt_ujail || true
    if [ "${SINGCTL_GO_DATAPLANE:-0}" != "1" ]; then
        fw_apply
        setup_route
    fi
    start_singbox
    sync_dnsmasq_ipv4_only
}

main
