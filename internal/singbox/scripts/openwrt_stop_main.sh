# 模块职责：OpenWrt sing-box TProxy 停止极简主流程编排（通过 fw_* 契约与具体防火墙后端解耦）。

# 捕获中断信号以安全退出
trap 'error_exit "脚本被中断"' INT TERM

main() {
    require_root
    if [ "${SINGCTL_GO_DATAPLANE:-0}" != "1" ]; then
        check_command "ip"
        fw_check_deps
    fi

    stop_singbox_proc
    if [ "${SINGCTL_GO_DATAPLANE:-0}" != "1" ]; then
        fw_stop_cleanup
        cleanup_route
    fi

    # 清理持久化缓存与沙盒工作区
    rm -f /etc/sing-box/cache.db /tmp/sing-box-cache.db 2>/dev/null && echo_succ "已清理缓存文件" || true
    cleanup_sandbox_work

    echo_succ "停止 sing-box 并清理完毕"
}

main
