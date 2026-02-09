# Tailscale 集成指南

本文档详细介绍了 `singctl` 中针对 OpenWrt 和 ImmortalWrt 系统的 Tailscale 管理功能的实现。

## 概述

该集成提供自动化的 Tailscale 安装和配置功能，支持两种模式：使用 `kmod-tun` 的内核模式 (Kernel Mode) 和用户态模式 (Userspace Mode)。

## 支持的系统

-   **OpenWrt**
-   **ImmortalWrt**

CLI 命令 `singctl install tailscale` 和 `singctl start tailscale` 会检查系统兼容性，如果运行在不支持的平台上将会中止操作。

## 实现细节

### 1. 安装 (`singctl install tailscale`)

安装过程执行以下步骤：

1.  **下载**: 获取官方 Tailscale 二进制文件（目前锁定版本 `1.94.1` amd64）。
2.  **安装**: 解压二进制文件 (`tailscale`, `tailscaled`) 到 `/usr/sbin` 目录。
3.  **创建服务**: 生成启动脚本 `/etc/init.d/tailscale`。
    -   **模式检测**: 脚本和安装程序使用 `lsmod` 检查 `tun` 内核模块。
        -   **内核模式**: 如果检测到 `tun`，服务配置为使用 TUN 设备 `/dev/net/tun`。
        -   **用户态模式**: 如果未检测到 `tun`，服务配置添加 `--tun=userspace-networking` 参数。
4.  **启用并启动**: 设置服务开机自启并立即启动。

### 2. 配置与启动 (`singctl start tailscale`)

启动命令负责配置环境并将 Tailscale 节点上线：

1.  **Tailscale Up**: 使用以下默认参数执行 `tailscale up`：
    -   `--advertise-routes=192.168.31.0/24`: 宣告本地子网（目前硬编码，未来可能需要在配置中指定）。
    -   `--accept-dns=false`: 禁用 Tailscale DNS 以避免冲突。
    -   `--netfilter-mode=on`: 仅在内核模式下启用。
2.  **网络配置 (UCI)**:
    -   创建一个绑定到 `tailscale0` 的非托管 (unmanaged) 网络接口 `tailscale`。
3.  **防火墙配置 (UCI)**:
    -   创建防火墙区域 `tailscale` 并启用 IP 伪装 (Masquerading)。
    -   设置转发规则：
        -   `tailscale` -> `lan`
        -   `lan` -> `tailscale`
        -   `tailscale` -> `wan`

### 3. 验证

验证安装是否成功：

-   检查服务状态: `/etc/init.d/tailscale status`
-   检查 Tailscale 状态: `tailscale status`
-   验证防火墙区域: `uci show firewall`

## 故障排除

-   **lsmod 失败**: 如果系统缺少 `lsmod` 命令或执行失败，安装程序将默认使用用户态模式逻辑（假设没有 TUN）。
-   **架构**: 目前硬编码为 `amd64`。对于其他架构（如 `arm64`），需要调整 `internal/tailscale/tailscale.go` 中的下载 URL。
