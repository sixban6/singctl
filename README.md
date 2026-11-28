<div align="center">

# ⚡ SingCtl

**纯 Go 单二进制 · 云端节点编排与本地网络网关一体化运维工具**

[![Release](https://img.shields.io/github/v/release/sixban6/singctl?style=flat-square&color=22c55e)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl?style=flat-square)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)](https://github.com/sixban6/singctl)
[![License](https://img.shields.io/github/license/sixban6/singctl?style=flat-square)](LICENSE)

[快速安装](#-快速安装) • [日常使用](#️-日常使用) • [文档导航](#-文档导航) • [合规与许可](#️-合规与许可)

</div>

---

## ✨ 核心特性

- **极简零依赖**：纯 Go 单二进制交付，无 Docker / 数据库外部依赖，常驻内存仅约 **10~15 MB**。
- **🏠 本地网络网关（OpenWrt / Linux / macOS / Win）**：支持主路由与旁路由模式，内置离线规则集、AdGuard Home DNS 过滤、Tailscale 组网、局域网安全审计与 `:8090` Web 面板。
- **☁️ 云端节点编排（VPS）**：一键协同部署 `sing-box + Caddy + SubHub + WARP`（HTTPS 管理面板），支持多机自动化纳入配置管理，自带全链路体检与定时健康检查。

---

## 🚀 快速安装

**客户端与服务端共用同一条安装命令**，脚本自动探测当前环境与网络拓扑（路由器/桌面 → 客户端；云端服务器 → 服务端），首次安装全程按 **回车** 即可：

```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

---

## 🖥️ 日常使用

- **客户端管理**：浏览器访问 **`http://<设备IP>:8090`**，即可一站完成配置拉取、节点切换、主/旁路由与双栈切换、移动端扫码导出、局域网审计及在线自更新。
- **单台 / 首台主控 VPS**：安装按提示输入解析域名与 Cloudflare API Token，部署完毕后终端直接输出 **专属 HTTPS 管理后台地址** 与 **配置订阅链接**。
- **第 2~N 台新 VPS 扩容**：**无需登录新机**，直接在首台主控 VPS 运行 `singctl fl new`（或点击主控 Web 后台），输入新机 IP 与初始密码即可自动配解析、加固 SSH 并并入管理列表。

```bash
singctl u s            # 一键平滑自更新至最新版（自动校验 SHA256 并热重启服务）
singctl sb start       # 启动本地网关核心与守护进程
singctl w status       # 查看客户端 :8090 WebUI 地址与状态
singctl sr web status  # 查看服务端专属 HTTPS 管理后台地址与凭据
singctl sr doctor      # 执行服务端端到端健康体检与出口诊断
singctl fl new         # 在主控 VPS 上交互式纳管新节点
```

---

## 📚 文档导航

| 分类 | 覆盖内容 | 深入指南 |
| :--- | :--- | :--- |
| **🚀 实战闭环** | 单节点部署排障、多节点编排 (`fleet.yaml` / 汇总配置) | [单节点实战](docs/guide-single-node.md) · [多节点舰队](docs/guide-multi-node-fleet.md) |
| **☁️ 服务端运维** | 组件运维、`2222` SSH 加固、mTLS Web 终端 | [服务端指南](docs/server.md) · [SSH 加固](docs/ssh.md) · [Web 终端](docs/terminal.md) |
| **🏠 客户端网关** | 网关路由与分流规则、`:8090` WebUI、本地 DNS 过滤、Tailscale 组网 | [客户端路由](docs/client.md) · [本地 WebUI](docs/webui.md) · [DNS 设置](docs/dns.md) · [Tailscale](docs/tailscale.md) |
| **🩺 诊断与系统** | 网络路径探测、健壮性评估、看门狗、防火墙与工具集 | [网络诊断](docs/net.md) · [健壮性评估](docs/gfw.md) · [看门狗](docs/daemon.md) · [防火墙](docs/firewall.md) · [工具集](docs/utils.md) |

---

## ⚖️ 合规与许可

- **安全机制**：安装与自更新全程执行官方 SHA256 强校验，配置与凭据文件默认权限 **`0600`** 落盘。
- **免责声明**：本项目仅用于多云网络工程调试、跨地域延迟优化、学术通信及网络安全研究，使用者须严格遵守所在地法律法规，维护者不对任何违规或不当使用承担责任。
- **开源协议**：基于 [MIT License](LICENSE) 开源。
