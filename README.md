<div align="center">

# ⚡ SingCtl

**新一代极简、硬核、企业级跨地域云节点与客户端网络运维中枢**

一条命令打通跨地域云主机边缘节点与 Mac / Linux / Windows 客户端全生命周期运维

[![Release](https://img.shields.io/github/v/release/sixban6/singctl?style=flat-square&color=22c55e)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl?style=flat-square)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)](https://github.com/sixban6/singctl)
[![License](https://img.shields.io/github/license/sixban6/singctl?style=flat-square)](LICENSE)

[快速上手](#-1-分钟极速上手) • [核心特性](#-为什么选择-singctl) • [控制台特性](#-专属隐蔽控制台与健康体检) • [文档导航](#-全功能深入文档导航) • [合规免责](#-合规与免责声明)

</div>

---

## 💡 为什么选择 SingCtl？

跨地域云主机与分布式网络运维常面临三大痛点：**多组件拼凑部署繁琐、网络扫描与异常阻断频发、节点故障排查困难**。  
`SingCtl` 为解决这三大运维挑战而生，由纯 Go 原生编译打造，运行时内存开销仅 **10~20MB**：

* 🛡️ **动态伪装与零特征防护**：基于 Caddy 443 统一反代分流，内置**高熵随机伪装博客引擎**，搭配 **16 位专属安全路径**（`/sr/<token>/`）与 **3 次输错封禁 IP** 防爆破安全网关，非授权探测一律回落至合法伪装站点。
* ⚡ **原生四核自愈协同**：**sing-box** (核心路由引擎) + **Caddy** (自动化证书/安全网关) + **SubHub** (纯 Go 零 Docker 订阅聚合中枢) + **WARP** (双出口智能分流) 深度融合。
* 🩺 **全链路一键体检 (`singctl doctor`)**：系统负载、BBR 拥塞控制、端口监听、四核组件健康度、TLS 证书周期、Reality SNI 握手及双出口网络画像端到端一键自检。
* 🌐 **三网骨干回程拓扑画像 (`singctl net`)**：并发探测中国电信 (163/CN2)、中国联通 (4837/9929)、中国移动 (CMI/CMIN2) 骨干网，输出精准路由画像与延迟报告。
* 🚀 **多端通用配置一键聚合**：内置纯 Go **SubHub** 订阅转换引擎（零 Docker 依赖、常驻内存 ~10MB，100% 兼容历史 Sub-Store 订阅路径），无缝对接 **Shadowrocket、Clash.Meta/Mihomo、Sing-box v1.14、Surge、Loon** 等客户端。

---

## 🚀 1 分钟极速上手

### 场景一：【服务端部署】（跨地域云服务器一键初始化并获取运维配置）

登录你的云服务器（Debian / Ubuntu / CentOS），执行自动化部署向导：

```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

> **全流程自动化**：
> 1. 选择 `1) 服务端部署 (Server)`，按向导填写解析域名与 Cloudflare Token；
> 2. 安装完成后，终端呈现 **专属 HTTPS 管理后台入口** 与 **客户端聚合订阅链接**；
> 3. 支持登录专属控制台一键导入客户端或调取二维码，开启双出口智能分流体验。

---

### 场景二：【客户端路由中枢】（Mac / Linux / 软路由 / Windows 本地透明路由）

**macOS (Homebrew)**
```bash
brew tap sixban6/singctl
brew install sixban6/singctl/singctl
```

**Linux / 软路由网关**
```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

**Windows 11 (管理员 PowerShell)**
```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "[System.IO.File]::WriteAllText('install.ps1', (irm https://raw.githubusercontent.com/sixban6/singctl/main/install.ps1 -UseBasicParsing), [System.Text.Encoding]::UTF8); & .\install.ps1"
```

**日常运维常用命令**：
```bash
singctl sb run       # 启动客户端透明路由引擎 (TUN / TProxy)
singctl sb stop      # 停止客户端路由引擎
singctl w            # 启动本地可视化 Web 控制台 (默认 http://127.0.0.1:8090)
singctl doctor       # 运行客户端全链路健康体检
```

---

## 🖥️ 专属隐蔽控制台与健康体检

SingCtl 服务端自带现代化 Web 控制台，基于 **Session Cookie** 严苛会话验证（浏览器标签关闭即自动注销），公网无裸露端口，流量均经由 Caddy HTTPS 网关进行隐蔽路径转发：

```bash
singctl sr web start   # 启动服务端管理后台
singctl sr web status  # 查看专属访问 URL、随机路径与管理员凭据
singctl sr doctor      # 终端执行端到端健康体检
singctl sr mask-site   # 重新生成或换一批随机伪装站点
```

```
═══════════════════════════════════════════════════════════
                 🩺 SINGCTL 全链路健康体检报告
═══════════════════════════════════════════════════════════
体检时间: 2026-11-03 02:04:06  |  综合健康指数: 100 / 100
───────────────────────────────────────────────────────────
  [✓] 基础运行环境             : Debian 12 (amd64), CPU: 1 核
  [✓] TCP 拥塞控制算法         : Google BBR 加速 [已激活启用]
  [✓] 网关与管理端口监听          : 核心端口 (80, 443, 8092) 均正常监听运行
  [✓] Caddy 网关           : 服务处于活跃运行状态 (active)
  [✓] sing-box 核心        : 服务处于活跃运行状态 (active)
  [✓] SubHub 订阅引擎         : 原生 Go 服务处于活跃运行状态 (active)
  [✓] WARP (wireproxy)     : 服务处于活跃运行状态 (active)
  [✓] HTTPS 证书状态         : Let's Encrypt 原生证书正常 (剩余 89 天)
  [✓] Reality 目标探测        : 目标 SNI [swdist.apple.com] 握手正常 (8 ms, TLS 1.3)
  [✓] SubHub 订阅聚合         : 原生 Go 引擎响应正常 (HTTP 200)
  [✓] VPS 原生出口画像         : OpenAI [SG] | Netflix [完整支持] | YouTube [原生]
  [✓] WARP 分流出口画像        : OpenAI [SG] | Netflix [完整支持] | YouTube [原生]
───────────────────────────────────────────────────────────
结论: 🎉 系统运行状态极佳！所有核心组件、TLS 证书与高可用链路均处于健康状态。
═══════════════════════════════════════════════════════════
```

---

## 📚 全功能深入文档导航

各项进阶模块与调优配置已整理至 `docs/` 目录中：

| 运维场景 | 对应模块 | 核心能力说明 | 完整指南 |
| :--- | :--- | :--- | :---: |
| **服务端全生命周期** | `singctl sr` | 四核组件安装、伪装站重置、凭据管理、专属Web后台 | [👉 服务端运维指南](docs/server.md) |
| **客户端透明路由** | `singctl sb` | TUN / TProxy 模式、规则集本地加速、iOS 配置生成 | [👉 客户端配置指南](docs/client.md) |
| **网络拓扑与选型** | `singctl net` | 跨境三网回程线路识别 (CN2/9929/CMI)、丢包抖动评测 | [👉 网络诊断指南](docs/net.md) |
| **网络健壮性仿真** | `singctl gfw` | 模拟复杂网络环境下的主动探测抗压与握手健壮度评分 | [👉 健壮性测试指南](docs/gfw.md) |
| **隐蔽 Web 终端** | `singctl term` | 基于 mTLS 双向认证的 Web 终端 (GoTTY) 与安全穿透 | [👉 隐蔽终端指南](docs/terminal.md) |
| **SSH 免密与加固** | `singctl ssh` | 批量免密分发、端口收敛至 2222、禁用密码与防失联 | [👉 SSH 加固指南](docs/ssh.md) |
| **客户端可视化控制** | `singctl web` | 本地浏览器控制台、实时多节点分流与流量监控 | [👉 WebUI 管理指南](docs/webui.md) |
| **Tailscale 私网互联**| `singctl ts` | 多机私有内网互联、Subnet 路由转发与 DERP 自建 | [👉 Tailscale 指南](docs/tailscale.md) |
| **守护进程与看门狗** | `singctl dm` | sing-box 后台进程自动看门狗、异常崩溃自动拉起 | [👉 守护进程指南](docs/daemon.md) |
| **系统防火墙加固** | `singctl fw` | Linux / OpenWrt 专用最小权限开放加固规则 | [👉 防火墙指南](docs/firewall.md) |
| **实用综合工具** | `singctl ut` | 单线程/多线程测速、配置迁移、核心组件自更新 | [👉 实用工具指南](docs/utils.md) |

---

## ⚖️ 合规与免责声明

1. 本项目为开源的网络工程辅助与分布式节点运维工具，旨在为多云网络调试、跨地域网络延迟优化、学术网络通信及网络安全研究提供自动化支持。
2. 使用者在部署与运行本项目时，应严格遵守所在国家与地区的法律法规，严禁将本项目用于任何违反当地法律法规的活动。
3. 项目维护者不对使用者因不当配置、违规使用所导致的直接或间接法律后果承担连带责任。

---

## 🔒 安全与完整性校验

SingCtl 在安装与升级时均严格执行 SHA256 完整性校验，配置文件（`singctl.yaml`）默认权限设为 `600`，严格杜绝配置与凭据泄露。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 协议开源。
