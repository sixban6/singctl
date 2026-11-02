<div align="center">

# ⚡ SingCtl

**新一代极简、硬核、无痛的自建节点与客户端透明代理运维中枢**

一条命令打通跨地域云主机边缘节点与 Mac / Linux / Windows 客户端全生命周期运维

[![Release](https://img.shields.io/github/v/release/sixban6/singctl?style=flat-square&color=22c55e)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl?style=flat-square)](https://golang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-blue?style=flat-square)](https://github.com/sixban6/singctl)
[![License](https://img.shields.io/github/license/sixban6/singctl?style=flat-square)](LICENSE)

[快速上手](#-1-分钟极速上手) • [核心特性](#-为什么选择-singctl) • [控制台特性](#-专属隐蔽控制台与健康体检) • [文档导航](#-全功能深入文档导航)

</div>

---

## 💡 为什么选择 SingCtl？

传统的跨地域云服务器常面临三大痛点：**多组件拼凑部署繁琐、公网端口裸露易受阻断、节点挂了排查困难**。  
`SingCtl` 为解决这三大难题而生，由纯 Go 原生编译打造，内存开销仅 **10~20MB**：

* 🛡️ **无特征极度隐形**：基于 Caddy 443 统一网关分流，搭配 **16 位随机专属入口**（`/sr/<token>/`）与 **3 次输错封 IP** 防爆破机制，对全网爬虫完全 404 伪装。
* ⚡ **原生四核一体自愈**：**sing-box** (核心代理) + **Caddy** (自动申请证书/反代) + **Sub-Store** (订阅转换分发) + **WARP** (原生流媒体/AI 解锁) 深度协同。
* 🩺 **全链路一键体检 (`singctl doctor`)**：系统负载、BBR 加速、端口、四核服务状态、TLS 证书有效期、Reality SNI 伪装握手及 OpenAI/Netflix 解锁画像一键自检。
* 🌐 **三网回程画像与网络选型 (`singctl net`)**：并发探测中国电信 (163/CN2)、中国联通 (4837/9929)、中国移动 (CMI/CMIN2) 骨干网，给出智能路由优化。
* 🚀 **全平台客户端一键导入**：内置 Sub-Store 聚合分发，支持 **Shadowrocket (客户端)、Clash Verge、Sing-box、Surge、Loon** 一键唤醒与二维码导入。

---

## 🚀 1 分钟极速上手

### 场景一：【服务端自建】（新购 VPS，一键部署并获取订阅）

登录你的海外 VPS（Debian / Ubuntu / CentOS），执行一键安装向导：

```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

> **自动化体验**：
> 1. 选择 `1) 服务端部署 (Server)`，按提示输入你的解析域名与 Cloudflare Token；
> 2. 安装完成后，终端将立即生成 **专属安全 HTTPS 控制台链接** 与 **全平台客户端导入链接**；
> 3. 手机扫码或一键导入 Shadowrocket / Clash，即可享受完整流媒体解锁。

---

### 场景二：【客户端代理】（Mac / Linux 软路由 / Windows 本地透明代理）

**macOS (Homebrew)**
```bash
brew tap sixban6/singctl
brew install sixban6/singctl/singctl
```

**Linux / OpenWrt 软路由**
```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

**Windows 11 (管理员 PowerShell)**
```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "[System.IO.File]::WriteAllText('install.ps1', (irm https://raw.githubusercontent.com/sixban6/singctl/main/install.ps1 -UseBasicParsing), [System.Text.Encoding]::UTF8); & .\install.ps1"
```

**客户端日常常用命令**：
```bash
singctl sb run       # 启动客户端透明代理 (TUN / TProxy)
singctl sb stop      # 停止客户端代理
singctl w            # 开启本地 Web 控制面板 (默认 http://127.0.0.1:8090)
singctl doctor       # 运行全链路健康自检
```

---

## 🖥️ 专属隐蔽控制台与健康体检

SingCtl 服务端自带现代化 Web 控制台，基于 **Session Cookie** 严苛会话验证（关标签即失效，无长期免密风险），公网端口严密关闭，完全经由 Caddy HTTPS 反代：

```bash
singctl sr web start   # 启动服务端管理后台
singctl sr web status  # 查看专属访问 URL、随机路径与管理员凭据
singctl sr doctor      # 终端执行端到端健康体检
```

```
═══════════════════════════════════════════════════════════
                 🩺 SINGCTL 全链路健康体检报告
═══════════════════════════════════════════════════════════
体检时间: 2026-11-03 01:20:54  |  综合健康指数: 95 / 100
───────────────────────────────────────────────────────────
  [✓] 基础运行环境             : Debian 12 (amd64), CPU: 1 核
  [✓] TCP 拥塞控制算法         : Google BBR 加速 [已激活启用]
  [✓] 网关与管理端口监听          : 核心端口 (80, 443, 8092) 均正常监听运行
  [✓] Caddy 网关           : 进程处于活跃运行状态 (active)
  [✓] sing-box 核心        : 进程处于活跃运行状态 (active)
  [✓] HTTPS 证书状态         : Let's Encrypt / ZeroSSL 证书正常 (剩余有效期 89 天)
  [✓] Reality 伪装目标探测     : 目标 SNI [swdist.apple.com] 握手正常 (延迟: 10 ms, TLS 1.3)
  [✓] Sub-Store 订阅聚合     : 本地 3001 端口响应正常 (HTTP 200)
  [✓] 全球边缘多点出口画像与服务连通性       : OpenAI [SG] | Netflix [完整支持] | YouTube [原生]
───────────────────────────────────────────────────────────
结论: 🎉 系统运行状态极佳！所有核心组件、TLS 证书与高可用链路均处于健康状态。
═══════════════════════════════════════════════════════════
```

---

## 📚 全功能深入文档导航

为了保持首页清爽易读，各项深度进阶配置已整理至 `docs/` 目录中，点击直接查阅：

| 运维场景 | 对应模块 | 核心能力说明 | 完整指南 |
| :--- | :--- | :--- | :---: |
| **服务端全生命周期** | `singctl sr` | 四核组件安装、SNI热更、凭据重置、专属Web控制台 | [👉 服务端运维指南](docs/server.md) |
| **客户端透明代理** | `singctl sb` | TUN / TProxy 代理、规则集本地缓存、iOS 配置生成 | [👉 客户端配置指南](docs/client.md) |
| **网络画像与选型** | `singctl net` | 跨境三网回程线路识别 (CN2/9929/CMI)、晚高峰丢包抖动 | [👉 网络诊断指南](docs/net.md) |
| **GFW 探测仿真** | `singctl gfw` | 模拟防火墙主动探测 (Active Probing)，0~100 分量化评分 | [👉 网络健壮性测试指南](docs/gfw.md) |
| **隐蔽 Web 终端** | `singctl term` | 基于 mTLS 双向认证的 Web 终端 (GoTTY) 与 SSH 穿透 | [👉 隐蔽终端指南](docs/terminal.md) |
| **SSH 免密与加固** | `singctl ssh` | 批量免密分发、端口收敛至 2222、禁用密码登录与防失联 | [👉 SSH 加固指南](docs/ssh.md) |
| **Web 管理界面** | `singctl web` | 客户端浏览器可视化控制台、节点切换与流量监控 | [👉 WebUI 管理指南](docs/webui.md) |
| **Tailscale 组网** | `singctl ts` | 多机私有内网互联、Subnet 路由转发与 DERP 自建 | [👉 Tailscale 指南](docs/tailscale.md) |
| **后台看门狗** | `singctl dm` | sing-box 后台进程自动守护、崩溃拉起与日志审计 | [👉 守护进程指南](docs/daemon.md) |
| **系统防火墙加固** | `singctl fw` | Linux / OpenWrt 专用最小权限开放加固规则 | [👉 防火墙指南](docs/firewall.md) |
| **实用综合工具** | `singctl ut` | 单线程/多线程测速、配置迁移、自更新 | [👉 实用工具指南](docs/utils.md) |

---

## 🔒 安全与完整性校验

SingCtl 在安装与每次升级（`singctl update self`）时，均严格执行 SHA256 完整性校验，配置文件（`singctl.yaml`）默认权限设为 `600`，杜绝凭据泄露。

```bash
# 查看配置文件路径
singctl info

# 默认配置路径:
# macOS: /opt/homebrew/etc/singctl/singctl.yaml
# Linux: /etc/singctl/singctl.yaml
```

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 协议开源。
