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
* 🚀 **多端通用配置一键聚合与防盗刷审计**：内置纯 Go **SubHub** 订阅转换引擎（零 Docker 依赖、常驻内存 ~10MB，100% 兼容历史 Sub-Store 订阅路径），无缝对接 **Shadowrocket、Clash.Meta/Mihomo、Sing-box v1.14、Surge、Loon** 等客户端，并内置客户端拉取防盗刷审计与一键轮换密钥。
* 📊 **实时流量与双出口分流雷达 (`singctl sr top`)**：本地回环零公网暴露采集上下行吞吐波形、Hysteria2 / VLESS Reality 协议负载、原生直出 / WARP 分流占比与活跃目标域名去向。
* 🌍 **无 Agent 全球多节点舰队编排 (`singctl fleet`)**：零子节点常驻开销，新购裸机只需提供 **IP + 初始密码**，自动继承主控凭据、按归属地分配代号、自动创建 Cloudflare 灰云 DNS、完成 `22 → 2222` 免密加固并汇入单一主控总订阅。
* 🛡️ **三层自动化安全漏洞自愈 (`singctl sr heal` / `fl heal`)**：零常驻内存（原生 `systemd timer` 凌晨窗口唤醒），覆盖核心代理组件（金丝雀预检 + 15s 异常秒级回滚）、系统安全补丁与残留 `.so` 动态库热重载、以及多节点内核单台串行滚动重启与故障熔断。

---

## 🚀 1 分钟极速上手

> [!TIP]
> **单节点与多节点怎么选？**
> - **只有 1 台 VPS**：直接按【场景一】跑完即可，全部功能一步到位。
> - **有 2 台及以上 VPS**：只在**第 1 台主控机（Master）**跑一次【场景一】；买第 2~N 台新机时**切勿再登新机跑 `install.sh`**，直接按【场景二】在主控机一条命令远程开荒，新节点会自动汇入第 1 台的同一条总订阅链接！

### 场景一：【单节点 VPS / 舰队首台主控部署】

登录你的**唯一一台 VPS**（或多节点架构中的**第 1 台主控 VPS**，支持 Debian / Ubuntu / CentOS），执行自动化部署向导：

```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

> **全流程一气呵成**（完整图文排障见 [👉 单节点实战全解](docs/guide-single-node.md)）：
> 1. 选择 `1) 服务端模式 (Server Mode)`，按向导填写解析域名与 Cloudflare Token；
> 2. 回车确认立即执行四核全量部署，完成后终端直接呈现 **专属 HTTPS 管理后台入口** 与 **唯一总订阅链接**；
> 3. 支持登录专属控制台一键导入客户端或调取二维码，开启双出口智能分流体验。

---

### 场景二：【第 2~N 台新 VPS 扩容组网】（多节点舰队 — 零配置复用主控信息）

新买第 2、第 3 台空白裸机 VPS 时，**无需手动登录新机，也无需提前去 Cloudflare 配解析**，直接在**第 1 台主控 VPS** 上只需提供**新机 IP 与初始密码**即可一键开荒（或在主控自适应 Web 后台点击「新机零配置开荒」）：

```bash
# 方式 A：零参数交互向导（最推荐：密码免回显，不留命令历史，回车前自动预览分配的代号与域名）
singctl fl new

# 方式 B：极简一行非交互命令（仅需新机 IP 与初始密码，其余全部自动复用主控配置）
singctl fl new --host 203.0.113.10 --password '<新机root初始密码>'

# 方式 C：共享 IP 的 NAT 小鸡一行开荒（指定商家映射的 SSH 端口与分配的 HY2 / VLESS 节点端口）
singctl fl new --host 203.0.113.10 --port 15500 --hy2-port 11501 --vless-port 11502 --password '<新机root初始密码>'
```

> **全自动智能闭环说明**（亦支持 `singctl fl new jp1 --domain ...` 手动指定，详见 [👉 多节点舰队全解](docs/guide-multi-node-fleet.md)）：
> - **自动归属地命名 + 自动 `.cdn` 灰云 DNS**：自动探测新机 IP 所在国家/城市分配唯一编号代号（如 `sg1` / `新加坡`，同国第 2 台自动递增为 `sg2`），并复用主控 `cf_dns_key` 在根域名下自动创建 `<id>.cdn.<根域名>`（如 `sg1.cdn.example.com`）灰云（仅 DNS）解析记录（退租执行 `singctl fl rm sg1` 时自动同步清理 DNS）。
> - **防锁死加固 + 汇入唯一总订阅**：自动注入双公钥、验证切换 SSH `22 → 2222` 免密禁密码（销毁明文密码） → 部署四核组件 → 自动提取新节点并入**第 1 台主控的总订阅链接**，家里软路由与随身手机无需改配置自动热同步上线。
> - **原生兼容共享 IP 的 NAT 小鸡**：通过 `--port 15500` 指定商家映射的初始 SSH 端口（若 `2222` 未分配会自动退回 `15500` 原地完成免密禁密码加固，并智能保留机内 `Port 22` 防止母鸡 DNAT 转发断联），同时通过 `--hy2-port 11501` / `--vless-port 11502` 将 Hysteria2 (UDP) 与 VLESS-Reality (TCP) 分别绑定至商家分配的可用端口并自动汇入总订阅。

---

### 场景三：【客户端路由中枢】（Mac / Linux / 软路由 / Windows 本地透明路由）

**macOS (Homebrew)**
```bash
brew tap sixban6/singctl
brew install sixban6/singctl/singctl
```

**Linux / OpenWrt 软路由网关**（自动识别软路由并选用 `-lite` 轻量包）
```bash
curl -fsSL https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh
```

**Windows 11 (管理员 PowerShell)**
```powershell
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "[System.IO.File]::WriteAllText('install.ps1', (irm https://raw.githubusercontent.com/sixban6/singctl/main/install.ps1 -UseBasicParsing), [System.Text.Encoding]::UTF8); & .\install.ps1"
```

**日常运维常用命令**：
```bash
singctl dns status   # 查看本地防劫持 AdGuard Home 运行状态、局域网面板地址与登录密码
singctl sb gen       # 拉取订阅并生成客户端配置 (已安装 AdGuard Home 时自动对接 dns_local)
singctl sb start     # 启动客户端路由引擎与看门狗 (看门狗自动静默热同步订阅变更并守护本地 DNS)
singctl sb stop      # 停止客户端路由引擎与看门狗 (Linux / 软路由后台模式)
singctl w start      # 后台启动本地可视化 Web 控制台 (默认监听 :8090，本机访问 http://127.0.0.1:8090)
singctl doctor       # 运行客户端全链路健康体检
```

---

## 🖥️ 专属隐蔽控制台与健康体检

SingCtl 服务端自带现代化 Web 控制台，基于 **Session Cookie** 严苛会话验证（浏览器标签关闭即自动注销），公网无裸露端口，流量均经由 Caddy HTTPS 网关进行隐蔽路径转发：

```bash
singctl sr web start   # 启动服务端管理后台
singctl sr web status  # 查看专属访问 URL、随机路径与管理员凭据
singctl sr top         # 终端实时观测上下行吞吐、协议负载与 WARP 分流雷达
singctl sr doctor      # 终端执行端到端健康体检
singctl sr heal        # 本机三层安全漏洞无感热修复 (--enable-timer 开启每日凌晨自动守护)
singctl fl heal        # 全舰队协同安全自愈 (单台串行滚动重启新内核 + 异常自动熔断)
singctl fl probe       # 并发对全球子节点发起零 SSH 日志 HTTPS :443 毫秒级探活与证书余量检测
singctl fleet doctor   # 并发对全球多台纳管子节点执行健康体检
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

全部进阶配置与排障手册均按四大场景归类于 `docs/` 目录：

| 所属分类 | 模块与命令 | 核心能力说明 | 深入指南 |
| :--- | :--- | :--- | :--- |
| **🚀 实战教程** | **单节点开荒闭环**<br>`singctl ssh` / `sr` | 新机 SSH 防锁死加固、四核一键部署、客户端接入与防盗刷全流程 | [👉 单节点实战](docs/guide-single-node.md) |
| **🚀 实战教程** | **多节点舰队闭环**<br>`singctl fl` / `dm` | 主从架构、`fleet.yaml` 纳管、60s 裸机开荒、巡检自愈与软路由无感热同步 | [👉 多节点舰队](docs/guide-multi-node-fleet.md) |
| **☁️ 服务端运维** | **服务端全生命周期**<br>`singctl sr` | 四核组件安装升级、`sr top` 实时雷达、WARP 解锁与隐蔽 Web 管理后台 | [👉 服务端指南](docs/server.md) |
| **☁️ 服务端运维** | **SSH 加固与隐蔽终端**<br>`singctl ssh` / `term` | 批量免密、端口平滑迁至 `2222`、mTLS 双向认证 Web 终端与 WSS 穿透 | [👉 SSH 加固](docs/ssh.md)<br>[👉 隐蔽终端](docs/terminal.md) |
| **🏠 客户端网关** | **透明路由与可视化面板**<br>`singctl sb` / `web` | TProxy/TUN 网关、两层极简分流 (`Game`/`Game-UDP`)、规则集离线缓存、iOS 导出与本地 WebUI | [👉 客户端路由](docs/client.md)<br>[👉 本地 WebUI](docs/webui.md) |
| **🏠 客户端网关** | **本地防劫持加密 DNS**<br>`singctl dns` | 一键托管 AdGuard Home (`127.0.0.1:5353` + 局域网面板)、纯 IP DoH 免向导部署 | [👉 防劫持 DNS](docs/dns.md) |
| **🏠 客户端网关** | **Tailscale 私网互联**<br>`singctl ts` | 异地多机私网直连、家庭局域网 Subnet 路由通告与 Exit Node 配置 | [👉 Tailscale 指南](docs/tailscale.md) |
| **🩺 诊断与系统** | **链路选型与健壮性评测**<br>`singctl net` / `gfw` | 三网回程骨干识别 (CN2/9929/CMI)、QUIC 丢包抖动测试与 5 维主动探测评分 | [👉 网络诊断](docs/net.md)<br>[👉 健壮性评估](docs/gfw.md) |
| **🩺 诊断与系统** | **看门狗、防火墙与工具**<br>`singctl dm` / `fw` / `ut` | 进程与本地 DNS 崩溃自愈、最小权限防火墙加固、带宽测速与平滑自更新 | [👉 看门狗守护](docs/daemon.md)<br>[👉 防火墙加固](docs/firewall.md)<br>[👉 实用工具](docs/utils.md) |

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
