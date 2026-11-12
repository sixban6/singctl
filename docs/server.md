# 服务端部署 (Server Deployment)

命令前缀：`singctl sr` / `singctl server`

一键在 Linux 服务器上部署完整的代理服务端。

---

## 架构概览

```
客户端
  │ VLESS / Hysteria2
  ▼
Caddy (反向代理 + TLS 证书)
  │
  ▼
sing-box (核心路由)
  │
  ├── SubHub (原生 Go 订阅聚合中枢 singctl-sub，零 Docker 依赖)
  └── WARP (出口节点，可选)
```

Caddy 负责统一监听 443 端口（TCP 与 UDP），基于 Layer 4 SNI 进行智能分流并申请 TLS 证书，sing-box 处理代理协议（所有入站均安全监听在 `127.0.0.1` 本地回环端口），内置原生 Go `SubHub`（`singctl-sub`）提供多客户端订阅聚合与动态格式转换服务（无缝兼容原有 `/etc/sub-store` 数据与客户端订阅 URL）。

服务端支持部署 2 种主力协议节点（全部统一通过 443 端口接入，ALPN 均为标准伪装）：
- **Hysteria 2**：基于 QUIC/UDP（端口 443，QUIC SNI `node_domain`，ALPN `h3`）与域名 TLS 证书。
- **VLESS Reality**：基于 TCP（端口 443，Reality SNI 伪装分流，默认伪装域名 `swdist.apple.com`）。

---

## 配置文件

相关字段位于 `singctl.yaml`：

```yaml
server:
  node_tag: "los"                         # (可选) 节点地区/名称标识 (例如: los, sg, hk)，留空自动根据公网 IP 智能识别
  node_domain: "node.example.com"         # 节点主域名（用于 Sub-Store 面板与 Hysteria 2，必填）
  substore_domain: ""                     # (可选) Sub-Store 专属域名，留空默认使用 node_domain
  cf_dns_key: "your_cloudflare_api_token" # Cloudflare API Token，用于自动申请 TLS 证书（必填）
  sni: "swdist.apple.com"                 # TLS SNI 伪装域名，默认 swdist.apple.com（可选）
  web_terminal:                           # (可选) mTLS Web 终端与 SSH 穿透配置 (singctl term install 自动生成)
    enabled: true
    port: 18080
    path: "/term-8f9a2b"
    mtls_ca: "/etc/caddy/mtls/ca.crt"
    ssh_tunnel_port: 18081
    ssh_tunnel_path: "/ssh-ws"
    ssh_port: 22
```

### 节点标识 (`node_tag`) 说明

- `node_tag` 用于在多台服务器集群部署时区分节点代号（如 `los` 代表洛杉矶，`sg` 代表新加坡，`hk` 代表香港）。
- 该代号会直接应用在 Sub-Store 聚合订阅的节点命名、客户端分享链接、mTLS 客户端证书命名（如 `los-client.crt`）以及本地 SSH 别名（`vps-los`）中。
- 若留空，singctl 将在部署或同步时自动基于公网 IP 通过 GeoIP 查询城市地区代号进行智能命名。

### 静态配置 vs 动态命令修改 SNI

**方式一（静态）**：直接在 `singctl.yaml` 中配置 `server.sni` 字段，然后重新部署。

**方式二（动态）**：使用 `singctl sr sni` 命令在不重新部署的情况下修改 SNI 并热重启服务：

```bash
singctl sr sni swdist.apple.com
```

> 动态修改会同步更新 `singctl.yaml` 中的 `server.sni` 字段，保证配置文件与运行时一致。

---

## 命令详解

### `singctl sr install` — 全量部署

一键部署所有服务端组件（sing-box、Caddy、SubStore、WARP）。

```bash
singctl sr install
```

---

### `singctl sr ri [target]` — 重装服务端组件

重装服务端组件（支持全量重装或指定单个组件重装）。

**版本检查机制**：
- **默认行为**：检查目标组件是否有更新。若已是最新版本，将跳过重装（输出组件当前版本与最新版本对比）；仅当发现新版本时才执行重装。
- **强制重装 (`-f` / `--force`)**：跳过版本检查，直接卸载并强制重新部署目标组件。

```bash
# 智能重装：检查最新版本，仅在有新版本时重装（简写）
singctl sr ri

# 强制重装所有服务端组件（跳过版本检查）
singctl sr ri -f

# 也可以重装指定组件（默认检查版本，有新版本才重装）
singctl sr ri caddy
singctl sr ri singbox
singctl sr ri substore
singctl sr ri warp

# 强制重装指定组件
singctl sr ri caddy -f
```

---

### `singctl sr cf-token <token>` — 轮换 Cloudflare API Token

轮换 `singctl.yaml` 中的 Cloudflare API Token（`server.cf_dns_key`），重新渲染 Caddyfile 并重启 Caddy 服务以生效。

```bash
# 轮换 Cloudflare API Token（支持别名 cf / token）
singctl sr cf-token your_new_cloudflare_api_token
singctl sr cf your_new_cloudflare_api_token
```

---

### 单独部署组件

```bash
# 仅部署 Caddy（反向代理 + TLS）
singctl sr install caddy

# 仅部署 sing-box 服务端核心
singctl sr install singbox

# 仅部署 SubStore（订阅管理）
singctl sr install substore

# 仅部署 WARP（出口节点）
singctl sr install warp
```

---

### `singctl sr sni <domain>` — 修改 SNI

动态修改服务端的 TLS SNI 伪装域名并重启相关服务，无需重新全量部署。

```bash
singctl sr sni swdist.apple.com
```

---

### `singctl sr reset [target]` — 重置节点凭证并同步 Sub-Store

定期重置本机配置的所有服务端节点凭证（密码/UUID、Reality 密钥对与 Short ID），重启 sing-box，并自动更新 Sub-Store 订阅中的节点配置与热重载 Sub-Store 容器，保证安全性。

```bash
# 重置 singbox 服务端节点凭证并同步 Sub-Store
singctl sr reset sb

# 或使用完整别名
singctl sr reset singbox
```

> **提示**：可将 `singctl sr reset sb` 配置到系统定时任务（cron）中，实现周期性自动轮转密码和更新订阅。

---

### `singctl sr sync [target]` — 同步最新节点信息到 Sub-Store

直接从当前正在运行的 `sing-box` 部署配置文件（`/etc/sing-box/config.json`）中读取实际生效的节点凭证与参数（包含 Hysteria 2 与 VLESS Reality 的 UUID/密码、Public Key、Short ID 及端口等），将其同步更新写入到 Sub-Store，并默认重启 Sub-Store 容器确保数据与内存缓存立即生效。

适用于：修改了 SNI、手动调整过 sing-box 配置，或者 Sub-Store 内节点与服务器实际配置不一致时进行一键同步矫正。

```bash
# 同步节点到 Sub-Store 并重启 Sub-Store 容器（默认）
singctl sr sync

# 快捷命令别名
singctl sr ss
singctl sr sync-substore

# 仅同步配置，跳过容器重启
singctl sr sync --restart=false
```

---

### `singctl sr sub` — 原生 SubHub 订阅中枢管理

管理原生 Go 订阅聚合服务（`singctl-sub`，监听 `127.0.0.1:3001`），无需安装 Docker：
- **全格式外部订阅解析**：原生支持 `Base64 URI`、明文分享链接、`Clash.Meta YAML` 与 `Sing-box JSON`（含 `VLESS Reality`、`Hysteria2`、`AnyTLS`、`Shadowsocks-2022`、`Trojan`、`TUIC`、`VMess`）无损互转。
- **反爬 WAF 自适应伪装与双出口容灾**：拉取第三方远程订阅时自动按真实客户端 `User-Agent` 瀑布流（`v2rayNG` → `Shadowrocket` → `Clash.Meta` → `Sing-box SFA`）协商并记忆最优指纹，拦截空白/HTML 盾页污染缓存；支持直连与本机 `WARP SOCKS5 (127.0.0.1:40000)` 智能切换。

```bash
# 查看订阅中枢运行状态与聚合订阅 URL
singctl sr sub status

# 启停或重启订阅中枢服务
singctl sr sub start
singctl sr sub stop
singctl sr sub restart

# 轮换客户端订阅安全密钥并自动热重载 Caddy 路由
singctl sr sub rotate-key
```

---

### `singctl sr info` — 查看服务端面板与节点信息

随时查看当前服务器的 Web 管理控制台入口、聚合订阅链接，以及正在运行的主力协议节点（Hysteria 2、VLESS Reality）的完整客户端分享链接。

```bash
# 查看服务端信息与节点分享链接
singctl sr info

# 别名
singctl sr show
```

---

### `singctl sr term` / `singctl term` — Web 终端与 SSH 穿透通道

一键在服务端开启基于 Caddy 443 端口与 mTLS 双向认证的隐蔽运维通道：
- **Web 终端**：内置 GoTTY + Tmux，支持手机 / 浏览器无感接入与会话后台持久化；
- **SSH-over-WSS 穿透**：通过 wstunnel 将 SSH 封装在 443 端口 WebSocket 中直连，穿透企业/校园网防火墙对 22 端口的拦截。

```bash
# 一键安装并配置
singctl term install

# 导出客户端证书与 SSH 连接配置
singctl term cert

# 查看运行状态
singctl term status

# 卸载恢复
singctl term uninstall
```

> 详细的证书导入与本地 WezTerm / `~/.ssh/config` 配置教程，请参阅专用文档：[Web 终端与 SSH-over-WSS 穿透通道文档](terminal.md)。

---

### `singctl sr web` — 服务端专属隐蔽控制台与安全运维

采用 **无特征 24 位随机安全路径** (`/<24-hex-token>/`) + Caddy 动态反向代理，默认公网端口严密关闭（仅监听 `127.0.0.1:8092`），全网爬虫探测一律返回静态伪装站点。内置增强运维能力：

- **精准封禁归因与全链路联动解封**：清晰区分「登录密码爆破（15 分钟）」与「嗅探雷达手动封禁（7 天）」，在安全页或嗅探雷达点击解封时同步清理内存限流器、嗅探状态与本机/子节点内核 `nftables` 黑名单（含单 IP 与 `/24` 网段）。
- **TLS 证书健康度倒计时**：零网络开销读取本机 Caddy ACME 证书并展示剩余天数，到期不足 14 天或异常时主动预警。
- **配置保存防断网与面板平滑自升级**：在线编辑 `sing-box` 配置强制先过 `sing-box check` 预检，重启异常自动回滚 `.bak`；服务页支持一键检测并平滑热升级 `SingCtl` 自身与 `SubHub`。
- **订阅防盗刷告警与一键拉黑**：自动分析 24 小时订阅拉取的多国 IP 扩散与爬虫 UA 特征，支持一键轮换订阅密钥或直接封禁可疑 IP。
- **AES-256-GCM 加密灾备快照**：使用 `PBKDF2-HMAC-SHA256`（21 万次迭代）+ `AES-256-GCM` 纯内存打包导出/恢复 `singctl.yaml`、`fleet.yaml`、`fleet_keys/*`、`sub-store` 与主控 SSH 密钥（落盘强制 `0600` 权限并自动对齐密钥路径）。

```bash
# 启动 Web 管理面板
singctl sr web start

# 查看专属访问 URL、随机路径与临时凭据
singctl sr web status

# 停止 Web 管理面板
singctl sr web stop

# 解除被防爆破或手动拦截的 IP
singctl sr web unban 198.51.100.10

# 一键解封所有受限 IP
singctl sr web unban all
```

---

### `singctl sr doctor` — 全链路健康体检与故障自检

全自动对系统环境、TCP BBR 加速、核心端口监听、四核服务状态、TLS 证书有效期、Reality SNI 伪装握手连通性及海外流媒体与 AI 出口解锁进行端到端自动化体检：

```bash
# 执行全链路体检
singctl sr doctor

# 快捷别名
singctl doctor
singctl doc
```

---

### `singctl sr top` — 实时流量与双出口分流雷达

基于 `sing-box` 本地回环遥测接口（`127.0.0.1:9099` + `0600` Bearer 密钥，零公网暴露），在终端或 WebUI 总览页实时观测上下行速率、Hysteria2 / VLESS Reality 协议负载占比、原生直出 / WARP 双出口分流占比以及 Top 活跃目标域名去向：

```bash
# 终端实时刷新分流雷达（默认 1.5s 刷新，按 Ctrl+C 退出）
singctl sr top

# 为历史旧配置无损开启本地遥测接口（不更改任何节点 UUID / 密码）
singctl sr top --enable

# 单次快照输出（适合脚本采集）
singctl sr top --once
```

---

### `singctl sr heal` — 三层自动化安全自愈与零中断升级

零常驻内存开销（基于每日 `04:00` `systemd timer` 维护窗口运行，状态以 `0600` 权限落盘于 `/etc/singctl/security_heal.json`），自动防御系统内核、系统库及核心代理组件漏洞：

- **Layer 1（核心二进制）**：巡检 `singctl`、`sing-box`、`Caddy`、`wireproxy` 上游稳定版，执行 SHA-256 完整性校验 + `sing-box check` / `caddy validate` 离线预检 + `.heal.bak` 备份 + 15 秒健康探针，失败自动秒级回滚。
- **Layer 2（系统安全补丁与残留动态库热重载）**：自动拉取 Debian/Ubuntu `-security` 或 RHEL `dnf --security` 安全更新（强制 `--force-confdef --force-confold` 保护 `2222` SSH 配置并经 `sshd -t` 校验），扫描 `/proc/*/maps` 清理仍占用旧漏洞 `.so`（如 `libssl.so (deleted)`）的守护进程并平滑重载。
- **Layer 3（内核高危漏洞感知）**：对比运行中 `uname -r` 与 `/boot/vmlinuz-*` 及 `/var/run/reboot-required`，单节点默认仅告警不擅自重启（除非开启 `--allow-reboot`）。

```bash
# 只读扫描三层漏洞状态（不执行变更）
singctl sr heal --check

# 立即执行三层安全自愈（热修复 Layer 1 + Layer 2）
singctl sr heal

# 开启每日凌晨 04:00 自动化安全自愈定时器（systemd timer，零常驻内存）
singctl sr heal --enable-timer

# 关闭自动化安全自愈定时器
singctl sr heal --disable-timer
```

---

### `singctl fleet` (`fl`) — 无 Agent 全球多节点舰队编排

无需在子节点常驻任何额外 Agent 进程，清单以人类易读的 `/etc/singctl/fleet.yaml`（`0600` 权限，自动无损迁移历史 `fleet.json`）存储。通过加密 SSH 并发管理多地域 VPS，自动继承主控配置并实时汇入主控 `SubHub` 统一订阅池：

```bash
# 极简零配置开荒：自动复用主控 Cloudflare Token / SNI / 带宽，自动识别地域代号并创建灰云 DNS 记录！
singctl fl new --host 203.0.113.10 --password '<root初始密码>'

# 零参数向导式开荒（密码不回显、不进 history）
singctl fl new

# 手动全参数覆盖模式（自定义代号 jp1 / 名称 / 域名）
singctl fleet new jp1 --name "日本东京" \
  --host 203.0.113.10 --port 22 --password '<root初始密码>' \
  --domain jp1.example.com --cf-token '<CF_API_TOKEN>'

# 纳管已有 SingCtl 节点并同步进主控订阅池
singctl fleet add tokyo --name "东京主力" --alias vps-tokyo --sync

# 查看所有子节点（不加代号默认操作全部子节点；加上代号如 jp1 则仅操作该台机器）
singctl fleet list
singctl fleet doctor          # 全网体检（单台点名: singctl fleet doctor jp1）
singctl fleet sync            # 全网同步（单台点名: singctl fleet sync jp1）
singctl fleet heal            # 全网三层安全自愈 + 内核漏洞 1-by-1 串行滚动重启（异常自动熔断！）
singctl fleet heal --enable-timer  # 为主控与全体子节点开启每日 04:00 自动安全自愈
singctl fleet reset           # 全网换血重置密码（单台点名: singctl fleet reset jp1）
singctl fleet update          # 全网升级（单台点名: singctl fleet update jp1）
singctl fleet remove jp1      # 机器到期下线，自动清理 fleet.yaml、总订阅池及自动托管的 DNS 记录（加 --keep-dns 可保留 DNS）
```

> 📘 **实战保姆级指南**：请查阅 [单节点 VPS 部署与运维全解](guide-single-node.md) 与 [多节点 VPS 舰队 + 软路由闭环全解](guide-multi-node-fleet.md)。




