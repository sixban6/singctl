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
  ├── SubStore (订阅管理面板，可选)
  └── WARP (出口节点，可选)
```

Caddy 负责 TLS 终止和域名路由，sing-box 处理代理协议，SubStore 提供订阅转换服务。

---

## 配置文件

相关字段位于 `singctl.yaml`：

```yaml
server:
  sb_domain: "sub.yourdomain.com"         # 你的域名（必填）
  cf_dns_key: "your_cloudflare_api_token" # Cloudflare API Token，用于自动申请 TLS 证书（必填）
  sni: "swdist.apple.com"                 # TLS SNI 伪装域名，默认 swdist.apple.com（可选）
```

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

直接从当前正在运行的 `sing-box` 部署配置文件（`/etc/sing-box/config.json`）中读取实际生效的节点凭证与参数（包含 Hysteria 2、VLESS Reality 的 UUID、Public Key、Short ID 及 SNI 域名等），将其同步更新写入到 Sub-Store，并默认重启 Sub-Store 容器确保数据与内存缓存立即生效。

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

