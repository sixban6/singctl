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
