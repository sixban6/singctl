# Tailscale 组网管理 (Networking)

命令前缀：`singctl ts`

在 Linux/OpenWrt 设备上管理 Tailscale 异地组网。

**原理**:
- 封装了tailscale，使用官方安装包。
- 统一关闭netfilter，不让tailscale修改防火墙配置，防止冲突。
- singctl ts统一接管tailscale的防火墙配置，保持稳定可靠。

> **平台限制**：以下命令仅适用于 Linux / OpenWrt，macOS/Windows 请使用 Tailscale 官方客户端。

---

## 两种部署模式

### 模式一：官方版本（推荐）

使用 Tailscale 官方二进制，功能最完整，**优先选择此模式**。

默认情况下无需配置 `tailscale` 字段，只有在需要授权密钥（`auth_key`）时才配置：

```yaml
tailscale:
  auth_key: "tskey-auth-xxxxxx"  # (可选) Tailscale 授权密钥
  use_build: false               # 使用官方二进制
```

### 模式二：sing-box 内置版本

将 Tailscale 集成进 sing-box，适用于官方版本安装受限的场景。

```yaml
tailscale:
  auth_key: "tskey-auth-xxxxxx"  # (必填) Tailscale 授权密钥
  use_build: true                # 使用 sing-box 内置 Tailscale
  subnets: "192.168.1.0/24"     # (可选) 要广播的子网，留空则自动探测局域网网段
```

> **建议**：优先使用官方版本（`use_build: false`），只有在官方版本无法满足需求时再切换到 sing-box 内置版本。

---

## 命令详解

### `singctl ts install` — 安装 Tailscale

```bash
singctl ts install
```

---

### `singctl ts start` — 启动 Tailscale

```bash
# 推荐：快速模式（一条命令）同时作为路由器 + 出口节点 + 并接收其他节点广播路由
singctl ts start -m gateway

# 作为路由器（广播本机局域网子网）
singctl ts start -r

# 作为出口节点（将本机设为其他设备的出口）
singctl ts start -e

# 同时作为路由器 + 出口节点（并接收其他节点广播路由）
singctl ts start -r -e -a
```

| 参数 | 说明 |
| :--- | :--- |
| `--router` / `-r` | 启用子网路由，广播本机局域网网段（适合部署在路由器上） |
| `--exit-node` / `-e` | 将本机设置为 Tailscale 网络的出口节点 |
| `--accept-routes` / `-a` | 接收其他节点广播路由（例如访问异地内网 IP） |
| `--mode` / `-m` | 快速模式：`client` / `router` / `exit` / `gateway` |

快速模式说明：

| 模式 | 等价行为                                               |
| :--- |:---------------------------------------------------|
| `client` | 普通客户端                                              |
| `router` | 等价 `-r`                                            |
| `exit` | 等价 `-e`                                            |
| `gateway` | 等价 `-r -e -a`（推荐路由器场景） |

注意事项：

- `--mode` 不能和 `--router/--exit-node` 同时使用。
- 未显式指定 `--accept-routes` 时：  
  普通模式默认 `true`；`--router` 或 `--exit-node` 默认 `false`（避免路由冲突）。
- 若你需要通过本机访问异地内网 IP（如老家 `192.168.x.x`），请显式加 `--accept-routes`，或直接用 `-m gateway`。
- 在 OpenWrt 上，`singctl ts start` 会按运行态自动选择 `netfilter-mode`：
  - 检测到活动中的 sing-box/TProxy 规则时，使用 `--netfilter-mode=off`，避免防火墙冲突。
  - 未检测到活动中的 sing-box/TProxy 时，使用 `--netfilter-mode=on`，让 Tailscale 正常接管网关所需规则。

---

### `singctl ts stop` — 停止 Tailscale

```bash
singctl ts stop
```

---

### `singctl ts update` — 更新 Tailscale

```bash
singctl ts update
```
