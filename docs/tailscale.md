# Tailscale 组网管理 (Networking)

命令前缀：`singctl ts` / `singctl tailscale`

在 Linux/OpenWrt 设备上管理 Tailscale 异地组网。

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
# 普通模式启动
singctl ts start

# 作为路由器（推荐用于路由器设备，广播局域网子网）
singctl ts start --router

# 作为出口节点（将本机设为其他设备的出口）
singctl ts start --exit-node
```

| 参数 | 说明 |
| :--- | :--- |
| `--router` | 启用子网路由，广播本机局域网网段（适合部署在路由器上） |
| `--exit-node` | 将本机设置为 Tailscale 网络的出口节点 |

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
