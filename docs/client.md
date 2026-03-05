# 客户端管理 (Client Management)

命令前缀：`singctl sb` / `singctl singbox`

管理 sing-box 客户端的安装、配置生成、启动与停止。

---

## 配置文件

相关字段位于 `singctl.yaml`：

```yaml
subs:                                         # 订阅配置（至少配置一个）
  - name: "main"                              # 订阅名称（多订阅时必填，且不可重复）
    url: "https://your-subscription-url"      # 订阅链接（必填）
    skip_tls_verify: false                    # 是否跳过 TLS 验证
    remove-emoji: true                        # 是否移除节点名称中的 emoji

github:
  mirror_url: "https://gh-proxy.com"         # GitHub 镜像加速地址（国内推荐）

hy2:
  up: 21                                      # Hysteria2 上行带宽 (Mbps)
  down: 200                                   # Hysteria2 下行带宽 (Mbps)
```

> **注意**：`singctl sb gen` 和 `singctl sb start`（首次启动）需要 `subs` 中至少有一条有效的订阅 URL，否则会提示配置错误。`singctl sb stop`、`singctl sb install`、`singctl sb update` 不依赖订阅配置。

---

## 命令详解

### `singctl sb install` — 安装 sing-box

在当前平台安装 sing-box 核心。

- **Linux/OpenWrt**：从 GitHub Releases 下载对应架构的二进制并安装到系统路径。
- **macOS/Windows**：下载并安装官方 GUI 客户端（SFM）。

```bash
singctl sb install
```

---

### `singctl sb gen` — 生成配置文件

根据 `singctl.yaml` 中的订阅信息拉取节点并生成 sing-box 配置文件。

```bash
# 生成到默认位置 (/etc/sing-box/config.json)，自动备份旧配置
singctl sb gen

# 输出到控制台（用于调试或预览）
singctl sb gen --stdout

# 指定输出路径
singctl sb gen -o /tmp/config.json
```

| 参数 | 说明 |
| :--- | :--- |
| `--stdout` | 将生成的 JSON 输出到标准输出，不写入文件 |
| `-o <path>` | 指定输出文件路径，覆盖默认的 `/etc/sing-box/config.json` |

---

### `singctl sb start` — 启动 sing-box

启动 sing-box。若当前没有有效的配置文件，会先自动调用 `gen` 生成。

```bash
singctl sb start
```

**平台行为差异：**

| 平台 | 行为 |
| :--- | :--- |
| Linux / OpenWrt | 以后台服务方式启动 sing-box，并打印控制面板地址 |
| macOS / Windows | 启动 GUI 客户端（SFM），并打开配置文件路径供手动导入 |

---

### `singctl sb stop` — 停止 sing-box

停止正在运行的 sing-box 进程，并关闭守护进程（如有）。

```bash
singctl sb stop
```

> macOS/Windows 上此命令无效，请直接退出 GUI 客户端。

---

### `singctl sb update` — 更新 sing-box 内核

重新从 GitHub 下载最新版本并替换当前安装的二进制。

```bash
singctl sb update
```
