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

> 启动时若检测到现有配置中存在远程规则集（remote rule_set），会自动迁移为
> 本地缓存引用，使 sing-box 启动不依赖 GitHub（详见 `sb cache`）。

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

---

### `singctl sb cache` — 规则集本地缓存管理

生成的配置中 `route.rule_set` 绝大多数为远程引用（URL 指向 GitHub），
sing-box 启动阶段必须完成远程规则集下载，一旦 GitHub 不可用服务将无法启动。

singctl 会将远程规则集预下载到本地缓存目录，并把配置改写为 `type: local`
的本地引用，使 sing-box 启动完全不依赖网络：

- 配置生成（`sb gen` / `sb start`）时自动下载并本地化；
- 下载失败时自动回退本地旧缓存（规则集变动低频，旧版本可接受）；
- 失败且无缓存时保持 remote 原样，行为与之前一致；
- 网络整体不可用时快速熔断，避免拖慢 start/restart；
- `manifest.json` 记录每个规则集的原始远程条目，支持刷新与还原。

```bash
# 刷新缓存：下载新的远程条目并本地化，同时刷新已本地化的条目
singctl sb cache update

# 查看缓存状态（每个规则集的来源、格式、更新时间、文件是否完好）
singctl sb cache status

# 还原配置为远程引用并清空缓存目录
singctl sb cache clear
```

缓存目录位于 sing-box 配置目录下的 `rule_sets/`（如 `/etc/sing-box/rule_sets`）。
下载依次尝试「镜像 → 直连」，并校验内容（.srs 魔数 / source JSON），
防止把镜像返回的错误页缓存下来。

> `sb gen --no-localize` 可生成保留远程引用的配置（例如需要迁移到其它机器时）。

