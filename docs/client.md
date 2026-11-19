# 客户端管理 (Client Management)

命令前缀：`singctl sb` / `singctl singbox`

管理 sing-box 客户端的安装、配置生成、启动与停止。

---

## 配置文件

相关字段位于 `singctl.yaml`：

```yaml
subs:                                         # 订阅配置（至少配置一个）
  - name: "main"                              # 订阅名称（多订阅时必填，且不可重复）
    url: "https://example.com/subscription"   # 订阅链接（必填）
    skip_tls_verify: false                    # 是否跳过 TLS 验证
    remove-emoji: true                        # 是否移除节点名称中的 emoji
    # include: "HK|SG|JP"                     # (可选) Go 正则：仅保留命中的节点
    # exclude: "剩余|到期|官网|流量"             # (可选) Go 正则：剔除命中的无效提示节点
    # rename:                                 # (可选) Go 正则：按顺序批量重命名节点
    #   - {match: " Premium$", replace: ""}

github:
  mirror_url: "https://gh-proxy.com"         # GitHub 镜像加速地址（国内推荐）

hy2:
  up: 21                                      # Hysteria2 上行带宽 (Mbps)
  down: 200                                   # Hysteria2 下行带宽 (Mbps)

dns:                                          # (可选) 客户端本地防劫持 DNS (AdGuard Home)
  enabled: true                               # 是否启用本地 AdGuard Home 接管 dns_local
  dns_port: 5353                              # 本地 DNS 监听端口 (仅绑定 127.0.0.1)
  web_port: 3000                              # Web 管理面板端口 (仅绑定本机局域网 IP，如 192.168.1.1)
  username: "root"                            # 管理账号 (首次安装可输入自定义账号，直接回车默认 root)
  password: ""                                # 管理密码 (首次安装留空时自动生成 16 位随机强密码)

gateway:                                      # (可选) 客户端网关拓扑模式配置
  mode: "main"                                # "main" (默认主路由模式) | "side" (旁路由单臂网关模式)
  main_router_ip: ""                          # (旁路由模式必填) 上级主路由/网关 IP，例如 "192.168.1.1"
  # lan_iface: ""                             # (可选) 指定单臂局域网网卡名，留空自动探测
```

### 主路由模式与旁路由模式（Side Router）说明

- **`mode: "main"`（主路由模式，默认）**：适用于设备直接拨号或接光猫充当全屋主网关的场景，保持标准原生 TProxy 规则运行。
- **`mode: "side"`（旁路由 / 单臂网关模式）**：适用于 N1、小主机、OpenWrt 盒子或 PVE LXC 单网口挂在主路由 LAN 口下的场景：
  - **安装阶段引导**：运行 `install.sh` 选择客户端模式后，可选择 `2) 旁路由模式`；脚本会自动探测当前上级主路由 IP（支持**直接回车确认**或**手动修改**，并自动拦截填成旁路由本机 IP 的自环错误）。
  - **内核与防火墙自动收口**：`singctl sb start` 启动时自动对齐上级默认路由、开启 `ip_forward=1` 并关闭单臂 `rp_filter` / `send_redirects` / `bridge-nf-call-iptables`，同时挂载独立可逆的 `table inet singctl-side`（含本机 `:53` 透明 DNS 接管、TCP MSS 自动钳制防止 PPPoE `1492` MTU 下 HTTPS 卡死、单臂 `masquerade` 消除主路由状态防火墙 `ct state invalid` 非对称丢包，并在 `sing-box` 内部完整保留终端真实局域网 IP 供行为审计使用）。`singctl sb stop` 时自动卸载并还原系统参数。
  - **终端 / 主路由 DHCP 接入要求**：将内网终端（或主路由 DHCP 下发）的 **默认网关** 与 **DNS 服务器** 同时设为旁路由 IP（如 `192.168.1.2`），为旁路由固定静态 IP，并在主路由关闭 LAN 侧 IPv6 RA/DHCPv6 通告以防终端经主路由 IPv6 直出绕过旁路由。

> **注意**：`singctl sb gen` 和 `singctl sb start`（首次启动）需要 `subs` 中至少有一条有效的订阅 URL，否则会提示配置错误。`singctl sb stop`、`singctl sb install`、`singctl sb update` 不依赖订阅配置。
>
> **订阅拉取可靠性增强（基于 `singgen v1.15.0`）**：
> - 遇到网络波动、`5xx` 或 `429` 时自动指数退避重试（最多 3 次）；多订阅并发拉取（最多 4 路并发），输出顺序保持确定性；
> - 每次成功拉取后以 URL 哈希落盘缓存副本（`0600` 权限，自动过滤错误页），后续若上游临时故障自动回退至上次可用副本并输出告警，防止生成空配置断网；
> - 自动解析订阅响应头 `subscription-userinfo`，在剩余流量低于 `10%` 或 `7` 天内到期/已过期时输出提示。

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

# 生成 iPhone (sing-box iOS App) 专用配置
singctl sb gen --platform ios
```

| 参数 | 说明 |
| :--- | :--- |
| `--stdout` | 将生成的 JSON 输出到标准输出，不写入文件 |
| `-o <path>` | 指定输出文件路径，覆盖默认的 `/etc/sing-box/config.json` |
| `--platform <p>` | 目标平台：`auto`（默认，当前系统）/`darwin`/`windows`/`linux`/`ios` |

### 生成 iOS (iPhone) 配置

`--platform ios` 会生成专供 iOS 官方 sing-box App (SFI) 导入的配置：

- **默认导出到 `~/Downloads/singctl-ios.json`**（不会写入本机 `/etc/sing-box/config.json`，避免看门狗误加载）；
- 拒绝通过 `-o` 覆盖本机 sing-box 配置文件；
- **保留远程规则集引用**（iPhone 沙盒无法读取本地规则集路径，也不做本地化缓存）；默认面向 `sing-box 1.14+` 自动注入顶层 `http_clients` 与 `route.default_http_client`（不再生成 1.14 弃用 / 1.16 移除的 `download_detour`），剥离国内镜像前缀后经优选代理策略组拉取规则集；
- DNS/客户端子网交由 iOS 模板默认，不注入本机局域网探测值，也不注入 clash API 与 Tailscale；
- 文件权限 `0600`（配置含节点凭据）。

导入方式：AirDrop/隔空投送该文件 → 文件 App → 分享给 sing-box App；或在 WebUI「配置」页扫码/点击下载。

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
的本地引用，使 sing-box 启动完全不依赖网络。采用三级兑底：

1. **在线下载**：镜像/直连双候选，优先获取最新版本；
2. **本地旧缓存**：下载失败时回退（规则集变动低频，旧版本可接受）；
3. **内置快照**：程序编译时打包了全部常用规则集快照（约 1.5MB，
   `go:embed` 嵌入），即使 GitHub 与镜像同时不可用、且从未建立过缓存
   （例如新装机器），也能解出快照落盘，sing-box 照常启动。

其他保障：

- 配置生成（`sb gen` / `sb start`）时自动下载并本地化；
- 失败且无任何兑底时保持 remote 原样，行为与之前一致；
- 网络整体不可用时快速熔断，避免拖慢 start/restart；
- `manifest.json` 记录每个规则集的原始远程条目，支持刷新与完整还原；
- 下载内容均经校验（新版 `SRS\x02` / 旧版 `RULE` 魔数 / source JSON），
  防止把镜像返回的错误页缓存下来。

```bash
# 刷新缓存：下载新的远程条目并本地化，同时刷新已本地化的条目
singctl sb cache update

# 查看缓存状态（每个规则集的来源、格式、更新时间、文件是否完好）
singctl sb cache status

# 还原配置为远程引用并清空缓存目录
singctl sb cache clear
```

缓存目录位于 sing-box 配置目录下的 `rule_sets/`（如 `/etc/sing-box/rule_sets`）。
`sb cache status` 会同时展示本地缓存与内置快照的覆盖情况（`📦` 标记）。

> `sb gen --no-localize` 可生成保留远程引用的配置（例如需要迁移到其它机器时）。

#### 维护：更新内置快照

快照由维护者手动刷新（规则集列表变更或快照过旧时）：

```bash
go run ./cmd/snapshotgen            # 直连下载（默认不走镜像）
go run ./cmd/snapshotgen -mirror https://gh-proxy.com  # 直连不可用时
```

工具会校验内容、gzip 压缩并生成 manifest（含 sha256），全部成功才会写入
`internal/singbox/ruleset_snapshot/assets/`，提交后随下次编译打包进二进制。

---

## 两层极简分流模型与本地防劫持 DNS

### 1. 面板分组结构（`singgen v1.17.0+`）

生成的客户端配置采用 **「4 个业务分流开关 + 3 个 `#` 底层节点池」** 两层布局：

- **业务分流开关**：
  - `Proxy`（默认 `#VPS`）：日常海外总开关及大型游戏资源下载；
  - `AI`（默认 `#VPS`）：ChatGPT / Claude / Grok 独立防锁区；
  - `Game`（默认 `#Auto`）：海外游戏大厅、匹配与禁选英雄 TCP 信令；
  - `Game-UDP`（默认 `DirectConn`）：海外游戏局内高端口（`1024:65535`）实时帧同步 UDP 直连。
- **底层节点池（带 `#` 微前缀）**：
  - `#VPS`：自建 `sec_` 节点池；
  - `#Auto`：机场 1 倍节点自动测速最低延迟池（自动剔除高倍率节点）；
  - `#Nodes`：机场全部节点手动选择池。

### 2. 本地防劫持 DNS (`singctl dns`)

Linux / OpenWrt 客户端网关可通过 `singctl dns install` 一键部署本地 AdGuard Home（监听 `127.0.0.1:5353` + 局域网管理面板），自动接管 `dns_local` 并通过纯 IP 加密 DoH/DoT 杜绝运营商明文 DNS 劫持。

> 📘 完整架构说明、配置项与子命令手册请参阅：**[👉 本地防劫持 DNS (AdGuard Home) 指南](dns.md)**

### 3. 局域网设备流量行为审计与双层拉黑 (`singctl sb audit`)

客户端内置正交双轴（🛡️安全 × 👁️隐私）非线性风险评估引擎与可选 L2 AI 深度复核闭环，支持在客户端 WebUI（`:8090`）或命令行一键治理：

```bash
# 查看局域网设备行为审计报告（支持 --suspicious、--device 192.168.1.50、--ai、--json、--csv）
singctl sb audit --suspicious --ai

# 一键双层拉黑（同时写入 sing-box reject 路由 + AdGuard Home DNS 黑名单 + 秒级斩断活跃连接）
singctl sb block bad-telemetry.example.com
singctl sb block bad-telemetry.example.com --device 192.168.1.50   # 仅限制单台局域网设备
singctl sb unblock bad-telemetry.example.com                       # 一键解封

# 管理审计信任放行白名单（自动豁免误报告警）
singctl sb whitelist sync.example.com
singctl sb whitelist sync.example.com --remove
singctl sb whitelist list
```

### 4. 声明式策略组编排 (`groups.yaml` / `singctl sb groups`)

通过与 `singctl.yaml` 同目录的 `/etc/singctl/groups.yaml`（零节点隐私信息），即可按地区语义宏、协议或订阅源动态构建自定义分组，并与客户端 WebUI「智能分流中心」及看门狗容灾无缝联动：

```yaml
# /etc/singctl/groups.yaml
version: 1
mode: merge   # merge (保留内置组并扩展) | replace (全量自定义接管)

groups:
  - name: "#HK"
    type: urltest
    match: ["@hk"]
    exclude: ["@high_rate"]

  - name: "Streaming"
    type: selector
    use: ["#SG", "#JP", "#HK", "#VPS"]
    default: "#JP"
    attach_to: []        # 独立供「智能分流中心」绑定，不混入顶层 Proxy
    failover: true       # 纳入看门狗故障切换守护
```

支持在客户端 WebUI（`:8090` -> `sing-box` -> `分组编排`）在线编辑并实时预览节点命中，或使用命令行工具管理：

```bash
singctl sb groups init      # 生成默认注释模板 /etc/singctl/groups.yaml
singctl sb groups preview   # 干跑预览各分组当前命中的节点清单
singctl sb groups apply     # 经 sing-box check 校验后通过 SIGHUP 无损热重载生效
```





