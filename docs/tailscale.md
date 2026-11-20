# Tailscale 组网管理 (Networking)

命令前缀：`singctl ts`

在 Linux/OpenWrt 设备上管理 Tailscale 异地组网。

**原理**:
- 封装了 tailscale，使用 [Tailscale 官方安装包](https://github.com/sixban6/auto_fetch_tailscale)。
- 统一关闭netfilter，不让tailscale修改防火墙配置，防止冲突。
- singctl ts统一接管tailscale的防火墙配置，保持稳定可靠。

> **平台限制**：以下命令仅适用于 Linux / OpenWrt，macOS/Windows 请使用 Tailscale 官方客户端。

---

## 两种部署模式

### 模式一：官方版本（推荐）

使用 Tailscale 官方二进制，功能最完整，**优先选择此模式**。

> **📦 安装包来源说明**：singctl 不直接从 Tailscale 官网下载，而是从 [sixban6/auto_fetch_tailscale](https://github.com/sixban6/auto_fetch_tailscale) 仓库的 Releases 拉取：
> - **ARM64 架构包**（`*_arm64.tgz`）：基于同版本 Tailscale 官方源码通过 `featuretags --min` 裁剪桌面冗余模块并启用 `ts_include_cli` 合体构建（`tailscale -> tailscaled` 软链接，**未 UPX 加壳**），大幅缩减体积同时减少小内存 OpenWrt 路由器的匿名内存驻留；
> - **amd64 架构包**（`*_amd64.tgz`）：官方原版静态包；
> - 发布包含校验文件 `checksums.txt`，singctl 安装/更新时自动校验。

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

# 在 tailscaled 运行期间热切换模式/路由策略（不重启守护进程）
singctl ts start -m gateway --reconfigure
```

| 参数 | 说明 |
| :--- | :--- |
| `--router` / `-r` | 启用子网路由，广播本机局域网网段（适合部署在路由器上） |
| `--exit-node` / `-e` | 将本机设置为 Tailscale 网络的出口节点 |
| `--accept-routes` / `-a` | 接收其他节点广播路由（例如访问异地内网 IP） |
| `--mode` / `-m` | 快速模式：`client` / `router` / `exit` / `gateway` |
| `--reconfigure` | 当 `tailscaled` 已在运行时跳过重启与二次 `auth_key` 认证，直接热切换模式并同步广播子网 / `--accept-routes` 策略 |

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

### `singctl ts update` — 两阶段零失联安全更新 Tailscale

支持 **OpenWrt (`procd`)** 与 **Linux (`systemd`)**（包括直接通过 Tailscale 隧道远程 SSH 或在 WebUI 控制台内发起更新）：

- **Phase 1（在线零 `/tmp` 预落盘与预检）**：体检剩余 Flash 与内存 → 直连 GitHub API 获取官方 SHA256 digest → 单遍流式解压直写 `/usr/sbin/.tailscaled.new`（`0 MB` `/tmp` 占用，自动保留 ARM64 精简合体版 `tailscale -> tailscaled` 软链接）→ 离线预检 `--version` 可执行兼容性。
- **Phase 2（脱离父进程原子切换与自动回滚）**：`setsid` 启动极简 POSIX `/bin/sh` 守护器（预留 2 秒缓冲刷新响应）→ 停旧服、同分区 `mv` 备份并原子替换、启新服 → 执行默认 `25s` 健康门禁校验（`BackendState == Running`）；若启动崩溃或超时未上线，自动回滚旧版并恢复隧道。

```bash
# 标准交互式更新（等待后台健康门禁完成并输出最终结果）
singctl ts update

# 仅执行升级前体检（不下载、不修改系统）
singctl ts update --dry-run

# 同版本强制重刷（如从标准版/UPX版换装精简合体版，或修复二进制）
singctl ts update --force

# 自定义健康门禁超时（5~60 秒）或移交后台后立即返回
singctl ts update --timeout 30 --no-wait
```

| 参数 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `--dry-run` | `false` | 仅执行版本、Flash 空间、内存、服务管理器体检并输出结果，不做修改 |
| `--force` / `-f` | `false` | 即使已为最新版本也强制重新下载校验并重刷 |
| `--timeout` | `25` | 后台切换健康门禁等待秒数（范围 `5~60`） |
| `--no-wait` | `false` | 移交脱离进程后台守护器后立即返回 |

> **WebUI 零失联集成**：在控制台 **「网络与组网 → Tailscale 异地组网」** 中可直接完成全生命周期操作（未安装时展示安装引导与内联 `auth_key`/`subnets` 表单；已安装后可修改运行模式与 `auth_key`/`subnets` 并通过确认弹窗点击 **「保存并热切换模式」** 在线热切换 `--reconfigure`，无需跳转其他菜单）。点击 **「零失联更新」** 会先展示升级前体检抽屉（含是否经 Tailscale 远程访问提示与可选「强制重刷当前版本」）；点击开始后即使隧道短暂重建 2~5 秒，页面也会保持静默自动重连并展示最终升级/回滚结果。

---

## P2P 直连防线 · 零常驻暴露 (`tailscale.p2p_assist`)

在保留 Tailscale P2P 直连高性能的同时，避免长期暴露公网 UDP `:41641` 并按节点精确收敛入向权限：

- **JIT 瞬时打洞（Layer 1）**：闲置与已直连期间 `TS_JIT_ALLOW4` / `TS_JIT_ALLOW6` 保持空集；仅当已授权节点处于活跃转发且走 DERP 中继时，瞬时放行候选公网 IP `3~10` 秒并触发 DISCO 探活，升级直连后毫秒级撤销集合条目（由 Linux `nf_conntrack` 五元组维持已建立会话）。若连续 2 次失败则自动进入 DERP 冷却退避（默认 300 秒）。
- **内核载荷魔法头过滤（Layer 2）**：可选开启 DISCO / WireGuard (Type 1–4) / STUN (RFC 5389) 魔法字节与长度校验 + `300/second` 限速。
- **可选 `ujail` 沙盒（Layer 3）**：在支持 `/sbin/ujail` 的 OpenWrt 设备上可选启用 `sandbox_ujail: true`。
- **3 态零信任双向控制（Layer 4）**：针对纳管节点支持 `outbound_only`（单向锁死）、`bidirectional_timed`（探亲限时双向，过期自动降级）与 `bidirectional`（长期双向，支持按 CIDR/`IP:port` 收窄至 `allowed_lan_targets`）；未纳入 `peers` 列表的个人终端（笔记本、手机等）不受限。

可在 WebUI **「Tailscale 组网」** 页面可视化配置并测试瞬时打洞，或在 `singctl.yaml` 中配置：

```yaml
tailscale:
  p2p_assist:
    enabled: true
    jit_window_sec: 5
    cooldown_sec: 300
    payload_filter: true
    sandbox_ujail: false
    peers:
      - name: "router-remote"
        jit_enabled: true
        access_mode: "outbound_only"          # outbound_only | bidirectional_timed | bidirectional
        bidirectional_until: ""               # RFC3339 时间戳（bidirectional_timed 时有效）
        allowed_lan_targets:
          - "192.168.1.0/24"
```
