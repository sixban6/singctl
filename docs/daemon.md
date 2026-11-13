# 守护进程管理 (Daemon)

命令前缀：`singctl dm` / `singctl daemon`

守护进程会在 sing-box 意外退出时自动将其重启，保证服务持续可用。

> **跟随启动**：`singctl sb start` / `sb restart` 会自动拉起看门狗（已在运行则跳过），
> `sb stop` 会一并停止——日常使用无需手动操作 `dm start`/`dm stop`。

---

## 命令详解

### `singctl dm start` — 启动守护进程

在后台启动守护进程，开始监控并自动保活 sing-box。

```bash
singctl dm start
```

---

### `singctl dm restart` — 平滑重启守护进程

在不中断、不重启 `sing-box` 代理进程的前提下，平滑重启看门狗守护进程自身，立即加载最新二进制与磁盘 `singctl.yaml` 配置（`singctl u s` 自更新时也会自动触发）。

```bash
singctl dm restart
```

---

### `singctl dm status` — 查看监控状态

显示守护进程和 sing-box 的详细运行状态，包括 PID、版本、五大防线实时状态、当前容灾接管分组、重启熔断计数、内存占用与最近关键守护事件。

```bash
singctl dm status
```

---

### `singctl dm logs` — 查看日志

查看守护进程日志输出（日志文件超过 `512 KB` 时自动截断轮转并保持 `0600` 权限）。

```bash
# 查看最近 50 条日志
singctl dm logs -n 50

# 仅查看看门狗与容灾切换关键事件日志
singctl dm logs -e -n 50

# 查看最近 20 条（默认）
singctl dm logs

# 持续跟踪新日志（类似 tail -f，Ctrl+C 退出）
singctl dm logs -f
```

| 参数 | 说明 |
| :--- | :--- |
| `-n <num>` | 显示最近 N 条日志，默认 20 |
| `-e, --events` | 仅筛选看门狗健康巡检、策略组容灾切换与订阅同步关键事件 |
| `-f` | 持续跟踪新增日志（类似 tail -f），自动兼容日志轮转 |

## 配置

`singctl.yaml` 中的 `watchdog` 段控制看门狗与策略组自动故障切换行为（均可省略，默认即开启全部核心守护）：

| 键 | 默认 | 说明 |
| :--- | :--- | :--- |
| `interval` | `180` | 进程与 Clash DNS 健康检查间隔（秒） |
| `confirm_wait` | `30` | 首次检测失败后的二次确认等待（秒） |
| `max_restarts` | `3` | 每小时最大自动重启次数（超出后触发熔断保护） |
| `sub_sync_interval` | `600` | 订阅节点指纹自动静默巡检与无感热同步间隔（秒），设为 `-1` 关闭 |
| `failover.enabled` | `true` | 是否开启策略组自动故障切换与恢复回切（默认开启） |
| `failover.groups` | `["#VPS", "Proxy", "AI", "#Nodes"]` | 受保护的 Clash Selector 策略组名称列表 |
| `failover.patrol_interval` | `300` | 策略组节点健康巡检间隔（秒） |
| `failover.probe_timeout_ms` | `2800` | 单节点连通性探测超时时间（毫秒） |
| `failover.confirm_retries` | `1` | 切备前复测确认次数（默认间隔 1.5s 复测 1 次防瞬时抖动；设为 `-1` 表示首次失败立即切备） |
| `failover.failback_cooldown` | `180` | 原主选节点恢复后的观察冷却期（秒，且需连续 2 轮健康；设为 `-1` 关闭自动回切） |
| `failover.max_failback_delay_ms` | `600` | 允许切回原主选节点的最高延迟上限（毫秒，拒绝高延迟假活乒乓回切） |
| `failover.probe_urls` | `["https://www.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"]` | 连通性探测目标 URL 列表 |

支持向运行中的看门狗进程发送 `SIGHUP`（或在 WebUI 保存配置时自动触发）即时热重载上述配置，无需重启 `sing-box`。

连续自动重启会渐进退避：第 2 次前等待 30s、第 3 次前等待 2min、之后 5min，
避免上游故障未恢复时的无意义重启风暴。

其他说明：

- 运行态快照与重启计数持久化在 `/tmp/singctl-daemon.state`（`0600` 权限，OpenWrt 上 tmpfs，系统重启自动清零）
- 守护进程日志：`/tmp/singctl-daemon.log`（`0600` 权限，超过 `512 KB` 自动保留尾部精华并清理冗余刷屏）
- `sing-box` 日志防护：客户端配置默认收敛为 `log.level: "warn"`，且看门狗对 `/tmp/sing-box-basic.log`（及 fallback `/tmp/sing-box-simple.log`）实施 `16 MB` 原地尾部截断兜底，防止写满 OpenWrt `/tmp`（tmpfs）导致断网
- 健康检测通过 sing-box 的 Clash API（`/dns/query`，自动携带 `secret` 鉴权）进行，并在拉起前执行 `sing-box check` 语法兜底校验
