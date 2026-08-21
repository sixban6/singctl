# 守护进程管理 (Daemon)

命令前缀：`singctl dm` / `singctl daemon`

守护进程会在 sing-box 意外退出时自动将其重启，保证服务持续可用。

---

## 命令详解

### `singctl dm start` — 启动守护进程

在后台启动守护进程，开始监控并自动保活 sing-box。

```bash
singctl dm start
```

---

### `singctl dm status` — 查看监控状态

显示守护进程和 sing-box 的详细运行状态，包括 PID、重启次数、内存占用等。

```bash
singctl dm status
```

---

### `singctl dm logs` — 查看日志

查看守护进程日志输出。

```bash
# 查看最近 50 条日志
singctl dm logs -n 50

# 查看最近 20 条（默认）
singctl dm logs
```

| 参数 | 说明 |
| :--- | :--- |
| `-n <num>` | 显示最近 N 条日志，默认 20 |

## 配置

`singctl.yaml` 中的 `watchdog` 段控制看门狗行为(均可省略,取默认值):

| 键 | 默认 | 说明 |
| :--- | :--- | :--- |
| `interval` | `180` | 健康检查间隔(秒) |
| `confirm_wait` | `30` | 首次检测失败后的二次确认等待(秒) |
| `max_restarts` | `3` | 每小时最大自动重启次数(超出后跳过自动重启) |

连续自动重启会渐进退避:第 2 次前等待 30s、第 3 次前等待 2min、之后 5min,
避免上游故障未恢复时的无意义重启风暴。

其他说明:

- 重启计数持久化在 `/tmp/singctl-daemon.state`(OpenWrt 上 tmpfs,重启自动清零),`dm status` 显示的是真实计数
- 守护进程日志:`/tmp/singctl-daemon.log`;看门狗事件日志:`/tmp/singctl-watchdog.log`
- 健康检测通过 sing-box 的 clash API(`/dns/query`)进行,会自动解析配置中的 `external_controller` 地址
