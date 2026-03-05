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
