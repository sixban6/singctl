# 防火墙加固 (Firewall Hardening)

命令前缀：`singctl fw` / `singctl firewall`

> **平台限制**：仅适用于 **Linux / OpenWrt**，需要 root 权限。

一键配置 iptables/nftables 安全拦截规则，屏蔽危险端口和恶意流量，并设置开机自启。

---

## 命令详解

### `singctl fw enable` — 启用防火墙规则

启用安全拦截规则并设置开机自启。

```bash
singctl fw enable
```

**效果**：
- 封锁常见高危端口
- 拦截已知恶意 IP 段
- 配置规则在系统重启后自动恢复

---

### `singctl fw disable` — 禁用防火墙规则

移除所有由 singctl 添加的安全规则并取消自启配置。

```bash
singctl fw disable
```
