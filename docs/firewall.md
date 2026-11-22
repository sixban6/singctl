# 防火墙加固 (Firewall Hardening)

命令前缀：`singctl fw` / `singctl firewall`

> **平台限制**：仅适用于 **Linux / OpenWrt**，需要 root 权限。

一键部署独立的安全护盾（优先 `nftables` `table inet security`，在 OpenWrt 21.02 / `fw3` 等无 `nft` 固件上自动切换 1:1 等价的 **`iptables` + `ip6tables` + `ipset`** `SINGCTL_SECURITY` 独立隔离链），屏蔽高危扫描端口并动态关押恶意探测源，同时内置多级防锁死机制与开机自启；卸载或禁用时整表/隔离链干净清理，不影响 OpenWrt `fw4`/`fw3`、`sing-box` 透明代理或其它既有表。

---

## 命令详解

### `singctl fw enable` — 启用防火墙规则

启用安全拦截规则并设置开机自启（OpenWrt 自动写入 `/etc/init.d/singctl-firewall`，systemd 发行版注册独立单元）。

```bash
singctl fw enable
```

**效果**：
- 自动识别 OpenSSH（`sshd_config`）与 OpenWrt Dropbear（`/etc/config/dropbear`）监听中的 SSH 端口并自动豁免，防止远程管理锁死
- 默认信任 RFC1918 局域网段、`100.64.0.0/10`（Tailscale）、回环及隧道接口（`lo`、`tailscale0`、`wg*`、`tun*`）与当前操作源 IP
- 在 `standard` 模式下启用常见高危端口诱捕，触发探测即自动关押进 `blocklist_ip4` / `blocklist_ip6` 动态黑名单（默认 7 天）
- 拦截内置高危恶意威胁网段（`blocklist_ip4_forever`）

---

### `singctl fw disable` — 禁用防火墙规则

移除所有由 singctl 添加的安全规则并取消自启配置。

```bash
singctl fw disable
```

---

## WebUI 可视化管控（网络与组网 → 防火墙加固）

除 CLI 外，路由器 WebUI 提供 4 层可视化安全中心：
1. **三态健康探测与实时 KPI**：核验内核规则生效态、开机自启态及漂移状态，实时展示累计拦截包数/流量、`blocklist_ip4` / `blocklist_ip6` 动态关押数、永久威胁段数与防锁死豁免状态。
2. **防自锁预检与热重载**：展示自动识别的 SSH 端口、核心豁免服务端口与共存内核表；支持切换 `standard`（标准防扫描）/ `minimal`（轻量仅黑名单），**热重载时保留当前在线的 7 天动态黑名单**（`preserveDynamic`）。
3. **3 标签规则治理**：
   - **封禁名单**：支持按 IPv4/IPv6 动态、永久黑段过滤与服务端分页检索，支持一键解封、手动封禁及清空动态黑名单（拒绝私网、Tailscale、公共 DNS、过宽网段与当前访问源 IP）。
   - **分级白名单**：区分内置防锁死白名单（锁定保护）、配置持久化白名单、内核历史附加项，支持一键放行当前访问者 IP。
   - **受保护端口与参数**：可微调动态封禁超时（1～30 天）、ICMP Ping 限速（1～100/秒）及自定义诱捕端口（SSH 与核心业务端口禁止误选）。
4. **实时日志与规则透视**：抽屉式查看已剥离本地 WAN 目的 IP（`DST=`）的 `[NFT]` 拦截日志，并支持大集合折叠后的 `table inet security` 规则骨架只读预览。

---

## `singctl.yaml` 持久化配置示例

以下为客户端 `firewall` 可选配置段（所有示例地址均为 RFC 5737 测试占位段，`singctl` 以 `0600` 权限落盘）：

```yaml
firewall:
  mode: standard          # standard（高危端口诱捕 + 黑名单）| minimal（仅黑名单）
  ban_timeout_days: 7     # 动态黑名单封禁天数 (1~30)
  ping_limit_per_sec: 10  # ICMP Echo 限速 (1~100 / 秒)
  # protected_ports: [20, 21, 22, 23, 25, 110, 465, 587, 993, 995, 1433, 1434, 1521, 3306, 3389, 6379]
  whitelist:
    - "203.0.113.10"
  extra_forever_ban:
    - "198.51.100.0/24"
```
