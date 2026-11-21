# AdGuard Home 私网 PTR / Bonjour DNS-SD 五跳死循环复盘

> 相关修复版本：`v1.14.152`（commit `2651376`）

## 1. 问题现象

- WebUI 面板与拓扑图（[TrafficFlowCard.tsx](../../web/src/client/components/TrafficFlowCard.tsx)）偶发标红提示 **`AdGuard 异常`**，但后台查看 `AdGuardHome` 进程并未崩溃（宿主机可用内存充足、`dmesg` 无 OOM/Kill 记录）。
- 看门狗日志持续出现 `[Watchdog] AdGuard Home (127.0.0.1:5353) 未响应，正在自动拉起恢复...`。
- 系统日志出现大量 `dnsproxy: response received upstream_type=local addr=127.0.0.1:53 / [::1]:53 proto=udp status="... i/o timeout"`，伴随进程打开句柄数激增（从正常 ~30 飙升至数百）及平均解析延迟显著升高（> 300ms）。
- QueryLog 中高频刷屏 `lb._dns-sd._udp.*.in-addr.arpa`、`db._dns-sd._udp.*.in-addr.arpa` 等 `PTR SERVFAIL` 请求（例如局域网网段 `192.168.1.0/24`、`10.0.0.0/8` 的服务发现反查）。

## 2. 根本原因：五跳 DNS 指数放大环路

1. **客户端发起 Bonjour / DNS-SD 服务发现**：macOS / iOS 等局域网设备定期向路由器 `:53` 发起 `lb._dns-sd._udp.<LAN>.in-addr.arpa` 类型的 PTR 查询，探测广域 Bonjour 服务。
2. **`dnsmasq` 未本地拦截该子域**：OpenWrt 默认 `bogus-priv` 仅拦截标准纯 IP 反查，不拦截 `_dns-sd._udp` 浏览子域，叠加 `no-negcache` 配置后将该请求转发给 `/tmp/resolv.conf.d/resolv.conf.auto` 中的外部 DNS（`:53`）。
3. **`nftables` output 链劫持透明代理**：`table inet sing-box` 对本机出站 UDP `:53` 打标并经 `lo` 送入 `tproxy :7895`（`sing-box`）。
4. **`sing-box` 回送 `dns_local`（`AdGuardHome :5353`）**：由于配置关闭了 `sing-box` 缓存（`disable_cache: true`），`hijack-dns` 截获请求并匹配 `geosite-private` 规则，经 `dns_local` 送往 `127.0.0.1:5353`。
5. **主路由模式下 `AdGuardHome` 回打 `dnsmasq`**：此前仅旁路由模式关闭了 `use_private_ptr_resolvers`，主路由模式仍开启且 `local_ptr_upstreams` 为空，导致 `AdGuardHome` 读取 `/etc/resolv.conf`（`127.0.0.1` 与 `[::1]`），把 1 条请求**并发放大为 2 条**打回本机 `dnsmasq :53`。

如此构成 `1 → 2 → 4 → 8 → …` 的指数放大环路，瞬间打满 `AdGuardHome` 的 `max_goroutines: 300` 上限并阻塞等待 `upstream_timeout: 5s`，触发 WebUI 与看门狗的 DNS 探活超时误判与频繁重启。

## 3. 架构根因与隐私安全评估

- **功能层面**：在 SingCtl 架构中，`AdGuardHome` 永远作为 `sing-box` 的后端上游运行于 `127.0.0.1:5353`（来源 IP 恒为 `127.0.0.1`），不直接服务终端 IP；局域网 `.lan` 解析由前端 `dnsmasq (:53)` 负责，AirDrop / HomeKit 等走组播 mDNS（`224.0.0.251:5353`），关闭私网 PTR 解析零功能损失。
- **隐私安全**：若仅关闭 AdGuard 私网 PTR 而不作本地阻断，此类私网/链路反查域名仍可能落入公网 DoH 或运营商 DNS，暴露内网网段结构（RFC 6303 私网反查泄漏）。

## 4. 三层根治方案（`v1.14.152` 已落地）

1. **P0 — 全局禁用私网 PTR + 自动自愈 + 探活降噪**（[config_gen.go](../../internal/adguard/config_gen.go)、[adguard.go](../../internal/adguard/adguard.go)）
   - 无论主路由或旁路由模式，`BuildInitialConfigYAML` 与 `SyncExistingConfig` 均强制设置 `use_private_ptr_resolvers: false`。
   - 新增 `NeedsHardeningSync()` 供看门狗 `EnsureHealthy()` 自动无损修复旧配置并平滑重启。
   - 在 `querylog` 与 `statistics` 中启用 `ignored_enabled: true` 并保留 `localhost`，消除周期性 `ProbeDNS` 探活刷屏排行。
2. **P1 — `sing-box` 本地 `predefined NXDOMAIN` 纵深兜底**（[local_dns.go](../../internal/singbox/local_dns.go)、[generator.go](../../internal/singbox/generator.go)）
   - 为非 iOS 客户端在 `dns.rules` 最前端前置两条规则：
     - `domain_suffix` 精确覆盖 RFC 6303 私网反查域（`0.in-addr.arpa`、`10.in-addr.arpa`、`127.in-addr.arpa`、`168.192.in-addr.arpa`、`254.169.in-addr.arpa`、`16.172.in-addr.arpa`～`31.172.in-addr.arpa` 及 `fc00::/7` / `fe80::/10` 对应 `.ip6.arpa` 域）→ `predefined NXDOMAIN`；
     - `domain_keyword: ["_dns-sd._udp."]` → `predefined NXDOMAIN`。
   - 既在源头阻断环路与内网拓扑外泄，又不影响公网 IP 反查（不使用宽泛的 `in-addr.arpa` 通配）。
3. **P2 — 探活重试抗抖动**（[service.go](../../internal/adguard/service.go)、[adguard_api.go](../../internal/webui/adguard_api.go)、[dns_leak_api.go](../../internal/webui/dns_leak_api.go)）
   - 新增 `ProbeDNSWithRetry()`，WebUI 与 LeakTest 使用 `800ms × 2`（间隔 `150ms`）、看门狗使用 `1500ms × 2`（间隔 `1s`），消除单次 UDP 抖动导致的界面闪红与误重启。
