# 本地防劫持 DNS 双引擎架构（SmartDNS / AdGuard Home）

命令前缀：`singctl dns` / `singctl agh`

> **平台支持**：适用于 **Linux / OpenWrt** 客户端透明代理网关（需 root 权限）。默认采用 `engine: auto` 按宿主机物理内存与闪存空间在 **SmartDNS** 与 **AdGuard Home** 之间自动分级推荐引擎，全程两阶段零断网原子切换；未安装外部引擎或故障应急时，由 `sing-box` 内置纯 IP 加密 DoH（强制 `optimistic: false`、`disable_cache: true`）无缝兜底。

SingCtl 将客户端本地防劫持 DNS 解耦为双引擎统一管控中心，彻底消除 `dns_local` 明文 `UDP 53` 劫持风险，并适配从 256MB 小闪存硬路由到高配 x86 软路由的全部硬件规格：

1. **SmartDNS 极速版（中小内存 / 紧张闪存路由推荐）**：流式安装 `pymumu/smartdns` 官方静态单文件（`~5 MB` 闪存 / `~10 MB` 内存），支持多加密上游并发测速优选最快 IP、`/tmp` 内存盘审计零闪存磨损（`audit-enable yes` + `audit-SOA yes` + `cache-persist no`）、轻量 AdBlock 规则库、白名单与内网重写；`force-AAAA-SOA` 自动与 `gateway.ipv6_mode` 单一真相源联动（`off` 屏蔽，`cn_only` / `full` 放行）。
2. **AdGuard Home 可视版（充裕内存 / 闪存网关推荐）**：全功能独立防劫持与多规则去广告中心，内置原生 Web 管理面板（仅绑定局域网私网 IP，免首次向导并自动生成 16 位强随机密码）。
3. **底层纯 IP 加密 DoH 应急兜底（零额外开销）**：未安装外部引擎或引擎异常/切换瞬间，`sing-box` `dns_local` 自动兜底至纯 IP 加密 DoH（`https://223.5.5.5:443/dns-query`，强制关闭乐观缓存 `optimistic: false` 与 `disable_cache: true`），确保全屋零断网。

---

## 核心特性与安全架构

1. **硬件自动分级与存量保护（`engine: auto`）**：
   - 已安装 AdGuard Home 或 SmartDNS 的存量设备升级后自动沿用原引擎，零配置打扰；
   - 全新设备按硬件画像分级推荐：`> 512MB RAM & > 256MB 可用 & >= 80MB 闪存` 推荐 AdGuard Home；其余网关推荐 SmartDNS（闪存不足硬拦截不可绕过）。历史配置若残留 `engine: singbox` 会平滑归一化为 `auto`。
2. **两阶段零断网原子切换与自动回滚**：
   - 切换外部引擎前先将 `sing-box` `dns_local` 热切至纯 IP 加密 DoH 安全区，再停旧引擎（保留原配置不删）、按需流式安装并启动目标引擎、实测 `127.0.0.1:5353` 解析可用（若 `5353` 被 mDNS 占用自动顺延至 `5354`）后再原子切回 `dns_local`；任意一步失败自动回滚保住全屋网络。
3. **回环隔离零冲突与 IPv6 单一真相源**：
   - SmartDNS / AdGuard Home 仅监听 `127.0.0.1:5353`（或顺延 `5354`），绝不抢占 OpenWrt `dnsmasq` 或 `systemd-resolved` 的 `53` 端口；SmartDNS 内置 `address /localhost/127.0.0.1` 确保本地探活零上游请求；AAAA 屏蔽由「网络与组网 → `gateway.ipv6_mode`」统一联动控制，变更后自动重载 SmartDNS 配置。
4. **双引擎紧凑下拉工作台与 24h 有界统计**：
   - 客户端控制台（`singctl web` -> 「防劫持 DNS」）统一接入 `/api/dns/*` 契约，页眉内嵌紧凑双引擎下拉切换器（自动选择 / SmartDNS / AdGuard Home），提供 24h 滑动环形统计（AdGuard 原生统计 / SmartDNS 内存盘审计）、加密上游测速与调度模式切换、暂停去广告倒计时、白名单、内网重写与实时生效配置预览抽屉。
5. **透明代理防回环死锁与看门狗零断网自愈**：
   - OpenWrt `nftables` 与 `iptables/ip6tables` TProxy `output` 链均自动直通放行 AdGuard Home 与 SmartDNS 加密 DNS 上游端口（`443`/`853`）；`singctl dm` 看门狗持续巡检本地外部引擎健康度，异常时自动拉起或应急降级至内置加密 DoH 并在恢复后自动回切，暂停倒计时到期后自动恢复过滤。

---

## 配置字段 (`singctl.yaml`)

```yaml
dns:                                             # 客户端双引擎防劫持 DNS 统一配置
  enabled: true                                  # 是否启用本地防劫持 DNS 管控
  engine: "auto"                                 # 引擎偏好: auto | smartdns | adguard
  dns_port: 5353                                 # 外部引擎本地回环监听端口 (仅绑定 127.0.0.1，冲突自动顺延 5354)
  web_port: 3000                                 # AdGuard Home Web 面板端口 (仅绑定局域网私网 IP)
  username: "root"                               # AdGuard Home 管理账号 (默认 root)
  password: ""                                   # AdGuard Home 管理密码 (首次安装自动生成 16 位强密码)
  upstream_mode: "fastest_ip"                    # 上游策略: fastest_ip | parallel | load_balance
  upstreams:                                     # 统一加密上游列表 (仅允许 https/tls/quic/h3)
    - "https://223.5.5.5/dns-query"
    - "https://1.12.12.12/dns-query"
    - "tls://223.6.6.6:853"
    - "tls://120.53.53.53:853"
  whitelist:                                     # 自定义放行白名单域名
    - "good.example.com"
  rewrites:                                      # 内网自定义解析重写
    - domain: "nas.example.com"
      answer: "192.168.1.50"
  smartdns_filters: []                           # SmartDNS 启用的轻量去广告规则集 URL 列表
```

---

## 命令详解

### `singctl dns switch` — 两阶段零断网切换底层引擎

```bash
# 零断网切换至 SmartDNS（未安装时自动流式下载官方静态单文件并验活接管）
singctl dns switch --engine smartdns

# 零断网切换至 AdGuard Home（按硬件门槛校验并两阶段原子接管）
singctl dns switch --engine adguard

# 恢复按硬件画像自动选型
singctl dns switch --engine auto
```

### `singctl dns install` — 安装并初始化外部 DNS 引擎

支持通过 `--engine smartdns` 或 `--engine adguard` 指定目标引擎（不指定时按硬件自动选型）。

```bash
# 交互式安装（可直接回车使用默认账号 root）
singctl dns install

# 非交互式安装或指定自定义管理员账号
singctl dns install --non-interactive
singctl dns install -u admin

# 强制重新下载最新官方版本
singctl dns install --force
```

安装完成后，若当前已有运行中的 `sing-box`，`singctl` 会在实测本地与加密上游解析正常后自动热重载 `sing-box` 切换 `dns_local`（无需手动重启）。

---

### `singctl dns status` — 查看运行状态、解析延迟与面板密码

检测本地 `127.0.0.1:5353` 引擎健康度、实测加密上游解析耗时，并展示局域网 Web 管理地址与登录凭据。

```bash
singctl dns status
```

---

### `singctl dns start | stop | restart` — 服务启停管理

```bash
singctl dns start
singctl dns stop
singctl dns restart
```

---

### `singctl dns reset-password` — 重置管理员账号密码

忘记密码或需要轮换凭据时，一键生成新的 16 位随机强密码并无损同步至 `AdGuardHome.yaml`（保留面板中已添加的自定义过滤清单与重写规则）。

```bash
# 重置当前账号密码
singctl dns reset-password

# 同时修改管理员账号并重置密码
singctl dns reset-password -u root
```

---

### `singctl dns uninstall` — 卸载服务

停止并移除系统自启服务与二进制文件，同时将 `singctl.yaml` 中的 `dns.enabled` 置为 `false`。

```bash
# 卸载程序（保留 /etc/AdGuardHome 配置目录）
singctl dns uninstall

# 彻底卸载并清理配置与数据目录
singctl dns uninstall --purge
```

---

## 常见问题

**Q：是否需要在 AdGuard Home 网页后台开启「加密设置（为 DNS 与网页管理界面启用 HTTPS/QUIC/TLS）」？**  
**A：不需要，建议保持关闭。** 防运营商劫持由「DNS 设置 -> 上游 DNS 服务器」中的 `https://` / `tls://` 加密上游实现（安装时已默认配好）。而后台的「加密设置」仅管入站访问：当前 DNS 仅在本机回环 `127.0.0.1:5353` 内部调用，Web 面板仅限内网私网 IP 访问，开启入站 HTTPS 反而会导致内网 IP 自签证书浏览器告警及 `443/853` 端口冲突。
