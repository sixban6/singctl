# 本地防劫持 DNS 三引擎架构（sing-box 加强版 / SmartDNS / AdGuard Home）

命令前缀：`singctl dns` / `singctl agh`

> **平台支持**：适用于 **Linux / OpenWrt** 客户端透明代理网关（需 root 权限）。默认采用 `engine: auto` 按宿主机物理内存与闪存空间自动分级推荐引擎，全程两阶段零断网原子切换。

SingCtl 将客户端本地防劫持 DNS 解耦为三引擎统一管控中心，彻底消除 `dns_local` 明文 `UDP 53` 劫持风险，并适配从 256MB 小闪存硬路由到高配 x86 软路由的全部硬件规格：

1. **`sing-box` 加强版（零额外开销，开箱即用）**：内核直接内置纯 IP 加密 DoH/DoT（默认 `https://223.5.5.5/dns-query` + `optimistic` 乐观缓存）、自定义内网解析重写、白名单、AAAA 屏蔽与 `geosite-ad` 规则集分流去广告，零额外进程与闪存占用。
2. **SmartDNS 极速版（中小内存 / 紧张闪存路由推荐）**：流式安装 `pymumu/smartdns` 官方静态单文件（`~5 MB` 闪存 / `~10 MB` 内存），支持多加密上游并发测速优选最快 IP、`/tmp` 内存盘审计零闪存磨损（`audit-enable yes` + `audit-SOA yes` + `cache-persist no`）、轻量 AdBlock 规则库、白名单、内网重写与 AAAA 屏蔽。
3. **AdGuard Home 可视版（充裕内存 / 闪存网关推荐）**：全功能独立防劫持与多规则去广告中心，内置原生 Web 管理面板（仅绑定局域网私网 IP，免首次向导并自动生成 16 位强随机密码）。

---

## 核心特性与安全架构

1. **硬件自动分级与存量保护（`engine: auto`）**：
   - 已安装 AdGuard Home 或 SmartDNS 的存量设备升级后自动沿用原引擎，零配置打扰；
   - 全新设备按硬件画像分级推荐：`> 512MB RAM & > 256MB 可用 & >= 80MB 闪存` 推荐 AdGuard Home；`> 288MB RAM & >= 128MB 可用 & >= 10MB 闪存` 推荐 SmartDNS；其余超低规格推荐 `sing-box` 加强版；闪存不足硬拦截不可绕过。
2. **两阶段零断网原子切换与自动回滚**：
   - 切换外部引擎前先将 `sing-box` `dns_local` 热切至纯 IP 加密 DoH 安全区，再停旧引擎（保留原配置不删）、按需流式安装并启动目标引擎、实测 `127.0.0.1:5353` 解析可用后再原子切回 `dns_local`；任意一步失败自动回滚保住全屋网络。
3. **回环隔离零冲突**：
   - SmartDNS / AdGuard Home 仅监听 `127.0.0.1:5353`，绝不抢占 OpenWrt `dnsmasq` 或 `systemd-resolved` 的 `53` 端口；SmartDNS 内置 `address /localhost/127.0.0.1` 确保本地探活零上游请求。
4. **全引擎统一 WebUI 工作台与 24h 有界统计**：
   - 客户端控制台（`singctl web` -> 「防劫持 DNS」）统一接入 `/api/dns/*` 契约，支持三引擎切换卡片、24h 滑动环形统计（AdGuard 原生统计 / SmartDNS 内存盘审计 / sing-box 连接遥测）、加密上游测速与调度模式切换、AAAA 屏蔽、暂停去广告倒计时、白名单、内网重写与实时生效配置预览抽屉。
5. **透明代理防回环死锁与看门狗零断网自愈**：
   - TProxy 防火墙 `output` 链自动直通放行加密 DNS 上游端口；`singctl dm` 看门狗持续巡检 `127.0.0.1:5353` 及 `sing-box` 主加密上游，异常时自动拉起、热切备用上游或应急降级至内置加密 DoH，暂停倒计时到期后自动恢复过滤。

---

## 配置字段 (`singctl.yaml`)

```yaml
dns:                                             # 客户端三引擎防劫持 DNS 统一配置
  enabled: true                                  # 是否启用本地防劫持 DNS 管控
  engine: "auto"                                 # 引擎偏好: auto | singbox | smartdns | adguard
  dns_port: 5353                                 # 外部引擎本地回环监听端口 (仅绑定 127.0.0.1)
  web_port: 3000                                 # AdGuard Home Web 面板端口 (仅绑定局域网私网 IP)
  username: "root"                               # AdGuard Home 管理账号 (默认 root)
  password: ""                                   # AdGuard Home 管理密码 (首次安装自动生成 16 位强密码)
  upstream_mode: "fastest_ip"                    # 上游策略: fastest_ip | parallel | load_balance
  upstreams:                                     # 统一加密上游列表 (仅允许 https/tls/quic/h3)
    - "https://223.5.5.5/dns-query"
    - "https://1.12.12.12/dns-query"
    - "tls://223.6.6.6:853"
    - "tls://120.53.53.53:853"
  block_aaaa: false                              # 是否开启 AAAA (IPv6) 解析屏蔽 (singbox / smartdns)
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

# 零断网切换至零开销 sing-box 加强版（停用外部引擎但保留其配置）
singctl dns switch --engine singbox

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
