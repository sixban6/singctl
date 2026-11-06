# 本地防劫持 DNS (AdGuard Home)

命令前缀：`singctl dns` / `singctl agh`

> **平台支持**：适用于 **Linux / OpenWrt** 客户端透明代理网关（需 root 权限）。使用 `install.sh` 选择客户端模式时会自动完成安装、免向导配置与启动。

一键部署并托管本地 AdGuard Home，接管 `sing-box` 的 `dns_local`（国内域名分流与代理节点域名引导解析），上游默认采用纯 IP 加密 DoH / DoT，彻底解决宽带运营商对明文 `UDP 53` 的旁路抢答与 DNS 劫持问题。

---

## 核心特性与安全架构

1. **回环隔离零冲突**：
   - DNS 引擎仅监听 `127.0.0.1:5353`，不抢占 OpenWrt `dnsmasq` 或系统 `systemd-resolved` 的 `53` 端口，局域网 DHCP 主机名解析不受影响；
   - 关闭单 IP 查询限流（`ratelimit: 0`），确保高并发网页加载不丢包。
2. **Web 面板仅绑定局域网私网 IP**：
   - 自动精准提取本机真实局域网私网 IPv4（如 `http://192.168.1.1:3000`），排除 PPPoE 公网口、TUN、Tailscale 与容器虚拟网卡，**绝不监听 `0.0.0.0` 或公网接口**；
   - 若旁路由因 DHCP 更换了局域网 IP，执行 `singctl dns start` / `restart` 时会自动同步监听地址。
3. **免首次引导向导 + 强随机密码**：
   - 首次安装支持自定义管理员用户名（直接回车默认 `root`），自动生成 16 位高强度随机密码并回写至 `/etc/singctl/singctl.yaml`（权限 `0600`）；
   - 启动前预置完整安全配置（`/etc/AdGuardHome/AdGuardHome.yaml`，权限 `0600`），跳过无鉴权的初始化引导向导，直接进入登录页。
4. **全加密纯 IP 上游 + 软路由闪存保护**：
   - 默认配置阿里（`223.5.5.5` / `223.6.6.6`）与腾讯（`1.12.12.12`）纯 IP DoH / DoT 并发查询，开启乐观缓存与 ECS 子网透传，禁用易被拦截的 HTTP/3；
   - 安装前自动检测磁盘可用空间（`< 80MB` 自动安全中止），OpenWrt 下默认关闭查询日志落盘以保护闪存寿命；
   - 自动将订阅域名加入放行白名单（`@@||sub.example.com^$important`），避免去广告规则误伤节点更新。
5. **透明代理防回环死锁与看门狗自愈**：
   - TProxy 防火墙 `output` 链自动直通放行加密 DNS 上游端口，确保冷启动与全局模式下均无回环死锁；
   - `singctl dm` 看门狗自动监控 `127.0.0.1:5353`，异常退出时自动拉起。

---

## 配置字段 (`singctl.yaml`)

```yaml
dns:                                             # 客户端本地防劫持 DNS (AdGuard Home) 配置
  enabled: true                                  # 是否启用本地 AdGuard Home 接管 dns_local
  dns_port: 5353                                 # 本地 DNS 监听端口 (仅绑定 127.0.0.1)
  web_port: 3000                                 # Web 管理面板端口 (仅绑定本机局域网 IP)
  username: "root"                               # 管理面板账号 (首次安装可自定义，回车默认 root)
  password: ""                                   # 管理面板密码 (首次安装留空时自动生成 16 位随机强密码)
```

---

## 命令详解

### `singctl dns install` — 安装并初始化 AdGuard Home

自动校验官方发布摘要（SHA256）、安装二进制、生成免向导配置、注册系统自启服务（OpenWrt `procd` / Linux `systemd`）并启动。

```bash
# 交互式安装（可直接回车使用默认账号 root）
singctl dns install

# 非交互式安装或指定自定义管理员账号
singctl dns install --non-interactive
singctl dns install -u admin

# 强制重新下载最新官方版本
singctl dns install --force
```

安装完成后，执行以下命令即可让 `sing-box` 立即切换至本地防劫持 DNS：

```bash
singctl sb gen && singctl sb restart
```

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
