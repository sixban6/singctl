# SingCtl 架构设计与扩展规范

> 本文档面向人类维护者与 AI 编程助手，明确 SingCtl 对标 `SagerNet/sing-box` 的四层无环依赖拓扑、核心可复用抽象、前后端对称目录规范与编译期 AST 防腐烂守卫。

## 1. 四层正交依赖拓扑（严格无环 DAG）

```text
  Layer 4: 控制面与常驻调度薄外壳（仅做鉴权、入参校验、领域调用与响应编排）
    [ cmd/singctl (~31行极薄入口) | internal/cmd | internal/webui | internal/serverweb | internal/daemon ]
                                           │
                                           ▼
  Layer 3: 高内聚领域引擎层（严禁反向依赖 cmd / webui / serverweb / daemon）
    [ singbox (+ sboption / clashapi / scripts / ruleset_snapshot)
      deploy | subhub | sniff | fleet | netdiag (+ ipgeo / dohprobe) | gateway
      localdns | smartdns | adguard | firewall | tailscale | audit | heal | doctor | telemetry | terminal | gfw | ssh | updater ]
                                           │
                                           ▼
  Layer 2: 基础契约与纯配置层（严禁反向依赖任何领域层与控制面层）
    [ constant | component | lifecycle | platform/servicemgr | config | logger ]
                                           │
                                           ▼
  Layer 1: 零业务耦合正交微基建层（纯标准库/基础库叶子，零上层内部依赖）
    [ internal/common/{execx,proc,fsx,sysinfo,release,netx,httpx,swrcache,cryptobak,redact,memlimit,table} ]
```

> **显式依赖注入铁律**：所有可替换 I/O 与策略协作者统一采用构造函数参数、`Options` / `Deps` 结构体字段或 `Option` 函数显式注入（未注入 `nil` 时自动回退生产默认实现），**严禁**使用隐式 `context.Value` 服务定位器或篡改包级可变全局单例。

---

## 2. 核心基础抽象与领域引擎规范

### 2.1 纯标准库微基建（[`internal/common/*`](../internal/common)）

- **`execx` & `proc`**：统一有界超时与 `WaitDelay` 子进程执行器、分离进程组属性、硬链接 PID 锁，以及基于 `syscall.Fstat` 校验 `S_IFIFO` 的安全就绪管道握手 `NotifyReadyPipe`（杜绝误关非 FIFO 文件描述符）。
- **`fsx` & `sysinfo`**：随机临时文件 `WriteAtomic0600`、带离线预检与失败自动回滚的事务化落盘 `CommitVerified`、`AsyncSnapshotWriter`，以及 `IsOpenWrt` / `Statfs` / `MemInfo` / 本地 POSIX 时区校准。
- **`release` & `netx`**：唯一信任锚直连 GitHub Release API + 镜像加速下载 + SHA256 强制校验 + 防 Zip-Slip 流式提取 `ExtractBinaryStream`；纯网卡/ECS 子网/DNS 解析与可注入公网 IP / GeoTag 探针。
- **`httpx`、`swrcache`、`cryptobak`、`redact`**：零反射泛型 HTTP Handler 与强制默认 `MaxBytesReader` 安全 JSON 解码、sync.Pool Gzip、泛型有界单飞缓存 `Bounded[T]`、PBKDF2+AES-256-GCM 灾备加密信封及零依赖订阅 URL 脱敏。

### 2.2 极薄宿主契约、声明式注册表与三阶段生命周期

- **宿主服务唯一出口（[`internal/platform/servicemgr`](../internal/platform/servicemgr)）**：统一封装 `SystemdManager`（systemd VPS）与 `ProcdManager`（OpenWrt BusyBox `procd`），全仓严禁绕过 `servicemgr` 直接拼装裸 `"systemctl"` 命令。
- **双内核防火墙策略隔离（OCP：`nftables` + `iptables/ip6tables/ipset`）**：OpenWrt TProxy 启停脚本拆分为共享主干（`openwrt_common.sh`，含 `ensure_openwrt_ujail` 自动按 `/overlay` 引导 `procd-ujail`）与严格隔离的 `openwrt_fw_{nftables,iptables}.sh`（独立 `SING_BOX`/`SING_BOX_OUTPUT` 隔离链，零宿主链清空）；Tailscale P2P 防线（`p2p_nft.go` / `p2p_iptables.go`）、行为审计限速（`throttler_nft.go` / `throttler_iptables.go`，含双栈分离 DNS 与 30 分钟公网 IP 韧性缓存）及主机安全防火墙加固（`firewall.go` / `firewall_iptables*.go`）均按自动探测无缝支持 `nftables` 与纯 `iptables+ipset` 固件。
- **声明式组件与算子注册表（`component` / `localdns` / `audit` / `doctor` / `subhub` / `heal`）**：新增受管服务、双引擎防劫持 DNS（`smartdns` / `adguard`，`force-AAAA-SOA` 单一真相源绑定 `gateway.ipv6_mode`）、非线性审计算子、体检项、代理协议编解码器或自愈步骤时，遵循「新增独立文件 + 向声明式切片/注册表挂载一行」横向扩展。
- **确定性三阶段生命周期（[`internal/lifecycle`](../internal/lifecycle)）**：`StageInit`（纯资源准备，零后台协程）→ `StageStart`（拉起监听与受控循环）→ `StagePostStart`（非阻塞首轮预热），停机或初始化失败时按注册**严格逆序**有界回收。

### 2.3 纯配置快照分离与 `sboption` 保真强类型流水线

- **不可变运行态快照（[`internal/config/store.go`](../internal/config/store.go)）**：`config.Config` 仅承载纯数据 Schema、零反射 `Clone()` 与 AST 注释保留保存；`webui`、`serverweb`、`subhub`、`daemon` 热路径读取统一经由 `config.Store`（`atomic.Pointer[Config]`），局部更新遵循 `Clone()` → 校验 → `0600` 原子落盘 → 写透发布。
- **保真强类型 `sing-box` 配置模型（[`internal/singbox/sboption`](../internal/singbox/sboption)）**：
  - 泛型双态切片 `Listable[T]` 自动无损兼容单值与数组；
  - 各层配置段内置 `Extra map[string]json.RawMessage` 无损信封，确保未知顶层键与新协议扩展字段 100% 零字节丢失；
  - 编译流水线共享单一内存 `*sboption.Document`（1 次解析 → 10 个类型化 Stage → 1 次格式化输出），路由与 DNS 插入统一由 `rule_anchors.go` 显式谓词定位。
- **统一 Clash API 与下沉领域引擎**：
  - 全仓 Clash 控制面查询（`webui`、`daemon`、`telemetry`、`audit`、`dohprobe`）统一复用实例级连接池客户端 [`internal/singbox/clashapi`](../internal/singbox/clashapi)；
  - 活跃嗅探追踪与封禁引擎独立归位于 [`internal/sniff`](../internal/sniff)（通过消费侧回调解耦 `fleet`），服务端遥测 `sniffing` 字段在 `serverweb` HTTP 序列化边界组合；
  - 双通道地理缓存归位于 [`internal/netdiag/ipgeo`](../internal/netdiag/ipgeo)，浏览器 DoH 旁路两阶段检测归位于 [`internal/netdiag/dohprobe`](../internal/netdiag/dohprobe)。

### 2.4 `<=512MB RAM / <=256MB 可用内存` 自适应低内存与单进程合体引擎

针对 224MB/256MB 小内存路由器及无线驱动预留大量内存的 512MB 硬路由（如 MT7986 `MemTotal ~480MiB`、`MemAvailable ~205MiB`、`/overlay ~50MB`），SingCtl 默认零配置自动激活五重资源治理：

1. **统一内存阶梯与 tmpfs 日志封顶（`common/sysinfo` + `common/memlimit` + `common/fsx`）**：
   - `sysinfo.IsLowMemoryHost()` 在 `MemTotal <= 512 MiB` 或 `MemAvailable <= 256 MiB` 时自动判定低内存宿主；`memlimit` 按 `<=288MiB`（`18/22MiB, GOGC=50`）与 `<=512MiB`（`24/28MiB, GOGC=50`）收紧常驻 Go 软内存上限；
   - `fsx.CapFileTail` / `OpenCappedAppendFile` 与原地保 inode 截断将 `/tmp/singctl-{daemon,web}.log` 及 `/tmp/sing-box-basic.log` 严格封顶在 `256 KiB`，防止长期运行撑爆路由器 tmpfs；
   - `updater` 在低内存或低 `/tmp` 空间时自动走 `ExtractBinaryStream` 零 `/tmp` 归档落盘流式 SHA256 直写升级。
2. **`sing-box` 低内存规则裁剪与自适应 `GOMEMLIMIT`（`config.LowMemory` + `singbox` + `servicemgr`）**：
   - `low_memory: "auto" | "on" | "off"` 默认 `auto` 自动在编译流水线 `prune_low_memory_rulesets` 阶段剥离巨无霸 `geosite-ad2`（节省 ~25–30 MB 堆内存）并清除悬空引用，完整保留高频轻量 `geosite-ad1` 与内置防 PCDN 集；
   - `servicemgr.UnitSpec.Env` 与启动脚本向 `sing-box`（含 OpenWrt `ujail -e`）注入 `GOMEMLIMIT=40MiB/44MiB` 与 `GOGC=50`；`adguard.Install` 与 WebUI 在超低可用内存下主动拦截防 OOM 并引导使用内置零额外内存 `sing-box 纯 IP DoH + geosite-ad1`。
3. **零环单进程合体运行时与冷态回收（`cmd` → `{daemon, webui}` + `audit`）**：
   - 通过 `DaemonOptions.EmbeddedService` 依赖反转钩子，在 `cmd/daemon.go` 自动将共享同一 `*config.Store` 与 `*audit.Collector` 的 `webui.Server` 内嵌进 `singctl dm` 单进程运行（立省一整套独立 Go Runtime ~16–18 MB），`singctl web status/start/restart` 无缝幂等兼容；
   - WebUI `IdleScavenger` 在连续 `3 分钟` 无请求后单次执行 `GC + FreeOSMemory` 归还物理内存且持续静默零重复唤醒；`audit.Collector` 收紧至 `256` 条风险感知有界流环（高危/可疑 PCDN 流永不误淘汰）并放宽邻居表刷新周期。
4. **`-tags lite` 小闪存精简发版矩阵与 `singbox-lite-latest` 滚动通道**：
   - 通过 `snapshot_lite.go` 与 `embed_lite.go` 剔除内嵌规则集快照与服务端 WebUI 静态资源，官方 GitHub Release 同步产出 `singctl-linux-{amd64,arm64}-lite.tar.gz`，`install.sh` 与 `updater` 自动识别匹配；
   - 独立滚动 Prerelease 通道 `singbox-lite-latest`（`singbox-lite-release.yml`）基于官方同版源码以 `with_quic,with_utls,with_clash_api` 裁剪产出无 UPX 精简版 `sing-box`，低内存或小闪存（`< 120 MiB`）网关执行 `sb install/update` 时零配置自动流式 SHA256 验签直写安装（0 MB `/tmp` 归档落盘，未就绪时平滑回退 `SagerNet/sing-box`）。

---

## 3. 代码组织与双端对称目录规范

### 3.1 Go 包内测试子目录隔离规范（`internal/<pkg>/test/`）

- `internal/**` 下所有包的单元测试文件统一收纳于各自模块的 **`test/` 子目录**（即 `internal/<pkg>/test/*_test.go`），保持业务源码目录 100% 纯净无测试混排；
- 包内测试统一声明为黑盒测试包 **`package <pkg>_test`**，通过公开导出契约、`Options` 或 `Deps` 结构体显式注入替身驱动验证（严禁包级可变 `*Override` 全局变量），与 `go test -race ./internal/...` 及 `deadcode -test ./...` 原生无缝兼容；
- 每个新增或拆分的 `.go` 文件首行标注 `// 文件职责：...`，常规业务源码单文件保持紧凑高内聚（`< 750` 行，硬红线 `<= 1,000` 行）。

### 3.2 前端 `web/src/` 双端 1:1 镜像对称规范（`<= 700` 行）

- **共享底座（[`web/src/lib/`](../web/src/lib)）**：`http.ts` 提供统一 `createHttpClient`（`requestJSON` / `requestText` / `requestNDJSON` / 401 会话拦截）与无泄漏 `composeAbortSignals(externalSignal, timeoutMs)`；`privacyMask.ts` 提供通用前端脱敏工具。
- **Client 与 Server 对称四元组（`api/ + shell/ + pages/ + types/`）**：
  - `web/src/client/`：`api/{session,system,singbox,dns,audit,network,actionStream,index}.ts`、`shell/`、`pages/`（顶层严格仅留 8 个一级路由 `*Page.tsx`，二级面板归入 `{adguard,audit,firewall,groups,network,singbox,watchdog}/`）、`components/{dns-leak,traffic-flow}/`、`types/`；
  - `web/src/server/`：`api/{http,overview,services,subscriptions,warp,fleet,security,index}.ts`、`shell/{Header,Navigation,LoginModal}.tsx`、`pages/`（9 个一级 `*Tab.tsx` 及 `{overview,services,warp,subscriptions,fleet,security}/` 子目录）、`types/navigation.ts`。

---

## 4. 永久 AST 架构防腐烂门禁

每次执行 `go test -short ./test/...` 时，[`test/architecture_guard_test.go`](../test/architecture_guard_test.go) 自动强制校验以下八条硬红线：

1. **`TestArchGuard_NoDuplicateSharedLiterals`**：`constant.GitHubRepo` 与本机回环默认监听端点仅允许在单一权威定义点出现；
2. **`TestArchGuard_SystemctlIsolatedToPlatformAllowlist`**：全仓仅允许 `internal/platform/servicemgr/` 调用 `"systemctl"`；
3. **`TestArchGuard_HotPathServersUseConfigStore`**：禁止 `subhub`、`webui`、`serverweb` 业务 handler 绕过 `config.Store` 裸调 `config.Load` / `config.Save`（零临时 CLI 白名单负债）；
4. **`TestArchGuard_MaxProductionFileLines`**：除静态内嵌 HTML 伪装站模板外，所有 `cmd/`、`internal/` 生产 `.go` 文件不得超过 **1,000 行**；
5. **`TestArchGuard_MaxFrontendFileLines`**：所有 `web/src/**/*.{ts,tsx}` 源码单文件不得超过 **700 行**；
6. **`TestArchGuard_CommonPackagesPureLeaf`**：`internal/common/*` 严禁导入任何非 `common` 的内部包；
7. **`TestArchGuard_InternalTestsInSubdir`**：`internal/**` 下所有 `*_test.go` 必须位于各自 `test/` 子目录且采用 `package <pkg>_test`；
8. **`TestArchGuard_LayeredDAGAcyclic`**：强制四层单向依赖无环（禁止 `common`/契约层上向依赖、禁止领域层反向导入 `cmd`/`webui`/`serverweb`/`daemon`、禁止 `sniff` 导入 `fleet`、禁止 `cmd` 除 `ui.go` 外导入 `serverweb`）。

> 文档、配置模板与单元测试中的示例地址与凭据必须严格使用 RFC 5737 保留网段（`192.0.2.x`、`198.51.100.x`、`203.0.113.x`）与 `example.com`。
