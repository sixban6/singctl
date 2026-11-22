# SingCtl 架构设计与扩展规范

> 本文档面向人类维护者与 AI 编程助手，明确 SingCtl 核心分层边界、四大可复用基础抽象与编译期 AST 防腐烂守卫规范。

## 1. 分层依赖拓扑（严格无环 DAG）

```
  [ cmd / webui / serverweb / daemon ]         <-- 控制面与调度入口层（组合 Registry / Lifecycle / Store）
                   │
                   ▼
  [ deploy / singbox / fleet / audit / subhub / adguard / firewall / tailscale / heal ]
                   │                           <-- 领域引擎与业务适配实现层
                   ▼
  [ config / component / lifecycle / platform/servicemgr / constant / util / logger ]
                                               <-- 基础契约层（严禁反向依赖上层业务包）
```

> 所有基础设施契约均采用**显式依赖注入**（结构体字段、`New*` 构造函数或 `Option` 函数；测试未注入时默认回退生产实现），**禁止**使用隐式 `context.Value` 服务定位器传递核心依赖。

---

## 2. 四大核心抽象与标准扩展路径

### 2.1 极薄宿主服务契约层（[`internal/platform/servicemgr`](../internal/platform/servicemgr)）

- **契约接口**：`Manager`（`Backend`, `InstallUnit`, `RemoveUnit`, `Start`, `Stop`, `Restart`, `Reload`, `IsActive`, `Logs`, `Run`）及 `HostInfo` / `IsOpenWrt()` / `ValidateUnitName()`。
- **内置实现**：`SystemdManager`（systemd VPS）、`ProcdManager`（OpenWrt BusyBox `procd` + 命名白名单防注入）、`NoopManager` 与 `MockManager`。
- **扩展约束**：除 `servicemgr` 与白名单宿主底层适配外，**禁止**在业务逻辑或 Web handler 中直接拼装裸 `exec.Command("systemctl", ...)`。

### 2.2 声明式组件注册表（[`internal/component`](../internal/component)）

- **契约接口**：
  - `Component`：`ID() string` / `DisplayName() string` / `UnitName() string` / `ServiceAction(ctx, action) (string, error)`；
  - `Configurable`（可选）：`ConfigTarget() ConfigTarget`；
  - `Upgradable`（可选）：`CheckUpdate(ctx) (CheckUpdateInfo, error)` / `Upgrade(ctx) (UpgradeInfo, error)`；
  - `Versioned`（可选）：`InstalledVersion() string`；
  - `ServerLifecycle`（可选）：`Install` / `Uninstall` / `Reinstall`。
- **服务端挂载点**：[`internal/deploy/comp_registry.go`](../internal/deploy/comp_registry.go) 默认注册 `sing-box`、`caddy`、`singctl-sub`、`warp`。
- **新增服务组件**：只需在对应适配包新增一个实现 `Component` 的独立文件并在注册表注册，**禁止**回退到多处复制 `switch service { ... }`。

### 2.3 三阶段确定性生命周期编排（[`internal/lifecycle`](../internal/lifecycle)）

- **启动阶段**：`StageInit`（加载配置/打开日志文件/申请锁）→ `StageStart`（拉起监听与后台巡检）→ `StagePostStart`（首轮预热与非阻塞同步）。
- **回滚与回收**：任一阶段失败或 `ctx` 取消时，自动按**注册严格逆序**调用已触达组件的 `Close()`，受 `WithCloseTimeout`（默认 `5s`）有界保护且幂等。
- **接入示例**：[`internal/serverweb/serverweb.go`](../internal/serverweb/serverweb.go) (`ServeContext` / `buildLifecycle`) 与 [`internal/daemon/daemon.go`](../internal/daemon/daemon.go) (`buildForegroundLifecycle`)。

### 2.4 纯配置模型与不可变运行态快照（[`internal/config/store.go`](../internal/config/store.go)）

- **职责分离**：
  - `Config`（含 [`Clone()`](../internal/config/clone.go)）专注 YAML 序列化、AST 无损注释保存与校验；
  - `config.Store` 维护 `atomic.Pointer[Config]` 无锁只读快照、`mtime+size` 指纹按需重载、坏 YAML 自动保留上一已知有效快照，以及互斥串行 `Update`（`0600` 原子写入）。
- **使用铁律**：热路径读配置统一读取不可变快照（`Store.Get()` / `Store.LoadLatest()`）；需要局部修改并落盘时，必须先 `Clone()` 再通过 `Store.Update` 或 `saveConfig` 写透发布，禁止原地修改共享快照。

---

## 3. 永久 AST 架构防腐烂门禁

每次提交或运行 `go test -short ./test/...` 时，[`test/architecture_guard_test.go`](../test/architecture_guard_test.go) 会通过 `go/ast` 自动校验以下四条硬红线：

1. **禁止跨包重复硬编码契约字面量**：`constant.GitHubRepo` 与服务回环默认端口仅允许在单一权威文件出现；
2. **隔离宿主 init 调用**：禁止在核心契约或白名单外新增裸 `"systemctl"` 系统调用；
3. **单文件复杂度上限**：除静态内嵌 HTML 伪装模板外，所有 `cmd/`、`internal/` 生产 `.go` 文件不得超过 **1,000 行**；
4. **分层零循环依赖**：`constant` / `component` / `lifecycle` / `platform/servicemgr` 禁止逆向导入上层业务包。

> 本地验证标准示例值（如配置单测与文档）必须使用 RFC 5737 保留网段（`192.0.2.x`、`198.51.100.x`、`203.0.113.x`）与 `example.com`。
