# SingCtl 架构设计与扩展规范

> 本文档面向人类维护者与 AI 编程助手，明确 SingCtl 核心分层边界、五大可复用基础抽象与编译期 AST 防腐烂守卫规范。

## 1. 分层依赖拓扑（严格无环 DAG）

```
  [ cmd / webui / serverweb / daemon ]         <-- 控制面与调度入口层（组合 Registry / Lifecycle / Store）
                   │
                   ▼
  [ deploy / singbox / fleet / audit / subhub / adguard / firewall / tailscale / netdiag / heal / doctor / gfw / terminal / telemetry ]
                   │                           <-- 领域引擎与业务适配实现层
                   ▼
  [ config / component / lifecycle / platform/servicemgr / constant / util / logger ]
                                               <-- 基础契约层（严禁反向依赖上层业务包）
```

> 所有基础设施契约均采用**显式依赖注入**（结构体字段、`New*` 构造函数或 `Option` 函数；测试未注入时默认回退生产实现），**禁止**使用隐式 `context.Value` 服务定位器传递核心依赖。

---

## 2. 核心抽象与标准扩展路径

### 2.1 极薄宿主服务契约层（[`internal/platform/servicemgr`](../internal/platform/servicemgr)）

- **契约接口**：`Manager`（`Backend`, `InstallUnit`, `RemoveUnit`, `Start`, `Stop`, `Restart`, `Reload`, `IsActive`, `Logs`, `Run`）、systemd 批量诊断扩展（`ShowUnitsBatch`, `ShowProperties`, `IsEnabled`, `EnableNow`, `DisableNow`, `ParseSystemdShowBatch`）及 `HostInfo` / `IsOpenWrt()` / `ValidateUnitName()`。
- **内置实现**：`SystemdManager`（systemd VPS）、`ProcdManager`（OpenWrt BusyBox `procd` + 命名白名单防注入）、`NoopManager` 与 `MockManager`。
- **扩展约束**：**严禁**在 `internal/platform/servicemgr/` 以外的任何业务包或 Web handler 中直接拼装裸 `exec.Command("systemctl", ...)`。

### 2.2 声明式注册表与正交算子（`component` / `audit` / `doctor`）

- **服务组件注册表（[`internal/component`](../internal/component)）**：
  - 核心契约 `Component` + 正交能力接口 `Configurable`、`Upgradable`、`Versioned`、`ServerLifecycle`；
  - 服务端挂载点 [`internal/deploy/comp_registry.go`](../internal/deploy/comp_registry.go) 默认注册 `sing-box`、`caddy`、`singctl-sub`、`warp`。
- **声明式健康体检注册表（[`internal/doctor`](../internal/doctor)）**：
  - `Registry` 按 `ScopeServer` / `ScopeClient` 有序调度 `Check` 算子（[`checks_server.go`](../internal/doctor/checks_server.go)、[`checks_client.go`](../internal/doctor/checks_client.go)）；
  - 所有宿主文件、端口与 TLS 探针通过 `Deps` 结构体显式注入，支持纯离线确定性表驱动单测。
- **扩展约束**：新增受管服务、审计算子或诊断项时，按「独立文件 + 向注册表注册一行」横向扩展，**禁止**在多处拷贝粘连 `switch` / `if-else`。

### 2.3 三阶段确定性生命周期编排（[`internal/lifecycle`](../internal/lifecycle)）

- **启动阶段**：`StageInit`（加载配置/打开日志文件/校验参数）→ `StageStart`（拉起监听与受控巡检循环）→ `StagePostStart`（非阻塞首轮预热与状态同步）。
- **回滚与回收**：任一阶段失败或 `ctx` 取消时，自动按**注册严格逆序**调用已触达组件的 `Close()`，受 `WithCloseTimeout`（默认 `5s`）有界保护且幂等。
- **全量覆盖**：[`internal/serverweb/serverweb.go`](../internal/serverweb/serverweb.go)、[`internal/webui/webui.go`](../internal/webui/webui.go)、[`internal/subhub/server.go`](../internal/subhub/server.go)（`ServeContext` / `buildLifecycle`）与 [`internal/daemon/daemon.go`](../internal/daemon/daemon.go)（`buildForegroundLifecycle`）。

### 2.4 纯配置模型与不可变运行态快照（[`internal/config/store.go`](../internal/config/store.go)）

- **职责分离**：
  - `Config`（含 [`Clone()`](../internal/config/clone.go)）专注 YAML 序列化、AST 无损注释保存与校验；
  - `config.Store` 维护 `atomic.Pointer[Config]` 无锁只读快照、`mtime+size` 指纹按需重载、坏 YAML 自动保留上一已知有效快照，以及互斥串行 `Update`（`0600` 原子写入）。
- **使用铁律**：`webui`、`serverweb`、`subhub`、`daemon` 等长驻模块热路径读配置必须经由 `config.Store` 只读快照；局部修改并落盘时必须遵循 `Clone()` → 校验 → `0600` 原子保存 → 刷新/失效快照，**禁止**原地修改共享快照或在 HTTP handler 中裸调 `config.Load` / `config.Save`。

### 2.5 前后端领域化目录边界（`internal/` & `web/src/`）

- **Go 后端**：按子领域职责拆分为 `< 800` 行内聚文件，每个新文件首行标注 `// 文件职责：...`。
- **React/TS 前端（[`web/src/`](../web/src)）**：
  - 服务端面板（`web/src/server/`）：按 `types/` 与 `components/{overview,services,security,warp,fleet,subscriptions}/` 领域子目录内聚组织；
  - 客户端面板（`web/src/client/`）：按 `types/`、`shell/`、`pages/{adguard,audit,firewall,groups,network,singbox,watchdog}/` 与 `components/{dns-leak,traffic-flow}/` 领域子目录内聚组织。

---

## 3. 永久 AST 架构防腐烂门禁

每次提交或运行 `go test -short ./test/...` 时，[`test/architecture_guard_test.go`](../test/architecture_guard_test.go) 会自动校验以下六条硬红线：

1. **禁止跨包重复硬编码契约字面量**：`constant.GitHubRepo` 与服务回环默认端口仅允许在单一权威文件出现；
2. **宿主 `systemctl` 零越界**：全仓仅允许 `internal/platform/servicemgr/` 调用 `"systemctl"`，零上层业务白名单负债；
3. **热路径服务强制走 `config.Store`**：禁止在 `subhub`、`webui`、`serverweb` 的业务 handler 中新增裸 `config.Load` / `config.Save`；
4. **Go 生产单文件复杂度上限**：除静态内嵌 HTML 伪装模板外，所有 `cmd/`、`internal/` 生产 `.go` 文件不得超过 **1,000 行**；
5. **前端源码单文件复杂度上限**：所有 `web/src/**/*.{ts,tsx}` 文件不得超过 **1,000 行**；
6. **基础契约层零反向依赖**：`constant` / `component` / `lifecycle` / `platform/servicemgr` 严禁逆向导入任何领域层或控制面层包。

> 本地验证标准示例值（如配置单测与文档）必须使用 RFC 5737 保留网段（`192.0.2.x`、`198.51.100.x`、`203.0.113.x`）与 `example.com`。
