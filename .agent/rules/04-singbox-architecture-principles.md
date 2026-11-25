# 规则 04：对标 sing-box 的模块化架构设计与防劣化铁律

在编写新功能、修复 Bug、重排包结构或扩展后台/平台能力时，必须严格遵循以下源自 `SagerNet/sing-box` 并结合本仓“显式依赖注入”改良后的架构铁律，从设计源头杜绝耦合与“屎山化”。

## 1. 总纲：取 `sing-box` 四大精髓，拒隐式全局魔法

- **四大必守精髓**：**极薄平台契约层** + **声明式组件注册表** + **确定性三阶段生命周期** + **纯配置模型与不可变运行态快照分离**。
- **零隐式服务定位器（硬红线）**：**严禁**模仿老式 `Context` 从 `context.Value` 里隐式掏取全局服务或篡改包级可变单例；所有可替换 I/O 与策略协作者必须采用**编译期显式依赖注入**（构造函数参数、`Option` 函数或结构体字段，未注入 `nil` 时回退生产默认实现）。

## 2. 单向无环分层（Strict Acyclic DAG）与宿主契约隔离

- **严格三层单向依赖**（底层绝对禁止反向 `import` 上层）：
  1. **基础契约层**：`internal/constant`、`internal/component`、`internal/lifecycle`、`internal/platform/servicemgr`、`internal/config`、`internal/util/*`、`internal/logger`。
  2. **领域引擎层**：`internal/deploy`、`internal/singbox`、`internal/fleet`、`internal/audit`、`internal/subhub`、`internal/adguard`、`internal/firewall`、`internal/tailscale`、`internal/netdiag`、`internal/heal`。
  3. **控制面与调度层**：`internal/cmd`、`internal/webui`、`internal/serverweb`、`internal/daemon`。
- **控制面保持薄外壳**：HTTP Handler 与 Cobra CLI 仅做鉴权、入参校验、调用领域接口与响应编排，**严禁**直接内嵌复杂路由编译、协议生成或远端 Shell 拼装。
- **宿主 init / 服务托管唯一出口**：除 `internal/platform/servicemgr`（`SystemdManager` / `ProcdManager` / `MockManager`）及 `test/architecture_guard_test.go` 明确白名单外，**严禁**在任何新增代码中直接拼装裸 `exec.Command("systemctl", ...)` 或 `/etc/init.d/*` 脚本调用。

## 3. 声明式注册表与正交小接口扩展（Registry & ISP over `switch` Sprawl）

- **3 个以上变体必收口为注册表 / 声明式表**：凡涉及多组件、多检测器或可持续扩充的维度（如受管服务 `component.Component`、审计算子 `audit.Detector`、配置清理规则、分流预设表），一律按**「新增能力 = 新增独立文件 + 向注册表注册一行」**扩展，**禁止**在多个处理函数里反复拷贝粘连 `switch service { ... }` 或在核心大函数里堆砌 `if-else`。
- **正交可选小接口（接口隔离）**：核心契约保持极简，差异能力通过 `Configurable`、`Upgradable`、`ServerLifecycle` 等正交小接口按类型断言能力分派，绝不逼迫简单组件实现无关空方法。

## 4. 确定性三阶段生命周期与逆序有界回收（`internal/lifecycle`）

- **三阶段顺序启停**：常驻 HTTP 服务、守护进程与后台巡检必须通过 `lifecycle.Group` 托管：
  1. `StageInit`：只做配置加载、文件锁、文件句柄与端口准备，**禁止**在该阶段启动并发后台协程；
  2. `StageStart`：拉起监听与受控巡检循环；
  3. `StagePostStart`：触发非阻塞首轮预热与状态同步。
- **严格逆序回收与取消传递**：所有后台协程必须绑定可取消的 `ctx`（**禁止**游离的 `go func() { for { ... } }()`），停机或中途初始化失败时严格按注册**逆序**关闭（后台写协程先停、持久化落盘与句柄最后关），并受 `WithCloseTimeout` 有界超时保护。

## 5. 纯配置数据模型与不可变运行态快照分离（`config.Store`）

- **纯数据 `Config`**：`config.Config` 仅承载序列化字段、校验与零反射深拷贝 `Clone()`，严禁混入运行期锁、HTTP 客户端或后台协程状态。
- **热路径只读无锁快照**：`webui`、`serverweb`、`daemon`、`audit` 等长驻模块读取配置必须统一经由 `config.Store`（基于 `atomic.Pointer[Config]` + `mtime+size` 文件指纹按需重载，坏配置自动保留上一已知有效快照）：
  - **禁止**在前端状态轮询或定时巡检热路径上反复调用磁盘 `config.Load` / 重跑 `yaml.Unmarshal`；
  - **严禁**原地修改共享快照指针字段；任何局部更新必须遵循 `Clone()` → 校验 → 原子 `0600` 落盘 → 写透发布（`Store.Update` / `saveConfig` / `Invalidate`）。

## 6. 高内聚小文件红线与 AST 编译测试守卫

- **单文件复杂度红线**：除静态内嵌 HTML/资源模板外，所有 `cmd/`、`internal/` 生产 `.go` 文件**硬上限 `<= 1,000` 行**；接近 `800` 行时应按内聚子职责拆分为同包多文件，并在新文件首行添加 `// 文件职责：...` 中文说明。
- **公共契约常量唯一归属**：仓库坐标（`constant.GitHubRepo`）与默认回环监听端点只允许存在单一权威定义点，严禁跨包复制魔数字符串。
- **不可绕过架构测试守卫**：`test/architecture_guard_test.go` 是永久生效的自动化架构门禁，新增代码不得通过扩大白名单来敷衍违规，架构分层变更须同步更新 `docs/architecture.md`。
