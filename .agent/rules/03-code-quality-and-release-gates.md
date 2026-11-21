# 规则 03：代码质量、权限安全与发布前门禁准则

## 1. 架构与安全编码红线

- **保持极简零外部依赖**：坚持单二进制内嵌静态资源架构，不引入 Docker、Redis、MySQL 等重型外部依赖，兼顾 512MB～1GB 小内存 VPS 与 OpenWrt 软路由。
- **敏感落盘强制 `0600`**：所有包含凭据、密钥、Token 或节点清单的持久化文件（`singctl.yaml`、`fleet.yaml`、`fleet_keys/*`、`config.json`、Token 文件）写入或原子替换时必须确保权限为 `0600`（目录 `0700`）。
- **防命令注入与防越权**：所有拼入远程 Shell 或系统命令的参数必须做严格白名单校验或 Base64 管道解码传递；服务端遥测端口（如 Clash API `9099`）与后台服务（`8092`、`3001`）仅允许绑定 `127.0.0.1` 回环地址。
- **遵循现代 Go 规范**：基于仓库 `go.mod` 目标版本使用标准库现代特性（`cmp.Or`、`slices`、`maps`、`strings.SplitSeq`、`atomic.Bool`、测试中使用 `t.Context()`）。

## 2. 提交与发版前必跑验证门禁

每次修改代码准备提交前，必须本地实际运行并通过以下检查（不得跳过或伪造结果）：

1. **若修改了 `web/` 前端代码**：必须执行 `cd web && npx tsc --noEmit && npm run build`，将最新构建产物同步至 `internal/serverweb/static/`。
2. **Go 静态检查与竞态测试**：必须执行并通过：
   ```bash
   go vet ./...
   go test -race ./internal/...
   go test -short ./test/...
   ```
3. **注释与文档同步**：保留无关既有注释；若新增或变更 CLI 参数、配置字段（如 `knownYAMLKeys`），同步更新配置模板与 `docs/` 文档。

## 3. Git Commit 信息规范（强制）

每次执行 `git commit` 时，必须使用语义化前缀，并在标题与正文中清晰说明以下内容：

- **前缀约定**：`feat:`（功能新增）、`fix:`（bug修复）、`perf:`（性能优化）、`refactor:`（重构）、`docs:`（文档）、`chore:`（杂项）。注意 `.github/workflows/release.yml` 会对 `docs` / `style` / `test` / `ci` 前缀跳过自动发版。
- **变更类型**：在提交正文明确标出本次属于「功能新增」、「bug修复」还是「性能优化」（复合改动需逐一注明）。
- **改动原因**：用 1～2 句简短说明本次改动的起因或要解决的问题，再列出核心改动要点。
