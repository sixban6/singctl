# SingCtl AI 助手强制执行守则目录 (`.agent/rules/`)

本目录存放所有 AI 编程助手（Antigravity / Gemini / Claude / Cursor / Codex 等）在本仓库执行**代码修改、文档编写、真机运维与上传 GitHub** 时每次都**必须无条件遵守**的红线规则。

根目录 [`AGENTS.md`](../../AGENTS.md) 已通过自动引用机制挂载本目录下的全部规则文件，确保每次新开对话自动生效，无需人工重复叮嘱。

## 规则文件清单

1. [`01-security-and-github-sanitization.md`](./01-security-and-github-sanitization.md) —— **敏感信息脱敏与 GitHub 提交前强制扫描铁律**
2. [`02-zero-downtime-live-ops.md`](./02-zero-downtime-live-ops.md) —— **软路由与线上 VPS 零断网、防失联操作铁律**
3. [`03-code-quality-and-release-gates.md`](./03-code-quality-and-release-gates.md) —— **代码质量、文件权限安全与发布前测试门禁**
