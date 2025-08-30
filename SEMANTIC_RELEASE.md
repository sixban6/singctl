# Semantic Release 使用指南

## 提交格式

使用 [Conventional Commits](https://conventionalcommits.org/) 格式：

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

## 版本规则

| 提交类型 | 版本变更 | 示例 |
|---------|---------|------|
| `feat:` | minor | `feat: 添加多订阅支持` → 1.0.0 → 1.1.0 |
| `fix:` | patch | `fix: 修复配置生成错误` → 1.1.0 → 1.1.1 |
| `perf:` | patch | `perf: 优化启动速度` → 1.1.1 → 1.1.2 |
| `refactor:` | patch | `refactor: 重构网络检测逻辑` → 1.1.2 → 1.1.3 |
| `BREAKING CHANGE:` | major | 任何包含 BREAKING CHANGE 的提交 → 1.1.3 → 2.0.0 |

## 不触发发版的提交

这些类型不会触发新版本发布：
- `docs:` - 文档更新
- `style:` - 代码格式化
- `test:` - 测试相关
- `chore:` - 构建工具、依赖更新等

## 使用示例

```bash
# 新功能 (minor版本)
git commit -m "feat: 添加Mac系统兼容性支持"

# Bug修复 (patch版本)  
git commit -m "fix: 修复权限错误导致的启动失败"

# 性能优化 (patch版本)
git commit -m "perf: 减少配置生成时间"

# 破坏性更改 (major版本)
git commit -m "feat!: 重新设计配置文件格式

BREAKING CHANGE: 配置文件格式已更改，需要重新配置"
```

## 发版流程

1. 按照规范提交代码到 main 分支
2. GitHub Actions 自动检测提交类型
3. 自动计算版本号并创建 release
4. 自动生成 CHANGELOG.md
5. 自动构建多平台二进制文件

## 手动触发发版

如果需要手动控制版本：

```bash
# 安装依赖
npm install

# 本地测试（不会真正发版）
npm run release -- --dry-run

# 手动发版（需要推送权限）
npm run release
```