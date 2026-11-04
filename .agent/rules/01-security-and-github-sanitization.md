# 规则 01：敏感数据零泄漏与上传 GitHub 前强制脱敏铁律

任何时候向 Git 暂存区添加文件、提交代码（`git commit`）、推送远程仓库（`git push`）、编写文档/测试或向用户展示日志时，**必须严格执行以下脱敏规范，严禁任何真实隐私数据进入版本库**。

## 1. 绝对禁止上传的敏感数据类型

- **真实网络标识**：用户的真实公网 IPv4/IPv6 地址、真实私人域名（包括子域名、NS 记录、伪装站真实绑定域名）、家庭宽带公网/运营商特征 IP。
- **各类密钥与凭据**：
  - Cloudflare DNS API Token（`cf_dns_key`）
  - Tailscale Auth Key（`tskey-auth-...`）
  - Sing-Box 节点凭据（真实 UUID、Hysteria2 密码、VLESS Reality 私钥/公钥/ShortID）
  - 订阅访问密钥（`/etc/sub-store/key`、真实订阅下载完整 URL）
  - Web 管理面板账号密码哈希或明文、Session/CLI Token、mTLS 证书密码
  - SSH 私钥（`*.pem`、`id_ed25519`、`master_ed25519`）与包含真实主机信息的 `ssh-init.yaml`、`fleet.yaml`、`fleet.json`

## 2. 文档与测试中的占位符标准

所有文档（`README.md`、`docs/*.md`）、配置模板（`configs/*.yaml`）及单元测试（`*_test.go`）必须统一使用标准虚拟示例值：
- **示例 IP**：统一使用 RFC 5737 文档保留网段（`192.0.2.x`、`198.51.100.x`、`203.0.113.x`）或局域网示例 `192.168.1.1`。
- **示例域名**：统一使用 `example.com`（如 `node.example.com`、`us1.example.com`、`jp1.example.com`）。
- **示例密钥**：统一使用语义化假值（如 `your_cloudflare_api_token`、`cf-test-token`、全 `1` 测试 UUID）。

## 3. 每次 `git commit` / `git push` 前必须执行的门禁检查

在执行提交或推送前，AI **必须先运行以下命令自检并确认零命中真实隐私数据**：

```bash
# 1. 检查暂存与未跟踪文件，严禁混入临时备份、配置快照或密钥文件
git status -s

# 2. 扫描暂存区 diff，确认不含真实域名、真实 Token、私钥头或真实订阅密钥
git diff --cached | grep -Ei "(BEGIN .*PRIVATE KEY|tskey-auth-|cf_dns_key:[[:space:]]*['\"]?[A-Za-z0-9_-]{20,})" || true
```

一旦发现历史提交或暂存区误含真实敏感信息，必须立即阻断推送并在本地彻底清理后再提交。
