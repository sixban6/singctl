# 实用工具 (Utilities)

各类辅助命令，包括宽带测速、自更新和系统信息查看。

---

## 命令详解

### `singctl ut testbd` — 宽带测速

测试当前网络的上下行带宽，帮助确认 `hy2.up` / `hy2.down` 的合理取值。

```bash
singctl ut testbd
```

---

### `singctl update self` — 自更新 singctl

从 GitHub Releases 下载最新版本的 singctl 并替换当前二进制。

```bash
singctl update self
```

**配置迁移**：自更新时会自动将旧版 `singctl.yaml` 的用户配置（订阅、域名、密钥等）合并进新版模板，保留注释结构，不会丢失已有配置。

---

### `singctl info` — 查看系统信息

快速显示当前设备的系统状态，包括 OS、架构、网络接口、IP 等信息。

```bash
singctl info
```
