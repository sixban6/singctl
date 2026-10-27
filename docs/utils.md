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

### `singctl gfw <ip>` — GFW 主动探测模拟与风险评分

模拟防火墙 (GFW) 经典主动探测 (Active Probing) 手段，对指定 IP 进行 5 大维度画像分析与 0~100 分量化评分，评估节点暴露面并输出安全加固建议。

```bash
# 基础探测
singctl gfw 1.2.3.4

# 指定伪装域名与业务域名深度比对
singctl gfw 1.2.3.4 --sni swdist.apple.com --domain cdn.example.com

# 指定自定义端口进行探测
singctl gfw 1.2.3.4 -p 8443
```

> 详细的 5 大维度检测机制、评分模型与加固建议，请参阅专用文档：[GFW 主动探测模拟与风险评估文档](gfw.md)。

---

### `singctl info` — 查看系统信息

快速显示当前设备的系统状态，包括 OS、架构、网络接口、IP 等信息。

```bash
singctl info
```
