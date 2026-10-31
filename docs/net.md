# 网络链路画像与选型诊断 (Network Diagnostics & Advice)

`singctl net`（简写 `singctl n`）提供针对跨境 VPS 与代理节点的网络链路质量体检、多轮丢包与抖动分析、国内三大运营商核心骨干线路智能识别（CN2 GIA / 163 / 9929 / 4837 / CMIN2 / CMI），并在晚高峰提供精准的选型避坑与协议自动调优建议。

---

## 🌟 核心特性

- 📡 **免 Root 跨平台高精度探测**: 优先采用 TCP 端口握手测量（默认 443 端口），直击代理节点真实可用性，完全无需 root 权限且免疫机房 ICMP 阻断；支持自动无缝回退至系统 ICMP Ping。
- 🛣️ **三网骨干线路全景识别**:
  - **中国电信**: 识别普通 163 骨干 (AS4134, `202.97`)、半程优化 CN2 GT 以及全程精品网 CN2 GIA (AS4809, `59.43`)。
  - **中国联通**: 识别大带宽 169 骨干 (AS4837, `219.158`) 与政企精品 A 网 (AS9929 / CUG 10099, `218.105` / `210.51`)。
  - **中国移动**: 识别亚太直连 CMI (AS9808, `221.183` / `221.179`) 与高端精品网 CMIN2 (AS58807, `223.120`)。
  - **国际 Tier 1 / IXP**: 识别 NTT、PCCW、Telia/Arelion、HE、Cogent、Tata、IIJ、软银 (Softbank) 等。
- 🌏 **服务端回程三网探测**: 在 VPS 上执行一条命令，自动化评测 VPS 回程到国内电信、联通、移动主要骨干节点的回程线路与丢包表现。
- 💡 **智能建议与自动调优引擎**:
  - 根据晚高峰拥堵度和丢包率，自动推荐 **VLESS-Reality (TCP)** 还是 **Hysteria 2 (UDP/QUIC)**。
  - 提供针对当前宽带（电信/联通/移动）的 VPS 选购与避坑指南。
  - 支持 `--apply` 一键将计算出的稳健带宽参数回写到 `singctl.yaml`（`hy2.up` / `hy2.down`），保留注释。

---

## 📚 命令详解

### 1. `singctl net diag [ip/domain]` — 一键综合链路体检

对目标节点进行端到端全方位体检（延迟、抖动、丢包、骨干识别、选型建议）。如果省略目标参数，默认读取 `singctl.yaml` 中配置的服务端节点。

```bash
# 基础体检
singctl net diag 154.22.x.x

# 指定端口与测试轮数
singctl net diag 154.22.x.x -p 8443 -n 20

# 显示详细每一跳路由与往返分布
singctl net diag 154.22.x.x -v

# 自动将推荐的 hy2.up / hy2.down 参数应用写入 singctl.yaml
singctl net diag 154.22.x.x --apply

# 输出结构化 JSON
singctl net diag 154.22.x.x --json
```

---

### 2. `singctl net ping <ip/domain>` — 丢包与抖动分析

高精度多轮 Ping，输出 Min/Avg/Max 延迟与 Jitter (标准差/抖动) 指标。

```bash
# 默认 TCP 443 Ping (免 root)
singctl net ping 154.22.x.x -n 20

# 指定端口
singctl net ping 154.22.x.x -p 2222

# 强制使用系统 ICMP Ping
singctl net ping 154.22.x.x --icmp -n 10
```

---

### 3. `singctl net trace <ip/domain>` — 路由跳点追踪与线路识别

追踪途经路由跳点，并自动标注沿途的运营商特征与 ASN 归属。

```bash
# 路由追踪
singctl net trace 154.22.x.x

# 指定最大跳数
singctl net trace 154.22.x.x -m 30
```

---

### 4. `singctl net return` — 服务端三网回程探测

在部署了 singctl 的 VPS 上执行，快速探测本机回程到国内三大运营商核心骨干（上海电信 163/CN2、北京联通 4837/9929、广州移动 CMI/CMIN2）的路由与丢包表现。

```bash
# 在 VPS 上执行
singctl net return
```

---

### 5. `singctl net advice` — 专属宽带画像与 VPS 选型优化指南

自动检测本地当前网络环境的物理宽带（电信/联通/移动、城市、公网IP），并输出**专属于当前网络环境**的晚高峰痛点、适配线路梯队排行、避坑机房与 `singctl.yaml` 调优建议。

```bash
# 默认：自动探测当前网络宽带并输出定制指南
singctl net advice

# 查看国内三大运营商全量对比百科
singctl net advice --all

# 手动指定查看特定运营商的选型建议 (ct: 电信, cu: 联通, cm: 移动)
singctl net advice --carrier ct
singctl net advice --carrier cu
singctl net advice --carrier cm
```
