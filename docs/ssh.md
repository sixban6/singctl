# SSH 批量免密、端口收敛与安全加固 (SSH Management)

`singctl ssh` 提供了开箱即用的跨平台服务器 SSH 自动化运维与安全基线加固能力。采用纯 Go 原生 SSH 客户端实现（零外部 Python/Ansible/sshpass 依赖），支持批量公钥注入、免密验证、平滑过渡并将默认 22 端口收敛至 2222 端口、禁用密码登录，并增量幂等回写本地 `~/.ssh/config`。

---

## 核心特性

- 🎯 **约定优于配置**：默认自动读取当前目录下的 `./ssh-init.yaml`，命令行无需反复指定 `-f`。
- 🛡️ **双端口过渡与防失联熔断**：先开启 `Port 22 + Port 2222` 双监听并放行防火墙/SELinux，本地发起外部探活，**只有 2222 端口免密验证 100% 成功后才收敛关闭 22 端口和密码认证**。若探活失败自动安全回滚至 22 端口并保留访问通道，绝不锁死主机。
- ⚡ **高性能并发执行**：内置 Worker Pool，支持多主机并发调度（默认 5 并发），几秒内即可完成数十台主机的巡检或加固。
- 📝 **~/.ssh/config 幂等托管**：采用专属标记块隔离，修改前自动生成时间戳备份，支持原地覆盖更新与安全清理，绝不破坏用户原本的 GitHub、GitLab 等现有配置。
- 🔒 **凭据安全与防泄漏**：内置敏感配置与密钥的全局 `.gitignore` 规则，支持 `${ENV_VAR:-default}` 环境变量动态展开，敏感密码无需硬编码落盘。

---

## 配置文件规范 (`ssh-init.yaml`)

使用 `singctl ssh tpl` 命令可在当前目录一键生成该标准模板：

```yaml
version: "1.0"

# 全局默认参数 (若主机项未显式声明，则继承此处的设定)
defaults:
  user: root                              # 默认登录用户
  current_port: 22                        # 目标机当前 SSH 端口
  target_port: 2222                       # 加固切换后的目标 SSH 端口
  identity_file: ~/.ssh/id_ed25519.pub    # 本地待分发的公钥路径
  private_key: ~/.ssh/id_ed25519          # 本地用于探活与写入 ~/.ssh/config 的私钥路径
  disable_password_auth: true             # 是否彻底关闭密码登录 (PasswordAuthentication no)
  manage_firewall: true                   # 是否自动配置远端防火墙 (ufw/firewalld) 与 SELinux
  strict_host_key_checking: false         # 首次连接是否自动忽略 known_hosts 提示
  timeout_seconds: 15                     # SSH 连接与命令超时时间 (秒)

# 目标主机清单
hosts:
  # 场景 1: 全新服务器 (仅有初始密码, 自动推公钥、改到 2222 端口、关密码、写 ~/.ssh/config)
  - name: hk-prod-01                      # 唯一别名 (写入 ~/.ssh/config 的 Host 项)
    ip: 43.154.10.1
    auth:
      password: "${HK_ROOT_PASS:-InitialPassword123}" # 推荐使用环境变量，亦可直接写密码

  # 场景 2: 非 root 用户、自定义目标端口、自定义临时密码
  - name: us-gpu-02
    ip: 104.21.33.8
    user: ubuntu
    target_port: 22222                    # 单机覆盖目标端口
    auth:
      password: "InitTempPassword123"

  # 场景 3: 已拥有临时 Key 的服务器 (无需密码)，仅做安全加固与端口收敛
  - name: jp-edge-03
    ip: 129.226.50.12
    auth:
      key: ~/.ssh/old_temp_rsa            # 初始连接时所使用的已有私钥
```

---

## 命令详解

### 1. `singctl ssh tpl` — 快速生成配置模板

在当前目录生成标准的 `ssh-init.yaml` 示例配置文件（支持别名 `template`）。

```bash
# 生成默认模板 ./ssh-init.yaml
singctl ssh tpl

# 若文件已存在，强制覆盖
singctl ssh tpl --force

# 指定输出路径
singctl ssh tpl -o my-nodes.yaml
```

---

### 2. `singctl ssh init` — 一键全流程批量加固

全自动流水线：注入公钥 ➔ 验证 22 端口免密 ➔ 开启双端口 (22+2222) ➔ 外部探活 2222 端口 ➔ 收敛关闭 22 端口与密码登录 ➔ 增量同步 `~/.ssh/config`。

```bash
# 默认读取当前目录 ./ssh-init.yaml 并以 5 并发执行
singctl ssh init

# 演练模式：仅检测通道与连通性，不写入破坏性配置
singctl ssh init --dry-run

# 指定并发数与自定义配置文件
singctl ssh init -f my-nodes.yaml -j 10

# 加固远端主机，但不回写本地 ~/.ssh/config
singctl ssh init --skip-config
```

---

### 3. `singctl ssh test` — 连通性与合规性体检

非破坏性体检工具。随时对目标主机进行端口监听探测、公钥免密登录有效性校验、密码登录状态审计，并输出格式化彩色表格。

```bash
singctl ssh test

# 指定配置文件
singctl ssh test -f my-nodes.yaml
```

---

### 4. `singctl ssh push-key` — 仅批量分发公钥

类似于跨平台的增强版 `ssh-copy-id`，仅负责将本地公钥推送并授权写入远程主机的 `~/.ssh/authorized_keys`，并做权限校验（`0700` / `0600`）。

```bash
singctl ssh push-key
```

---

### 5. `singctl ssh harden` — 仅对已免密主机执行安全加固

适用于已配置免密的主机，执行端口收敛、关闭密码登录及防火墙规则放行。

```bash
# 使用配置文件中定义的参数加固
singctl ssh harden

# 强制将目标端口统一收敛至 2222 并关闭密码登录
singctl ssh harden -p 2222 --disable-password
```

---

### 6. `singctl ssh config` — 本地 ~/.ssh/config 增量托管

管理本地 `~/.ssh/config`，采用项目独占的标记块隔离（如 `# === BEGIN SINGCTL MANAGED HOST: <name> ===`）。

```bash
# 将 ssh-init.yaml 中的节点批量渲染并增量写入 ~/.ssh/config (自动生成时间戳备份)
singctl ssh config sync

# 查看当前已由 singctl 托管的所有 SSH 节点
singctl ssh config list

# 清理指定主机的托管标记块
singctl ssh config clean -n hk-prod-01

# 清理所有由 singctl 托管的标记块
singctl ssh config clean
```

---

## 防失联保障机制 (Safe-by-Design)

```
[步骤 1: 建立连接] ────> [步骤 2: 注入公钥] ────> [关卡 1: 验证 22 端口免密]
                                                        │ (失败即刻中止)
                                                        ▼
[步骤 5: 最终收紧] <──── [关卡 2: 验证 2222 端口免密] <──── [步骤 3 & 4: 放行防火墙/SELinux, 开启双端口 22+2222]
  - 移出 22 端口监听             │ (探测失败触发熔断)
  - 彻底关闭密码认证             ▼
  - 回写 ~/.ssh/config      【安全熔断回滚】
                         - 恢复仅监听 22 端口并保留密码登录
                         - 告警提示: 2222 端口不通 (检查外部安全组)
                         - 保障通道完好, 绝不失联
```
