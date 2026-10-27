# Web 终端与 SSH-over-WSS 穿透通道 (Web Terminal & SSH-over-WSS)

命令前缀：`singctl term` / `singctl terminal` / `singctl sr term`

基于 Caddy 443 端口与 mTLS 双向 TLS 认证的隐蔽运维通道，提供两种接入方式：
1. **方案一：Web 终端 (GoTTY + Tmux)**：手机 / 平板 / 电脑浏览器直接打开，无需安装客户端，断网重连会话不丢；
2. **方案二：本地终端原生 SSH 穿透 (WezTerm / Terminal + wstunnel)**：将 SSH 封装在 443 端口 WebSocket (WSS) 流量中并携带客户端证书，绕过防火墙封锁，获得原生 SSH 的全功能极速体验。

---

## 架构与安全模型

```
                                      ┌── [方案一] 浏览器 (Web mTLS) ──> GoTTY (127.0.0.1:18080) ──> Tmux 会话
客户端 (443 HTTPS / WSS + mTLS 证书) ──> Caddy (443)
                                      └── [方案二] wstunnel (SSH WSS) ──> wstunnel (127.0.0.1:18081) ──> 本机 SSH (127.0.0.1:22/2222)
```

### 核心安全特性

- **严格 mTLS 双向认证**：Caddy 在 TLS 握手阶段强制校验客户端证书（`client_auth { mode require_and_verify }`），任何未携带有效客户端证书的扫描器或探测请求直接返回 **HTTP 404**，完全隐藏服务端真实意图。
- **隐蔽路径分流**：终端服务与 SSH 隧道隐藏在随机生成的隐蔽路径（如 `/term-8f9a2b/` 与 `/ssh-ws`）后，外层表现为完全合规的普通静态博客/网站。
- **多节点自动隔离**：根据服务端配置的节点代号（如 `los`、`sg`、`hk`）自动为导出的证书与 `~/.ssh/config` 命名，多台 VPS 部署时证书与主机别名互不冲突。
- **会话持久化**：Web 终端底层挂载 `tmux`，浏览器关闭或网络中断后任务仍在后台持续运行，重新连接即可恢复工作现场。

---

## 配置文件

相关配置位于 `singctl.yaml` 的 `server.web_terminal` 字段（在执行 `singctl term install` 时会自动生成并写入）：

```yaml
server:
  node_tag: "los"                               # 节点标识代号 (例如: los, sg)，用于多节点证书与 SSH 配置隔离
  node_domain: "node.yourdomain.com"            # 节点主域名 (必填)
  web_terminal:
    enabled: true                               # 是否启用 Web 终端与 SSH 穿透
    port: 18080                                 # GoTTY 本地监听端口 (仅监听 127.0.0.1)
    path: "/term-8f9a2b"                        # Web 终端隐蔽访问路径
    mtls_ca: "/etc/caddy/mtls/ca.crt"           # CA 证书路径
    password: "YourExportPassword123"           # client.p12 客户端证书导出密码
    ssh_tunnel_port: 18081                      # wstunnel 本地监听端口
    ssh_tunnel_path: "/ssh-ws"                  # SSH WebSocket 穿透路径
    ssh_port: 2222                              # 本机实际 SSH 监听端口 (自动探测非标端口)
```

---

## 命令详解

### `singctl term install` — 一键安装与配置

自动安装系统依赖（`tmux`, `openssl`, `wget`）、下载并安装 `gotty` 与 `wstunnel` 二进制、生成专属 mTLS 证书体系（CA、服务端验证配置、客户端证书）、注册 systemd 守护进程并热加载 Caddy 路由。

```bash
# 一键自动安装（自动生成高强度随机路径与安全密码，自动探测实际 SSH 端口）
singctl term install

# 常用参数
singctl term install --port 18080            # 指定 GoTTY 内部端口
singctl term install --path /my-ops-path     # 指定自定义访问路径
singctl term install --password mypassword   # 指定客户端证书导入密码
singctl term install -f                      # 强制重新生成证书与覆盖安装
```

| 参数 | 说明 |
| :--- | :--- |
| `-p, --port <int>` | GoTTY 本地监听端口（默认 `18080`，仅监听 `127.0.0.1`） |
| `--path <string>` | Web 终端隐蔽访问路径（默认自动生成随机安全路径，如 `/term-8f9a2b`） |
| `--password <string>` | 客户端 `.p12` 证书导出密码（默认自动生成强密码） |
| `-f, --force` | 强制重新生成 CA/客户端证书并覆盖安装 |

---

### `singctl term cert` — 查看/导出客户端证书与连接指引

查看证书路径、导入密码，并生成适用于当前 VPS 的一键下载命令与本地配置代码片段：

```bash
singctl term cert
```

输出示例：
```bash
📁 证书路径: /etc/caddy/mtls/client.p12
🔑 导入密码: A3k9mP2x9L1q

📱【方案一：Web 终端 (.p12 证书)】
  scp -P 2222 root@cdn.example.com:/etc/caddy/mtls/client.p12 ./los-client.p12

⚡【方案二：WezTerm 原生 SSH (client.crt + client.key)】
  mkdir -p ~/.ssh
  scp -P 2222 root@cdn.example.com:/etc/caddy/mtls/client.crt ~/.ssh/los-client.crt
  scp -P 2222 root@cdn.example.com:/etc/caddy/mtls/client.key ~/.ssh/los-client.key

  追加到本地 ~/.ssh/config:
  cat << 'EOF' >> ~/.ssh/config

Host vps-los
    HostName cdn.example.com
    Port 2222
    User root
    ProxyCommand wstunnel client --log-lvl off --tls-certificate ~/.ssh/los-client.crt --tls-private-key ~/.ssh/los-client.key --http-upgrade-path-prefix ssh-ws -L stdio://127.0.0.1:2222 wss://cdn.example.com
EOF

  在 WezTerm 中直接敲原生命令直连:
  ssh vps-los
```

---

### `singctl term status` — 查看运行状态

查看 Web 终端、Tmux 会话、wstunnel 守护进程运行状态与证书就绪情况：

```bash
singctl term status
```

---

### `singctl term uninstall` — 一键卸载与路由复原

安全停止并禁用 `gotty.service` 与 `wstunnel.service`，清理对应的 systemd 单元文件，恢复 Caddyfile 路由并重启 Caddy：

```bash
singctl term uninstall
```

---

## 客户端连接实战教程

### 方案一：Web 终端访问（适合手机 / 临时电脑）

1. 从 VPS 下载客户端证书到本地：
   ```bash
   scp -P 2222 root@你的域名:/etc/caddy/mtls/client.p12 ./client.p12
   ```
2. **导入证书**：
   - **macOS**：双击 `client.p12`，输入安装时生成的密码，将其导入系统的「钥匙串访问 (Keychain)」中（存储在“登录”钥匙串）；
   - **iOS / iPadOS**：通过 AirDrop 发送给手机，在「设置」->「已下载描述文件」中安装并信任证书；
   - **Windows**：双击 `client.p12`，选择“当前用户”，输入密码并完成导入。
3. **访问 Web Shell**：使用 Safari / Chrome / Edge 访问 `https://你的域名/term-xxxx/`，浏览器会弹出证书选择框，确认后即可秒进终端。

---

### 方案二：本地 WezTerm / Terminal 原生 SSH 穿透（推荐，体验最佳）

通过 `wstunnel` 将 SSH 流量封装为携带 mTLS 客户端证书的标准 443 端口 WSS 请求，不仅可穿透严格限制 22 端口的企业/校园防火墙，还完整保留了原生 SSH 的窗口动态调整、快捷键、以及 `scp` 文件传输能力。

#### 1. 本地安装 wstunnel

- **macOS**：
  ```bash
  brew install wstunnel
  ```
- **Linux**：
  ```bash
  # 从 GitHub 官方仓库下载对应架构的二进制放入 /usr/local/bin
  # https://github.com/erebe/wstunnel/releases
  ```
- **Windows**：
  ```powershell
  winget install erebe.wstunnel
  # 或 scoop install wstunnel
  ```

#### 2. 下载证书公私钥到 `~/.ssh/`

```bash
mkdir -p ~/.ssh
# 自动带上节点标签（如 los），避免多服务器互相覆盖
scp -P 2222 root@你的域名:/etc/caddy/mtls/client.crt ~/.ssh/los-client.crt
scp -P 2222 root@你的域名:/etc/caddy/mtls/client.key ~/.ssh/los-client.key
```

#### 3. 配置本地 `~/.ssh/config`

```ssh-config
Host vps-los
    HostName 你的域名
    Port 2222
    User root
    ProxyCommand wstunnel client --log-lvl off --tls-certificate ~/.ssh/los-client.crt --tls-private-key ~/.ssh/los-client.key --http-upgrade-path-prefix ssh-ws -L stdio://127.0.0.1:2222 wss://你的域名
```

> **注意**：
> - `HostName` 配置为真实域名，隔离每台 VPS 在 `~/.ssh/known_hosts` 中的公钥指纹，彻底防止多节点切换时出现“Host identification changed”报警。
> - `-L stdio://127.0.0.1:2222` 为 wstunnel 解包后在 VPS 本机投递的目标地址与端口。

#### 4. 直连进入

```bash
ssh vps-los
```
