# SingCtl

[![Release](https://img.shields.io/github/v/release/sixban6/singctl)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl)](https://golang.org/)
[![License](https://img.shields.io/github/license/sixban6/singctl)](https://github.com/sixban6/singctl/blob/main/LICENSE)

SingCtl是多功能网络工具。可以用管理singbox客户端和服务端，异地组网，加固防火墙。

## Features
- 🚀 **跨平台支持**: 一条命令跨平台安全的使用singbox
- 📡 **多协议支持**: VLESS, Trojan, Hysteria2, Shadowsocks, TUIC
- 🔌 **规则集本地缓存**: 预下载远程规则集并改写为本地引用，sing-box 启动不依赖 GitHub（`sb cache update/status/clear`）
- 🔧 **防止DNS泄漏**: 配置文件已经把国内IP和国外IP的DNS请求分开处理
- 🍚 **服务端部署**: 自动部署singbox服务端


## Installation

### 🎯 一键安装 (推荐)

**Mac**
```bash
brew tap sixban6/singctl
brew install sixban6/singctl/singctl
```

**OpenWrt**
```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh 
```

**Linux** (root)
```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sh 
```

**Windows 11** (用管理员权限运行Powershell)
```cmd
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "[System.IO.File]::WriteAllText('install.ps1', (irm https://raw.githubusercontent.com/sixban6/singctl/main/install.ps1 -UseBasicParsing), [System.Text.Encoding]::UTF8); & .\install.ps1"
```

### 🔒 安全与校验

安装和更新（`singctl update self` / `sb install` / `sb update`）会对下载的安装包做完整性校验：
- 校验和与发布元数据**必须从 GitHub 直连获取**（不走镜像），安装包本身仍可走镜像加速。因此这些操作需要能直连 `github.com` / `api.github.com`（仅小请求）。
- 所有安装包（singctl/sing-box/tailscale）都与 **GitHub 官方资产 digest（sha256）**比对，失败即中止；镜像投毒、等长篡改、网络损坏都会被拒收。
- `singctl update self` 在 digest 之外还有 `checksums.txt` 双重回退（均直连获取）。
- 极少数无 digest 的资产退化为按官方元数据校验文件大小并提示风险。
- 网络无法直连 GitHub 时，可设置 `SINGCTL_SKIP_CHECKSUM=1` 跳过校验（自担风险）：

```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | SINGCTL_SKIP_CHECKSUM=1 sh
```

另外，`singctl.yaml` 及生成的 sing-box 配置包含订阅地址、auth_key 等敏感信息，默认权限为 `600`。

## 📚 使用指南 (Usage)

SingCtl 按功能模块分为以下几个部分，点击链接查看详细说明：

| 模块 | 命令前缀 | 描述 | 文档 |
| :--- | :--- | :--- | :--- |
| **客户端管理** | `singctl sb` | 管理 sing-box 客户端的安装、配置生成、启停 | [查看文档](docs/client.md) |
| **服务端部署** | `singctl sr` | 一键部署服务端组件（Sing-box、Caddy、SubStore、WARP） | [查看文档](docs/server.md) |
| **异地组网** | `singctl ts` | 管理 Tailscale 的安装、启动与路由配置 | [查看文档](docs/tailscale.md) |
| **守护进程** | `singctl dm` | 管理后台守护进程，查看日志与监控状态 | [查看文档](docs/daemon.md) |
| **防火墙加固** | `singctl fw` | Linux/OpenWrt 专用的防火墙安全规则配置 | [查看文档](docs/firewall.md) |
| **实用工具** | `singctl ut` | 宽带测速、自更新、系统信息查看 | [查看文档](docs/utils.md) |

## ⚙️ 配置文件

核心配置位于 `singctl.yaml`，各模块的配置项说明请参阅对应子文档。

配置文件路径:
- MacOS: `/opt/homebrew/etc/singctl/singctl.yaml`
- Other: `/etc/singctl/singctl.yaml`

## License

[MIT License](LICENSE)