# SingCtl

[![Release](https://img.shields.io/github/v/release/sixban6/singctl)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl)](https://golang.org/)
[![License](https://img.shields.io/github/license/sixban6/singctl)](https://github.com/sixban6/singctl/blob/main/LICENSE)

SingCtl是多功能网络工具。可以用管理singbox客户端和服务端，异地组网，加固防火墙。

## Features
- 🚀 **跨平台支持**: 一条命令跨平台安全的使用singbox
- 📡 **多协议支持**: VLESS, Trojan, Hysteria2, Shadowsocks, TUIC
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