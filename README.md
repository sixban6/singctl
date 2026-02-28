# SingCtl

[![Release](https://img.shields.io/github/v/release/sixban6/singctl)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl)](https://golang.org/)
[![License](https://img.shields.io/github/license/sixban6/singctl)](https://github.com/sixban6/singctl/blob/main/LICENSE)

SingCtl是多功能网络工具。可以用管理singbox客户端和服务端，异地组网，加固防火墙。

## Features
- 🚀 **跨平台支持**: 一条命令跨平台安全的使用singbox
- 📡 **多协议支持**: VMess, VLESS, Trojan, Hysteria2, Shadowsocks, TUIC
- 🔧 **防止DNS泄漏**: 配置文件已经把国内IP和国外IP的DNS请求分开处理


## Installation

### 🎯 一键安装 (推荐)

**Mac**
```bash
curl -fsSL https://gh-proxy.com/https://raw.githubusercontent.com/sixban6/singctl/main/install.sh | sudo sh 
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

## Usage
- 1.客户端
```bash
# 安装sing-box客户端              
singctl sb install   

# 生成客户端配置到默认位置并备份         
singctl sb gen     

# 启动sing-box客户端
singctl sb start           

# 停止 sing-box 客户端 & 关闭守护进程     
singctl sb stop       

# 更新sing-box客户单
singctl sb update           

# 输出到控制台查看        
singctl sb gen --stdout       

# 自定义输出路径             
singctl sb gen -o /tmp/config.json  
```
- 2.服务端管理
```bash
singctl sr install

# 单独部署caddy
singctl sr install caddy

# 单独部署singbox
singctl sr install singbox

# 单独部署substore
singctl sr install substore

# 单独部署warp
singctl sr install warp
```
Tips:服务端需要singctl.yaml中配置
```yaml
server:                                         # (可选) 服务器部署配置
  sb_domain: "sub.yourdomain.com"               # 你的域名
  cf_dns_key: "your_cloudflare_api_token"       # 你的 Cloudflare API Token
```

- 3.tailscale管理
```bash
# 安装 Tailscale (仅 OpenWrt/Linux)
singctl ts install 

# 配置并启动 Tailscale (仅 OpenWrt/Linux)
singctl ts start 

# 启动Tailscale 并作为出口节点
singctl ts start  --exit-node

singctl ts stop 

singctl ts update 
```
Tips: 可以在singctl.yaml中配置
```yaml
tailscale:                                        # (可选) Tailscale 部署配置
    auth_key: ""                                  # (可选) Tailscale 授权密钥
```
- 4.守护进程使用
```bash

# 启动守护进程
singctl dm start

# 查看详细监控状态
singctl dm status

# 查看守护进程日志
singctl dm logs -n 50
```
- 5.防火墙加固 (Linux/OpenWrt专有)
```bash
# 启用安全拦截规则并设置开机自启 (需 root)
singctl fw enable

# 禁用安全拦截规则并移除自启配置 (需 root)
singctl fw disable
```

- 6.其他
```bash
# 测试宽带带宽
singctl ut testbd

# 更新 singctl 自身         
singctl update self  

# 快速查看系统状态
singctl info
```



## License

[MIT License](LICENSE)