# SingCtl

[![Release](https://img.shields.io/github/v/release/sixban6/singctl)](https://github.com/sixban6/singctl/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sixban6/singctl)](https://golang.org/)
[![License](https://img.shields.io/github/license/sixban6/singctl)](https://github.com/sixban6/singctl/blob/main/LICENSE)

SingCtl是一个简单高效的命令行VPN客户端, 能让你根据订阅地址，快速使用singbox，和管理singbox。

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
- 基本使用
```bash
# 安装 sing-box               
singctl install sb   

# 生成配置到默认位置并备份         
singctl gen     

# 生成配置并启动 sing-box
singctl start           

# 停止 sing-box & 关闭守护进程     
singctl stop       

# 更新 sing-box
singctl update sb        

# 更新 singctl 自身         
singctl update self      

```
- 守护进程使用
```bash
# 快速查看系统状态
singctl info

# 启动守护进程
singctl daemon start

# 查看详细监控状态
singctl daemon status

# 查看守护进程日志
singctl daemon logs -n 50
```
- tailscale使用
```bash
# 安装 Tailscale (仅 OpenWrt/Linux)
singctl install tailscale

# 配置并启动 Tailscale (仅 OpenWrt/Linux)
singctl start tailscale

# 启动Tailscale 并作为出口节点
singctl start tailscale --exit-node

singctl stop tailscale

singctl update tailscale
```
- 其他
```bash
# 输出到控制台查看        
singctl gen --stdout       

# 自定义输出路径             
singctl gen -o /tmp/config.json  

# 测试宽带带宽
singctl test bd
```
- 防火墙加固 (Linux/OpenWrt专有)
```bash
# 启用安全拦截规则并设置开机自启 (需 root)
singctl firewall enable

# 禁用安全拦截规则并移除自启配置 (需 root)
singctl firewall disable
```
- 服务端部署
Tips:需要singctl.yaml中配置
```yaml
server:                                         # (可选) 服务器部署配置
  sb_domain: "sub.yourdomain.com"               # 你的域名
  cf_dns_key: "your_cloudflare_api_token"       # 你的 Cloudflare API Token
```

执行部署
```bash
singctl server install
```

## License

[MIT License](LICENSE)