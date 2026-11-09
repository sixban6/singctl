package configs

import _ "embed"

// DefaultConfigYAML embeds the full singctl.yaml template.
//
//go:embed singctl.yaml
var DefaultConfigYAML []byte

// ClientConfigYAML is the concise client-only singctl.yaml template (without server section).
var ClientConfigYAML = []byte(`subs:
  - name: "main"                              # 订阅名称 (多订阅时必填)
    url: ""                                   # 你VPN订阅地址
    skip_tls_verify: false                    # 是否跳过TLS验证
    remove-emoji: true
    # include: ""                             # (可选) 仅保留匹配正则的节点 (如 "HK|SG|JP")
    # exclude: ""                             # (可选) 剔除匹配正则的节点 (如 "剩余|到期|官网|流量")
    # rename:                                 # (可选) 按正则顺序批量重命名节点
    #   - {match: " Premium$", replace: ""}
  # 多订阅示例 (可选):
  # - name: "backup"
  #   url: "https://example.com/subscription"
  #   skip_tls_verify: false
  #   remove-emoji: true

github:
  mirror_url: "https://gh-proxy.com"            # GitHub镜像地址,用于加速

hy2:
  up: 20                                         # Hysteria2 上行带宽 (Mbps)
  down: 200                                      # Hysteria2 下行带宽 (Mbps)

dns:                                             # (可选) 客户端本地防劫持 DNS (AdGuard Home) 配置
  enabled: true                                  # 是否启用本地 AdGuard Home 接管 dns_local
  dns_port: 5353                                 # 本地 DNS 监听端口 (仅绑定 127.0.0.1)
  web_port: 3000                                 # Web 管理面板端口 (仅绑定本机局域网 IP)
  username: "root"                               # 管理面板账号 (安装时可自定义，回车默认 root)
  password: ""                                   # 管理面板密码 (留空首次安装自动生成随机强密码)

tailscale:                                      # (可选) Tailscale 部署配置
  auth_key: ""                                  # (可选) Tailscale 授权密钥。默认是: ""
  subnets: ""                                   # (可选) 配置通告的子网，默认为空，程序会自动获取
  use_build: false                              # (可选) 是否使用singbox内置的TailScale。默认：false, 不启用

watchdog:                                      # (可选) 看门狗守护进程配置 (singctl dm)
  interval: 180                                 # 检查间隔(秒), 默认 180
  confirm_wait: 30                              # 检测失败后二次确认等待(秒), 默认 30
  max_restarts: 3                               # 每小时最大自动重启次数, 默认 3
  sub_sync_interval: 600                        # 订阅节点变化自动无感同步间隔(秒), 默认 600 (10分钟; 设为 -1 关闭)

# custom_rules:                                 # (可选) 自定义策略组、路由与 DNS 规则注入扩展
#   outbounds:                                  # 按 tag 定制或过滤策略组候选节点池与测速参数
#     - tag: "#Auto"
#       include: "香港|HK|Hong Kong|台灣|台湾|TW|Taiwan|獅城|新加坡|SG|Singapore|日本|JP|Japan"
#       exclude: "美國|美国|US|德國|德国|英國|英国|澳門|澳门"
#       interval: "3m"
#       tolerance: 80
#       interrupt_exist_connections: false
#   route:
#     - action: route
#       domain_suffix: [example.com, internal.example.org]
#       outbound: "#DC"
#   dns:
#     - domain_suffix: [example.com, internal.example.org]
#       server: dns_local
`)

// ServerConfigYAML is the concise server-only singctl.yaml template (only server section).
var ServerConfigYAML = []byte(`server: # 服务器部署配置
  node_tag: "" # (可选) 节点地区/代号 (例如: los, sg, hk)，留空自动根据公网 IP 智能识别
  node_domain: "node.example.com" # 你的域名（用于 SubHub 订阅与 Hysteria 2）
  # hy2_port: 443 # (可选) Hysteria 2 (UDP) 对外监听与订阅端口，默认 443；NAT 小鸡可指定独立 UDP 端口 (如 11501)
  # vless_port: 443 # (可选) VLESS Reality (TCP) 与 HTTPS 网关对外监听与订阅端口，默认 443；NAT 小鸡可指定独立 TCP 端口 (如 11502)
  substore_domain: "" # (可选) 订阅聚合专属域名，留空默认使用 node_domain
  server_ip: "" # (可选) 公网 IP 地址（未填自动探测用于申请 Let's Encrypt 原生 IP 证书）
  cf_dns_key: "your_cloudflare_api_token" # 你的 Cloudflare API Token
  sni: "" # (可选) Reality SNI 伪装域名。默认: swdist.apple.com
  # web_admin: # (可选) 服务端专属管理后台 (通过 Caddy HTTPS 自动反代，免开公网端口)
  #   enabled: true
  #   port: 8092
  #   path: "" # (留空首次部署自动生成随机安全路径如 /sr/k9X2Mn8Pq4Rw7T1Z)
  #   username: "singctl"
  #   password: "" # (留空首次部署自动生成高强度随机密码)
`)
