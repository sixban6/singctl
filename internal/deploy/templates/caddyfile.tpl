{
    # layer4 是顶层模块，必须将其放在全局选项块中才能被正确识别

    layer4 {
        :443 {
            # VLESS Reality 流量 -> Sing-box
            @vless_reality {
                tls {
                    sni swdist.apple.com
                }
            }
            route @vless_reality {
                proxy 127.0.0.1:8443
            }

            # Sub-Store 域名流量 -> Caddy HTTP 层
            @substore {
                tls {
                    sni {{.SBDomain}}
                }
            }
            route @substore {
                proxy 127.0.0.1:9443
            }


        }

        # Hysteria2 (UDP) on port 443
        udp/:443 {
            route {
                proxy udp/127.0.0.1:52021
            }
        }
    }
}

# --- Layer 7 (HTTP) 网站层 ---
# 监听本地 9443 端口，处理真正的 HTTPS 请求

# Sub-Store 反向代理
https://{{.SBDomain}}:9443 {
    bind 127.0.0.1
    tls {
        issuer acme {
            dns cloudflare {{.CFDNSKey}}
        }
    }
    reverse_proxy http://127.0.0.1:3001
}
