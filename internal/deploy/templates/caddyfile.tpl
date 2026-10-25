{
    # layer4 是顶层模块，必须将其放在全局选项块中才能被正确识别

    layer4 {
        :443 {
            # VLESS Reality 流量 -> Sing-box
            @vless_reality {
                tls {
                    sni {{.Sni}}
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

        # UDP 443: TUIC 与 Hysteria 2 基于 QUIC SNI 分流 (ALPN 均为标准 h3)
        udp/:443 {
            # TUIC 流量 (QUIC SNI: {{.TuicDomain}}) -> Sing-box
            @tuic quic {
                sni {{.TuicDomain}}
            }
            route @tuic {
                proxy udp/127.0.0.1:52023
            }

            # Hysteria 2 (QUIC SNI: {{.SBDomain}}) -> Sing-box (默认/回退路由)
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

# TUIC 域名 TLS 证书自动化申请与续期
https://{{.TuicDomain}}:9444 {
    bind 127.0.0.1
    tls {
        issuer acme {
            dns cloudflare {{.CFDNSKey}}
        }
    }
    respond "OK" 200
}
