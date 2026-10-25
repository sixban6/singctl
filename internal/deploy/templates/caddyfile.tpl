{
    # 禁用 Caddy 全局自动针对 80 端口的 HTTP 重定向，确保 80 端口完全不被占用
    auto_https disable_redirects

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

            # HTTP 域名流量 (Sub-Store 域名及节点域名) -> Caddy HTTP 层
            @http_domains {
                tls {
                    sni {{.SubstoreDomain}}{{if and .NodeDomain (ne .NodeDomain .SubstoreDomain)}} {{.NodeDomain}}{{end}}
                }
            }
            route @http_domains {
                proxy 127.0.0.1:9443
            }

            # 兜底路由：Direct-IP 直连、未定义 SNI 探测 -> 本地 9445 伪装站
            route {
                proxy 127.0.0.1:9445
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

            # Hysteria 2 (QUIC SNI: {{.NodeDomain}}) -> Sing-box (默认/回退路由)
            route {
                proxy udp/127.0.0.1:52021
            }
        }
    }
}

# --- Layer 7 (HTTP) 网站层 ---
# 监听本地 9443 端口，处理真正的 HTTPS 请求

# 业务网站层 (Sub-Store 专用路由反代 + 根路径及全站静态伪装站)
https://{{.SubstoreDomain}}:9443{{if and .NodeDomain (ne .NodeDomain .SubstoreDomain)}}, https://{{.NodeDomain}}:9443{{end}} {
    bind 127.0.0.1
    tls {
        issuer acme {
            dns cloudflare {{.CFDNSKey}}
        }
    }

    # 1. Sub-Store 专属路径反代（根据 key、subs、download、api 分流）
    @substore path /subs* /download* /api* {{if .SSKey}}/{{.SSKey}}*{{end}}
    handle @substore {
        reverse_proxy http://127.0.0.1:3001
    }

    # 2. 根路径及其他一切探测 -> 返回逼真的静态业务站点（杜绝空白页探测特征）
    handle {
        root * /var/www/mask-site
        file_server
        try_files {path} /index.html
    }
}

# 兜底回落伪装站 (监听 9445，用于 Direct-IP 直连与异常 SNI 握手响应)
:9445 {
    bind 127.0.0.1
    tls internal {
        on_demand
    }
    root * /var/www/mask-site
    file_server
    try_files {path} /index.html
}

# TUIC 域名 TLS 证书自动化申请与续期 (如与 Substore/Node 域名不同)
{{if and .TuicDomain (and (ne .TuicDomain .SubstoreDomain) (ne .TuicDomain .NodeDomain))}}
https://{{.TuicDomain}}:9444 {
    bind 127.0.0.1
    tls {
        issuer acme {
            dns cloudflare {{.CFDNSKey}}
        }
    }
    respond "OK" 200
}
{{end}}
