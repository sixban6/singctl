{{- define "server_options" -}}
        protocols h1 h2
        listener_wrappers {
            proxy_protocol {
                allow 127.0.0.0/8 ::1/128
                timeout 2s
                fallback_policy ignore
            }
            tls
        }
        trusted_proxies static 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/32 2c0f:f248::/32
        client_ip_headers CF-Connecting-IP X-Forwarded-For
{{- end -}}

{{- define "common_site_routes" -}}
    bind 127.0.0.1
    header {
        -Server
        -Alt-Svc
        Strict-Transport-Security "max-age=31536000"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "camera=(), microphone=(), geolocation=()"
    }
    tls {
        issuer acme {
            dns cloudflare {{.CFDNSKey}}
        }
        issuer acme {
            dir https://acme.zerossl.com/v2/DV90
            {{- if .ACMEEmail}}
            email {{.ACMEEmail}}
            {{- end}}
            dns cloudflare {{.CFDNSKey}}
        }
{{if .MtlsCA}}
        client_auth {
            mode verify_if_given
            trust_pool file {{.MtlsCA}}
        }
{{end}}
    }
{{if .TerminalPath}}

    # GoTTY Web 终端安全路由 (双向 TLS 认证保护)
    redir {{.TerminalPath}} {{.TerminalPath}}/
    handle {{.TerminalPath}}/* {
        @unauth expression {http.request.tls.client.subject} == ''
        respond @unauth 404
        reverse_proxy 127.0.0.1:{{.TerminalPort}}
    }
{{end}}
{{if .SSHTunnelPath}}

    # Native SSH-over-WSS 终端安全路由 (wstunnel + 双向 TLS 认证保护)
    handle {{.SSHTunnelPath}}* {
        @unauth expression {http.request.tls.client.subject} == ''
        respond @unauth 404
        reverse_proxy 127.0.0.1:{{.SSHTunnelPort}}
    }
{{end}}
{{if .AdminPath}}
    # SingCtl Server WebUI 专属随机安全路径反代 (转发至 127.0.0.1:{{.AdminPort}})
    redir {{.AdminPath}} {{.AdminPath}}/ 308
    handle_path {{.AdminPath}}/* {
        header {
            Clear-Site-Data "cache"
            Cache-Control "no-store, no-cache, must-revalidate"
        }
        reverse_proxy http://127.0.0.1:{{.AdminPort}} {
            header_up X-Real-IP {client_ip}
            header_up X-Geo-Country {header.CF-IPCountry}
            {{- if .AdminGatewayToken}}
            header_up X-Singctl-Gateway {{.AdminGatewayToken}}
            {{- end}}
            header_up -CF-Connecting-IP
            header_up -X-Forwarded-For
        }
    }
{{end}}

    # 彻底注销并屏蔽 Sub-Store 的 PWA Service Worker，避免跨路径劫持 /sr/ 页面或静态资源
    handle /registerSW.js {
        header Content-Type application/javascript
        header Cache-Control "no-cache, no-store, must-revalidate"
        respond `if ('serviceWorker' in navigator) {
  navigator.serviceWorker.getRegistrations().then(function(regs) {
    for (let reg of regs) { reg.unregister(); }
  });
}
if ('caches' in window) {
  caches.keys().then(function(keys) {
    for (let key of keys) caches.delete(key);
  });
}` 200
    }

    handle /sw.js {
        header Content-Type application/javascript
        header Cache-Control "no-cache, no-store, must-revalidate"
        respond `self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil(
    self.registration.unregister().then(() => {
      return self.clients.matchAll();
    }).then(clients => {
      clients.forEach(c => c.navigate(c.url));
    })
  );
});` 200
    }
{{- end -}}
{
    # 禁用 Caddy 全局自动针对 80 端口的 HTTP 重定向，确保 80 端口完全不被占用
    auto_https disable_redirects
{{if .ServerIP}}
    default_sni {{.ServerIP}}
    fallback_sni {{.ServerIP}}
{{end}}

    # 启用 PROXY Protocol v2 解析与 Cloudflare 真实 IP 信任，确保获取访客真实客户端 IP
    servers 127.0.0.1:9443 {
{{template "server_options" .}}
    }

    servers :9443 {
{{template "server_options" .}}
    }

    servers 127.0.0.1:9445 {
        protocols h1 h2
    }

    servers :9445 {
        protocols h1 h2
    }

    # layer4 是顶层模块，必须将其放在全局选项块中才能被正确识别
    layer4 {
        :443{{if ne .VlessPort 443}} :{{.VlessPort}}{{end}} {
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
                proxy {
                    upstream 127.0.0.1:9443
                    proxy_protocol v2
                }
            }

            # 兜底路由：Direct-IP 直连、未定义 SNI 探测 -> 本地 9445 伪装站
            route {
                proxy 127.0.0.1:9445
            }
        }

        # UDP 443{{if ne .Hy2Port 443}} & {{.Hy2Port}}{{end}}: Hysteria 2 流量 -> Sing-box (标准 h3)
        udp/:443{{if ne .Hy2Port 443}} udp/:{{.Hy2Port}}{{end}} {
            route {
                proxy udp/127.0.0.1:52021
            }
        }
    }
}

# --- HTTP 80 端口 (用于 Let's Encrypt 公网 IP 证书的 HTTP-01 验证及 301 重定向至 443) ---
:80 {
    header -Server
    @validMethods method GET POST HEAD OPTIONS
    handle @validMethods {
        redir https://{host}{uri} 301
    }
    handle {
        respond "Method Not Allowed" 405
    }
}

# --- Layer 7 (HTTP) 网站层 ---
# 监听本地 9443 端口，处理真正的 HTTPS 请求

{{if and .NodeDomain (ne .NodeDomain .SubstoreDomain)}}
# 1. 订阅与控制面板域名层 (仅密钥订阅路径转发至原生 SubHub，其余路径回落静态伪装站，零代理指纹)
https://{{.SubstoreDomain}}:9443 {
{{template "common_site_routes" .}}

    @subhub path {{if .SSKey}}/{{.SSKey}}/*{{else}}/download/* /api/file/*{{end}}
    handle @subhub {
        request_header -If-Modified-Since
        request_header -If-None-Match
        reverse_proxy http://127.0.0.1:3001 {
            header_up X-Real-IP {client_ip}
            header_up X-Geo-Country {header.CF-IPCountry}
            header_down Cache-Control "private, no-cache, no-store, max-age=0, must-revalidate"
            header_down CDN-Cache-Control "no-store"
            header_down Cloudflare-CDN-Cache-Control "no-store"
        }
    }

    # 根路径及未授权探测统一回落静态伪装博客
    handle {
        root * /var/www/mask-site
        file_server
        try_files {path} /index.html
    }
}

# 2. 节点专属域名层 (独立域名，纯静态伪装站，彻底隐藏节点服务背后的真实意图)
https://{{.NodeDomain}}:9443 {
{{template "common_site_routes" .}}

    # 默认静态伪装站 (必须包裹在 handle 块内，确保 handle 互斥，防止 try_files 劫持其他路径)
    handle {
        root * /var/www/mask-site
        file_server
        try_files {path} /index.html
    }
}
{{else}}
# 单域名兼容模式：根路径静态伪装站 + 专属密钥路径反代原生 SubHub
https://{{.SubstoreDomain}}:9443 {
{{template "common_site_routes" .}}

    @subhub path {{if .SSKey}}/{{.SSKey}}/*{{else}}/subs* /download/* /api/file/*{{end}}
    handle @subhub {
        request_header -If-Modified-Since
        request_header -If-None-Match
        reverse_proxy http://127.0.0.1:3001 {
            header_up X-Real-IP {client_ip}
            header_up X-Geo-Country {header.CF-IPCountry}
            header_down Cache-Control "private, no-cache, no-store, max-age=0, must-revalidate"
            header_down CDN-Cache-Control "no-store"
            header_down Cloudflare-CDN-Cache-Control "no-store"
        }
    }

    # 根路径及常规探测 -> 静态伪装站
    handle {
        root * /var/www/mask-site
        file_server
        try_files {path} /index.html
    }
}
{{end}}

{{if .ServerIP}}
# 公网 IP 专属站点：采用 Let's Encrypt shortlived profile 签发原生公网 IP 证书
https://{{.ServerIPFormatted}}:9445 {
    bind 127.0.0.1
    header {
        -Server
        -Alt-Svc
    }
    tls {
        issuer acme {
            profile shortlived
        }
    }
    root * /var/www/mask-site
    file_server
    try_files {path} /index.html
}
{{else}}
# 兜底回落伪装站 (监听 9445，用于 Direct-IP 直连与异常 SNI 握手响应)
:9445 {
    bind 127.0.0.1
    header {
        -Server
        -Alt-Svc
    }
    tls internal {
        on_demand
    }
    root * /var/www/mask-site
    file_server
    try_files {path} /index.html
}
{{end}}
