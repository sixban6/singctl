package webui

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"singctl/internal/singbox"
)

// clash 目标地址缓存(避免每个请求都读配置文件/枚举网卡)
var (
	clashCacheMu  sync.Mutex
	clashCachedAt time.Time
	clashCacheURL *url.URL
	clashCacheSec string
)

const clashCacheTTL = 10 * time.Second

// cachedClashTarget 解析并缓存 clash API 目标地址。
// 解析顺序见 singbox.ClashAPIEndpoints:生成配置中的 external_controller
// 优先,127.0.0.1 与 LAN IP 兜底。
func cachedClashTarget() (*url.URL, string) {
	clashCacheMu.Lock()
	defer clashCacheMu.Unlock()

	if clashCacheURL != nil && time.Since(clashCachedAt) < clashCacheTTL {
		return clashCacheURL, clashCacheSec
	}
	clashCacheURL, clashCacheSec = nil, ""
	for _, ep := range singbox.ClashAPIEndpoints() {
		if u, err := url.Parse(ep); err == nil && u.Host != "" {
			clashCacheURL, clashCacheSec = u, singbox.ClashAPISecret()
			break
		}
	}
	clashCachedAt = time.Now()
	return clashCacheURL, clashCacheSec
}

// setupClashProxy 注册 clash API/控制面板反向代理路由。
//
//   - /clash/*        → clash API(面板页面为 /clash/ui/)
//   - /connections 等 → clash API 根路径直通,兼容 Yacd 等面板
//     以"页面 origin"作为后端地址发起的请求(这些路径与 WebUI
//     自身路由不冲突,/api/* 前缀已隔离)
//
// 注意:代理路由不经过 WebUI 口令鉴权。原因:① clash API 在内网
// 本就以 external_controller 明文开放(这也是用户直接访问面板的方式),
// 代理未增加新的暴露面;② 面板的 WebSocket 握手无法携带 Basic Auth。
// 如需收敛暴露面,请在 sing-box 配置中设置 clash_api.secret。
func (s *Server) setupClashProxy() {
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			target, secret := cachedClashTarget()
			if target == nil {
				return
			}
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.Host = target.Host
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
		},
		// 及时下发 /logs /traffic 等流式响应
		FlushInterval: 100 * time.Millisecond,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"clash api 不可达: sing-box 可能未运行或控制端口未监听"}`))
		},
	}

	s.mux.Handle("/clash/", http.StripPrefix("/clash", proxy))

	// clash API 根路径(面板 JS 可能直接以页面 origin 调用)
	for _, base := range []string{
		"/connections", "/proxies", "/configs", "/logs", "/traffic",
		"/memory", "/version", "/rules", "/dns", "/group", "/providers",
		"/restart", "/upgrade", "/cache", "/gc", "/close",
	} {
		s.mux.Handle(base, proxy)
		s.mux.Handle(base+"/", proxy)
	}
}
