package deploy

import "singctl/internal/component"

var defaultServerRegistry = func() *component.Registry {
	reg := component.NewRegistry()
	reg.MustRegister(&singboxServerComponent{})
	reg.MustRegister(&caddyServerComponent{})
	reg.MustRegister(&subhubServerComponent{})
	reg.MustRegister(&warpServerComponent{})
	return reg
}()

// ServerRegistry 返回预注册了全部服务端核心托管组件（singbox / caddy / subhub / warp）的全局注册表。
func ServerRegistry() *component.Registry {
	return defaultServerRegistry
}
