//go:build lite

// 文件职责：在路由器客户端轻量构建（lite）下提供空静态资源文件系统，剔除服务端 WebUI 静态包体积。
package serverweb

import "embed"

var staticFS embed.FS
