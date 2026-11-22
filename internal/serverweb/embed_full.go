//go:build !lite

// 文件职责：在标准完整构建（!lite）下内嵌服务端 Web 管理面板前端静态资源。
package serverweb

import "embed"

//go:embed all:static
var staticFS embed.FS
