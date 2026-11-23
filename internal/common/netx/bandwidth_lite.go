//go:build lite

// 文件职责：提供 -tags lite 精简版带宽测速占位实现，剥离 speedtest-go 重型依赖并保留导出契约兼容。
package netx

import (
	"errors"
	"time"
)

func defaultSpeedTest() (upMbps, downMbps float64, latency time.Duration, serverDesc string, err error) {
	return 0, 0, 0, "", errors.New("当前为 SingCtl -lite 路由器客户端精简版，不含内置 Speedtest 测速引擎；请使用标准完整版执行该操作")
}
