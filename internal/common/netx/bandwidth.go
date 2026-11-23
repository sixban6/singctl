//go:build !lite

// 文件职责：提供标准版的 Speedtest.net 带宽测速底层实现（lite 构建期剥离重型 speedtest-go 依赖）。
package netx

import (
	"fmt"
	"time"

	"github.com/showwin/speedtest-go/speedtest"
)

func defaultSpeedTest() (upMbps, downMbps float64, latency time.Duration, serverDesc string, err error) {
	client := speedtest.New()
	serverList, err := client.FetchServers()
	if err != nil {
		return 0, 0, 0, "", fmt.Errorf("获取服务器列表失败: %w", err)
	}
	targets, err := serverList.FindServer([]int{})
	if err != nil || len(targets) == 0 {
		return 0, 0, 0, "", fmt.Errorf("无法找到合适的测速服务器: %v", err)
	}

	server := targets[0]
	serverDesc = fmt.Sprintf("%s (%s, %s) [%s, %.2f km]", server.Name, server.Country, server.Sponsor, server.Host, server.Distance)
	fmt.Printf("\n\033[1;36m🎯 已选择测速服务器:\n")
	fmt.Printf("   ├─ 名称: %s (%s, %s)\n", server.Name, server.Country, server.Sponsor)
	fmt.Printf("   ├─ 主机: %s\n", server.Host)
	fmt.Printf("   └─ 距离: %.2f km\033[0m\n\n", server.Distance)

	if err := server.PingTest(nil); err != nil {
		return 0, 0, 0, serverDesc, fmt.Errorf("延迟测试失败: %w", err)
	}
	fmt.Printf("   \033[1;33m⏳ 延迟: %v\033[0m\n", server.Latency)

	if err := server.DownloadTest(); err != nil {
		return 0, 0, 0, serverDesc, fmt.Errorf("下行测速失败: %w", err)
	}
	downMbps = float64(server.DLSpeed) * 8 / 1024 / 1024

	if err := server.UploadTest(); err != nil {
		return 0, 0, 0, serverDesc, fmt.Errorf("上行测速失败: %w", err)
	}
	upMbps = float64(server.ULSpeed) * 8 / 1024 / 1024

	return upMbps, downMbps, server.Latency, serverDesc, nil
}
