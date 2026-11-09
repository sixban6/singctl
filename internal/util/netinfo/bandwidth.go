package netinfo

import (
	"fmt"
	"time"

	"singctl/internal/logger"

	"github.com/showwin/speedtest-go/speedtest"
)

// SpeedTestFn 执行底层带宽测速，返回原始上行/下行速率 (Mbps)、延迟与测速节点描述（支持单元测试注入桩函数）。
var SpeedTestFn = defaultSpeedTest

func defaultSpeedTest() (upMbps, downMbps float64, latency time.Duration, serverDesc string, err error) {
	logger.Info("初始化测速客户端...")
	client := speedtest.New()

	logger.Info("正在获取服务器列表...")
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

	// 测试延迟
	logger.Info("正在测试网络延迟...")
	if err := server.PingTest(nil); err != nil {
		return 0, 0, 0, serverDesc, fmt.Errorf("延迟测试失败: %w", err)
	}
	fmt.Printf("   \033[1;33m⏳ 延迟: %v\033[0m\n", server.Latency)

	// 测试下载
	logger.Info("正在测试下行带宽...")
	if err := server.DownloadTest(); err != nil {
		return 0, 0, 0, serverDesc, fmt.Errorf("下行测速失败: %w", err)
	}
	downMbps = float64(server.DLSpeed) * 8 / 1024 / 1024 // 转换为 Mbps (speedtest-go 返回 byte/s)

	// 测试上传
	logger.Info("正在测试上行带宽...")
	if err := server.UploadTest(); err != nil {
		return 0, 0, 0, serverDesc, fmt.Errorf("上行测速失败: %w", err)
	}
	upMbps = float64(server.ULSpeed) * 8 / 1024 / 1024 // 转换为 Mbps (speedtest-go 返回 byte/s)

	return upMbps, downMbps, server.Latency, serverDesc, nil
}

// MeasureHy2Bandwidth 自动测定当前网络上下行带宽，并折算为 Hysteria2 推荐参数 (up=80%, down=90%)。
func MeasureHy2Bandwidth() (up int, down int, err error) {
	upMbps, downMbps, latency, _, err := SpeedTestFn()
	if err != nil {
		return 0, 0, err
	}

	up = max(int(upMbps*0.8), 5)
	down = max(int(downMbps*0.9), 20)

	fmt.Println("\n===========================================================")
	fmt.Println("                 🚀 测速结果 (Speedtest.net)                 ")
	fmt.Println("===========================================================")
	fmt.Printf("  ⬇️  下行带宽 (Download) :  \033[1;32m%8.2f Mbps\033[0m (建议 hy2.down: %d Mbps)\n", downMbps, down)
	fmt.Printf("  ⬆️  上行带宽 (Upload)   :  \033[1;32m%8.2f Mbps\033[0m (建议 hy2.up  : %d Mbps)\n", upMbps, up)
	fmt.Printf("  ⏳  网络延迟 (Ping)     :  \033[1;33m%8s\033[0m\n", latency.Round(time.Millisecond))
	fmt.Println("===========================================================")

	return up, down, nil
}

// RunSpeedTest 执行测速并打印结果
func RunSpeedTest() error {
	up, down, err := MeasureHy2Bandwidth()
	if err != nil {
		return err
	}

	fmt.Println("\n💡 提示: 您可以根据上述测试结果, 修改配置中的带宽参数:")
	fmt.Println("\033[0;36m      # singctl.yaml")
	fmt.Println("      hy2:")
	fmt.Printf("        up: %d\n", up)
	fmt.Printf("        down: %d\033[0m\n\n", down)

	return nil
}
