package netinfo

import (
	"fmt"
	"time"

	"singctl/internal/logger"

	"github.com/showwin/speedtest-go/speedtest"
)

// RunSpeedTest 执行测速并打印结果
func RunSpeedTest() error {
	logger.Info("初始化测速客户端...")
	client := speedtest.New()

	logger.Info("正在获取服务器列表...")
	serverList, err := client.FetchServers()
	if err != nil {
		return fmt.Errorf("获取服务器列表失败: %w", err)
	}

	targets, err := serverList.FindServer([]int{})
	if err != nil || len(targets) == 0 {
		return fmt.Errorf("无法找到合适的测速服务器: %v", err)
	}

	server := targets[0]
	// 粗体亮色显示服务器信息
	fmt.Printf("\n\033[1;36m🎯 已选择测速服务器:\n")
	fmt.Printf("   ├─ 名称: %s (%s, %s)\n", server.Name, server.Country, server.Sponsor)
	fmt.Printf("   ├─ 主机: %s\n", server.Host)
	fmt.Printf("   └─ 距离: %.2f km\033[0m\n\n", server.Distance)

	// 测试延迟
	logger.Info("正在测试网络延迟...")
	err = server.PingTest(nil)
	if err != nil {
		return fmt.Errorf("延迟测试失败: %w", err)
	}
	fmt.Printf("   \033[1;33m⏳ 延迟: %v\033[0m\n", server.Latency)

	// 测试下载
	logger.Info("正在测试下行带宽...")
	err = server.DownloadTest()
	if err != nil {
		return fmt.Errorf("下行测速失败: %w", err)
	}
	downMbps := server.DLSpeed * 8 / 1024 / 1024 // 转换为 Mbps (speedtest-go 返回 byte/s)

	// 测试上传
	logger.Info("正在测试上行带宽...")
	err = server.UploadTest()
	if err != nil {
		return fmt.Errorf("上行测速失败: %w", err)
	}
	upMbps := server.ULSpeed * 8 / 1024 / 1024 // 转换为 Mbps (speedtest-go 返回 byte/s)

	// 重点显示测试结果
	fmt.Println("\n===========================================================")
	fmt.Println("                 🚀 测速结果 (Speedtest.net)                 ")
	fmt.Println("===========================================================")
	fmt.Printf("  ⬇️  下行带宽 (Download) :  \033[1;32m%8.2f Mbps\033[0m\n", downMbps)
	fmt.Printf("  ⬆️  上行带宽 (Upload)   :  \033[1;32m%8.2f Mbps\033[0m\n", upMbps)
	fmt.Printf("  ⏳  网络延迟 (Ping)     :  \033[1;33m%8s\033[0m\n", server.Latency.Round(time.Millisecond))
	fmt.Println("===========================================================")

	fmt.Println("\n💡 提示: 您可以根据上述测试结果, 修改配置中的带宽参数:")
	fmt.Println("\033[0;36m      # singctl.yaml")
	fmt.Println("      hy2:")
	fmt.Printf("        up: %d\n", int(upMbps*0.8))
	fmt.Printf("        down: %d\033[0m\n\n", int(downMbps*0.9))

	return nil
}
