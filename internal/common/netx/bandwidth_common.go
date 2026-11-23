// 文件职责：提供可注入桩函数的上下行带宽折算与 Hysteria2 推荐参数计算（支持标准版与 lite 精简版共享契约）。
package netx

import (
	"fmt"
	"time"
)

// SpeedTestFn 执行底层带宽测速，返回上行/下行 Mbps、延迟与节点描述（支持单测注入桩函数）。
var SpeedTestFn = defaultSpeedTest

// MeasureHy2Bandwidth 自动测定当前上下行带宽并折算为 Hysteria2 推荐参数（up=80%, down=90%，最低兜底 5/20 Mbps）。
func MeasureHy2Bandwidth() (up, down int, err error) {
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

// RunSpeedTest 执行测速并输出 singctl.yaml 配置提示。
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
