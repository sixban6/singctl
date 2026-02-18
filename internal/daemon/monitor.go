package daemon

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"singctl/internal/config"
)

// Monitor 监控器
type Monitor struct {
	config *config.Config
}

// NewMonitor 创建监控器
func NewMonitor(cfg *config.Config) *Monitor {
	return &Monitor{
		config: cfg,
	}
}

// InternetCheckResult 互联网访问检测结果
type InternetCheckResult struct {
	Accessible    bool              // 是否能上网
	TargetResults map[string]string // 每个目标的检测结果 (url -> "ok" 或 错误信息)
	CheckTime     time.Time         // 检测时间
}

// CheckInternetAccess 检测实际互联网可访问性 (HTTP GET)
// 通过实际的 HTTP 请求验证是否能上网
// 任意一个目标可达即视为可上网
func (m *Monitor) CheckInternetAccess() InternetCheckResult {
	targets := []string{
		"http://www.baidu.com",
		"http://www.google.com/generate_204",
		"http://cp.cloudflare.com",
	}

	result := InternetCheckResult{
		Accessible:    false,
		TargetResults: make(map[string]string),
		CheckTime:     time.Now(),
	}

	client := &http.Client{
		Timeout: 8 * time.Second,
		// 不跟随重定向，只检查是否能拿到响应
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for _, target := range targets {
		resp, err := client.Get(target)
		if err != nil {
			result.TargetResults[target] = fmt.Sprintf("error: %v", err)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			result.TargetResults[target] = "ok"
			result.Accessible = true
		} else {
			result.TargetResults[target] = fmt.Sprintf("http %d", resp.StatusCode)
		}
	}

	return result
}

// MonitorStatus 监控状态
type MonitorStatus struct {
	ProcessRunning bool      // SingBox进程是否运行
	DaemonRunning  bool      // 守护进程是否运行
	CheckTime      time.Time // 检查时间
}

// GetStatus 获取状态信息
func (m *Monitor) GetStatus() MonitorStatus {
	return MonitorStatus{
		ProcessRunning: IsSingBoxRunning(),
		DaemonRunning:  IsDaemonRunning(),
		CheckTime:      time.Now(),
	}
}

// String 返回状态的字符串表示
func (ms MonitorStatus) String() string {
	var status []string

	if ms.DaemonRunning {
		status = append(status, "Daemon: Running ✓")
	} else {
		status = append(status, "Daemon: Stopped ✗")
	}

	if ms.ProcessRunning {
		status = append(status, "SingBox: Running ✓")
	} else {
		status = append(status, "SingBox: Stopped ✗")
	}

	if !ms.CheckTime.IsZero() {
		status = append(status, fmt.Sprintf("Last check: %s", ms.CheckTime.Format("15:04:05")))
	}

	return strings.Join(status, "\n├─ ")
}
