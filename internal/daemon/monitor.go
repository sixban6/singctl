package daemon

import (
	"encoding/json"
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

// HealthCheckResult 综合健康检测结果
type HealthCheckResult struct {
	Healthy      bool      // 综合健康状态
	CheckTime    time.Time // 检测时间
	FailedReason string    // 失败原因（空=健康）
	DNSOK        bool      // DNS 解析是否正常
	Details      string    // 详细信息
}

// CheckHealth 综合健康检测
//
// 核心检测: 通过 sing-box 的 clash API 直接测试 DNS 解析
//
// 为什么不用 net.Resolver 直接发 DNS:
//
//	daemon 进程发出的 DNS 包经 OUTPUT 链标记 fwmark=1 → 策略路由到 lo →
//	但 PREROUTING 链的 "fib daddr type local accept" 规则匹配 →
//	直接放行到 8.8.8.8, 完全绕过了 sing-box 的 TProxy.
//	所以旧方案测的是路由器直连, 不是 sing-box 的 DNS 处理器.
//
// 正确做法: 通过 clash API 的 /dns/query 端点, 让 sing-box 内部执行 DNS 查询.
// 如果 sing-box 的 DNS 卡死, 这个 HTTP 请求会超时或返回空结果.
func (m *Monitor) CheckHealth() HealthCheckResult {
	result := HealthCheckResult{
		Healthy:   true,
		CheckTime: time.Now(),
	}

	// 1. 检查 sing-box 进程是否运行
	if !IsSingBoxRunning() {
		result.Healthy = false
		result.FailedReason = "sing-box process not running"
		result.Details = "sing-box 进程未运行"
		return result
	}

	// 2. 核心检测: 通过 clash API 测试 DNS
	dnsOK, dnsDetail := m.CheckDNSHealth()
	result.DNSOK = dnsOK
	if !dnsOK {
		result.Healthy = false
		result.FailedReason = "dns_stuck"
		result.Details = dnsDetail
		return result
	}

	result.Details = "all checks passed"
	return result
}

// clashDNSResponse clash API /dns/query 的响应结构
type clashDNSResponse struct {
	Status   int  `json:"Status"`
	TC       bool `json:"TC"`
	RD       bool `json:"RD"`
	RA       bool `json:"RA"`
	AD       bool `json:"AD"`
	CD       bool `json:"CD"`
	Question []struct {
		Name string `json:"Name"`
		Type int    `json:"Qtype"`
	} `json:"Question"`
	Answer []struct {
		Name string `json:"Name"`
		Type int    `json:"Type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// CheckDNSHealth 通过 sing-box 的 clash API 检测 DNS 是否正常
//
// 原理: 直接 HTTP 调用 sing-box 的 /dns/query 端点,
// 让 sing-box 内部执行 DNS 查询. 不经过任何 nftables 规则,
// 直接测试 sing-box 的 DNS 处理器是否能正常工作.
//
// 如果 DNS 处理器卡死:
//   - HTTP 请求会超时 → 检测到故障
//   - 或返回空 Answer → 检测到故障
func (m *Monitor) CheckDNSHealth() (ok bool, detail string) {
	// clash API 地址 (sing-box 在 Linux 上监听 0.0.0.0:9090 或 LAN_IP:9090)
	clashAPI := "http://127.0.0.1:9090"

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// 测试多个域名, 任意一个返回 A 记录即视为 DNS 正常
	domains := []string{"www.baidu.com", "www.google.com"}
	var lastErr string

	for _, domain := range domains {
		url := fmt.Sprintf("%s/dns/query?name=%s&type=A", clashAPI, domain)
		resp, err := client.Get(url)
		if err != nil {
			lastErr = fmt.Sprintf("%s: %v", domain, err)
			continue
		}

		var dnsResp clashDNSResponse
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			resp.Body.Close()
			lastErr = fmt.Sprintf("%s: failed to decode response: %v", domain, err)
			continue
		}
		resp.Body.Close()

		// 检查是否有有效的 A 记录 (Type=1)
		for _, answer := range dnsResp.Answer {
			if answer.Type == 1 && answer.Data != "" {
				return true, fmt.Sprintf("DNS OK: %s → %s", domain, answer.Data)
			}
		}
		lastErr = fmt.Sprintf("%s: no A record in response (status=%d, answers=%d)", domain, dnsResp.Status, len(dnsResp.Answer))
	}

	return false, fmt.Sprintf("sing-box DNS handler may be stuck: %s", lastErr)
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
