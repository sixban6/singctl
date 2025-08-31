package daemon

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
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

// CheckSubscriptionHealth 检查订阅链接健康状态
func (m *Monitor) CheckSubscriptionHealth() (bool, []string) {
	if len(m.config.Subs) == 0 {
		return true, nil // 没有订阅，认为是健康的
	}

	var failedSubs []string
	allHealthy := true

	for _, sub := range m.config.Subs {
		if !m.checkSingleSubscription(sub) {
			failedSubs = append(failedSubs, m.maskSubscriptionURL(sub.URL))
			allHealthy = false
		}
	}

	return allHealthy, failedSubs
}

// checkSingleSubscription 检查单个订阅
func (m *Monitor) checkSingleSubscription(sub config.Subscription) bool {
	if sub.URL == "" {
		return false
	}

	transport := &http.Transport{}
	
	// 如果配置跳过TLS验证，则设置相应的Transport
	if sub.SkipTlsVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	// 发送HEAD请求检查链接可用性
	resp, err := client.Head(sub.URL)
	if err != nil {
		logger.Warn("Subscription check failed: %s - %v", m.maskSubscriptionURL(sub.URL), err)
		return false
	}
	defer resp.Body.Close()

	// 检查HTTP状态码
	if resp.StatusCode >= 400 {
		logger.Warn("Subscription returned error status: %s - %d", m.maskSubscriptionURL(sub.URL), resp.StatusCode)
		return false
	}

	return true
}

// CheckNetworkConnectivity 检查网络连通性
func (m *Monitor) CheckNetworkConnectivity() bool {
	// 检查多个知名DNS服务器的连通性
	testAddresses := []string{
		"8.8.8.8:53",     // Google DNS
		"1.1.1.1:53",     // Cloudflare DNS
		"114.114.114.114:53", // 114 DNS
	}

	for _, addr := range testAddresses {
		if m.testTCPConnection(addr) {
			return true // 只要有一个能连通就认为网络正常
		}
	}

	logger.Warn("Network connectivity check failed - no DNS servers reachable")
	return false
}

// testTCPConnection 测试TCP连接
func (m *Monitor) testTCPConnection(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// maskSubscriptionURL 对订阅URL进行脱敏处理
func (m *Monitor) maskSubscriptionURL(url string) string {
	if url == "" {
		return "未配置"
	}

	// 找到://后的部分
	parts := strings.Split(url, "//")
	if len(parts) < 2 {
		return "***"
	}

	scheme := parts[0] + "//"
	remaining := parts[1]

	// 按/分割获取域名部分
	pathParts := strings.Split(remaining, "/")
	if len(pathParts) == 0 {
		return "***"
	}

	domain := pathParts[0]

	// 域名脱敏，保留第一个字符和顶级域名
	domainParts := strings.Split(domain, ".")
	if len(domainParts) >= 2 {
		if len(domainParts[0]) > 1 {
			domainParts[0] = string(domainParts[0][0]) + strings.Repeat("*", len(domainParts[0])-1)
		}
		domain = strings.Join(domainParts, ".")
	}

	return scheme + domain + "/***"
}

// GetMonitorStatus 获取监控状态信息（包含网络检查）
func (m *Monitor) GetMonitorStatus() MonitorStatus {
	subHealthy, failedSubs := m.CheckSubscriptionHealth()
	networkHealthy := m.CheckNetworkConnectivity()

	return MonitorStatus{
		ProcessRunning:      IsSingBoxRunning(),
		DaemonRunning:       IsDaemonRunning(),
		SubscriptionHealthy: subHealthy,
		NetworkHealthy:      networkHealthy,
		FailedSubscriptions: failedSubs,
		TotalSubscriptions:  len(m.config.Subs),
		CheckTime:           time.Now(),
	}
}

// GetQuickStatus 获取快速状态信息（不进行网络检查）
func (m *Monitor) GetQuickStatus() MonitorStatus {
	return MonitorStatus{
		ProcessRunning:      IsSingBoxRunning(),
		DaemonRunning:       IsDaemonRunning(),
		SubscriptionHealthy: true, // 快速模式不检查订阅
		NetworkHealthy:      true, // 快速模式不检查网络
		FailedSubscriptions: []string{},
		TotalSubscriptions:  len(m.config.Subs),
		CheckTime:           time.Time{}, // 快速模式不显示检查时间
	}
}

// MonitorStatus 监控状态
type MonitorStatus struct {
	ProcessRunning       bool      // SingBox进程是否运行
	DaemonRunning        bool      // 守护进程是否运行
	SubscriptionHealthy  bool      // 订阅是否健康
	NetworkHealthy       bool      // 网络是否连通
	FailedSubscriptions  []string  // 失败的订阅列表
	TotalSubscriptions   int       // 总订阅数
	CheckTime            time.Time // 检查时间
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

	// 只有在有失败的订阅时才显示详细信息
	if len(ms.FailedSubscriptions) > 0 {
		status = append(status, fmt.Sprintf("Subscriptions: %d/%d reachable ✗", 
			ms.TotalSubscriptions-len(ms.FailedSubscriptions), ms.TotalSubscriptions))
	} else {
		if ms.TotalSubscriptions > 0 {
			status = append(status, fmt.Sprintf("Subscriptions: %d configured", ms.TotalSubscriptions))
		}
	}

	// 只有在有真实检查时间时才显示
	if !ms.CheckTime.IsZero() {
		status = append(status, fmt.Sprintf("Last check: %s", ms.CheckTime.Format("15:04:05")))
	}

	return strings.Join(status, "\n├─ ")
}