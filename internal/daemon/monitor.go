// 文件职责：通过统一 clashapi 客户端探测 sing-box 进程存活与内部 DNS 解析延迟健康度。
package daemon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
	"singctl/internal/singbox/clashapi"
)

var defaultClashClient = clashapi.NewClient(clashapi.Options{
	RequestTimeout: 5 * time.Second,
})

// Monitor 监控器
type Monitor struct {
	config *config.Config
	clash  *clashapi.Client
}

// NewMonitor 创建监控器
func NewMonitor(cfg *config.Config) *Monitor {
	return &Monitor{
		config: cfg,
		clash:  defaultClashClient,
	}
}

// HealthCheckResult 综合健康检测结果
type HealthCheckResult struct {
	Healthy      bool      // 综合健康状态
	CheckTime    time.Time // 检测时间
	FailedReason string    // 失败原因（空=健康）
	DNSOK        bool      // DNS 解析是否正常
	LatencyMs    int       // Clash API 内部 DNS 查询耗时(毫秒)
	Details      string    // 详细信息
}

// CheckHealth 综合健康检测（进程存活 + Clash API 内部 DNS 解析探活）。
func (m *Monitor) CheckHealth() HealthCheckResult {
	result := HealthCheckResult{
		Healthy:   true,
		CheckTime: time.Now(),
	}

	if !IsSingBoxRunning() {
		result.Healthy = false
		result.FailedReason = "sing-box process not running"
		result.Details = "sing-box 进程未运行"
		return result
	}

	dnsOK, latencyMs, dnsDetail := m.CheckDNSHealthWithLatency()
	result.DNSOK = dnsOK
	result.LatencyMs = latencyMs
	if !dnsOK {
		result.Healthy = false
		result.FailedReason = "dns_stuck"
		result.Details = dnsDetail
		return result
	}

	result.Details = dnsDetail
	return result
}

// CheckDNSHealthWithLatency 通过 sing-box 的 Clash API 检测 DNS 是否正常并返回耗时毫秒。
func (m *Monitor) CheckDNSHealthWithLatency() (ok bool, latencyMs int, detail string) {
	cli := defaultClashClient
	if m != nil && m.clash != nil {
		cli = m.clash
	}
	return cli.QueryDNSAcross(context.Background(), singbox.ClashAPIEndpoints(), singbox.ClashAPISecret(), nil)
}

// CheckDNSHealthAgainstEndpoints 对给定 Clash API 地址池与可选 Bearer Secret 执行内部 DNS 查询探测。
func CheckDNSHealthAgainstEndpoints(endpoints []string, secret string) (ok bool, latencyMs int, detail string) {
	return defaultClashClient.QueryDNSAcross(context.Background(), endpoints, secret, nil)
}

// MonitorStatus 监控状态
type MonitorStatus struct {
	ProcessRunning bool      // SingBox进程是否运行
	DaemonRunning  bool      // 守护进程是否运行
	CheckTime      time.Time // 看门狗最近一次真实巡检时间
}

// GetStatus 获取状态信息（CheckTime 读取看门狗真实持久化巡检时间）。
func (m *Monitor) GetStatus() MonitorStatus {
	var lastCheck time.Time
	snap := LoadRuntimeSnapshot()
	if snap.LastHealthAt != "" {
		if t, err := time.ParseInLocation(time.DateTime, snap.LastHealthAt, time.Local); err == nil {
			lastCheck = t
		}
	}
	return MonitorStatus{
		ProcessRunning: IsSingBoxRunning(),
		DaemonRunning:  IsDaemonRunning(),
		CheckTime:      lastCheck,
	}
}

// String 返回状态的字符串表示。
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
