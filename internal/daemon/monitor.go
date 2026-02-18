package daemon

import (
	"context"
	"fmt"
	"net"
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
// 核心检测: DNS 解析是否正常（绕过 dnsmasq 缓存，直接走 TProxy → sing-box）
// 辅助检测: HTTP 可达性
//
// 为什么重点测 DNS:
//
//	手机 VPN 开关后, sing-box 的 DNS 处理器可能进入卡死状态.
//	路由器 curl 还能用是因为 dnsmasq 缓存命中, DNS 不经过 sing-box.
//	但客户端的 DNS 请求被 nftables 直接 TProxy 到 sing-box, 全部卡住.
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

	// 2. 核心检测: DNS 解析（绕过 dnsmasq 缓存）
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

// CheckDNSHealth 检测 DNS 解析是否正常
//
// 原理: 使用 Go 的 net.Resolver 直接向 8.8.8.8:53 发送 DNS 查询,
// 绕过路由器本地的 dnsmasq 缓存. 这个 UDP 包从 daemon 进程发出后:
//
//	OUTPUT 链 → 无 fwmark → 被 nftables 标记 fwmark=1 → 策略路由 →
//	table 100 → local default dev lo → TProxy 端口(7895) → sing-box 处理 DNS
//
// 这条路径和 LAN 客户端的 DNS 走的是同一个 sing-box DNS 处理器.
// 如果 sing-box 的 DNS 卡死了, 这个查询也会超时,
// 从而精确检测到 "路由器 curl 能用但客户端全挂" 的场景.
func (m *Monitor) CheckDNSHealth() (ok bool, detail string) {
	// 构造一个绕过 dnsmasq 的 resolver, 直接发到外部 DNS
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	// 测试多个域名，任意一个成功即视为 DNS 正常
	domains := []string{"www.baidu.com", "www.google.com"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, domain := range domains {
		addrs, err := resolver.LookupHost(ctx, domain)
		if err == nil && len(addrs) > 0 {
			return true, fmt.Sprintf("DNS OK: %s → %s", domain, addrs[0])
		}
	}

	// 所有域名都解析失败
	return false, "DNS resolution timed out or failed (sing-box DNS handler may be stuck)"
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
