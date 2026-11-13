package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/singbox"
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
	LatencyMs    int       // Clash API 内部 DNS 查询耗时(毫秒)
	Details      string    // 详细信息
}

// CheckHealth 综合健康检测
//
// 核心检测: 通过 sing-box 的 clash API 直接测试 DNS 解析
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

	// 2. 核心检测: 通过 clash API 测试 DNS（自动附带 secret 鉴权）
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
func (m *Monitor) CheckDNSHealth() (ok bool, detail string) {
	ok, _, detail = m.CheckDNSHealthWithLatency()
	return ok, detail
}

// CheckDNSHealthWithLatency 通过 sing-box 的 clash API 检测 DNS 是否正常并返回耗时毫秒。
func (m *Monitor) CheckDNSHealthWithLatency() (ok bool, latencyMs int, detail string) {
	return CheckDNSHealthAgainstEndpoints(singbox.ClashAPIEndpoints(), singbox.ClashAPISecret())
}

// CheckDNSHealthAgainstEndpoints 对给定 Clash API 地址池与可选 Bearer Secret 执行内部 DNS 查询探测。
func CheckDNSHealthAgainstEndpoints(endpoints []string, secret string) (ok bool, latencyMs int, detail string) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	domains := []string{"cn.bing.com", "www.google.com"}
	var lastErr string

	for _, base := range endpoints {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}
		for _, domain := range domains {
			reqURL := fmt.Sprintf("%s/dns/query?name=%s&type=A", base, domain)
			req, err := http.NewRequest(http.MethodGet, reqURL, nil)
			if err != nil {
				lastErr = fmt.Sprintf("%s: %v", domain, err)
				continue
			}
			if secret != "" {
				req.Header.Set("Authorization", "Bearer "+secret)
			}

			t0 := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				lastErr = fmt.Sprintf("%s: %v", domain, err)
				continue
			}

			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				_ = resp.Body.Close()
				lastErr = fmt.Sprintf("%s: clash API auth rejected (HTTP %d)", domain, resp.StatusCode)
				continue
			}

			var dnsResp clashDNSResponse
			err = json.NewDecoder(resp.Body).Decode(&dnsResp)
			_ = resp.Body.Close()
			if err != nil {
				lastErr = fmt.Sprintf("%s: failed to decode response: %v", domain, err)
				continue
			}

			for _, answer := range dnsResp.Answer {
				if answer.Type == 1 && answer.Data != "" {
					ms := max(1, int(time.Since(t0).Milliseconds()))
					return true, ms, fmt.Sprintf("DNS 正常: %s → %s (%dms)", domain, answer.Data, ms)
				}
			}
			lastErr = fmt.Sprintf("%s: no A record in response (status=%d, answers=%d)", domain, dnsResp.Status, len(dnsResp.Answer))
		}
	}

	return false, 0, fmt.Sprintf("sing-box DNS handler may be stuck: %s (tried %v)", lastErr, endpoints)
}

// MonitorStatus 监控状态
type MonitorStatus struct {
	ProcessRunning bool      // SingBox进程是否运行
	DaemonRunning  bool      // 守护进程是否运行
	CheckTime      time.Time // 看门狗最近一次真实巡检时间
}

// GetStatus 获取状态信息（CheckTime 读取看门狗真实持久化巡检时间，不再伪造当前秒数）
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
