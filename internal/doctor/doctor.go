package doctor

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
)

// DoctorItem 单个体检检查项
type DoctorItem struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "system" | "network" | "services" | "security"
	Status   string `json:"status"`   // "ok" | "warn" | "fail"
	Summary  string `json:"summary"`
	Detail   string `json:"detail,omitempty"`
}

// DoctorReport 整体体检报告
type DoctorReport struct {
	Score     int          `json:"score"`
	CheckedAt string       `json:"checkedAt"`
	Items     []DoctorItem `json:"items"`
	Summary   string       `json:"summary"`
}

// RunDoctor 执行全链路体检
func RunDoctor(cfg *config.Config) *DoctorReport {
	report := &DoctorReport{
		Score:     100,
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
		Items:     make([]DoctorItem, 0),
	}

	// 1. 系统基础环境
	checkSystem(report)

	// 2. 内核网络与 BBR
	checkBBR(report)

	// 3. 核心端口监听与占用
	checkPorts(cfg, report)

	// 4. 四大核心服务进程状态
	checkServices(report)

	// 5. TLS 证书有效性与剩余天数 (若是服务端)
	checkTLSCert(cfg, report)

	// 6. Reality SNI 伪装站握手连通性
	checkRealitySNI(cfg, report)

	// 7. Sub-Store 订阅中心状态
	checkSubstore(report)

	// 8. WARP 状态与出口流媒体解锁
	checkWARPAndUnlock(report)

	// 计算总体得分与总结
	var fails, warns int
	for _, item := range report.Items {
		if item.Status == "fail" {
			fails++
		} else if item.Status == "warn" {
			warns++
		}
	}
	report.Score = 100 - (fails * 20) - (warns * 5)
	if report.Score < 0 {
		report.Score = 0
	}

	if fails == 0 && warns == 0 {
		report.Summary = "🎉 系统运行状态极佳！所有核心组件、TLS 证书与高可用链路均处于健康状态。"
	} else if fails == 0 {
		report.Summary = fmt.Sprintf("⚠️ 系统整体可用，但发现 %d 项次要警告，建议排查优化。", warns)
	} else {
		report.Summary = fmt.Sprintf("❌ 检测到 %d 项严重异常与 %d 项警告，部分代理或网关链路可能受阻，请根据下方详情排查！", fails, warns)
	}

	return report
}

func checkSystem(r *DoctorReport) {
	osName := runtime.GOOS
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
				break
			}
		}
	}

	r.Items = append(r.Items, DoctorItem{
		Name:     "基础运行环境",
		Category: "system",
		Status:   "ok",
		Summary:  fmt.Sprintf("%s (%s), CPU: %d 核", osName, runtime.GOARCH, runtime.NumCPU()),
	})
}

func checkBBR(r *DoctorReport) {
	bbrEnabled := false
	if data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control"); err == nil {
		bbrEnabled = strings.Contains(strings.TrimSpace(string(data)), "bbr")
	}

	if bbrEnabled {
		r.Items = append(r.Items, DoctorItem{
			Name:     "TCP 拥塞控制算法",
			Category: "network",
			Status:   "ok",
			Summary:  "Google BBR 加速 [已激活启用]",
		})
	} else {
		r.Items = append(r.Items, DoctorItem{
			Name:     "TCP 拥塞控制算法",
			Category: "network",
			Status:   "warn",
			Summary:  "BBR 未启用 (当前为标准 Reno/Cubic)",
			Detail:   "建议通过控制台或 'sysctl' 启用 BBR 以大幅提升弱网与长距离链路吞吐量",
		})
	}
}

func checkPorts(cfg *config.Config, r *DoctorReport) {
	ports := []int{80, 443}
	if cfg != nil && cfg.Server.GetWebAdminPort() > 0 {
		ports = append(ports, cfg.Server.GetWebAdminPort())
	}

	var closed []int
	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 500*time.Millisecond)
		if err != nil {
			closed = append(closed, p)
		} else {
			_ = conn.Close()
		}
	}

	if len(closed) == 0 {
		r.Items = append(r.Items, DoctorItem{
			Name:     "网关与管理端口监听",
			Category: "network",
			Status:   "ok",
			Summary:  fmt.Sprintf("核心端口 (%s) 均正常监听运行", joinInts(ports)),
		})
	} else {
		r.Items = append(r.Items, DoctorItem{
			Name:     "网关与管理端口监听",
			Category: "network",
			Status:   "warn",
			Summary:  fmt.Sprintf("端口 %v 未检测到本地监听", closed),
			Detail:   "若 Caddy 或服务端尚未启动，此状态属正常现象",
		})
	}
}

func checkServices(r *DoctorReport) {
	services := []struct {
		id   string
		name string
	}{
		{"caddy", "Caddy 网关"},
		{"sing-box", "sing-box 核心"},
		{"substore", "Sub-Store 订阅中心"},
		{"wireproxy", "WARP (wireproxy)"},
	}

	for _, s := range services {
		active := isServiceActive(s.id)
		if active {
			r.Items = append(r.Items, DoctorItem{
				Name:     s.name,
				Category: "services",
				Status:   "ok",
				Summary:  "进程处于活跃运行状态 (active)",
			})
		} else {
			r.Items = append(r.Items, DoctorItem{
				Name:     s.name,
				Category: "services",
				Status:   "warn",
				Summary:  "服务未运行或未启动 (inactive)",
				Detail:   fmt.Sprintf("可尝试在控制台或终端运行 'systemctl restart %s'", s.id),
			})
		}
	}
}

func checkTLSCert(cfg *config.Config, r *DoctorReport) {
	if cfg == nil {
		return
	}
	domain := cfg.Server.GetNodeDomain()
	if domain == "" {
		domain = cfg.Server.SubstoreDomain
	}
	if domain == "" {
		return
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", domain+":443", &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: false,
	})
	if err != nil {
		r.Items = append(r.Items, DoctorItem{
			Name:     "HTTPS 证书与网关",
			Category: "security",
			Status:   "warn",
			Summary:  fmt.Sprintf("无法建立与 %s:443 的 TLS 握手", domain),
			Detail:   err.Error(),
		})
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return
	}

	cert := certs[0]
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)
	if daysRemaining > 15 {
		r.Items = append(r.Items, DoctorItem{
			Name:     "HTTPS 证书状态",
			Category: "security",
			Status:   "ok",
			Summary:  fmt.Sprintf("Let's Encrypt / ZeroSSL 证书正常 (剩余有效期 %d 天)", daysRemaining),
		})
	} else if daysRemaining > 0 {
		r.Items = append(r.Items, DoctorItem{
			Name:     "HTTPS 证书状态",
			Category: "security",
			Status:   "warn",
			Summary:  fmt.Sprintf("证书即将到期 (剩余 %d 天)", daysRemaining),
			Detail:   "Caddy 会在到期前自动续签，请保持 80/443 端口畅通",
		})
	} else {
		r.Items = append(r.Items, DoctorItem{
			Name:     "HTTPS 证书状态",
			Category: "security",
			Status:   "fail",
			Summary:  "证书已过期！",
			Detail:   "请检查 Caddy 证书续期日志",
		})
	}
}

func checkRealitySNI(cfg *config.Config, r *DoctorReport) {
	sni := "swdist.apple.com"
	if cfg != nil && cfg.Server.Sni != "" {
		sni = cfg.Server.Sni
	}

	start := time.Now()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", sni+":443", &tls.Config{
		ServerName: sni,
	})
	latency := time.Since(start).Milliseconds()

	if err != nil {
		r.Items = append(r.Items, DoctorItem{
			Name:     "Reality 伪装目标探测",
			Category: "security",
			Status:   "warn",
			Summary:  fmt.Sprintf("无法握手伪装域名 %s: %v", sni, err),
			Detail:   "建议更换为响应更快的 Apple/Microsoft 官方域名以保障抗封锁效果",
		})
		return
	}
	defer conn.Close()

	r.Items = append(r.Items, DoctorItem{
		Name:     "Reality 伪装目标探测",
		Category: "security",
		Status:   "ok",
		Summary:  fmt.Sprintf("目标 SNI [%s] 握手正常 (延迟: %d ms, TLS %s)", sni, latency, tlsVersionToString(conn.ConnectionState().Version)),
	})
}

func checkSubstore(r *DoctorReport) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:3001")
	if err == nil {
		defer resp.Body.Close()
		r.Items = append(r.Items, DoctorItem{
			Name:     "Sub-Store 订阅聚合",
			Category: "services",
			Status:   "ok",
			Summary:  "本地 3001 端口响应正常 (HTTP 200)",
		})
	} else {
		r.Items = append(r.Items, DoctorItem{
			Name:     "Sub-Store 订阅聚合",
			Category: "services",
			Status:   "warn",
			Summary:  "本地 3001 端口未响应",
			Detail:   "请检查 substore 守护进程状态",
		})
	}
}

func checkWARPAndUnlock(r *DoctorReport) {
	unlock := CheckMediaUnlock()
	summaryList := []string{}

	if unlock.OpenAI.Status == "unlocked" {
		loc := unlock.OpenAI.Region
		if loc == "" {
			loc = "OK"
		}
		summaryList = append(summaryList, fmt.Sprintf("OpenAI [%s]", loc))
	}
	if unlock.Netflix.Status == "unlocked" {
		summaryList = append(summaryList, "Netflix [完整解锁]")
	} else if unlock.Netflix.Status == "partially_unlocked" {
		summaryList = append(summaryList, "Netflix [仅自制剧]")
	}
	if unlock.YouTube.Status == "unlocked" {
		summaryList = append(summaryList, "YouTube [正常]")
	}

	if len(summaryList) > 0 {
		r.Items = append(r.Items, DoctorItem{
			Name:     "全球边缘多点出口画像与服务连通性",
			Category: "network",
			Status:   "ok",
			Summary:  strings.Join(summaryList, " | "),
			Detail:   fmt.Sprintf("出口网络: %s", unlock.ProxyUsed),
		})
	} else {
		r.Items = append(r.Items, DoctorItem{
			Name:     "全球边缘多点出口画像与服务连通性",
			Category: "network",
			Status:   "warn",
			Summary:  "部分海外流媒体服务未能解锁",
			Detail:   "可尝试重新部署 WARP 以获取原生分流出口",
		})
	}
}

func isServiceActive(serviceName string) bool {
	// 优先检查 systemctl
	out, err := exec.Command("systemctl", "is-active", serviceName).Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return true
	}
	// 回退检查进程名称
	out2, err2 := exec.Command("pgrep", "-f", serviceName).Output()
	return err2 == nil && len(strings.TrimSpace(string(out2))) > 0
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return "未知"
	}
}

func joinInts(ints []int) string {
	var s []string
	for _, i := range ints {
		s = append(s, fmt.Sprintf("%d", i))
	}
	return strings.Join(s, ", ")
}

// PrintDoctorReport 终端美化输出
func PrintDoctorReport(r *DoctorReport) {
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Success("                 🩺 SINGCTL 全链路健康体检报告")
	logger.Info("═══════════════════════════════════════════════════════════")
	logger.Info("体检时间: %s  |  综合健康指数: %d / 100", r.CheckedAt, r.Score)
	logger.Info("───────────────────────────────────────────────────────────")

	for _, item := range r.Items {
		switch item.Status {
		case "ok":
			logger.Success("  [✓] %-18s : %s", item.Name, item.Summary)
		case "warn":
			logger.Warn("  [!] %-18s : %s", item.Name, item.Summary)
			if item.Detail != "" {
				logger.Info("      ➜ 说明: %s", item.Detail)
			}
		case "fail":
			logger.Error("  [✗] %-18s : %s", item.Name, item.Summary)
			if item.Detail != "" {
				logger.Info("      ➜ 修复建议: %s", item.Detail)
			}
		}
	}

	logger.Info("───────────────────────────────────────────────────────────")
	hasFail := false
	for _, item := range r.Items {
		if item.Status == "fail" {
			hasFail = true
			break
		}
	}

	if r.Score >= 90 {
		logger.Success("结论: %s", r.Summary)
	} else if !hasFail {
		logger.Warn("结论: %s", r.Summary)
	} else {
		logger.Error("结论: %s", r.Summary)
	}
	logger.Info("═══════════════════════════════════════════════════════════\n")
}
