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
	"singctl/internal/constant"
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

// IsServerEnvironment 判断当前主机/配置是否处于服务端部署模式
func IsServerEnvironment(cfg *config.Config) bool {
	if _, err := os.Stat("/etc/caddy/Caddyfile"); err == nil {
		return true
	}
	if _, err := os.Stat("/etc/sub-store"); err == nil {
		return true
	}
	if cfg != nil {
		domain := cfg.Server.GetNodeDomain()
		if domain != "" && domain != "node.yourdomain.com" {
			return true
		}
		if cfg.Server.GetWebAdminPath() != "" {
			return true
		}
	}
	return false
}

// RunDoctor 根据当前环境自动识别服务端或客户端模式并执行体检
func RunDoctor(cfg *config.Config) *DoctorReport {
	if IsServerEnvironment(cfg) {
		return RunServerDoctor(cfg)
	}
	return RunClientDoctor(cfg)
}

// RunServerDoctor 执行服务端全链路体检
func RunServerDoctor(cfg *config.Config) *DoctorReport {
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

	finalizeReport(report, "🎉 系统运行状态极佳！所有核心组件、TLS 证书与高可用链路均处于健康状态。")
	return report
}

// RunClientDoctor 执行客户端透明代理/桌面网关模式体检
func RunClientDoctor(cfg *config.Config) *DoctorReport {
	report := &DoctorReport{
		Score:     100,
		CheckedAt: time.Now().Format("2006-01-02 15:04:05"),
		Items:     make([]DoctorItem, 0),
	}

	// 1. 系统基础环境
	checkSystem(report)

	// 2. Linux 内核下顺带检查 BBR
	if runtime.GOOS == "linux" {
		checkBBR(report)
	}

	// 3. 客户端订阅配置检查
	hasValidSub := false
	if cfg != nil {
		for _, sub := range cfg.Subs {
			if strings.TrimSpace(sub.URL) != "" {
				hasValidSub = true
				break
			}
		}
	}
	if hasValidSub {
		report.Items = append(report.Items, DoctorItem{
			Name:     "客户端订阅配置",
			Category: "system",
			Status:   "ok",
			Summary:  fmt.Sprintf("已配置 %d 个订阅源", len(cfg.Subs)),
		})
	} else {
		report.Items = append(report.Items, DoctorItem{
			Name:     "客户端订阅配置",
			Category: "system",
			Status:   "warn",
			Summary:  "尚未配置有效订阅链接 (subs.url)",
			Detail:   "若作为客户端使用，请编辑 singctl.yaml 填入订阅地址；若为服务端请运行 'singctl sr doctor'",
		})
	}

	// 4. 客户端 sing-box 配置与进程状态
	if _, err := os.Stat(constant.SingBoxConfigFile); err == nil {
		if isServiceActive("sing-box") {
			report.Items = append(report.Items, DoctorItem{
				Name:     "sing-box 客户端核心",
				Category: "services",
				Status:   "ok",
				Summary:  "配置文件就绪且 sing-box 正在运行",
			})
		} else {
			report.Items = append(report.Items, DoctorItem{
				Name:     "sing-box 客户端核心",
				Category: "services",
				Status:   "warn",
				Summary:  "配置文件已生成，但 sing-box 当前未运行",
				Detail:   "可执行 'singctl sb start' 启动客户端代理",
			})
		}
	} else {
		report.Items = append(report.Items, DoctorItem{
			Name:     "sing-box 客户端核心",
			Category: "services",
			Status:   "warn",
			Summary:  "未检测到客户端配置 (" + constant.SingBoxConfigFile + ")",
			Detail:   "可执行 'singctl sb install && singctl sb start' 初始化客户端",
		})
	}

	// 5. 本地控制面端口探测 (Clash API 9090 / Web 面板 8090)
	var activeLocalPorts []int
	for _, p := range []int{9090, 8090} {
		if conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 300*time.Millisecond); err == nil {
			_ = conn.Close()
			activeLocalPorts = append(activeLocalPorts, p)
		}
	}
	if len(activeLocalPorts) > 0 {
		report.Items = append(report.Items, DoctorItem{
			Name:     "本地控制面板监听",
			Category: "network",
			Status:   "ok",
			Summary:  fmt.Sprintf("已检测到本地控制端口 (%s) 在线", joinInts(activeLocalPorts)),
		})
	}

	// 6. 基础外网连通性探测
	client := &http.Client{Timeout: 3 * time.Second}
	start := time.Now()
	if resp, err := client.Get("https://cp.cloudflare.com/generate_204"); err == nil {
		_ = resp.Body.Close()
		report.Items = append(report.Items, DoctorItem{
			Name:     "外网 HTTPS 连通性",
			Category: "network",
			Status:   "ok",
			Summary:  fmt.Sprintf("Cloudflare 连通探测正常 (延迟: %d ms)", time.Since(start).Milliseconds()),
		})
	} else {
		report.Items = append(report.Items, DoctorItem{
			Name:     "外网 HTTPS 连通性",
			Category: "network",
			Status:   "warn",
			Summary:  "无法直连 cp.cloudflare.com",
			Detail:   err.Error(),
		})
	}

	finalizeReport(report, "🎉 客户端运行环境健康，代理与网络组件状态良好。")
	return report
}

func finalizeReport(report *DoctorReport, healthyMsg string) {
	var fails, warns int
	for _, item := range report.Items {
		if item.Status == "fail" {
			fails++
		} else if item.Status == "warn" {
			warns++
		}
	}
	report.Score = max(0, 100-(fails*20)-(warns*5))

	if fails == 0 && warns == 0 {
		report.Summary = healthyMsg
	} else if fails == 0 {
		report.Summary = fmt.Sprintf("⚠️ 系统整体可用，但发现 %d 项次要警告，建议排查优化。", warns)
	} else {
		report.Summary = fmt.Sprintf("❌ 检测到 %d 项严重异常与 %d 项警告，部分代理或网关链路可能受阻，请根据下方详情排查！", fails, warns)
	}
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
		id       string
		name     string
		fixGuide string
	}{
		{"caddy", "Caddy 网关", "systemctl restart caddy"},
		{"sing-box", "sing-box 核心", "systemctl restart sing-box"},
		{"singctl-sub", "SubHub 订阅引擎", "systemctl restart singctl-sub"},
		{"wireproxy", "WARP (wireproxy)", "systemctl restart wireproxy"},
	}

	for _, s := range services {
		active := isServiceActive(s.id)
		if active {
			r.Items = append(r.Items, DoctorItem{
				Name:     s.name,
				Category: "services",
				Status:   "ok",
				Summary:  "服务处于活跃运行状态 (active)",
			})
		} else {
			r.Items = append(r.Items, DoctorItem{
				Name:     s.name,
				Category: "services",
				Status:   "warn",
				Summary:  "服务未运行或未启动 (inactive)",
				Detail:   fmt.Sprintf("可尝试在控制台或终端运行: %s", s.fixGuide),
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
	resp, err := client.Get("http://127.0.0.1:3001/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		resp, err = client.Get("http://127.0.0.1:3001/")
	}
	if err == nil && resp.StatusCode == http.StatusOK {
		defer resp.Body.Close()
		r.Items = append(r.Items, DoctorItem{
			Name:     "SubHub 订阅聚合",
			Category: "services",
			Status:   "ok",
			Summary:  "本地 3001 端口原生引擎响应正常 (HTTP 200)",
		})
	} else {
		if resp != nil {
			_ = resp.Body.Close()
		}
		r.Items = append(r.Items, DoctorItem{
			Name:     "SubHub 订阅聚合",
			Category: "services",
			Status:   "warn",
			Summary:  "本地 3001 端口未响应",
			Detail:   "可执行 'singctl sr sub restart' 或 'systemctl status singctl-sub' 检查状态",
		})
	}
}

func checkWARPAndUnlock(r *DoctorReport) {
	unlock := CheckMediaUnlock()

	// 1. VPS 原生出口
	directSummary := formatProfileSummary(&unlock.Direct)
	r.Items = append(r.Items, DoctorItem{
		Name:     "VPS 原生出口画像",
		Category: "network",
		Status:   "ok",
		Summary:  directSummary,
		Detail:   fmt.Sprintf("出口公网 IP: %s (%s)", unlock.Direct.ExitIP, unlock.Direct.ExitLoc),
	})

	// 2. WARP 分流出口
	if unlock.WARP.Available {
		warpSummary := formatProfileSummary(&unlock.WARP)
		r.Items = append(r.Items, DoctorItem{
			Name:     "WARP 分流出口画像",
			Category: "network",
			Status:   "ok",
			Summary:  warpSummary,
			Detail:   fmt.Sprintf("出口公网 IP: %s (%s)", unlock.WARP.ExitIP, unlock.WARP.ExitLoc),
		})
	} else {
		r.Items = append(r.Items, DoctorItem{
			Name:     "WARP 分流出口画像",
			Category: "network",
			Status:   "warn",
			Summary:  "WARP 服务未运行或 40000 端口未就绪",
			Detail:   "若需要海外流媒体/AI 解锁增强，可运行 'singctl sr install warp'",
		})
	}
}

func formatProfileSummary(p *ExitProfile) string {
	list := []string{}
	if p.OpenAI.Status == "unlocked" {
		loc := p.OpenAI.Region
		if loc == "" {
			loc = "OK"
		}
		list = append(list, fmt.Sprintf("OpenAI [%s]", loc))
	} else {
		list = append(list, "OpenAI [受阻]")
	}

	if p.Netflix.Status == "unlocked" {
		list = append(list, "Netflix [完整解锁]")
	} else if p.Netflix.Status == "partially_unlocked" {
		list = append(list, "Netflix [仅自制剧]")
	} else {
		list = append(list, "Netflix [未解锁]")
	}

	if p.YouTube.Status == "unlocked" {
		list = append(list, "YouTube [原生]")
	}
	if p.Google.Status == "unlocked" {
		list = append(list, "Google [无验证码]")
	}

	return strings.Join(list, " | ")
}

func isServiceActive(serviceName string) bool {
	// 针对 SubHub 原生订阅引擎: 优先检查 singctl-sub systemd 服务及本地 3001 端口
	if serviceName == "singctl-sub" || serviceName == "substore" || serviceName == "sub-store" {
		if out, err := exec.Command("systemctl", "is-active", "singctl-sub").Output(); err == nil {
			if strings.TrimSpace(string(out)) == "active" {
				return true
			}
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:3001", 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}

	// 针对 WARP: 检查 wireproxy 或 warp-svc 或 40000 端口
	if serviceName == "wireproxy" {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if out, err := exec.Command("systemctl", "is-active", "warp-svc").Output(); err == nil && strings.TrimSpace(string(out)) == "active" {
			return true
		}
	}

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
