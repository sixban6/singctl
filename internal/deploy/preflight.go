package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"singctl/internal/config"
	"singctl/internal/logger"
)

// PreflightReport 包含服务端部署前检查的结果
type PreflightReport struct {
	PublicIPv4 string
	PublicIPv6 string
	DNSMatches bool
	DNSErrors  []string
	IsCFProxy  bool
	TokenValid bool
	TokenMsg   string
	BusyPorts  []int
	BBREnabled bool
}

// RunPreflight 执行全量预检
func RunPreflight(cfg *config.Config, fixBBR bool) (*PreflightReport, error) {
	logger.Info("🔍 开始执行服务端部署前环境与网络预检...")
	report := &PreflightReport{}

	// 1. 获取公网 IP
	report.PublicIPv4, report.PublicIPv6 = detectServerPublicIP()
	if report.PublicIPv4 != "" {
		logger.Success("  ✓ 检测到公网 IPv4: %s", report.PublicIPv4)
	} else {
		logger.Warn("  ⚠ 未检测到公网 IPv4 (可能处于纯 IPv6 或 NAT 环境)")
	}
	if report.PublicIPv6 != "" {
		logger.Info("  ➜ 检测到公网 IPv6: %s", report.PublicIPv6)
	}

	// 2. DNS 解析校验
	domain := cfg.Server.GetNodeDomain()
	if domain != "" {
		logger.Info("  ➜ 检查域名解析 [%s]...", domain)
		ips, err := net.LookupIP(domain)
		if err != nil {
			msg := fmt.Sprintf("域名 %s 暂未解析成功: %v", domain, err)
			report.DNSErrors = append(report.DNSErrors, msg)
			logger.Warn("    ⚠ %s (若刚添加 DNS 解析, 请等待解析生效)", msg)
		} else {
			var ipStrs []string
			for _, ip := range ips {
				ipStrs = append(ipStrs, ip.String())
				if ip.String() == report.PublicIPv4 || (report.PublicIPv6 != "" && ip.String() == report.PublicIPv6) {
					report.DNSMatches = true
				}
				if IsCloudflareIP(ip) {
					report.IsCFProxy = true
				}
			}

			if report.IsCFProxy {
				msg := fmt.Sprintf("域名 %s 当前解析到 Cloudflare CDN 代理节点 (已开启小黄云)", domain)
				report.DNSErrors = append(report.DNSErrors, msg)
				logger.Error("    🚨 严重警告: 检测到域名 [%s] 解析为 Cloudflare CDN 节点 IP (%s)！", domain, strings.Join(ipStrs, ", "))
				logger.Warn("    ➜ 影响: Hysteria 2 UDP 流量与 Reality 伪装无法穿透 CDN，且会导致 TLS 证书申请出现重定向循环！")
				logger.Warn("    ➜ 解决方式: 请前往 Cloudflare 控制台 DNS 记录中，将 [%s] 由【已代理 (小黄云)】切换为【仅 DNS (灰云)】！", domain)
			} else if report.DNSMatches {
				logger.Success("  ✓ 域名 %s 解析与当前服务器公网 IP 匹配 (%s) [灰云直连]", domain, strings.Join(ipStrs, ", "))
			} else {
				msg := fmt.Sprintf("域名 %s 解析为 [%s], 与当前公网 IP [%s] 不一致", domain, strings.Join(ipStrs, ", "), report.PublicIPv4)
				report.DNSErrors = append(report.DNSErrors, msg)
				logger.Warn("    ⚠ %s", msg)
				logger.Warn("    提示: 请确认 Cloudflare DNS 是否开启了小黄云(代理), 若用于 Hysteria2 请关闭小黄云(设为仅 DNS 解析)")
			}
		}
	}

	// 3. 校验 Cloudflare API Token
	if cfg.Server.CFDNSKey != "" {
		logger.Info("  ➜ 验证 Cloudflare API Token 权限...")
		valid, msg := verifyCloudflareToken(cfg.Server.CFDNSKey)
		report.TokenValid = valid
		report.TokenMsg = msg
		if valid {
			logger.Success("  ✓ Cloudflare API Token 校验通过: %s", msg)
		} else {
			logger.Warn("  ⚠ Cloudflare API Token 校验异常: %s", msg)
		}
	}

	// 4. 端口占用检测 (80, 443)
	logger.Info("  ➜ 检查 80 与 443 端口状态...")
	report.BusyPorts = checkBusyPorts(80, 443)
	if len(report.BusyPorts) == 0 {
		logger.Success("  ✓ 核心端口 80, 443 空闲可用")
	} else {
		for _, p := range report.BusyPorts {
			logger.Warn("  ⚠ 端口 %d 已被占用 (可能已被现有 caddy/nginx/apache 占用)", p)
		}
	}

	// 5. 检查并开启 BBR
	report.BBREnabled = isBBREnabled()
	if report.BBREnabled {
		logger.Success("  ✓ Linux 内核 TCP BBR 加速已启用")
	} else if fixBBR {
		logger.Info("  ➜ 正在尝试自动开启 TCP BBR 加速...")
		if err := enableBBR(); err != nil {
			logger.Warn("  ⚠ 开启 BBR 失败 (非致命, 可能处于容器沙盒环境): %v", err)
		} else {
			report.BBREnabled = isBBREnabled()
			if report.BBREnabled {
				logger.Success("  ✓ 已成功开启 TCP BBR 加速！")
			}
		}
	}

	logger.Success("预检完成。\n")
	return report, nil
}

func detectServerPublicIP() (ipv4, ipv6 string) {
	client := &http.Client{Timeout: 3 * time.Second}

	// IPv4 探测
	if resp, err := client.Get("https://api.ipify.org"); err == nil {
		defer resp.Body.Close()
		if b, _ := io.ReadAll(resp.Body); len(b) > 0 {
			ip := strings.TrimSpace(string(b))
			if net.ParseIP(ip) != nil {
				ipv4 = ip
			}
		}
	}
	if ipv4 == "" {
		if resp, err := client.Get("https://ip.sb"); err == nil {
			defer resp.Body.Close()
			if b, _ := io.ReadAll(resp.Body); len(b) > 0 {
				ip := strings.TrimSpace(string(b))
				if net.ParseIP(ip) != nil {
					ipv4 = ip
				}
			}
		}
	}

	// IPv6 探测
	if resp, err := client.Get("https://api64.ipify.org"); err == nil {
		defer resp.Body.Close()
		if b, _ := io.ReadAll(resp.Body); len(b) > 0 {
			ip := strings.TrimSpace(string(b))
			parsed := net.ParseIP(ip)
			if parsed != nil && parsed.To4() == nil {
				ipv6 = ip
			}
		}
	}

	return ipv4, ipv6
}

func verifyCloudflareToken(token string) (bool, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.cloudflare.com/client/v4/user/tokens/verify", nil)
	if err != nil {
		return false, err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, "网络请求失败: " + err.Error()
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err.Error()
	}

	type cfVerifyResponse struct {
		Success  bool     `json:"success"`
		Messages []any    `json:"messages"`
		Errors   []any    `json:"errors"`
		Result   struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"result"`
	}

	var res cfVerifyResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return false, "解析 Cloudflare 响应失败"
	}

	if res.Success && res.Result.Status == "active" {
		return true, "Token 有效且处于活跃状态 (Status: active)"
	}
	return false, fmt.Sprintf("Token 无效或权限不足 (HTTP %d)", resp.StatusCode)
}

func checkBusyPorts(ports ...int) []int {
	var busy []int
	for _, p := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			busy = append(busy, p)
		} else {
			_ = ln.Close()
		}
	}
	return busy
}

func isBBREnabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	if err != nil {
		return false
	}
	return strings.Contains(strings.TrimSpace(string(data)), "bbr")
}

// EnableBBR installs and activates the Google BBR TCP congestion control algorithm.
func EnableBBR() error {
	return enableBBR()
}

func enableBBR() error {
	_ = exec.Command("modprobe", "tcp_bbr").Run()

	sysctlPath := "/etc/sysctl.d/99-singctl-bbr.conf"
	content := "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n"
	if err := os.WriteFile(sysctlPath, []byte(content), 0644); err != nil {
		// 回退写入 /etc/sysctl.conf
		f, err := os.OpenFile("/etc/sysctl.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, _ = f.WriteString("\n" + content)
	}

	_ = exec.Command("sysctl", "--system").Run()
	_ = exec.Command("sysctl", "-p").Run()
	return nil
}

// cfCIDRs 包含官方公布的 Cloudflare CDN 边缘代理节点 IP 范围
var cfCIDRs = []string{
	// IPv4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// IPv6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// IsCloudflareIP 检查 IP 是否属于 Cloudflare 代理节点
func IsCloudflareIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range cfCIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil && ipNet.Contains(ip) {
			return true
		}
	}
	return false
}
