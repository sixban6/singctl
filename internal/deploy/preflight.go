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
			}
			if report.DNSMatches {
				logger.Success("  ✓ 域名 %s 解析与当前服务器公网 IP 匹配 (%s)", domain, strings.Join(ipStrs, ", "))
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
