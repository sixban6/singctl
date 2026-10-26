package gfw

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// probePorts 探测端口与基础服务画像（满分 15 分）
func probePorts(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "基础端口与服务画像探测",
		MaxScore: 15,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// 1. 检查 80 与 443 端口状态
	p80Open := isPortOpen(opts.IP, 80, timeout)
	p443Open := isPortOpen(opts.IP, 443, timeout)

	itemPort80 := CheckItem{
		Name:        "80/443 端口对称性分析",
		Description: "分析公网 Web 标准端口开放状态",
		MaxScore:    10,
	}

	if p443Open && !p80Open {
		itemPort80.Score = 10
		itemPort80.Passed = false
		itemPort80.Details = "端口 443 开放，但端口 80 关闭/超时。正常商业 Web 站点几乎 100% 开放 80 端口用于 ACME 与 HTTP 跳转，只有 443 开放具备极高的翻墙特征。"
		itemPort80.Mitigation = "在服务器放行 80 端口，并由 Caddy/Nginx 提供 80 到 443 的 301 重定向。"
	} else if !p443Open && !p80Open {
		itemPort80.Score = 0
		itemPort80.Passed = false
		itemPort80.Details = "80 与 443 端口均不可达，可能服务器未运行或防火墙已拦截。"
	} else {
		itemPort80.Score = 0
		itemPort80.Passed = true
		itemPort80.Details = fmt.Sprintf("80 端口 (%v), 443 端口 (%v) 状态符合常见公网服务器标准。", p80Open, p443Open)
	}
	cat.Items = append(cat.Items, itemPort80)

	// 2. HTTP 到 HTTPS 规范跳转检测
	itemRedirect := CheckItem{
		Name:        "HTTP 80 到 HTTPS 443 重定向合规度",
		Description: "检测端口 80 是否返回规范的 301/302/308 重定向",
		MaxScore:    5,
	}

	if p80Open {
		redirects, targetURL, err := checkHTTPRedirect(opts.IP, timeout)
		if err != nil || !redirects {
			itemRedirect.Score = 5
			itemRedirect.Passed = false
			itemRedirect.Details = fmt.Sprintf("80 端口未返回到 HTTPS 的重定向响应 (状态: %v, 目标: %s)", err, targetURL)
			itemRedirect.Mitigation = "配置 Caddy 对 80 端口全部请求返回 308/301 强制跳转至 HTTPS。"
		} else {
			itemRedirect.Score = 0
			itemRedirect.Passed = true
			itemRedirect.Details = fmt.Sprintf("80 端口正确重定向至 HTTPS (Location: %s)", targetURL)
		}
	} else {
		itemRedirect.Score = 0
		itemRedirect.Passed = true
		itemRedirect.Details = "80 端口未开放，已在上一项计入特征，本项跳过。"
	}
	cat.Items = append(cat.Items, itemRedirect)

	// 3. 敏感代理/面板管理端口暴露检测
	sensitivePorts := []int{7895, 9090, 9091, 2080, 1080}
	var exposed []int
	for _, port := range sensitivePorts {
		if isPortOpen(opts.IP, port, 1500*time.Millisecond) {
			exposed = append(exposed, port)
		}
	}

	itemSensitive := CheckItem{
		Name:        "敏感代理管理端口暴露扫描",
		Description: "扫描 7895(tproxy), 9090(clash api), 9091(api), 2080(mixed), 1080(socks)",
		MaxScore:    15,
	}

	if len(exposed) > 0 {
		itemSensitive.Score = min(15, len(exposed)*5)
		itemSensitive.Passed = false
		itemSensitive.Details = fmt.Sprintf("公网暴露了敏感端口: %v，直接泄露了代理程序运行痕迹！", exposed)
		itemSensitive.Mitigation = "在 Linux 防火墙 (nftables/ufw) 中阻断非信任 IP 对上述管理端口的访问，或仅监听 127.0.0.1。"
	} else {
		itemSensitive.Score = 0
		itemSensitive.Passed = true
		itemSensitive.Details = "未在公网探测到常见的代理入站与管理端口暴露。"
	}
	cat.Items = append(cat.Items, itemSensitive)

	// 统计当前分类总分
	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func checkHTTPRedirect(ip string, timeout time.Duration) (bool, string, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(fmt.Sprintf("http://%s/", ip))
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	loc := resp.Header.Get("Location")
	if (resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 307 || resp.StatusCode == 308) &&
		strings.HasPrefix(strings.ToLower(loc), "https://") {
		return true, loc, nil
	}

	return false, loc, nil
}
