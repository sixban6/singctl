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

	httpPort := opts.GetHTTPPort()
	httpsPort := opts.GetHTTPSPort()

	// 1. 检查 HTTP 与 HTTPS 端口状态
	pHTTPOpen := isPortOpen(ctx, opts.IP, httpPort, timeout)
	pHTTPSOpen := isPortOpen(ctx, opts.IP, httpsPort, timeout)

	itemPortSymmetry := CheckItem{
		Name:        fmt.Sprintf("%d/%d 端口对称性分析", httpPort, httpsPort),
		Description: "分析公网 Web 标准端口开放状态",
		MaxScore:    10,
	}

	if pHTTPSOpen && !pHTTPOpen {
		itemPortSymmetry.Score = 10
		itemPortSymmetry.Passed = false
		itemPortSymmetry.Details = fmt.Sprintf("端口 %d (HTTPS) 开放，但端口 %d (HTTP) 关闭/超时。正常商业 Web 站点几乎 100%% 开放标准 HTTP 端口用于证书 ACME 挑战与协议跳转，只有 HTTPS 开放具备极高的翻墙特征。", httpsPort, httpPort)
		itemPortSymmetry.Mitigation = fmt.Sprintf("在服务器防火墙放行 %d 端口，并由 Web 服务器 (Caddy/Nginx) 提供强制重定向至 HTTPS。", httpPort)
	} else if !pHTTPSOpen && !pHTTPOpen {
		itemPortSymmetry.Score = 0
		itemPortSymmetry.Passed = false
		itemPortSymmetry.Details = fmt.Sprintf("%d 与 %d 端口均不可达，可能服务器未运行或防火墙已拦截。", httpPort, httpsPort)
	} else {
		itemPortSymmetry.Score = 0
		itemPortSymmetry.Passed = true
		itemPortSymmetry.Details = fmt.Sprintf("%d 端口 (%v), %d 端口 (%v) 状态符合公网服务器标准。", httpPort, pHTTPOpen, httpsPort, pHTTPSOpen)
	}
	cat.Items = append(cat.Items, itemPortSymmetry)

	// 2. HTTP 到 HTTPS 规范跳转检测
	itemRedirect := CheckItem{
		Name:        fmt.Sprintf("HTTP %d 到 HTTPS 重定向合规度", httpPort),
		Description: fmt.Sprintf("检测端口 %d 是否返回规范的 301/302/307/308 重定向", httpPort),
		MaxScore:    5,
	}

	if pHTTPOpen {
		redirects, targetURL, err := checkHTTPRedirect(ctx, opts.IP, httpPort, timeout)
		if err != nil || !redirects {
			itemRedirect.Score = 5
			itemRedirect.Passed = false
			itemRedirect.Details = fmt.Sprintf("%d 端口未返回到 HTTPS 的重定向响应 (状态: %v, 目标: %s)", httpPort, err, targetURL)
			itemRedirect.Mitigation = "配置 Caddy / Web 服务器对 HTTP 端口全部请求返回 308/301 强制跳转至 HTTPS。"
		} else {
			itemRedirect.Score = 0
			itemRedirect.Passed = true
			itemRedirect.Details = fmt.Sprintf("%d 端口正确重定向至 HTTPS (Location: %s)", httpPort, targetURL)
		}
	} else {
		itemRedirect.Score = 0
		itemRedirect.Passed = true
		itemRedirect.Details = fmt.Sprintf("%d 端口未开放，已在前项计入特征，本项跳过。", httpPort)
	}
	cat.Items = append(cat.Items, itemRedirect)

	// 3. 敏感代理/面板管理端口暴露检测
	// 首先通过随机金丝雀高位端口检测当前测试客户端是否处于软路由/透明代理全端口劫持环境中
	canaryPort := 59183
	isTransparentProxy := isPortOpen(ctx, opts.IP, canaryPort, 800*time.Millisecond)

	sensitivePorts := []int{7895, 9090, 9091, 2080, 1080}
	var exposed []int
	for _, port := range sensitivePorts {
		if isPortOpen(ctx, opts.IP, port, 1500*time.Millisecond) {
			exposed = append(exposed, port)
		}
	}

	itemSensitive := CheckItem{
		Name:        "敏感代理管理端口暴露扫描",
		Description: "扫描 7895(tproxy), 9090(clash api), 9091(api), 2080(mixed), 1080(socks)",
		MaxScore:    15,
	}

	if isTransparentProxy {
		itemSensitive.Score = 0
		itemSensitive.Passed = true
		itemSensitive.Details = fmt.Sprintf("检测到当前测试客户端处于透明代理/软路由全端口拦截环境中 (金丝雀端口 %d 异常联通)，已自动规避假阳性误报。建议在直连网络中复测。", canaryPort)
	} else if len(exposed) > 0 {
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

func isPortOpen(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func checkHTTPRedirect(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := fmt.Sprintf("http://%s/", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, "", err
	}
	resp, err := client.Do(req)
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
