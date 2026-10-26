package gfw

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// probeHTTP 探测 HTTP 规范与回落伪装测试（满分 20 分）
func probeHTTP(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "HTTP 规范与回落伪装测试",
		MaxScore: 20,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// 1. 直接以 IP 访问 HTTP/HTTPS 根路径探测
	itemDirect := CheckItem{
		Name:        "裸 IP 访问与伪装页面真实性",
		Description: "模拟扫描器直接以 IP 作为 Host 访问 443/80 端口",
		MaxScore:    15,
	}

	directResult, isProxyFeature, err := testDirectIPAccess(opts.IP, timeout)
	if isProxyFeature {
		itemDirect.Score = 15
		itemDirect.Passed = false
		itemDirect.Details = fmt.Sprintf("直接以 IP 访问触发代理特征: %s", directResult)
		itemDirect.Mitigation = "请确保配置了真实静态博客站点，并保证 Caddyfile 中对直接 IP 访问能正常输出伪装网页，而非代理报错或空白连接。"
	} else if err != nil {
		itemDirect.Score = 5
		itemDirect.Passed = false
		itemDirect.Details = fmt.Sprintf("直接以 IP 访问连接失败或超时: %v", err)
		itemDirect.Mitigation = "检查 Caddy / Web 服务器是否在监听并正确处理直接 IP 请求。"
	} else {
		itemDirect.Score = 0
		itemDirect.Passed = true
		itemDirect.Details = fmt.Sprintf("直接以 IP 访问返回合法 Web 站点响应: %s", directResult)
	}
	cat.Items = append(cat.Items, itemDirect)

	// 2. 畸形 HTTP / 非法 Method 探测
	itemMalformed := CheckItem{
		Name:        "畸形 HTTP 报文容错合规性",
		Description: "发送非标或超长非法请求头，检验服务端是否返回标准 RFC 400 响应",
		MaxScore:    5,
	}

	malformedPass, malformedDetails := testMalformedHTTPRequest(opts.IP, timeout)
	if !malformedPass {
		itemMalformed.Score = 5
		itemMalformed.Passed = false
		itemMalformed.Details = malformedDetails
		itemMalformed.Mitigation = "使用合规的 Web 服务器（如 Caddy/Nginx），确保底层协议栈严格遵循 RFC 7230 错误处理规范。"
	} else {
		itemMalformed.Score = 0
		itemMalformed.Passed = true
		itemMalformed.Details = malformedDetails
	}
	cat.Items = append(cat.Items, itemMalformed)

	// 统计当前分类总分
	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

// testDirectIPAccess 检查裸 IP 访问行为
func testDirectIPAccess(ip string, timeout time.Duration) (string, bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         ip,
		},
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	// 优先测试 HTTPS 443
	resp, err := client.Get(fmt.Sprintf("https://%s/", ip))
	if err != nil {
		// 回退尝试 HTTP 80
		httpResp, httpErr := client.Get(fmt.Sprintf("http://%s/", ip))
		if httpErr != nil {
			return "", false, err
		}
		resp = httpResp
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 10240))
	bodyStr := string(bodyBytes)

	// 检测特征：Sub-Store 关键词、sing-box 关键词、空白无内容、或明显代理报错
	lower := strings.ToLower(bodyStr)
	if strings.Contains(lower, "sub-store") || strings.Contains(lower, "substore") {
		return "检测到 Sub-Store 面板直接对公网裸露！", true, nil
	}
	if strings.Contains(lower, "sing-box") || strings.Contains(lower, "vless") || strings.Contains(lower, "hysteria") {
		return "页面中直接包含代理软件名称！", true, nil
	}
	if resp.StatusCode == 200 && len(strings.TrimSpace(bodyStr)) == 0 {
		return "返回 200 OK 但内容完全为空白", true, nil
	}

	serverHeader := resp.Header.Get("Server")
	contentType := resp.Header.Get("Content-Type")

	return fmt.Sprintf("状态码: %d, Server: %q, Content-Type: %q, 页面大小: %d 字节",
		resp.StatusCode, serverHeader, contentType, len(bodyBytes)), false, nil
}

// testMalformedHTTPRequest 发送非标畸形请求
func testMalformedHTTPRequest(ip string, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "80"), timeout)
	if err != nil {
		// 如果 80 端口关闭，尝试 443 明文发送（测试 400 Plain HTTP sent to HTTPS port）
		conn, err = net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), timeout)
		if err != nil {
			return true, "无法连接端口执行畸形测试，跳过"
		}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// 发送语法畸形请求（缺少冒号的非法报文头部），检验服务端是否返回标准 RFC 400 响应
	malformedReq := "GET / HTTP/1.1\r\nHost: " + ip + "\r\nInvalidHeaderWithoutColon\r\n\r\n"
	if _, err := conn.Write([]byte(malformedReq)); err != nil {
		return false, fmt.Sprintf("写入畸形请求失败: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return false, fmt.Sprintf("未收到任何响应直接断开 (EOF/RST): %v", err)
	}

	statusLine = strings.TrimSpace(statusLine)
	if strings.Contains(statusLine, "400") || strings.Contains(statusLine, "405") || strings.Contains(statusLine, "501") {
		return true, fmt.Sprintf("服务端底层协议栈符合 RFC 规范，正确响应: %s", statusLine)
	}

	if strings.Contains(statusLine, "301") || strings.Contains(statusLine, "302") || strings.Contains(statusLine, "307") || strings.Contains(statusLine, "308") {
		return true, fmt.Sprintf("服务端运行规范的 HTTP->HTTPS 重定向网关 (%s)，符合主流 Web 服务器标准", statusLine)
	}

	return false, fmt.Sprintf("服务端对非法请求返回了非标准响应: %s", statusLine)
}
