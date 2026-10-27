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

// probeHTTP 探测 HTTP 规范与回落伪装测试（满分 25 分）
func probeHTTP(ctx context.Context, opts ProbeOptions) Category {
	cat := Category{
		Name:     "HTTP 规范与回落伪装测试",
		MaxScore: 25,
		Items:    make([]CheckItem, 0),
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	httpPort := opts.GetHTTPPort()
	httpsPort := opts.GetHTTPSPort()

	// 1. 直接以 IP 访问 HTTP/HTTPS 根路径探测
	itemDirect := CheckItem{
		Name:        "裸 IP 访问与伪装页面真实性",
		Description: fmt.Sprintf("模拟扫描器直接以 IP 作为 Host 访问 %d/%d 端口", httpsPort, httpPort),
		MaxScore:    10,
	}

	directResult, isProxyFeature, err := testDirectIPAccess(ctx, opts.IP, httpPort, httpsPort, timeout)
	if isProxyFeature {
		itemDirect.Score = 10
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

	malformedPass, malformedDetails := testMalformedHTTPRequest(ctx, opts.IP, httpPort, httpsPort, timeout)
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

	// 3. WebSocket / 常见代理特征分流路径探测
	itemWS := CheckItem{
		Name:        "WebSocket / 代理特征路径探测",
		Description: "针对 /ws, /vless, /ray, /grpc 发送 WebSocket Upgrade 探针，与随机路径对照分析",
		MaxScore:    10,
	}

	hostHeader := opts.Domain
	if hostHeader == "" {
		hostHeader = opts.SNI
	}
	wsPassed, wsScore, wsDetails, wsMitigation := testWebSocketProbePaths(ctx, opts.IP, httpPort, httpsPort, hostHeader, timeout)
	itemWS.Passed = wsPassed
	itemWS.Score = wsScore
	itemWS.Details = wsDetails
	itemWS.Mitigation = wsMitigation
	cat.Items = append(cat.Items, itemWS)

	// 统计当前分类总分
	for _, it := range cat.Items {
		cat.Score += it.Score
	}
	if cat.Score > cat.MaxScore {
		cat.Score = cat.MaxScore
	}

	return cat
}

// testDirectIPAccess 检查裸 IP 访问行为 (RFC 6066 规范：严禁在 SNI 填入 IP 字面量)
func testDirectIPAccess(ctx context.Context, ip string, httpPort, httpsPort int, timeout time.Duration) (string, bool, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			// 根据 RFC 6066 规范，裸 IP 访问不发送 SNI 扩展，ServerName 保持为空
		},
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	// 优先测试 HTTPS
	httpsURL := fmt.Sprintf("https://%s/", net.JoinHostPort(ip, fmt.Sprintf("%d", httpsPort)))
	req, err := http.NewRequestWithContext(ctx, "GET", httpsURL, nil)
	var resp *http.Response
	if err == nil {
		resp, err = client.Do(req)
	}

	if err != nil {
		// 回退尝试 HTTP
		httpURL := fmt.Sprintf("http://%s/", net.JoinHostPort(ip, fmt.Sprintf("%d", httpPort)))
		httpReq, httpErr := http.NewRequestWithContext(ctx, "GET", httpURL, nil)
		if httpErr != nil {
			return "", false, err
		}
		httpResp, httpErr := client.Do(httpReq)
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
func testMalformedHTTPRequest(ctx context.Context, ip string, httpPort, httpsPort int, timeout time.Duration) (bool, string) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", httpPort)))
	if err != nil {
		// 如果 HTTP 端口关闭，尝试 HTTPS 端口明文发送（测试 400 Plain HTTP sent to HTTPS port）
		conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", httpsPort)))
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

// testWebSocketProbePaths 测试常见 WebSocket 代理特征分流路径
func testWebSocketProbePaths(ctx context.Context, ip string, httpPort, httpsPort int, hostHeader string, timeout time.Duration) (bool, int, string, string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         hostHeader,
		},
		DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}

	baseURL := fmt.Sprintf("https://%s", net.JoinHostPort(ip, fmt.Sprintf("%d", httpsPort)))
	// 尝试向基准控制随机路径发送 WebSocket 握手
	controlPath := fmt.Sprintf("/rnd-probe-%x", time.Now().UnixNano()%0xffff)
	controlReq, err := http.NewRequestWithContext(ctx, "GET", baseURL+controlPath, nil)
	if err != nil {
		return true, 0, "创建控制测试请求失败，跳过", ""
	}
	setWSHeaders(controlReq, hostHeader)

	controlResp, err := client.Do(controlReq)
	if err != nil {
		// HTTPS 失败时尝试普通 HTTP
		baseURL = fmt.Sprintf("http://%s", net.JoinHostPort(ip, fmt.Sprintf("%d", httpPort)))
		controlReq, _ = http.NewRequestWithContext(ctx, "GET", baseURL+controlPath, nil)
		setWSHeaders(controlReq, hostHeader)
		controlResp, err = client.Do(controlReq)
		if err != nil {
			return true, 0, "Web 端口无法连接，跳过 WebSocket 路径探测", ""
		}
	}
	defer controlResp.Body.Close()
	controlStatus := controlResp.StatusCode

	// 探测候选代理特征路径
	candidatePaths := []string{"/ws", "/vless", "/ray", "/grpc"}
	for _, path := range candidatePaths {
		select {
		case <-ctx.Done():
			return true, 0, "探测超时中断", ""
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
		if err != nil {
			continue
		}
		setWSHeaders(req, hostHeader)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		statusCode := resp.StatusCode
		resp.Body.Close()

		if statusCode == 101 {
			return false, 10, fmt.Sprintf("路径 %s 响应了 101 Switching Protocols，直接暴露出活跃的 WebSocket 代理服务端！", path),
				"修改 WebSocket 代理路径为高强度随机路径，或使用 mTLS / 凭证校验保护。"
		}

		if (statusCode == 400 || statusCode == 200) && controlStatus == 404 {
			return false, 8, fmt.Sprintf("特征路径 %s 响应 %d，而随机基准路径响应 404，存在明显的分流与后端代理特征！", path, statusCode),
				"在 Caddy/Web 反向代理配置中统一错误回落处理，避免未认证代理路径与正常 404 页面表现差异过大。"
		}
	}

	return true, 0, fmt.Sprintf("测试特征路径 (/ws, /vless, /ray, /grpc) 表现与随机路径一致 (%d)，未暴露异常分流痕迹。", controlStatus), ""
}

func setWSHeaders(req *http.Request, hostHeader string) {
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	if hostHeader != "" {
		req.Host = hostHeader
	}
}
