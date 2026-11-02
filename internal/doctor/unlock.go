package doctor

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ServiceUnlockStatus 单个流媒体/AI 服务解锁状态
type ServiceUnlockStatus struct {
	Status  string `json:"status"`            // "unlocked" | "partially_unlocked" | "locked" | "error"
	Region  string `json:"region,omitempty"`  // e.g. "US", "SG", "JP"
	Details string `json:"details,omitempty"` // 描述信息
}

// MediaUnlockReport 流媒体与 AI 解锁测试报告
type MediaUnlockReport struct {
	OpenAI    ServiceUnlockStatus `json:"openai"`
	Netflix   ServiceUnlockStatus `json:"netflix"`
	YouTube   ServiceUnlockStatus `json:"youtube"`
	Disney    ServiceUnlockStatus `json:"disney"`
	Google    ServiceUnlockStatus `json:"google"`
	TestedAt  string              `json:"testedAt"`
	ProxyUsed string              `json:"proxyUsed,omitempty"`
}

// getHTTPClient 获取测试用 HTTP 客户端 (若 WARP 40000 监听则通过 WARP，否则直连)
func getHTTPClient(timeout time.Duration) (*http.Client, string) {
	proxyUsed := "direct"
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 15 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: timeout,
	}

	// 检查 WARP SOCKS5 是否在 127.0.0.1:40000 运行
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 500*time.Millisecond); err == nil {
		_ = conn.Close()
		if socksURL, err := url.Parse("socks5://127.0.0.1:40000"); err == nil {
			transport.Proxy = http.ProxyURL(socksURL)
			proxyUsed = "WARP (SOCKS5 127.0.0.1:40000)"
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, proxyUsed
}

// CheckMediaUnlock 并发检测主要流媒体与 AI 服务解锁情况
func CheckMediaUnlock() *MediaUnlockReport {
	client, proxyUsed := getHTTPClient(5 * time.Second)
	report := &MediaUnlockReport{
		TestedAt:  time.Now().Format("2006-01-02 15:04:05"),
		ProxyUsed: proxyUsed,
	}

	var wg sync.WaitGroup
	wg.Add(5)

	// 1. OpenAI / ChatGPT
	go func() {
		defer wg.Done()
		report.OpenAI = checkOpenAI(client)
	}()

	// 2. Netflix
	go func() {
		defer wg.Done()
		report.Netflix = checkNetflix(client)
	}()

	// 3. YouTube Premium
	go func() {
		defer wg.Done()
		report.YouTube = checkYouTube(client)
	}()

	// 4. Disney+
	go func() {
		defer wg.Done()
		report.Disney = checkDisney(client)
	}()

	// 5. Google Search
	go func() {
		defer wg.Done()
		report.Google = checkGoogle(client)
	}()

	wg.Wait()
	return report
}

func checkOpenAI(client *http.Client) ServiceUnlockStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://chatgpt.com/cdn-cgi/trace", nil)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		// 回退尝试 api.openai.com
		return ServiceUnlockStatus{Status: "locked", Details: "无法连接 OpenAI 认证节点"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if resp.StatusCode == 403 || strings.Contains(content, "1020") || strings.Contains(content, "cloudflare") && strings.Contains(content, "challenge") {
		return ServiceUnlockStatus{Status: "locked", Details: "受到 Cloudflare 阻断 (403)"}
	}

	region := ""
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "loc=") {
			region = strings.TrimPrefix(line, "loc=")
			break
		}
	}

	if region != "" && region != "CN" && region != "HK" && region != "RU" && region != "IR" {
		return ServiceUnlockStatus{Status: "unlocked", Region: region, Details: "支持完整访问与原生交互"}
	}

	return ServiceUnlockStatus{Status: "locked", Region: region, Details: "当前出口地区受限"}
}

func checkNetflix(client *http.Client) ServiceUnlockStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	// 81280792 为非全区自制版权剧目 (Squid Game / 鱿鱼游戏)
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.netflix.com/title/81280792", nil)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: "探测超时或网络错误"}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return ServiceUnlockStatus{Status: "unlocked", Details: "完整解锁 (支持非自制剧播放)"}
	}

	// 检查自制剧 80018499 (Stranger Things)
	req2, _ := http.NewRequestWithContext(ctx, "GET", "https://www.netflix.com/title/80018499", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	if resp2, err := client.Do(req2); err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode == http.StatusOK {
			return ServiceUnlockStatus{Status: "partially_unlocked", Details: "仅解锁自制剧 (Originals Only)"}
		}
	}

	return ServiceUnlockStatus{Status: "locked", Details: "未解锁或 IP 遭流媒体风控"}
}

func checkYouTube(client *http.Client) ServiceUnlockStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.youtube.com/premium", nil)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: "无法连接 YouTube"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	str := string(body)

	if strings.Contains(str, "Premium is not available in your country") {
		return ServiceUnlockStatus{Status: "locked", Details: "所在地区不支持 Premium"}
	}

	return ServiceUnlockStatus{Status: "unlocked", Details: "原生支持 (无地区限制)"}
}

func checkDisney(client *http.Client) ServiceUnlockStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.disneyplus.com", nil)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: "无法连接 Disney+"}
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 {
		return ServiceUnlockStatus{Status: "locked", Details: "受到地区风控或拦截 (403)"}
	}
	return ServiceUnlockStatus{Status: "unlocked", Details: "支持正常访问"}
}

func checkGoogle(client *http.Client) ServiceUnlockStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.google.com/search?q=singctl", nil)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := client.Do(req)
	if err != nil {
		return ServiceUnlockStatus{Status: "error", Details: "无法连接 Google"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if strings.Contains(content, "detected unusual traffic") || strings.Contains(content, "recaptcha") || resp.StatusCode == 429 {
		return ServiceUnlockStatus{Status: "warn", Details: "触发人机验证 (可能存在滥用记录)"}
	}
	return ServiceUnlockStatus{Status: "unlocked", Details: "正常 (无验证码)"}
}
