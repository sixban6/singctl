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
	Status  string `json:"status"`            // "unlocked" | "partially_unlocked" | "locked" | "warn" | "error"
	Region  string `json:"region,omitempty"`  // e.g. "US", "SG", "JP"
	Details string `json:"details,omitempty"` // 描述信息
}

// ExitProfile 单个网络出口链路的解锁画像
type ExitProfile struct {
	Name        string              `json:"name"`        // "VPS 原生出口 (Direct)" | "WARP 分流出口 (127.0.0.1:40000)"
	Available   bool                `json:"available"`   // 该出口是否在线
	ExitIP      string              `json:"exitIP"`      // 出口公网 IP
	ExitLoc     string              `json:"exitLoc"`     // 出口国家/地区代码
	OpenAI      ServiceUnlockStatus `json:"openai"`
	Netflix     ServiceUnlockStatus `json:"netflix"`
	YouTube     ServiceUnlockStatus `json:"youtube"`
	Disney      ServiceUnlockStatus `json:"disney"`
	Google      ServiceUnlockStatus `json:"google"`
	ErrorReason string              `json:"errorReason,omitempty"`
}

// MediaUnlockReport 包含双出口 (VPS 原生 vs WARP 分流) 对比画像
type MediaUnlockReport struct {
	Direct   ExitProfile `json:"direct"` // VPS 本机原生出口
	WARP     ExitProfile `json:"warp"`   // WARP 40000 分流出口
	TestedAt string      `json:"testedAt"`
}

// CheckMediaUnlock 并发检测 VPS 原生出口与 WARP 分流出口的双链路解锁能力
func CheckMediaUnlock() *MediaUnlockReport {
	report := &MediaUnlockReport{
		Direct: ExitProfile{
			Name: "VPS 原生直连出口 (Direct)",
		},
		WARP: ExitProfile{
			Name: "WARP 本地分流出口 (127.0.0.1:40000)",
		},
		TestedAt: time.Now().Format("2006-01-02 15:04:05"),
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// 1. 测试 VPS 原生直连出口
	go func() {
		defer wg.Done()
		directClient := newDirectClient(4 * time.Second)
		report.Direct = runExitDiagnostics("VPS 原生直连出口 (Direct)", directClient, false)
	}()

	// 2. 测试 WARP 40000 分流出口
	go func() {
		defer wg.Done()
		conn, err := net.DialTimeout("tcp", "127.0.0.1:40000", 500*time.Millisecond)
		if err != nil {
			report.WARP.Available = false
			report.WARP.ErrorReason = "WARP 服务未运行或 40000 端口未就绪"
			return
		}
		_ = conn.Close()

		warpClient, err := newWarpClient(4 * time.Second)
		if err != nil {
			report.WARP.Available = false
			report.WARP.ErrorReason = err.Error()
			return
		}
		report.WARP = runExitDiagnostics("WARP 本地分流出口 (127.0.0.1:40000)", warpClient, true)
	}()

	wg.Wait()
	return report
}

func newDirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: timeout,
		},
		Timeout: timeout,
	}
}

func newWarpClient(timeout time.Duration) (*http.Client, error) {
	socksURL, err := url.Parse("socks5://127.0.0.1:40000")
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(socksURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: 15 * time.Second,
			}).DialContext,
			ResponseHeaderTimeout: timeout,
		},
		Timeout: timeout,
	}, nil
}

func runExitDiagnostics(name string, client *http.Client, isWarp bool) ExitProfile {
	profile := ExitProfile{
		Name:      name,
		Available: true,
	}

	// 探测出口 IP 与 Loc
	exitIP, loc := probeExitIPAndLoc(client)
	profile.ExitIP = exitIP
	profile.ExitLoc = loc

	var wg sync.WaitGroup
	wg.Add(5)

	go func() {
		defer wg.Done()
		profile.OpenAI = checkOpenAI(client)
	}()

	go func() {
		defer wg.Done()
		profile.Netflix = checkNetflix(client)
	}()

	go func() {
		defer wg.Done()
		profile.YouTube = checkYouTube(client)
	}()

	go func() {
		defer wg.Done()
		profile.Disney = checkDisney(client)
	}()

	go func() {
		defer wg.Done()
		profile.Google = checkGoogle(client)
	}()

	wg.Wait()
	return profile
}

func probeExitIPAndLoc(client *http.Client) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return "", ""
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var ip, loc string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ip=") {
			ip = strings.TrimPrefix(line, "ip=")
		} else if strings.HasPrefix(line, "loc=") {
			loc = strings.TrimPrefix(line, "loc=")
		}
	}
	return ip, loc
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
		return ServiceUnlockStatus{Status: "locked", Details: "无法连接 OpenAI 认证节点"}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	content := string(body)

	if resp.StatusCode == 403 || strings.Contains(content, "1020") || (strings.Contains(content, "cloudflare") && strings.Contains(content, "challenge")) {
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
