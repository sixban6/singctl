package netinfo

import (
	"net/http"
	"singctl/internal/logger"
	"strings"
	"sync"
	"time"
)

const googleCacheTTL = 5 * time.Minute

var (
	googleProbeMu   sync.Mutex
	googleCachedVal bool
	googleCachedAt  time.Time
)

func GetReachableURL(downloadURL string, mirrorURL string) string {
	// 优化下载逻辑：检查Google连通性（带 5 分钟缓存，避免并发探查与日志刷屏）
	if !CheckGoogleConnectivity() {
		if mirrorURL != "" {
			logger.Info("Google is not accessible, using mirror for download...")
			if !strings.HasSuffix(mirrorURL, "/") {
				mirrorURL += "/"
			}
			downloadURL = mirrorURL + downloadURL
		}
	}
	return downloadURL
}

// CheckGoogleConnectivity 检查是否能访问Google（带 5 分钟内存缓存与并发合并）
func CheckGoogleConnectivity() bool {
	googleProbeMu.Lock()
	defer googleProbeMu.Unlock()

	if !googleCachedAt.IsZero() && time.Since(googleCachedAt) < googleCacheTTL {
		return googleCachedVal
	}

	client := http.Client{
		Timeout: 2500 * time.Millisecond,
	}
	resp, err := client.Head("https://www.google.com")
	ok := false
	if err == nil {
		_ = resp.Body.Close()
		ok = resp.StatusCode >= 200 && resp.StatusCode < 400
	}
	googleCachedVal = ok
	googleCachedAt = time.Now()
	return ok
}
